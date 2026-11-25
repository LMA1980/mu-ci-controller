use chrono::Utc;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn};

use crate::cluster::{ClusterRegistry, WorkerCommand};
use crate::config::Config;
use crate::job::{Job, JobStatus, JobStore, StageRecord, StageStatus};
use crate::storage_backend::{classify_ci_error_message, job_root_trace_context};
use crate::workflow::{ActionRunnerWorkflow, StageConfig, UnavailableAction};
use mu_ci_ipc::{
    NetworkEgressMode, SandboxBackendKind, SandboxConstraintSpec, SccacheMode, StageDispatchTask,
    TypedTaskInvocation,
};
use mu_ci_tools::{SandboxProfileRequirement, ToolInvocation, ToolRegistry};
use mu_observable_ipc::{encode_hex, OtelSpanEntry};

// ============================================================================
// Sub-tasks #37 & #38: ToolAdapter Dispatch & Security Validation
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    #[error("Unapproved or prohibited tool: {0}")]
    UnapprovedTool(String),
    #[error("Task '{0}' not found in workflow tasks")]
    TaskNotFound(String),
    #[error("Stage '{0}' not found in workflow")]
    StageNotFound(String),
}

pub fn sandbox_req_to_ipc_spec(
    profile_name: &str,
    req: &SandboxProfileRequirement,
) -> SandboxConstraintSpec {
    let network_mode = if req.allow_network {
        if req.allowed_egress_hosts.is_empty() {
            NetworkEgressMode::RestrictedCidrs(vec!["0.0.0.0/0".to_string()])
        } else {
            NetworkEgressMode::RestrictedCidrs(req.allowed_egress_hosts.clone())
        }
    } else {
        NetworkEgressMode::Offline
    };

    let read_paths = req
        .readable_dirs
        .iter()
        .filter(|p| p.starts_with('/'))
        .cloned()
        .collect();
    let write_paths = req
        .writable_dirs
        .iter()
        .filter(|p| p.starts_with('/'))
        .cloned()
        .collect();
    let exec_paths = req
        .exec_binaries
        .iter()
        .filter(|p| p.starts_with('/'))
        .cloned()
        .collect();

    SandboxConstraintSpec {
        profile_name: profile_name.to_string(),
        backend: SandboxBackendKind::Kernel,
        read_paths,
        write_paths,
        exec_paths,
        network_mode,
        memlock_limit_kb: req.required_memlock_kb,
        max_pids: 256,
        require_set_ai_thread: false,
    }
}

pub fn build_v3_stage_dispatch_task(
    job_id: &str,
    repo_name: &str,
    clone_url: &str,
    commit_sha: &str,
    stage: &StageConfig,
    workflow: &ActionRunnerWorkflow,
    default_timeout: u64,
) -> Result<StageDispatchTask, DispatchError> {
    let registry = ToolRegistry::with_builtin_adapters();
    let mut typed_tasks = Vec::new();
    let mut stage_timeout = default_timeout;

    for task_id in &stage.tasks {
        let task_cfg = workflow
            .tasks
            .get(task_id)
            .ok_or_else(|| DispatchError::TaskNotFound(task_id.clone()))?;

        // Immediately reject prohibited shell wrappers
        if mu_ci_tools::sanitize::is_prohibited_shell_wrapper(&task_cfg.tool) {
            return Err(DispatchError::UnapprovedTool(format!(
                "Tool '{}' in task '{}' is a prohibited shell wrapper",
                task_cfg.tool, task_id
            )));
        }

        let adapter = registry.get(&task_cfg.tool).map_err(|e| {
            DispatchError::UnapprovedTool(format!(
                "Tool '{}' in task '{}' is not registered: {}",
                task_cfg.tool, task_id, e
            ))
        })?;

        let mut inv = ToolInvocation::new(&task_cfg.tool, task_cfg.args.clone());
        if let Some(ref wd) = task_cfg.working_dir {
            inv = inv.with_working_dir(wd);
        }
        for (k, v) in &task_cfg.env {
            inv = inv.with_env(k, v);
        }

        // Validate invocation arguments via adapter
        adapter.validate(&inv).map_err(|e| {
            DispatchError::UnapprovedTool(format!(
                "Task '{}' validation failed for tool '{}': {}",
                task_id, task_cfg.tool, e
            ))
        })?;

        let sandbox_req = adapter.sandbox_profile(&inv);
        let profile_name = task_cfg.sandbox_profile.as_deref().unwrap_or("default");
        let sandbox_spec = sandbox_req_to_ipc_spec(profile_name, &sandbox_req);

        let env_pairs: Vec<(String, String)> = task_cfg
            .env
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        if let Some(to) = task_cfg.timeout_seconds {
            stage_timeout = stage_timeout.min(to);
        }

        let task_sccache = workflow.resolve_task_sccache(stage, task_cfg);

        typed_tasks.push(TypedTaskInvocation {
            task_id: task_id.clone(),
            tool_name: task_cfg.tool.clone(),
            args: task_cfg.args.clone(),
            working_dir: task_cfg.working_dir.clone(),
            env_vars: env_pairs,
            sandbox: sandbox_spec,
            sccache_mode: task_sccache,
        });
    }

    let command_summary = if typed_tasks.is_empty() {
        stage.name.clone()
    } else {
        typed_tasks
            .iter()
            .map(|t| format!("{} {}", t.tool_name, t.args.join(" ")))
            .collect::<Vec<_>>()
            .join(" && ")
    };

    let sandbox_constraints = typed_tasks
        .first()
        .map(|t| t.sandbox.clone())
        .unwrap_or_default();

    let stage_env_pairs: Vec<(String, String)> = workflow
        .env
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    let stage_sccache = if typed_tasks
        .iter()
        .any(|t| t.sccache_mode == SccacheMode::Mandatory)
    {
        SccacheMode::Mandatory
    } else {
        workflow.resolve_stage_sccache(stage)
    };

    Ok(StageDispatchTask {
        job_id: job_id.to_string(),
        stage_id: stage.id.clone(),
        stage_name: stage.name.clone(),
        repo_name: repo_name.to_string(),
        clone_url: clone_url.to_string(),
        commit_sha: commit_sha.to_string(),
        command: command_summary,
        working_dir: None,
        env_vars: stage_env_pairs,
        timeout_seconds: stage_timeout,
        threads: stage.threads,
        toolchain: stage.toolchain.clone(),
        exclusive: stage.exclusive,
        max_concurrent_per_node: stage.max_concurrent_per_node,
        tasks: typed_tasks,
        sandbox_constraints,
        traceparent: Some(crate::storage_backend::job_root_traceparent(
            job_id, commit_sha,
        )),
        sccache_mode: stage_sccache,
    })
}

// ============================================================================
// Sub-task #27: Declarative ActionRunner.yml Resolver
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedWorkflow {
    V3(ActionRunnerWorkflow),
}

#[derive(Debug, thiserror::Error)]
pub enum WorkflowResolveError {
    #[error("Legacy workflows are disabled via ACTIONRUNNER_DISABLE_LEGACY=1")]
    LegacyDisabled,
    #[error("No workflow found for event '{event}' in '{path}'")]
    NotFound { path: String, event: String },
    #[error("Failed to parse or validate workflow: {0}")]
    Validation(String),
    #[error("I/O error: {0}")]
    Io(String),
}

pub const WORKFLOW_CONFIG_CANDIDATES: &[&str] = &[
    ".muci/mu-ci.yml",
    ".muci/mu-ci.yaml",
    ".muci/ActionRunner.yml",
    ".muci/ActionRunner.yaml",
    ".actionrunner/ActionRunner.yml",
    ".actionrunner/ActionRunner.yaml",
];

pub const SECURITY_CONFIG_CANDIDATES: &[&str] = &[
    ".muci/security.yml",
    ".muci/security.yaml",
    ".actionrunner/security.yml",
    ".actionrunner/security.yaml",
];

pub fn resolve_security_path(repo_path: &Path) -> Option<std::path::PathBuf> {
    for rel in SECURITY_CONFIG_CANDIDATES {
        let p = repo_path.join(rel);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

pub fn resolve_workflow_from_repo(
    repo_path: &Path,
    event: &str,
    max_timeout: u64,
) -> Result<ResolvedWorkflow, WorkflowResolveError> {
    resolve_workflow_for_event(repo_path, event, max_timeout)
}

pub fn resolve_workflow_for_event(
    repo_path: &Path,
    event: &str,
    _max_timeout: u64,
) -> Result<ResolvedWorkflow, WorkflowResolveError> {
    // 1. Check for .muci/ candidates first, falling back to .actionrunner/ candidates
    for rel in WORKFLOW_CONFIG_CANDIDATES {
        let v3_path = repo_path.join(rel);
        if v3_path.exists() {
            let content = std::fs::read_to_string(&v3_path)
                .map_err(|e| WorkflowResolveError::Io(e.to_string()))?;
            let wf = ActionRunnerWorkflow::from_yaml(&content)
                .map_err(WorkflowResolveError::Validation)?;
            let subgraph = wf
                .subgraph_for_event(event)
                .map_err(|e| WorkflowResolveError::Validation(e.to_string()))?;
            return Ok(ResolvedWorkflow::V3(subgraph));
        }
    }

    // 2. If workflow configuration is absent, check if legacy workflows are disabled
    if std::env::var("ACTIONRUNNER_DISABLE_LEGACY").as_deref() == Ok("1")
        || std::env::var("MUCI_DISABLE_LEGACY").as_deref() == Ok("1")
    {
        return Err(WorkflowResolveError::LegacyDisabled);
    }

    Err(WorkflowResolveError::NotFound {
        path: repo_path.display().to_string(),
        event: event.to_string(),
    })
}

/// Default distributed pipeline used when a repository has no `.actionrunner/ActionRunner.yml`
/// (fmt and clippy on x86 workers, native verification on the RISC-V board).
pub const DEFAULT_WORKFLOW_YAML: &str = r#"
version: "3"
name: "Default Distributed Pipeline"
tasks:
  cargo-fmt:
    tool: "cargo-fmt"
    args: ["--check"]
  cargo-clippy:
    tool: "cargo-clippy"
    args: ["--all-targets", "--", "-D", "warnings"]
  cargo-test:
    tool: "cargo-test"
    args: ["--workspace"]
stages:
  - id: fmt-check
    name: "Verify Formatting"
    tasks: ["cargo-fmt"]
    tags: ["fmt"]
    threads: 2
  - id: clippy-check
    name: "Verify Linter Hygiene"
    tasks: ["cargo-clippy"]
    tags: ["clippy"]
    threads: 4
  - id: native-k3
    name: "Native Verification"
    tasks: ["cargo-test"]
    tags: ["k3"]
    depends_on: ["fmt-check", "clippy-check"]
    threads: 6
on_action:
  push: ["fmt-check", "clippy-check", "native-k3"]
  pull_request: ["fmt-check", "clippy-check", "native-k3"]
  pullrequest: ["fmt-check", "clippy-check", "native-k3"]
  merge: ["fmt-check", "clippy-check", "native-k3"]
  tag: ["fmt-check", "clippy-check", "native-k3"]
  release: ["fmt-check", "clippy-check", "native-k3"]
"#;

pub struct DAGScheduler {
    config: Config,
    job_store: JobStore,
    cluster: ClusterRegistry,
}

impl DAGScheduler {
    pub fn new(config: Config, job_store: JobStore, cluster: ClusterRegistry) -> Self {
        Self {
            config,
            job_store,
            cluster,
        }
    }

    pub async fn run_loop(self: Arc<Self>) {
        info!("ActionRunner DAG Scheduler loop active");

        loop {
            while let Some(job) = self
                .job_store
                .claim_next_queued_job_for_cluster(
                    self.config.max_concurrent_jobs,
                    Some(&self.cluster),
                )
                .await
            {
                let this = self.clone();
                tokio::spawn(async move {
                    this.execute_job(job).await;
                });
            }

            tokio::select! {
                _ = self.job_store.wait_for_event() => {}
                _ = sleep(Duration::from_millis(500)) => {}
            }
        }
    }

    async fn execute_job(&self, job: Job) {
        let mut _guard = crate::job::InFlightJobGuard::new(self.job_store.clone(), job.id.clone());
        let start_time = Utc::now();
        info!(
            job_id = %job.id,
            repo = %job.repo_name,
            commit = %job.commit_sha,
            event = %job.event_type,
            "Starting DAG pipeline execution"
        );

        self.job_store
            .update_status(
                &job.id,
                JobStatus::Running {
                    started_at: start_time,
                },
            )
            .await;

        let target_url = job_target_url(&job.id);
        self.report_github_status(
            &job.repo_name,
            &job.commit_sha,
            "pending",
            "ActionRunner distributed pipeline running...",
            Some(&target_url),
        )
        .await;

        let repo_workspace = self.config.workspace_dir.join("repos").join(&job.repo_name);
        let log_file_path = self
            .config
            .workspace_dir
            .join("logs")
            .join(&job.repo_name)
            .join(format!("{}.log", job.id));

        if let Some(parent) = log_file_path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }

        // 1. Sync or inspect repo to resolve .actionrunner/ActionRunner.yml
        let workflow = match self.resolve_and_load_workflow(&job, &repo_workspace).await {
            Ok(wf) => wf,
            Err(err) => {
                warn!(job_id = %job.id, error = %err, "Failed to load workflow; failing job");
                let final_status = JobStatus::Failed { error: err.clone() };
                self.job_store
                    .update_status(&job.id, final_status.clone())
                    .await;
                self.report_github_status(
                    &job.repo_name,
                    &job.commit_sha,
                    "failure",
                    &format!("Failed to load workflow: {}", err),
                    Some(&target_url),
                )
                .await;
                self.emit_pipeline_root_span(&job, &final_status, start_time);
                _guard.disarm();
                return;
            }
        };

        // 1b. Validate v4 toolchain.min_version against canonical cluster Rust semver (#185)
        if let Some(min_ver) = workflow
            .toolchain
            .as_ref()
            .and_then(|t| t.min_version.as_deref())
        {
            match self.cluster.validate_workflow_min_version(min_ver).await {
                Ok(tc_snap) => {
                    if tc_snap.drift_detected {
                        let drift_summary: Vec<String> = tc_snap
                            .drift_details
                            .iter()
                            .map(|d| format!("{}: {}", d.node_id, d.reason))
                            .collect();
                        warn!(
                            job_id = %job.id,
                            min_version = %min_ver,
                            canonical_semver = ?tc_snap.canonical_semver,
                            drift = %drift_summary.join("; "),
                            "Cluster Rust toolchain drift detected while validating workflow min_version"
                        );
                        self.job_store.append_job_log(
                            &job.id,
                            &format!(
                                "[controller] warning=toolchain_drift canonical={:?} details=\"{}\"\n",
                                tc_snap.canonical_semver,
                                drift_summary.join("; ")
                            ),
                        );
                    }
                }
                Err(crate::cluster::ClusterToolchainError::MissingWorkerSemver { .. }) => {
                    warn!(
                        job_id = %job.id,
                        min_version = %min_ver,
                        "No live worker reported rust_semver; proceeding under 3-phase migration compatibility"
                    );
                }
                Err(err) => {
                    let err_msg = err.to_string();
                    warn!(
                        job_id = %job.id,
                        min_version = %min_ver,
                        error = %err_msg,
                        "Failing job fast due to workflow toolchain.min_version check"
                    );
                    self.job_store.append_job_log(
                        &job.id,
                        &format!("[controller] status=failed error=\"{}\"\n", err_msg),
                    );
                    let final_status = JobStatus::Failed {
                        error: err_msg.clone(),
                    };
                    self.job_store
                        .update_status(&job.id, final_status.clone())
                        .await;
                    self.report_github_status(
                        &job.repo_name,
                        &job.commit_sha,
                        "failure",
                        &err_msg,
                        Some(&target_url),
                    )
                    .await;
                    self.job_store.flush_job_log(Some(&job.id));
                    self.emit_pipeline_root_span(&job, &final_status, start_time);
                    _guard.disarm();
                    return;
                }
            }
        }

        // 2. Initialize or preserve existing stage records in job store
        let existing_stages = self.job_store.get_stages(&job.id).await;
        let stage_records: Vec<StageRecord> = if !existing_stages.is_empty() {
            info!(
                job_id = %job.id,
                "Resuming existing DAG stage progression; preserving completed stages"
            );
            let existing_by_id: HashMap<String, StageRecord> = existing_stages
                .into_iter()
                .map(|s| (s.id.clone(), s))
                .collect();

            workflow
                .stages
                .iter()
                .map(|s| {
                    if let Some(mut existing) = existing_by_id.get(&s.id).cloned() {
                        if matches!(
                            existing.status,
                            StageStatus::Assigned { .. } | StageStatus::Running { .. }
                        ) {
                            existing.status = StageStatus::Pending;
                            existing.assigned_node = None;
                        }
                        existing.tags = workflow.effective_stage_tags(s);
                        existing.exclusive = s.exclusive;
                        existing.skip_if_unavailable = s
                            .if_unavailable
                            .as_ref()
                            .is_some_and(|p| p.policy == UnavailableAction::Skip);
                        existing
                    } else {
                        StageRecord {
                            id: s.id.clone(),
                            name: s.name.clone(),
                            tags: workflow.effective_stage_tags(s),
                            threads: s.threads,
                            toolchain: s.toolchain.clone(),
                            depends_on: s.depends_on.clone(),
                            status: StageStatus::Pending,
                            assigned_node: None,
                            exclusive: s.exclusive,
                            skip_if_unavailable: s
                                .if_unavailable
                                .as_ref()
                                .is_some_and(|p| p.policy == UnavailableAction::Skip),
                            skip_reason_code: None,
                            skip_capability: None,
                        }
                    }
                })
                .collect()
        } else {
            workflow
                .stages
                .iter()
                .map(|s| StageRecord {
                    id: s.id.clone(),
                    name: s.name.clone(),
                    tags: workflow.effective_stage_tags(s),
                    threads: s.threads,
                    toolchain: s.toolchain.clone(),
                    depends_on: s.depends_on.clone(),
                    status: StageStatus::Pending,
                    assigned_node: None,
                    exclusive: s.exclusive,
                    skip_if_unavailable: s
                        .if_unavailable
                        .as_ref()
                        .is_some_and(|p| p.policy == UnavailableAction::Skip),
                    skip_reason_code: None,
                    skip_capability: None,
                })
                .collect()
        };

        self.job_store.set_stages(&job.id, stage_records).await;
        self.cluster.set_stage_concurrency_limits(
            &job.id,
            workflow
                .stages
                .iter()
                .map(|s| (s.id.clone(), s.max_concurrent_per_node)),
        );
        self.cluster.set_stage_miri_flags(
            &job.id,
            workflow
                .stages
                .iter()
                .filter(|s| workflow.stage_invokes_miri(s))
                .map(|s| s.id.clone()),
        );

        // 3. Orchestration loop: evaluate DAG progression
        let stages_by_id: HashMap<String, StageConfig> = workflow
            .stages
            .iter()
            .map(|s| (s.id.clone(), s.clone()))
            .collect();

        let mut leased_slots: HashMap<String, String> = HashMap::new(); // stage_id -> node_id

        loop {
            let mut job_record = match self.job_store.get_job(&job.id).await {
                Some(r) => r,
                None => break,
            };

            // Check if job was cancelled or finished, or heal Queued -> Running while active
            match &job_record.status {
                JobStatus::Completed { .. } | JobStatus::Failed { .. } => {
                    self.cluster
                        .cancel_and_release_job_slots(
                            &job.id,
                            "Job finished, cancelled, or superseded",
                        )
                        .await;
                    self.job_store.notify_event();
                    break;
                }
                JobStatus::Skipped { .. } => {
                    self.cluster
                        .cancel_and_release_job_slots(
                            &job.id,
                            "Job finished, cancelled, or superseded",
                        )
                        .await;
                    self.emit_pipeline_root_span(&job, &job_record.status, start_time);
                    self.job_store.notify_event();
                    _guard.disarm();
                    break;
                }
                JobStatus::Queued => {
                    self.job_store
                        .update_status(
                            &job.id,
                            JobStatus::Running {
                                started_at: start_time,
                            },
                        )
                        .await;
                }
                JobStatus::Running { .. } => {}
            }

            // Watchdog: verify if assigned worker nodes are still online and hold the stage lease
            let mut stage_state_changed = false;
            for stage in &job_record.stages {
                if let StageStatus::Assigned {
                    node_id,
                    started_at,
                }
                | StageStatus::Running {
                    node_id,
                    started_at,
                    ..
                } = &stage.status
                {
                    let is_online = self.cluster.is_node_online(node_id).await;
                    let has_lease = self
                        .cluster
                        .has_stage_lease(node_id, &job.id, &stage.id)
                        .await;
                    let orphan_lease_expired =
                        !has_lease && (Utc::now() - *started_at).num_seconds() >= 5;
                    if !is_online || orphan_lease_expired {
                        if is_online && orphan_lease_expired {
                            sleep(Duration::from_millis(20)).await;
                        }
                        self.cluster
                            .release_stage_slot(node_id, &job.id, &stage.id)
                            .await;
                        if self
                            .job_store
                            .recover_stage_if_active(&job.id, &stage.id)
                            .await
                        {
                            warn!(
                                job_id = %job.id,
                                stage = %stage.id,
                                node = %node_id,
                                is_online,
                                has_lease,
                                "Watchdog detected assigned stage worker is offline or lease was lost; returning stage to Pending"
                            );
                        }
                        leased_slots.remove(&stage.id);
                        stage_state_changed = true;
                    }
                }
            }

            if stage_state_changed {
                job_record = match self.job_store.get_job(&job.id).await {
                    Some(r) => r,
                    None => break,
                };
            }

            let mut all_completed = true;
            let mut any_failed = false;
            let mut failure_error = String::new();
            let mut skipped_any_stage_this_pass = false;

            for stage in &job_record.stages {
                match &stage.status {
                    StageStatus::Completed { exit_code, .. } => {
                        leased_slots.remove(&stage.id);
                        if *exit_code != 0 {
                            any_failed = true;
                            failure_error =
                                format!("Stage '{}' failed with code {}", stage.id, exit_code);
                        }
                    }
                    StageStatus::Failed { error } => {
                        leased_slots.remove(&stage.id);
                        any_failed = true;
                        failure_error = error.clone();
                    }
                    StageStatus::Pending => {
                        all_completed = false;
                        // Check if dependencies are satisfied (completed cleanly or skipped)
                        let deps_satisfied = stage.depends_on.iter().all(|dep_id| {
                            job_record.stages.iter().any(|s| {
                                s.id == *dep_id
                                    && matches!(
                                        s.status,
                                        StageStatus::Completed { exit_code: 0, .. }
                                            | StageStatus::Skipped { .. }
                                    )
                            })
                        });

                        if deps_satisfied {
                            let Some(stage_cfg) = stages_by_id.get(&stage.id) else {
                                let err_msg = format!(
                                    "Stage '{}' missing from resolved workflow configuration",
                                    stage.id
                                );
                                warn!(job_id = %job.id, stage = %stage.id, "{}", err_msg);
                                self.job_store
                                    .update_stage_status(
                                        &job.id,
                                        &stage.id,
                                        StageStatus::Failed {
                                            error: err_msg.clone(),
                                        },
                                    )
                                    .await;
                                any_failed = true;
                                failure_error = err_msg;
                                continue;
                            };
                            let required_tags = workflow.effective_stage_tags(stage_cfg);
                            if self
                                .try_skip_unavailable_stage(&job, stage_cfg, &required_tags)
                                .await
                            {
                                skipped_any_stage_this_pass = true;
                                continue;
                            }
                            // Attempt to lease a slot (respecting node capacity, per-stage limits, and exclusive stage locks)
                            if let Some((node_id, cmd_tx)) = self
                                .cluster
                                .lease_slot_with_limit(
                                    &job.id,
                                    &stage.id,
                                    &required_tags,
                                    stage_cfg.toolchain.as_deref(),
                                    stage_cfg.exclusive,
                                    Some(stage_cfg.max_concurrent_per_node),
                                )
                                .await
                            {
                                info!(
                                    job_id = %job.id,
                                    stage = %stage.id,
                                    node = %node_id,
                                    "Dispatched stage to cluster worker"
                                );

                                leased_slots.insert(stage.id.clone(), node_id.clone());

                                self.job_store
                                    .update_stage_status(
                                        &job.id,
                                        &stage.id,
                                        StageStatus::Assigned {
                                            node_id: node_id.clone(),
                                            started_at: Utc::now(),
                                        },
                                    )
                                    .await;

                                let task = match build_v3_stage_dispatch_task(
                                    &job.id,
                                    &job.repo_name,
                                    &job.clone_url,
                                    &job.commit_sha,
                                    stage_cfg,
                                    &workflow,
                                    self.config.job_timeout_seconds,
                                ) {
                                    Ok(t) => t,
                                    Err(e) => {
                                        warn!(
                                            job_id = %job.id,
                                            stage = %stage.id,
                                            error = %e,
                                            "Failed to build stage dispatch task"
                                        );
                                        leased_slots.remove(&stage.id);
                                        self.cluster
                                            .release_stage_slot(&node_id, &job.id, &stage.id)
                                            .await;
                                        self.job_store
                                            .update_stage_status(
                                                &job.id,
                                                &stage.id,
                                                StageStatus::Failed {
                                                    error: e.to_string(),
                                                },
                                            )
                                            .await;
                                        any_failed = true;
                                        failure_error = e.to_string();
                                        continue;
                                    }
                                };

                                if cmd_tx.send(WorkerCommand::Dispatch(task)).await.is_err() {
                                    warn!(
                                        job_id = %job.id,
                                        stage = %stage.id,
                                        node = %node_id,
                                        "Worker command channel closed during stage dispatch; releasing slot and returning stage to Pending"
                                    );
                                    leased_slots.remove(&stage.id);
                                    self.cluster
                                        .release_stage_slot(&node_id, &job.id, &stage.id)
                                        .await;
                                    let _ = self
                                        .job_store
                                        .recover_stage_if_active(&job.id, &stage.id)
                                        .await;
                                }
                            }
                        }
                    }
                    StageStatus::Assigned { .. } | StageStatus::Running { .. } => {
                        all_completed = false;
                    }
                    StageStatus::Skipped { .. } => {
                        leased_slots.remove(&stage.id);
                    }
                }
            }

            if any_failed {
                // Cancel and release only stages belonging to THIS job that are still leased
                self.cluster
                    .cancel_and_release_job_slots(&job.id, &failure_error)
                    .await;
                leased_slots.clear();
                self.job_store.notify_event();
                warn!(job_id = %job.id, error = %failure_error, "Pipeline stage failed");
                if job_record.metrics.is_none() {
                    let extracted =
                        crate::db::CatalogStore::extract_metrics_from_log_and_workspace(
                            &self.config.workspace_dir,
                            &job.repo_name,
                            &log_file_path,
                            false,
                        )
                        .or_else(|| {
                            self.job_store
                            .get_job_log(&job.id)
                            .filter(|s| !s.trim().is_empty())
                            .map(|content| {
                                crate::db::CatalogStore::extract_metrics_from_content_and_workspace(
                                    &self.config.workspace_dir,
                                    &job.repo_name,
                                    &content,
                                    false,
                                )
                            })
                        });
                    if let Some(m) = extracted {
                        self.job_store.update_metrics(&job.id, m).await;
                    }
                }
                let final_status = JobStatus::Failed {
                    error: failure_error.clone(),
                };
                self.job_store
                    .update_status(&job.id, final_status.clone())
                    .await;
                self.report_github_status(
                    &job.repo_name,
                    &job.commit_sha,
                    "failure",
                    &failure_error,
                    Some(&target_url),
                )
                .await;
                self.job_store.flush_job_log(Some(&job.id));
                self.emit_pipeline_root_span(&job, &final_status, start_time);
                _guard.disarm();
                break;
            }

            if all_completed {
                let duration = (Utc::now() - start_time).num_seconds().max(0) as u64;
                info!(job_id = %job.id, duration_secs = duration, "All DAG stages completed successfully");

                // Release any lingering slots belonging strictly to THIS job
                self.cluster
                    .cancel_and_release_job_slots(&job.id, "All stages completed")
                    .await;
                leased_slots.clear();
                self.job_store.notify_event();

                if job_record.metrics.is_none()
                    || job_record
                        .metrics
                        .as_ref()
                        .map(|m| m.submodules.is_empty())
                        .unwrap_or(true)
                {
                    let extracted =
                        crate::db::CatalogStore::extract_metrics_from_log_and_workspace(
                            &self.config.workspace_dir,
                            &job.repo_name,
                            &log_file_path,
                            true,
                        )
                        .or_else(|| {
                            self.job_store
                            .get_job_log(&job.id)
                            .filter(|s| !s.trim().is_empty())
                            .map(|content| {
                                crate::db::CatalogStore::extract_metrics_from_content_and_workspace(
                                    &self.config.workspace_dir,
                                    &job.repo_name,
                                    &content,
                                    true,
                                )
                            })
                        });
                    if let Some(m) = extracted {
                        self.job_store.update_metrics(&job.id, m).await;
                    }
                }

                let mut final_status = JobStatus::Completed {
                    duration_secs: duration,
                    exit_code: 0,
                };

                let gate_req = mu_observable_ipc::RegressionGateRequest {
                    request_id: format!("reg-{}", job.id),
                    repo_key: job.repo_name.to_ascii_lowercase(),
                    candidate_commit: job.commit_sha.clone(),
                    baseline_branch: "main".to_string(),
                    max_slowdown_pct: 10.0,
                    max_flakiness_pct: 5.0,
                };
                if let Some(gate_report) = self.job_store.evaluate_regression_gate(&gate_req) {
                    let mut metrics = self
                        .job_store
                        .get_job(&job.id)
                        .await
                        .and_then(|r| r.metrics)
                        .unwrap_or_else(|| crate::job::JobMetrics {
                            quality_score: 100,
                            letter_grade: "A+".to_string(),
                            coverage_pct: None,
                            benchmark_summary: None,
                            tests_passed: 0,
                            tests_total: 0,
                            advisories_count: 0,
                            clippy_warnings: 0,
                            submodules: std::collections::BTreeMap::new(),
                        });
                    crate::storage_backend::apply_regression_gate_to_job(
                        &mut metrics,
                        &mut final_status,
                        &gate_report,
                    );
                    self.job_store.update_metrics(&job.id, metrics).await;
                }

                self.job_store
                    .update_status(&job.id, final_status.clone())
                    .await;
                match final_status {
                    JobStatus::Failed { ref error } => {
                        self.report_github_status(
                            &job.repo_name,
                            &job.commit_sha,
                            "failure",
                            error,
                            Some(&target_url),
                        )
                        .await;
                    }
                    _ => {
                        self.report_github_status(
                            &job.repo_name,
                            &job.commit_sha,
                            "success",
                            &format!("All stages completed successfully in {}s", duration),
                            Some(&target_url),
                        )
                        .await;
                        let post_ci_job = job.clone();
                        let post_ci_workspace = repo_workspace.clone();
                        tokio::spawn(async move {
                            let _ =
                                trigger_post_ci_cd_pipeline(&post_ci_job, &post_ci_workspace).await;
                        });
                    }
                }
                self.job_store.flush_job_log(Some(&job.id));

                // Emit root CI pipeline W3C trace span to MuObserve telemetry
                let now_ns = current_unix_nano();
                let span_entry = build_pipeline_root_span(&job, &final_status, duration, now_ns);
                self.job_store.emit_trace_spans(&[span_entry]);

                _guard.disarm();
                break;
            }

            // "Food sample" yield-and-requeue: if this job currently holds zero active stage leases
            // (all ready stages are blocked waiting on busy worker nodes), return the job to
            // `JobStatus::Queued` in-place while preserving its original priority (`queued_at`)
            // and completed stages so other queued jobs can execute on idle worker nodes.
            let latest_stages = self.job_store.get_stages(&job.id).await;
            let all_latest_terminal = !latest_stages.is_empty()
                && !latest_stages.iter().any(|s| {
                    matches!(
                        s.status,
                        StageStatus::Pending
                            | StageStatus::Assigned { .. }
                            | StageStatus::Running { .. }
                    )
                });
            if all_latest_terminal || skipped_any_stage_this_pass {
                continue;
            }
            let has_active_stages = !leased_slots.is_empty()
                || self.cluster.has_active_leases_for_job(&job.id).await
                || latest_stages.iter().any(|s| {
                    matches!(
                        s.status,
                        StageStatus::Assigned { .. } | StageStatus::Running { .. }
                    )
                });
            if !has_active_stages && self.job_store.requeue_preserving_priority(&job.id).await {
                self.job_store.flush_job_log(Some(&job.id));
                _guard.disarm();
                let completed_count = latest_stages
                    .iter()
                    .filter(|s| matches!(s.status, StageStatus::Completed { exit_code: 0, .. }))
                    .count();
                let total_count = latest_stages.len();
                let pos = self
                    .job_store
                    .job_queue_position(&job.id)
                    .await
                    .unwrap_or(1);
                info!(
                    job_id = %job.id,
                    repo = %job.repo_name,
                    completed_stages = completed_count,
                    total_stages = total_count,
                    queue_position = pos,
                    "Re-queued job in-place preserving original priority after completing available stages"
                );
                let desc = format!(
                    "Queued (#{}, {}/{} stages pre-computed) waiting for target worker...",
                    pos, completed_count, total_count
                );
                self.report_github_status(
                    &job.repo_name,
                    &job.commit_sha,
                    "pending",
                    &desc,
                    Some(&target_url),
                )
                .await;
                break;
            }

            // Sleep briefly or wait for notification
            tokio::select! {
                _ = self.job_store.wait_for_event() => {}
                _ = sleep(Duration::from_millis(500)) => {}
            }
        }
    }

    async fn resolve_and_load_workflow(
        &self,
        job: &Job,
        repo_workspace: &Path,
    ) -> Result<ActionRunnerWorkflow, String> {
        // 1. Sync or initialize repo_workspace and fetch commit_sha if commit_sha is provided
        if !job.commit_sha.is_empty() {
            if !repo_workspace.exists() {
                if let Some(parent) = repo_workspace.parent() {
                    let _ = tokio::fs::create_dir_all(parent).await;
                }
                let clone_target = if !job.clone_url.is_empty() {
                    job.clone_url.clone()
                } else {
                    format!("https://github.com/{}.git", job.repo_name)
                };

                let clone_res = tokio::process::Command::new("git")
                    .arg("clone")
                    .arg("--no-checkout")
                    .arg(&clone_target)
                    .arg(repo_workspace)
                    .output()
                    .await;

                if let Err(e) = clone_res {
                    warn!(
                        repo = %job.repo_name,
                        error = %e,
                        "Failed to execute git clone for workflow resolution"
                    );
                }
            }

            if repo_workspace.exists() {
                let _ = tokio::process::Command::new("git")
                    .arg("-C")
                    .arg(repo_workspace)
                    .arg("fetch")
                    .arg("origin")
                    .arg(&job.commit_sha)
                    .output()
                    .await;

                // Check .muci/ + .actionrunner/ candidates in git tree
                for cand in WORKFLOW_CONFIG_CANDIDATES {
                    let git_spec = format!("{}:{}", job.commit_sha, cand);
                    let show_res = tokio::process::Command::new("git")
                        .arg("-C")
                        .arg(repo_workspace)
                        .arg("show")
                        .arg(&git_spec)
                        .output()
                        .await;

                    if let Ok(out) = show_res {
                        if out.status.success() {
                            if let Ok(content) = String::from_utf8(out.stdout) {
                                if let Ok(wf) = ActionRunnerWorkflow::from_yaml(&content) {
                                    if let Ok(sub) = wf.subgraph_for_event(&job.event_type) {
                                        info!(
                                            job_id = %job.id,
                                            commit = %job.commit_sha,
                                            candidate = %cand,
                                            "Resolved declarative workflow from commit tree via git show"
                                        );
                                        return Ok(sub);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 2. Resolve from local disk workspace (.actionrunner/ActionRunner.yml)
        match resolve_workflow_for_event(
            repo_workspace,
            &job.event_type,
            self.config.job_timeout_seconds,
        ) {
            Ok(ResolvedWorkflow::V3(wf)) => return Ok(wf),
            Err(_) => {}
        }

        // If not found locally, create a default 3-stage distributed workflow (fmt on x86, clippy on x86, verify on k3)
        let default_yaml = DEFAULT_WORKFLOW_YAML;
        let wf = ActionRunnerWorkflow::from_yaml(default_yaml)?;
        if let Ok(sub) = wf.subgraph_for_event(&job.event_type) {
            if !sub.stages.is_empty() {
                return Ok(sub);
            }
        }
        Ok(wf)
    }

    async fn report_github_status(
        &self,
        repo: &str,
        sha: &str,
        state: &str,
        description: &str,
        target_url: Option<&str>,
    ) {
        report_github_commit_status(&self.config, repo, sha, state, description, target_url).await;
    }

    async fn try_skip_unavailable_stage(
        &self,
        job: &Job,
        stage_cfg: &StageConfig,
        required_tags: &[String],
    ) -> bool {
        let Some(ref unavailable_policy) = stage_cfg.if_unavailable else {
            return false;
        };
        if unavailable_policy.policy != UnavailableAction::Skip {
            return false;
        }
        if self
            .cluster
            .has_live_capable_worker_for_stage(
                &job.id,
                &stage_cfg.id,
                required_tags,
                stage_cfg.toolchain.as_deref(),
            )
            .await
        {
            return false;
        }

        let capability_label = ActionRunnerWorkflow::stage_capability_label(stage_cfg);
        let reason_code = "no_capable_node";
        let sha7: String = job.commit_sha.chars().take(7).collect();
        let skip_reason = format!(
            "Stage '{}' skipped for {}: No {} node accessible.",
            stage_cfg.id, sha7, capability_label
        );

        warn!(
            job_id = %job.id,
            stage = %stage_cfg.id,
            reason_code = reason_code,
            capability = %capability_label,
            "Skipping optional stage immediately because zero capable live workers exist"
        );

        self.job_store
            .mark_stage_skipped_unavailable(
                &job.id,
                &stage_cfg.id,
                skip_reason.clone(),
                reason_code.to_string(),
                capability_label.clone(),
            )
            .await;

        self.job_store.append_job_log(
            &job.id,
            &format!(
                "[controller] stage={} status=skipped reason_code={} capability={} message=\"{}\"\n",
                stage_cfg.id, reason_code, capability_label, skip_reason
            ),
        );

        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64;
        let root_ctx = job_root_trace_context(&job.id, &job.commit_sha);
        let skip_attrs = serde_json::json!({
            "job_id": job.id,
            "repo": job.repo_name,
            "stage": stage_cfg.id,
            "reason_code": reason_code,
            "capability": capability_label,
            "sha": job.commit_sha,
        })
        .to_string();
        let span_entry = OtelSpanEntry {
            trace_id: encode_hex(&root_ctx.trace_id),
            span_id: encode_hex(&root_ctx.span_id),
            parent_span_id: Some(encode_hex(&root_ctx.span_id)),
            service_name: "mu-ci-controller".to_string(),
            node_id: "controller".to_string(),
            span_name: format!("ci.stage.skipped:{}", stage_cfg.id),
            span_kind: "INTERNAL".to_string(),
            start_time_unix_nano: now_ns,
            end_time_unix_nano: now_ns,
            duration_ns: 0,
            status_code: "OK".to_string(),
            status_message: Some(skip_reason),
            attributes_json: skip_attrs,
        };
        self.job_store.emit_trace_spans(&[span_entry]);

        if unavailable_policy.pr_comment && job.event_type == "pull_request" {
            if let Some(pr_number) = job.pr_number {
                upsert_pr_skip_comment(
                    &self.config,
                    &job.repo_name,
                    pr_number,
                    &stage_cfg.id,
                    &job.commit_sha,
                    &capability_label,
                )
                .await;
            }
        }

        true
    }

    fn emit_pipeline_root_span(
        &self,
        job: &Job,
        final_status: &JobStatus,
        start_time: chrono::DateTime<Utc>,
    ) {
        let duration = (Utc::now() - start_time).num_seconds().max(0) as u64;
        let now_ns = current_unix_nano();
        let span = build_pipeline_root_span(job, final_status, duration, now_ns);
        self.job_store.emit_trace_spans(&[span]);
    }
}

fn current_unix_nano() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as i64
}

/// Classifies a terminal [`JobStatus`] into `(status_code, status_message, ci.outcome, ci.failure_class)`
/// for root `ci.pipeline.run:<repo>` spans (`#219`).
#[must_use]
pub(crate) fn classify_pipeline_span_outcome(
    final_status: &JobStatus,
) -> (&'static str, Option<String>, &'static str, &'static str) {
    match final_status {
        JobStatus::Completed { exit_code: 0, .. } => ("OK", None, "passed", "none"),
        JobStatus::Completed { .. } => ("OK", None, "user_failure", "user_code"),
        JobStatus::Skipped { reason } => {
            if reason.to_ascii_lowercase().contains("superseded") {
                ("OK", None, "superseded", "superseded")
            } else {
                ("OK", None, "cancelled", "cancelled")
            }
        }
        JobStatus::Failed { error } => {
            let kind = classify_ci_error_message(error);
            let status_msg = if kind.span_status_code() == "ERROR" {
                Some(error.clone())
            } else {
                None
            };
            (
                kind.span_status_code(),
                status_msg,
                kind.outcome_label(),
                kind.failure_class_label(),
            )
        }
        JobStatus::Queued | JobStatus::Running { .. } => ("OK", None, "in_progress", "none"),
    }
}

/// Builds the root `ci.pipeline.run:<repo>` [`OtelSpanEntry`] with controller-health-aligned
/// span status and structured CI outcome attributes (`#219`).
#[must_use]
pub(crate) fn build_pipeline_root_span(
    job: &Job,
    final_status: &JobStatus,
    duration_secs: u64,
    now_ns: i64,
) -> OtelSpanEntry {
    let root_ctx = job_root_trace_context(&job.id, &job.commit_sha);
    let duration_ns = duration_secs.saturating_mul(1_000_000_000);
    let start_ns = (now_ns - duration_ns as i64).max(0);
    let (span_status_code, span_status_msg, outcome, failure_class) =
        classify_pipeline_span_outcome(final_status);
    let attrs = serde_json::json!({
        "job_id": job.id,
        "repo": job.repo_name,
        "ref": job.ref_name,
        "sha": job.commit_sha,
        "ci.outcome": outcome,
        "ci.failure_class": failure_class,
    });
    OtelSpanEntry {
        trace_id: encode_hex(&root_ctx.trace_id),
        span_id: encode_hex(&root_ctx.span_id),
        parent_span_id: None,
        service_name: "mu-ci-controller".to_string(),
        node_id: "controller".to_string(),
        span_name: format!("ci.pipeline.run:{}", job.repo_name),
        span_kind: "SERVER".to_string(),
        start_time_unix_nano: start_ns,
        end_time_unix_nano: now_ns,
        duration_ns,
        status_code: span_status_code.to_string(),
        status_message: span_status_msg,
        attributes_json: attrs.to_string(),
    }
}

/// Returns the canonical dashboard deep-link URL for a job.
#[must_use]
pub fn job_target_url(job_id: &str) -> String {
    format!("https://hook.lma1980.duckdns.org/web/#/jobs/{job_id}")
}

/// Immediately reports a `"pending"` (`context: "continuous integration"`) commit status to GitHub when a job
/// enters `JobStatus::Queued`, provided the job has not already transitioned out of `Queued`.
pub async fn report_queued_github_status(
    config: &Config,
    job_store: &JobStore,
    job_id: &str,
    repo: &str,
    sha: &str,
    queue_position: usize,
) {
    if !matches!(
        job_store.get_job(job_id).await.map(|r| r.status),
        Some(JobStatus::Queued)
    ) {
        return;
    }
    let target_url = job_target_url(job_id);
    let desc = format!(
        "ActionRunner distributed pipeline queued (position #{})...",
        queue_position.max(1)
    );
    report_github_commit_status(config, repo, sha, "pending", &desc, Some(&target_url)).await;
}

/// Reports a `continuous integration` commit status to GitHub (`/repos/{repo}/statuses/{sha}`).
pub async fn report_github_commit_status(
    config: &Config,
    repo: &str,
    sha: &str,
    state: &str,
    description: &str,
    target_url: Option<&str>,
) {
    let base_url = std::env::var("GITHUB_API_BASE_URL")
        .unwrap_or_else(|_| "https://api.github.com".to_string());
    report_github_commit_status_with_base_url(
        &base_url,
        config,
        repo,
        sha,
        state,
        description,
        target_url,
    )
    .await;
}

fn resolve_github_token_and_base_url<'a>(
    config: &'a Config,
    api_base_url: &str,
) -> Option<(&'a str, String)> {
    let raw_token = config
        .github_token
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())?;
    let (token, resolved_base_url) = match raw_token.split_once("@http") {
        Some((tok, rest)) => (tok, format!("http{rest}")),
        None => (raw_token, api_base_url.trim_end_matches('/').to_string()),
    };
    Some((token, resolved_base_url.trim_end_matches('/').to_string()))
}

fn github_request(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
    token: &str,
) -> reqwest::RequestBuilder {
    client
        .request(method, url)
        .header("Authorization", format!("Bearer {}", token))
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "ActionRunner-Controller/0.1.0")
        .header("X-GitHub-Api-Version", "2022-11-28")
}

/// Upserts a deduplicated sticky GitHub PR comment when an optional stage is skipped due to no
/// capable live worker nodes (`<!-- mu-ci-skip:<stage> -->`).
pub async fn upsert_pr_skip_comment(
    config: &Config,
    repo: &str,
    pr_number: u64,
    stage_id: &str,
    commit_sha: &str,
    capability_label: &str,
) {
    let base_url = std::env::var("GITHUB_API_BASE_URL")
        .unwrap_or_else(|_| "https://api.github.com".to_string());
    upsert_pr_skip_comment_with_base_url(
        &base_url,
        config,
        repo,
        pr_number,
        stage_id,
        commit_sha,
        capability_label,
    )
    .await;
}

/// Upserts a sticky PR comment against a configurable GitHub REST API base URL.
pub async fn upsert_pr_skip_comment_with_base_url(
    api_base_url: &str,
    config: &Config,
    repo: &str,
    pr_number: u64,
    stage_id: &str,
    commit_sha: &str,
    capability_label: &str,
) {
    let Some((token, resolved_base_url)) = resolve_github_token_and_base_url(config, api_base_url)
    else {
        return;
    };

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "Failed to create HTTP client for GitHub PR comment upsert");
            return;
        }
    };

    let marker = format!("<!-- mu-ci-skip:{stage_id} -->");
    let sha7: String = commit_sha.chars().take(7).collect();
    let comment_body = format!(
        "{marker}\nStage '{stage_id}' skipped for {sha7}: No {capability_label} node accessible."
    );

    let mut existing_comment_id: Option<u64> = None;
    for page in 1..=10u32 {
        let list_url = format!(
            "{resolved_base_url}/repos/{repo}/issues/{pr_number}/comments?per_page=100&page={page}"
        );
        let resp = match github_request(&client, reqwest::Method::GET, &list_url, token)
            .send()
            .await
        {
            Ok(r) => r,
            Err(err) => {
                warn!(repo = %repo, pr = pr_number, error = %err, "Failed to list PR comments");
                return;
            }
        };
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            warn!(
                repo = %repo,
                pr = pr_number,
                status = %status,
                body = %text,
                "GitHub PR comment list API responded with error"
            );
            return;
        }
        let items: Vec<serde_json::Value> = match resp.json().await {
            Ok(v) => v,
            Err(err) => {
                warn!(repo = %repo, pr = pr_number, error = %err, "Invalid PR comment list JSON");
                return;
            }
        };
        if let Some(found_id) = items.iter().find_map(|item| {
            let body = item.get("body").and_then(|b| b.as_str())?;
            if body.contains(&marker) {
                item.get("id").and_then(|id| id.as_u64())
            } else {
                None
            }
        }) {
            existing_comment_id = Some(found_id);
            break;
        }
        if items.len() < 100 {
            break;
        }
    }

    let payload = serde_json::json!({ "body": comment_body });
    let (method, url) = match existing_comment_id {
        Some(comment_id) => (
            reqwest::Method::PATCH,
            format!("{resolved_base_url}/repos/{repo}/issues/comments/{comment_id}"),
        ),
        None => (
            reqwest::Method::POST,
            format!("{resolved_base_url}/repos/{repo}/issues/{pr_number}/comments"),
        ),
    };

    match github_request(&client, method.clone(), &url, token)
        .json(&payload)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            info!(
                repo = %repo,
                pr = pr_number,
                stage = %stage_id,
                method = %method,
                "Upserted sticky PR skip comment"
            );
        }
        Ok(resp) => {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            warn!(
                repo = %repo,
                pr = pr_number,
                stage = %stage_id,
                status = %status,
                body = %text,
                "GitHub PR comment upsert API responded with error"
            );
        }
        Err(err) => {
            warn!(
                repo = %repo,
                pr = pr_number,
                stage = %stage_id,
                error = %err,
                "Failed to upsert PR skip comment"
            );
        }
    }
}

/// Reports a `continuous integration` commit status against a configurable GitHub API base URL.
pub async fn report_github_commit_status_with_base_url(
    api_base_url: &str,
    config: &Config,
    repo: &str,
    sha: &str,
    state: &str,
    description: &str,
    target_url: Option<&str>,
) {
    let Some((token, resolved_base_url)) = resolve_github_token_and_base_url(config, api_base_url)
    else {
        return;
    };

    let mut desc = description.to_string();
    if desc.len() > 140 {
        desc.truncate(137);
        desc.push_str("...");
    }

    let url = format!("{}/repos/{}/statuses/{}", resolved_base_url, repo, sha);
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "Failed to create HTTP client for GitHub status reporting");
            return;
        }
    };

    let payload = serde_json::json!({
        "state": state,
        "target_url": target_url,
        "description": desc,
        "context": "continuous integration",
    });

    match github_request(&client, reqwest::Method::POST, &url, token)
        .json(&payload)
        .send()
        .await
    {
        Ok(resp) => {
            if resp.status().is_success() {
                info!(
                    repo = %repo,
                    sha = %sha,
                    state = %state,
                    context = "continuous integration",
                    "Reported commit status to GitHub"
                );
            } else {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                warn!(
                    repo = %repo,
                    sha = %sha,
                    status = %status,
                    body = %body,
                    "GitHub commit status API responded with error"
                );
            }
        }
        Err(err) => {
            warn!(repo = %repo, sha = %sha, error = %err, "Failed to send commit status to GitHub");
        }
    }
}

/// Ordered candidate paths for Continuous Delivery (`MuConDe`) manifests.
pub const CD_MANIFEST_CANDIDATES: &[&str] = &[
    ".mucd/mu-cd.yml",
    ".mucd/mu-cd.yaml",
    ".mucd/MuConDe.yml",
    ".mucd/MuConDe.yaml",
    ".muconde/MuConDe.yml",
    ".muconde/MuConDe.yaml",
    ".muconde/mu-cd.yml",
    ".muconde/mu-cd.yaml",
];

/// Canonical deployable services eligible for manifest-free post-CI CD triggers.
pub const DEFAULT_CD_MANAGED_SERVICES: &[&str] = &[
    "jero-runner",
    "mu-cd-agent",
    "mu-cd-controller",
    "mu-ci-controller",
    "mu-ci-web",
    "mu-ci-worker",
    "mu-console",
    "mu-observable-collector",
    "mu-observable-hub",
    "mu-observable-sentinel",
    "mu-registry",
];

const MU_CI_WORKFLOW_CANDIDATES: &[&str] = &[".muci/mu-ci.yml", ".muci/mu-ci.yaml"];

/// Returns `true` when `job` represents a `push` or `merge` event on the `main` branch.
#[must_use]
pub fn is_main_push_or_merge(job: &Job) -> bool {
    !job.commit_sha.trim().is_empty()
        && (job.event_type == "push" || job.event_type == "merge")
        && (job.ref_name == "refs/heads/main" || job.ref_name == "main")
}

async fn resolve_repo_text_file(
    repo_workspace: &Path,
    commit_sha: &str,
    candidates: &[&str],
) -> Option<String> {
    if !commit_sha.trim().is_empty() && repo_workspace.join(".git").exists() {
        for cand in candidates {
            let git_spec = format!("{commit_sha}:{cand}");
            if let Ok(out) = tokio::process::Command::new("git")
                .arg("-C")
                .arg(repo_workspace)
                .arg("show")
                .arg(&git_spec)
                .output()
                .await
            {
                if out.status.success() {
                    if let Ok(content) = String::from_utf8(out.stdout) {
                        if !content.trim().is_empty() {
                            return Some(content);
                        }
                    }
                }
            }
        }
    }

    for cand in candidates {
        let p = repo_workspace.join(cand);
        if let Ok(content) = tokio::fs::read_to_string(&p).await {
            if !content.trim().is_empty() {
                return Some(content);
            }
        }
    }
    None
}

async fn repo_has_file_at_commit_or_workspace(
    repo_workspace: &Path,
    commit_sha: &str,
    rel_path: &str,
) -> bool {
    if repo_workspace.join(rel_path).is_file() {
        return true;
    }
    if !commit_sha.trim().is_empty() && repo_workspace.join(".git").exists() {
        let git_spec = format!("{commit_sha}:{rel_path}");
        if let Ok(out) = tokio::process::Command::new("git")
            .arg("-C")
            .arg(repo_workspace)
            .args(["cat-file", "-e", &git_spec])
            .output()
            .await
        {
            return out.status.success();
        }
    }
    false
}

/// Resolves the raw YAML content of a repository's CD manifest from either `git show <sha>:<cand>`
/// or the local `repo_workspace` checkout.
pub async fn resolve_cd_manifest_yaml(repo_workspace: &Path, commit_sha: &str) -> Option<String> {
    resolve_repo_text_file(repo_workspace, commit_sha, CD_MANIFEST_CANDIDATES).await
}

async fn resolve_mu_ci_workflow_yaml(repo_workspace: &Path, commit_sha: &str) -> Option<String> {
    resolve_repo_text_file(repo_workspace, commit_sha, MU_CI_WORKFLOW_CANDIDATES).await
}

pub(crate) fn repo_short_slug(repo_name: &str) -> &str {
    repo_name
        .rsplit('/')
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| repo_name.trim())
}

/// Extracts the `service` identifier from a `MuConDe` YAML manifest, falling back to the repository short name.
#[must_use]
pub fn extract_cd_service_name(manifest_yaml: &str, repo_name: &str) -> String {
    if let Ok(val) = serde_yaml::from_str::<serde_yaml::Value>(manifest_yaml) {
        if let Some(svc) = val.get("service").and_then(|v| v.as_str()) {
            let trimmed = svc.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    repo_short_slug(repo_name).to_string()
}

fn load_secret_from_values(
    token_file: Option<&str>,
    token_literal_or_path: Option<&str>,
) -> Option<String> {
    if let Some(file_path) = token_file.map(str::trim).filter(|s| !s.is_empty()) {
        return std::fs::read_to_string(file_path)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
    }
    if let Some(val) = token_literal_or_path
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if val.starts_with('/') {
            return std::fs::read_to_string(val)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
        }
        return Some(val.to_string());
    }
    None
}

/// Resolves the `MuConDe` CD API bearer token from an explicit file path or literal/file environment value.
/// Fails closed (`None`) if a configured file path cannot be read or is empty.
#[must_use]
pub fn load_cd_api_token_from_values(
    token_file: Option<&str>,
    token_literal_or_path: Option<&str>,
) -> Option<String> {
    load_secret_from_values(token_file, token_literal_or_path)
}

/// Loads the `MuConDe` CD API bearer token from `MU_CD_CONTROLLER_API_TOKEN*`,
/// `MU_CD_API_TOKEN*`, or legacy `MUCONDE_CD_API_TOKEN*`.
#[must_use]
pub fn load_cd_api_token() -> Option<String> {
    let token_file = first_non_empty_env(&[
        "MU_CD_CONTROLLER_API_TOKEN_FILE",
        "MU_CD_API_TOKEN_FILE",
        "MUCONDE_CD_API_TOKEN_FILE",
    ]);
    let token_val = first_non_empty_env(&[
        "MU_CD_CONTROLLER_API_TOKEN",
        "MU_CD_API_TOKEN",
        "MUCONDE_CD_API_TOKEN",
    ]);
    load_cd_api_token_from_values(token_file.as_deref(), token_val.as_deref())
}

/// Resolves a `MuRegist` bearer token from an explicit file path or literal/file value.
/// Fails closed (`None`) if a configured file path cannot be read or is empty.
#[must_use]
pub fn load_registry_api_token_from_values(
    token_file: Option<&str>,
    token_literal_or_path: Option<&str>,
) -> Option<String> {
    load_secret_from_values(token_file, token_literal_or_path)
}

fn resolve_env_secret_pairs(pairs: &[(&str, &str)]) -> Result<Option<String>, String> {
    for (value_var, file_var) in pairs {
        let file_val = std::env::var(file_var).ok();
        let literal_val = std::env::var(value_var).ok();
        let has_file = file_val.as_deref().is_some_and(|s| !s.trim().is_empty());
        let has_literal = literal_val.as_deref().is_some_and(|s| !s.trim().is_empty());
        if has_file || has_literal {
            return load_registry_api_token_from_values(
                file_val.as_deref(),
                literal_val.as_deref(),
            )
            .map(Some)
            .ok_or_else(|| {
                format!(
                    "Configured registry token environment variable ({value_var}/{file_var}) could not be read or is empty"
                )
            });
        }
    }
    Ok(None)
}

/// Loads the `MuRegist` bearer token from `MUREGIST_API_TOKEN*`, `MUREGIST_TOKEN*`, or `MUCONDE_REGISTRY_TOKEN*`.
#[must_use]
pub fn load_registry_api_token() -> Option<String> {
    resolve_env_secret_pairs(&[
        ("MUREGIST_API_TOKEN", "MUREGIST_API_TOKEN_FILE"),
        ("MUREGIST_TOKEN", "MUREGIST_TOKEN_FILE"),
        ("MUCONDE_REGISTRY_TOKEN", "MUCONDE_REGISTRY_TOKEN_FILE"),
    ])
    .ok()
    .flatten()
}

fn first_non_empty_env(vars: &[&str]) -> Option<String> {
    for var in vars {
        if let Ok(raw) = std::env::var(var) {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// Endpoint, authentication, and mTLS configuration for post-CI bundle upload and rollout dispatch.
#[derive(Debug, Clone, Default)]
pub struct PostCiCdEndpointConfig<'a> {
    pub muregist_api_url: Option<&'a str>,
    pub muregist_api_token: Option<&'a str>,
    pub muregist_client_cert_san: Option<&'a str>,
    pub tls_ca_path: Option<&'a str>,
    pub tls_cert_path: Option<&'a str>,
    pub tls_key_path: Option<&'a str>,
    pub muconde_cd_api_url: Option<&'a str>,
    pub cd_api_token: Option<&'a str>,
}

mod post_ci_cd {
    use super::{
        extract_cd_service_name, first_non_empty_env, repo_short_slug, DEFAULT_CD_MANAGED_SERVICES,
    };
    use flate2::{read::GzDecoder, write::GzEncoder, Compression};
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, HashSet};
    use std::io::Write;
    use std::path::{Component, Path, PathBuf};
    use std::time::{Duration, SystemTime};
    use tar::{Archive, Builder, EntryType, Header};

    pub(super) const MAX_IT_ARCHIVE_UNCOMPRESSED_BYTES: u64 = 64 * 1024 * 1024;

    #[derive(Debug, Default, Deserialize)]
    struct RawCdManifest {
        #[serde(default)]
        target_nodes: Vec<String>,
        #[serde(default)]
        integration_tests: Option<serde_yaml::Value>,
        #[serde(default)]
        deployment: RawCdDeployment,
    }

    #[derive(Debug, Default, Deserialize)]
    struct RawCdDeployment {
        binary: Option<String>,
        install_path: Option<String>,
        web_root: Option<String>,
        artifact: Option<String>,
        #[serde(default)]
        target_nodes: Vec<String>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct CdManifestSummary {
        pub(super) service_name: String,
        pub(super) binary: Option<String>,
        pub(super) install_path: Option<String>,
        pub(super) web_root: Option<String>,
        pub(super) artifact: Option<String>,
        pub(super) target_nodes: Vec<String>,
        pub(super) integration_tests: Vec<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub(super) enum ExpectedElfArch {
        X86_64,
        Riscv64,
        Aarch64,
    }

    impl ExpectedElfArch {
        pub(super) const fn e_machine(self) -> u16 {
            match self {
                Self::X86_64 => 0x003E,
                Self::Riscv64 => 0x00F3,
                Self::Aarch64 => 0x00B7,
            }
        }

        pub(super) const fn from_e_machine(e_machine: u16) -> Option<Self> {
            match e_machine {
                0x003E => Some(Self::X86_64),
                0x00F3 => Some(Self::Riscv64),
                0x00B7 => Some(Self::Aarch64),
                _ => None,
            }
        }

        pub(super) const fn label(self) -> &'static str {
            match self {
                Self::X86_64 => "x86_64",
                Self::Riscv64 => "riscv64",
                Self::Aarch64 => "aarch64",
            }
        }

        pub(super) const fn target_triple(self) -> &'static str {
            match self {
                Self::X86_64 => "x86_64-unknown-linux-gnu",
                Self::Riscv64 => "riscv64gc-unknown-linux-gnu",
                Self::Aarch64 => "aarch64-unknown-linux-gnu",
            }
        }
    }

    #[derive(Debug, Clone)]
    pub(super) struct PackagedArtifact {
        pub(super) filename: String,
        pub(super) bytes: Vec<u8>,
        pub(super) sha256_hex: String,
    }

    #[derive(Debug, Deserialize)]
    struct CanaryBundleUploadResponse {
        bundle_id: Option<String>,
        service_name: Option<String>,
        binary_digest: String,
        it_archive_digest: String,
    }

    fn clean_opt(value: Option<String>) -> Option<String> {
        value.and_then(|s| {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
    }

    fn parse_integration_tests(val: Option<serde_yaml::Value>) -> Vec<String> {
        match val {
            Some(serde_yaml::Value::String(s)) => {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    Vec::new()
                } else {
                    vec![trimmed.to_string()]
                }
            }
            Some(serde_yaml::Value::Sequence(items)) => items
                .into_iter()
                .filter_map(|v| v.as_str().map(str::trim).map(ToOwned::to_owned))
                .filter(|s| !s.is_empty())
                .collect(),
            _ => Vec::new(),
        }
    }

    #[derive(Debug, Default, Deserialize)]
    struct RawMuCiCdConfig {
        #[serde(default)]
        enabled: Option<bool>,
        #[serde(default)]
        service: Option<String>,
        #[serde(default)]
        binary: Option<String>,
        #[serde(default)]
        install_path: Option<String>,
        #[serde(default)]
        web_root: Option<String>,
        #[serde(default)]
        artifact: Option<String>,
        #[serde(default)]
        target_nodes: Vec<String>,
        #[serde(default)]
        integration_tests: Option<serde_yaml::Value>,
    }

    enum MuCiCdDirective {
        Disabled,
        Enabled(Box<RawMuCiCdConfig>),
        Unspecified,
    }

    fn parse_mu_ci_cd_directive(muci_yaml: Option<&str>) -> MuCiCdDirective {
        let Some(raw) = muci_yaml else {
            return MuCiCdDirective::Unspecified;
        };
        let Ok(val) = serde_yaml::from_str::<serde_yaml::Value>(raw) else {
            return MuCiCdDirective::Unspecified;
        };
        let Some(cd_val) = val.get("cd") else {
            return MuCiCdDirective::Unspecified;
        };
        match cd_val {
            serde_yaml::Value::Bool(false) | serde_yaml::Value::Null => MuCiCdDirective::Disabled,
            serde_yaml::Value::Bool(true) => MuCiCdDirective::Enabled(Box::default()),
            serde_yaml::Value::Mapping(_) => {
                let parsed =
                    serde_yaml::from_value::<RawMuCiCdConfig>(cd_val.clone()).unwrap_or_default();
                if parsed.enabled == Some(false) {
                    MuCiCdDirective::Disabled
                } else {
                    MuCiCdDirective::Enabled(Box::new(parsed))
                }
            }
            _ => MuCiCdDirective::Unspecified,
        }
    }

    pub(super) fn is_managed_service_slug(
        repo_short: &str,
        managed_override: Option<&str>,
    ) -> bool {
        let normalized_slug = repo_short.trim().to_ascii_lowercase();
        if normalized_slug.is_empty() {
            return false;
        }
        if let Some(csv) = managed_override.map(str::trim).filter(|s| !s.is_empty()) {
            return csv
                .split(',')
                .map(|item| item.trim().to_ascii_lowercase())
                .filter(|item| !item.is_empty())
                .any(|item| item == normalized_slug);
        }
        DEFAULT_CD_MANAGED_SERVICES
            .iter()
            .any(|svc| svc.eq_ignore_ascii_case(&normalized_slug))
    }

    pub(super) fn synthesize_cd_manifest_summary(
        repo_name: &str,
        muci_yaml: Option<&str>,
        managed_override: Option<&str>,
        has_trunk_toml: bool,
    ) -> Option<CdManifestSummary> {
        let repo_short = repo_short_slug(repo_name);
        let cfg = match parse_mu_ci_cd_directive(muci_yaml) {
            MuCiCdDirective::Disabled => return None,
            MuCiCdDirective::Enabled(cfg) => *cfg,
            MuCiCdDirective::Unspecified => {
                if !is_managed_service_slug(repo_short, managed_override) {
                    return None;
                }
                RawMuCiCdConfig::default()
            }
        };

        let service_name = clean_opt(cfg.service).unwrap_or_else(|| repo_short.to_string());
        let is_spa = has_trunk_toml || is_static_web_service_name(&service_name);
        let artifact = clean_opt(cfg.artifact).or_else(|| is_spa.then(|| "dist".to_string()));
        let integration_tests = parse_integration_tests(cfg.integration_tests);

        Some(CdManifestSummary {
            service_name,
            binary: clean_opt(cfg.binary),
            install_path: clean_opt(cfg.install_path),
            web_root: clean_opt(cfg.web_root),
            artifact,
            target_nodes: cfg.target_nodes,
            integration_tests,
        })
    }

    pub(super) fn parse_cd_manifest_summary(
        manifest_yaml: &str,
        repo_name: &str,
    ) -> CdManifestSummary {
        let service_name = extract_cd_service_name(manifest_yaml, repo_name);
        let parsed = serde_yaml::from_str::<RawCdManifest>(manifest_yaml).unwrap_or_default();
        let target_nodes = if !parsed.deployment.target_nodes.is_empty() {
            parsed.deployment.target_nodes
        } else {
            parsed.target_nodes
        };
        let integration_tests = parse_integration_tests(parsed.integration_tests);
        CdManifestSummary {
            service_name,
            binary: clean_opt(parsed.deployment.binary),
            install_path: clean_opt(parsed.deployment.install_path),
            web_root: clean_opt(parsed.deployment.web_root),
            artifact: clean_opt(parsed.deployment.artifact),
            target_nodes,
            integration_tests,
        }
    }

    pub(super) fn compute_sha256_hex(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex::encode(hasher.finalize())
    }

    pub(super) fn infer_target_arch_from_nodes(target_nodes: &[String]) -> Option<ExpectedElfArch> {
        let mut detected = HashSet::new();
        for raw_node in target_nodes {
            let node = raw_node.trim().to_ascii_lowercase();
            if node.is_empty() {
                continue;
            }
            if node.contains("riscv64") || node.contains("riscv") {
                detected.insert(ExpectedElfArch::Riscv64);
            } else if node.contains("aarch64") || node.contains("arm64") {
                detected.insert(ExpectedElfArch::Aarch64);
            } else if node.contains("x86_64") || node.contains("amd64") {
                detected.insert(ExpectedElfArch::X86_64);
            } else {
                // Generic host aliases (e.g., node-a / node-b) do not pin a single ISA.
                return None;
            }
        }
        if detected.len() == 1 {
            detected.into_iter().next()
        } else {
            None
        }
    }

    fn parse_elf_machine(bytes: &[u8]) -> Option<(u8, u16)> {
        if bytes.len() < 20 || &bytes[..4] != b"\x7fELF" {
            return None;
        }
        let ei_class = bytes[4];
        let ei_data = bytes[5];
        let e_machine = match ei_data {
            1 => u16::from_le_bytes([bytes[18], bytes[19]]),
            2 => u16::from_be_bytes([bytes[18], bytes[19]]),
            _ => return None,
        };
        Some((ei_class, e_machine))
    }

    pub(super) fn validate_elf_architecture(
        bytes: &[u8],
        expected: Option<ExpectedElfArch>,
        artifact_path: &Path,
    ) -> Result<(), String> {
        let Some((ei_class, e_machine)) = parse_elf_machine(bytes) else {
            return Ok(());
        };
        if ei_class != 2 {
            return Err(format!(
                "Artifact '{}' is not a 64-bit ELF binary (EI_CLASS={}, expected 2)",
                artifact_path.display(),
                ei_class
            ));
        }
        if let Some(arch) = expected {
            if e_machine != arch.e_machine() {
                return Err(format!(
                    "Artifact '{}' ELF target (class={}, e_machine=0x{e_machine:04x}) does not match target_nodes architecture {} (0x{:04x})",
                    artifact_path.display(),
                    ei_class,
                    arch.label(),
                    arch.e_machine()
                ));
            }
        }
        Ok(())
    }

    fn sanitize_relative_subpath(raw: &str) -> Result<PathBuf, String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.contains('\0') {
            return Err("Artifact subpath must not be empty or contain NUL bytes".to_string());
        }
        let mut clean = PathBuf::new();
        for comp in Path::new(trimmed).components() {
            match comp {
                Component::Normal(part) => clean.push(part),
                Component::CurDir => {}
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(format!(
                        "Artifact subpath '{trimmed}' contains disallowed path traversal or root component"
                    ));
                }
            }
        }
        if clean.as_os_str().is_empty() {
            return Err(format!(
                "Artifact subpath '{trimmed}' resolves to repository root"
            ));
        }
        Ok(clean)
    }

    fn collect_sorted_files(
        root: &Path,
        current: &Path,
        out: &mut Vec<PathBuf>,
    ) -> Result<(), String> {
        let mut entries: Vec<_> = std::fs::read_dir(current)
            .map_err(|e| format!("Failed to list '{}': {e}", current.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Failed to read entry in '{}': {e}", current.display()))?;
        entries.sort_by_key(std::fs::DirEntry::file_name);

        for entry in entries {
            let path = entry.path();
            let meta = std::fs::symlink_metadata(&path)
                .map_err(|e| format!("Failed to stat '{}': {e}", path.display()))?;
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "Refusing to package symlink '{}' into release bundle",
                    path.display()
                ));
            }
            if meta.is_dir() {
                collect_sorted_files(root, &path, out)?;
            } else if meta.is_file() {
                let rel = path.strip_prefix(root).map_err(|e| {
                    format!(
                        "Failed to relativize '{}' against '{}': {e}",
                        path.display(),
                        root.display()
                    )
                })?;
                out.push(rel.to_path_buf());
            }
        }
        Ok(())
    }

    fn append_tar_file(
        builder: &mut Builder<GzEncoder<Vec<u8>>>,
        archive_path: &Path,
        contents: &[u8],
        mode: u32,
    ) -> Result<(), String> {
        let mut header = Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(mode);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_cksum();
        builder
            .append_data(&mut header, archive_path, contents)
            .map_err(|e| {
                format!(
                    "Failed to append archive entry '{}': {e}",
                    archive_path.display()
                )
            })
    }

    fn is_executable_file(path: &Path, force_exec_sh: bool) -> bool {
        if force_exec_sh
            && path
                .extension()
                .and_then(|s| s.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("sh"))
        {
            return true;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(path) {
                return (meta.permissions().mode() & 0o111) != 0;
            }
        }
        false
    }

    fn package_directory_tar_gz(
        source_dir: &Path,
        archive_prefix: Option<&str>,
        force_exec_sh: bool,
    ) -> Result<(Vec<u8>, usize), String> {
        let mut rel_files = Vec::new();
        collect_sorted_files(source_dir, source_dir, &mut rel_files)?;
        if rel_files.is_empty() {
            return Ok((Vec::new(), 0));
        }

        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = Builder::new(encoder);
        for rel in &rel_files {
            let full_path = source_dir.join(rel);
            let bytes = std::fs::read(&full_path)
                .map_err(|e| format!("Failed to read '{}': {e}", full_path.display()))?;
            let archive_path = match archive_prefix {
                Some(prefix) => Path::new(prefix).join(rel),
                None => rel.clone(),
            };
            let mode = if is_executable_file(&full_path, force_exec_sh) {
                0o755
            } else {
                0o644
            };
            append_tar_file(&mut builder, &archive_path, &bytes, mode)?;
        }

        let file_count = rel_files.len();
        builder
            .finish()
            .map_err(|e| format!("Failed to finalize tar stream: {e}"))?;
        let encoder = builder
            .into_inner()
            .map_err(|e| format!("Failed to unwrap tar encoder: {e}"))?;
        let gz_bytes = encoder
            .finish()
            .map_err(|e| format!("Failed to finalize gzip archive: {e}"))?;
        Ok((gz_bytes, file_count))
    }

    fn validate_prebuilt_tar_gz(bytes: &[u8], artifact_path: &Path) -> Result<(), String> {
        if bytes.is_empty() {
            return Err(format!(
                "Prebuilt archive '{}' is empty",
                artifact_path.display()
            ));
        }
        let mut archive = Archive::new(GzDecoder::new(bytes));
        let entries = archive.entries().map_err(|e| {
            format!(
                "Invalid gzip tar archive '{}': {e}",
                artifact_path.display()
            )
        })?;
        let mut regular_files = 0usize;
        for entry in entries {
            let entry = entry.map_err(|e| {
                format!(
                    "Corrupt entry in archive '{}': {e}",
                    artifact_path.display()
                )
            })?;
            let entry_type = entry.header().entry_type();
            if matches!(entry_type, EntryType::Symlink | EntryType::Link) {
                return Err(format!(
                    "Archive '{}' contains disallowed symlink or hardlink",
                    artifact_path.display()
                ));
            }
            let rel = entry
                .path()
                .map_err(|e| format!("Invalid entry path in '{}': {e}", artifact_path.display()))?;
            if rel.components().any(|c| {
                matches!(
                    c,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            }) {
                return Err(format!(
                    "Archive '{}' contains unsafe path '{}'",
                    artifact_path.display(),
                    rel.display()
                ));
            }
            if entry_type.is_file() {
                regular_files += 1;
            }
        }
        if regular_files == 0 {
            return Err(format!(
                "Archive '{}' contains no regular files",
                artifact_path.display()
            ));
        }
        Ok(())
    }

    fn is_static_web_service_name(service_name: &str) -> bool {
        let canonical = service_name.trim().to_ascii_lowercase().replace('_', "-");
        matches!(
            canonical.as_str(),
            "muconsole" | "mu-console" | "action-runner-web" | "mu-ci-web"
        )
    }

    pub(super) fn is_static_web_deployment(summary: &CdManifestSummary) -> bool {
        if is_static_web_service_name(&summary.service_name) || summary.web_root.is_some() {
            return true;
        }
        summary.artifact.as_deref().is_some_and(|raw| {
            let trimmed = raw.trim().trim_end_matches('/');
            trimmed == "dist"
                || trimmed == "./dist"
                || trimmed.ends_with(".tar.gz")
                || trimmed.ends_with(".tgz")
        })
    }

    fn resolve_static_web_bundle(
        repo_workspace: &Path,
        summary: &CdManifestSummary,
    ) -> Result<PackagedArtifact, String> {
        let sub_rel = match summary.artifact.as_deref() {
            Some(art) => sanitize_relative_subpath(art)?,
            None => PathBuf::from("dist"),
        };
        let target_path = repo_workspace.join(&sub_rel);
        let meta = std::fs::symlink_metadata(&target_path).map_err(|e| {
            format!(
                "Static web bundle source '{}' not found: {e}",
                target_path.display()
            )
        })?;
        if meta.file_type().is_symlink() {
            return Err(format!(
                "Static web bundle source '{}' must not be a symlink",
                target_path.display()
            ));
        }

        let bytes = if meta.is_file() {
            let raw = std::fs::read(&target_path)
                .map_err(|e| format!("Failed to read '{}': {e}", target_path.display()))?;
            validate_prebuilt_tar_gz(&raw, &target_path)?;
            raw
        } else if meta.is_dir() {
            let (gz_bytes, file_count) =
                package_directory_tar_gz(&target_path, Some("dist"), false)?;
            if file_count == 0 {
                return Err(format!(
                    "Static web bundle directory '{}' contains no regular files",
                    target_path.display()
                ));
            }
            gz_bytes
        } else {
            return Err(format!(
                "Static web bundle source '{}' is neither a regular file nor directory",
                target_path.display()
            ));
        };

        let sha256_hex = compute_sha256_hex(&bytes);
        let filename = format!("{}-dist.tar.gz", summary.service_name);
        Ok(PackagedArtifact {
            filename,
            bytes,
            sha256_hex,
        })
    }

    pub(crate) fn canonical_public_binary_candidates(name: &str) -> &'static [&'static str] {
        let normalized = name.trim().to_ascii_lowercase().replace('_', "-");
        match normalized.as_str() {
            "action-runner" | "action-runner-worker" | "mu-ci-worker" => {
                &["mu-ci-worker", "action-runner"]
            }
            "action-runner-controller" | "mu-ci-controller" => {
                &["mu-ci-controller", "action-runner-controller"]
            }
            "muregist" | "mu-registry" => &["mu-registry", "muregist"],
            "muconde-agent" | "mu-cd-agent" => &["mu-cd-agent", "muconde-agent"],
            "muconde-controller" | "mu-cd-controller" => {
                &["mu-cd-controller", "muconde-controller"]
            }
            "muobserve" | "muobservectl" | "mu-observable-hub" => {
                &["mu-observable-hub", "muobservectl", "muobserve"]
            }
            "muobserve-collector" | "mu-observable-collector" => {
                &["mu-observable-collector", "muobserve-collector"]
            }
            "musentinel" | "muobserve-sentinel" | "mu-observable-sentinel" => {
                &["mu-observable-sentinel", "musentinel", "muobserve-sentinel"]
            }
            "jero-engine" | "jero-worker" | "k3-worker" => {
                &["jero-engine", "jero-worker", "k3-worker"]
            }
            "jero-kv-cache" | "k3-kv" => &["jero-kv-cache", "k3-kv"],
            "jero-manager" | "k3-manager" => &["jero-manager", "k3-manager"],
            _ => &[],
        }
    }

    fn push_unique_name(out: &mut Vec<String>, candidate: &str) {
        let trimmed = candidate.trim();
        if !trimmed.is_empty() && !out.iter().any(|existing| existing == trimmed) {
            out.push(trimmed.to_string());
        }
    }

    pub(crate) fn candidate_binary_names(
        summary: &CdManifestSummary,
        repo_name: &str,
    ) -> Vec<String> {
        let mut names = Vec::new();
        if let Some(bin) = summary.binary.as_deref() {
            push_unique_name(&mut names, bin);
            for alias in canonical_public_binary_candidates(bin) {
                push_unique_name(&mut names, alias);
            }
        }
        for alias in canonical_public_binary_candidates(&summary.service_name) {
            push_unique_name(&mut names, alias);
        }
        if let Some(install_path) = summary.install_path.as_deref() {
            if let Some(base) = Path::new(install_path).file_name().and_then(|s| s.to_str()) {
                push_unique_name(&mut names, base);
            }
        }
        push_unique_name(&mut names, &summary.service_name);
        push_unique_name(
            &mut names,
            &summary.service_name.to_ascii_lowercase().replace('_', "-"),
        );
        if let Some(repo_short) = repo_name.rsplit('/').next() {
            push_unique_name(&mut names, repo_short);
        }
        names
    }

    fn candidate_target_release_subdirs(expected_arch: Option<ExpectedElfArch>) -> Vec<PathBuf> {
        match expected_arch {
            Some(arch) => vec![
                PathBuf::from(arch.target_triple()).join("release"),
                PathBuf::from("release"),
            ],
            None => vec![
                PathBuf::from("release"),
                PathBuf::from(ExpectedElfArch::Riscv64.target_triple()).join("release"),
                PathBuf::from(ExpectedElfArch::X86_64.target_triple()).join("release"),
                PathBuf::from(ExpectedElfArch::Aarch64.target_triple()).join("release"),
            ],
        }
    }

    fn read_validated_binary(
        path: &Path,
        expected_arch: Option<ExpectedElfArch>,
    ) -> Result<Option<PackagedArtifact>, String> {
        let Ok(meta) = std::fs::symlink_metadata(path) else {
            return Ok(None);
        };
        if meta.file_type().is_symlink() {
            return Err(format!(
                "Refusing symlink binary artifact '{}'",
                path.display()
            ));
        }
        if !meta.is_file() {
            return Ok(None);
        }
        let bytes = std::fs::read(path)
            .map_err(|e| format!("Failed to read binary artifact '{}': {e}", path.display()))?;
        if bytes.is_empty() {
            return Err(format!("Binary artifact '{}' is empty", path.display()));
        }
        validate_elf_architecture(&bytes, expected_arch, path)?;
        let sha256_hex = compute_sha256_hex(&bytes);
        let filename = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("artifact.bin")
            .to_string();
        Ok(Some(PackagedArtifact {
            filename,
            bytes,
            sha256_hex,
        }))
    }

    fn resolve_binary_artifact_in_dirs(
        workspace_root: &Path,
        target_dir: &Path,
        repo_name: &str,
        summary: &CdManifestSummary,
    ) -> Result<PackagedArtifact, String> {
        let expected_arch = infer_target_arch_from_nodes(&summary.target_nodes);
        let candidates = candidate_binary_names(summary, repo_name);

        if let Some(raw_art) = summary.artifact.as_deref() {
            let rel_art = sanitize_relative_subpath(art_or_raw(raw_art))?;
            let art_path = workspace_root.join(&rel_art);
            if let Some(pkg) = read_validated_binary(&art_path, expected_arch)? {
                return Ok(pkg);
            }
            if art_path.is_dir() {
                for bin_name in &candidates {
                    let candidate_path = art_path.join(bin_name);
                    if let Some(pkg) = read_validated_binary(&candidate_path, expected_arch)? {
                        return Ok(pkg);
                    }
                }
            }
        }

        if let Some(explicit_bin) = summary.binary.as_deref() {
            if explicit_bin.contains('/') {
                let rel_bin = sanitize_relative_subpath(explicit_bin)?;
                let bin_path = workspace_root.join(&rel_bin);
                if let Some(pkg) = read_validated_binary(&bin_path, expected_arch)? {
                    return Ok(pkg);
                }
            }
        }

        for rel_dir in candidate_target_release_subdirs(expected_arch) {
            let abs_dir = target_dir.join(&rel_dir);
            for bin_name in &candidates {
                let bin_path = abs_dir.join(bin_name);
                if let Some(pkg) = read_validated_binary(&bin_path, expected_arch)? {
                    return Ok(pkg);
                }
            }
        }

        if workspace_root.join("Cargo.toml").is_file() {
            let (cargo_bins, _) = discover_cargo_bin_targets(workspace_root);
            let extra_bins: Vec<String> = cargo_bins
                .into_iter()
                .filter(|b| !candidates.iter().any(|existing| existing == b))
                .collect();
            if !extra_bins.is_empty() {
                for rel_dir in candidate_target_release_subdirs(expected_arch) {
                    let abs_dir = target_dir.join(&rel_dir);
                    for bin_name in &extra_bins {
                        let bin_path = abs_dir.join(bin_name);
                        if let Some(pkg) = read_validated_binary(&bin_path, expected_arch)? {
                            return Ok(pkg);
                        }
                    }
                }
            }
        }

        Err(format!(
            "No release binary found in '{}' (target_dir '{}') matching candidates {:?}",
            workspace_root.display(),
            target_dir.display(),
            candidates
        ))
    }

    fn resolve_binary_artifact(
        repo_workspace: &Path,
        repo_name: &str,
        summary: &CdManifestSummary,
    ) -> Result<PackagedArtifact, String> {
        resolve_binary_artifact_in_dirs(
            repo_workspace,
            &repo_workspace.join("target"),
            repo_name,
            summary,
        )
    }

    const fn art_or_raw(raw: &str) -> &str {
        raw
    }

    pub(super) fn resolve_and_package_artifact(
        repo_workspace: &Path,
        repo_name: &str,
        summary: &CdManifestSummary,
    ) -> Result<PackagedArtifact, String> {
        if is_static_web_deployment(summary) {
            resolve_static_web_bundle(repo_workspace, summary)
        } else {
            resolve_binary_artifact(repo_workspace, repo_name, summary)
        }
    }

    const fn default_it_critical() -> bool {
        true
    }

    const fn default_it_schema_version() -> u32 {
        1
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub(super) struct ItManifestEntryJson {
        pub(super) name: String,
        pub(super) command: String,
        #[serde(default)]
        pub(super) args: Vec<String>,
        #[serde(default = "default_it_critical")]
        pub(super) critical: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub(super) timeout_secs: Option<u64>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub(super) struct ItManifestJson {
        #[serde(default = "default_it_schema_version")]
        pub(super) schema_version: u32,
        #[serde(default)]
        pub(super) service: String,
        #[serde(default)]
        pub(super) git_commit: String,
        #[serde(default)]
        pub(super) artifact_sha256: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub(super) target_arch: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub(super) target_triple: Option<String>,
        #[serde(default)]
        pub(super) tests: Vec<ItManifestEntryJson>,
    }

    pub(super) struct ArchivedItEntry {
        pub(super) archive_path: PathBuf,
        pub(super) bytes: Vec<u8>,
        pub(super) mode: u32,
    }

    pub(super) fn build_bounded_tar_gz_with_limit(
        entries: &[ArchivedItEntry],
        max_uncompressed_bytes: u64,
    ) -> Result<Vec<u8>, String> {
        let mut total_uncompressed = 0u64;
        let mut seen_paths = HashSet::new();
        for entry in entries {
            let clean = sanitize_relative_subpath(&entry.archive_path.to_string_lossy())?;
            if !seen_paths.insert(clean) {
                return Err(format!(
                    "Duplicate archive path '{}' in IT bundle",
                    entry.archive_path.display()
                ));
            }
            total_uncompressed = total_uncompressed
                .checked_add(entry.bytes.len() as u64)
                .ok_or_else(|| "IT archive uncompressed size overflow".to_string())?;
            if total_uncompressed > max_uncompressed_bytes {
                return Err(format!(
                    "IT archive uncompressed payload ({total_uncompressed} bytes) exceeds {max_uncompressed_bytes} byte budget"
                ));
            }
        }

        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = Builder::new(encoder);
        for entry in entries {
            let clean = sanitize_relative_subpath(&entry.archive_path.to_string_lossy())?;
            append_tar_file(&mut builder, &clean, &entry.bytes, entry.mode)?;
        }
        builder
            .finish()
            .map_err(|e| format!("Failed to finalize IT tar archive: {e}"))?;
        let mut encoder = builder
            .into_inner()
            .map_err(|e| format!("Failed to unwrap IT tar builder: {e}"))?;
        encoder
            .flush()
            .map_err(|e| format!("Failed to flush IT gzip stream: {e}"))?;
        encoder
            .finish()
            .map_err(|e| format!("Failed to finish IT gzip stream: {e}"))
    }

    fn build_bounded_tar_gz(entries: &[ArchivedItEntry]) -> Result<Vec<u8>, String> {
        build_bounded_tar_gz_with_limit(entries, MAX_IT_ARCHIVE_UNCOMPRESSED_BYTES)
    }

    fn track_homogeneous_elf(
        homogeneous_machine: &mut Option<u16>,
        bytes: &[u8],
        expected_arch: Option<ExpectedElfArch>,
        path: &Path,
    ) -> Result<(), String> {
        let Some((ei_class, e_machine)) = parse_elf_machine(bytes) else {
            return Ok(());
        };
        if ei_class != 2 {
            return Err(format!(
                "IT binary '{}' is not a 64-bit ELF binary (EI_CLASS={}, expected 2)",
                path.display(),
                ei_class
            ));
        }
        validate_elf_architecture(bytes, expected_arch, path)?;
        if let Some(prev) = *homogeneous_machine {
            if prev != e_machine {
                return Err(format!(
                    "Heterogeneous ELF architectures in IT bundle: '{}' has e_machine=0x{e_machine:04x}, expected 0x{prev:04x}",
                    path.display()
                ));
            }
        } else {
            *homogeneous_machine = Some(e_machine);
        }
        Ok(())
    }

    pub(super) fn parse_smoke_binary_stem(file_name: &str) -> Option<String> {
        let trimmed = file_name.trim();
        if !trimmed.starts_with("smoke_") {
            return None;
        }
        for ignored in [".d", ".o", ".rlib", ".rmeta", ".so", ".dylib", ".a", ".pdb"] {
            if trimmed.ends_with(ignored) {
                return None;
            }
        }
        let stem = if let Some((prefix, suffix)) = trimmed.rsplit_once('-') {
            if suffix.len() == 16 && suffix.bytes().all(|b| b.is_ascii_hexdigit()) {
                prefix
            } else {
                trimmed
            }
        } else {
            trimmed
        };
        if !stem.starts_with("smoke_") || stem.len() <= "smoke_".len() || stem.contains('.') {
            return None;
        }
        Some(stem.to_string())
    }

    fn candidate_smoke_deps_dirs(expected_arch: Option<ExpectedElfArch>) -> Vec<PathBuf> {
        let mut dirs = Vec::new();
        match expected_arch {
            Some(arch) => {
                let triple = arch.target_triple();
                dirs.push(PathBuf::from("target").join(triple).join("release/deps"));
                dirs.push(PathBuf::from("target/release/deps"));
                dirs.push(PathBuf::from("target").join(triple).join("debug/deps"));
                dirs.push(PathBuf::from("target/debug/deps"));
            }
            None => {
                dirs.push(PathBuf::from("target/release/deps"));
                for arch in [
                    ExpectedElfArch::Riscv64,
                    ExpectedElfArch::X86_64,
                    ExpectedElfArch::Aarch64,
                ] {
                    dirs.push(
                        PathBuf::from("target")
                            .join(arch.target_triple())
                            .join("release/deps"),
                    );
                }
                dirs.push(PathBuf::from("target/debug/deps"));
                for arch in [
                    ExpectedElfArch::Riscv64,
                    ExpectedElfArch::X86_64,
                    ExpectedElfArch::Aarch64,
                ] {
                    dirs.push(
                        PathBuf::from("target")
                            .join(arch.target_triple())
                            .join("debug/deps"),
                    );
                }
            }
        }
        dirs
    }

    fn package_it_directory(
        dir_path: &Path,
        service_name: &str,
        expected_arch: Option<ExpectedElfArch>,
    ) -> Result<Option<PackagedArtifact>, String> {
        let mut rel_files = Vec::new();
        collect_sorted_files(dir_path, dir_path, &mut rel_files)?;
        if rel_files.is_empty() {
            return Ok(None);
        }

        let mut homogeneous_machine = None;
        let mut entries = Vec::with_capacity(rel_files.len());
        for rel in rel_files {
            let full_path = dir_path.join(&rel);
            let bytes = std::fs::read(&full_path)
                .map_err(|e| format!("Failed to read '{}': {e}", full_path.display()))?;
            track_homogeneous_elf(&mut homogeneous_machine, &bytes, expected_arch, &full_path)?;
            let mode = if is_executable_file(&full_path, true) {
                0o755
            } else {
                0o644
            };
            entries.push(ArchivedItEntry {
                archive_path: rel,
                bytes,
                mode,
            });
        }

        let gz_bytes = build_bounded_tar_gz(&entries)?;
        let sha256_hex = compute_sha256_hex(&gz_bytes);
        Ok(Some(PackagedArtifact {
            filename: format!("{service_name}-it.tar.gz"),
            bytes: gz_bytes,
            sha256_hex,
        }))
    }

    fn matches_manifest_command_name(file_name: &str, target_base: &str) -> bool {
        if file_name == target_base {
            return true;
        }
        if let Some((prefix, suffix)) = file_name.rsplit_once('-') {
            return prefix == target_base
                && suffix.len() == 16
                && suffix.bytes().all(|b| b.is_ascii_hexdigit());
        }
        false
    }

    fn find_binary_in_cargo_outputs(
        repo_workspace: &Path,
        base_name: &str,
        expected_arch: Option<ExpectedElfArch>,
    ) -> Result<Option<(PathBuf, Vec<u8>)>, String> {
        let mut search_dirs = candidate_smoke_deps_dirs(expected_arch);
        if let Some(arch) = expected_arch {
            search_dirs.push(
                PathBuf::from("target")
                    .join(arch.target_triple())
                    .join("release"),
            );
            search_dirs.push(
                PathBuf::from("target")
                    .join(arch.target_triple())
                    .join("debug"),
            );
        }
        search_dirs.push(PathBuf::from("target/release"));
        search_dirs.push(PathBuf::from("target/debug"));

        for rel_dir in search_dirs {
            let abs_dir = repo_workspace.join(&rel_dir);
            let Ok(dir_meta) = std::fs::symlink_metadata(&abs_dir) else {
                continue;
            };
            if dir_meta.file_type().is_symlink() {
                return Err(format!(
                    "Refusing symlink Cargo build directory '{}'",
                    abs_dir.display()
                ));
            }
            if !dir_meta.is_dir() {
                continue;
            }
            let mut dir_entries: Vec<_> = std::fs::read_dir(&abs_dir)
                .map_err(|e| format!("Failed reading '{}': {e}", abs_dir.display()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("Failed listing '{}': {e}", abs_dir.display()))?;
            dir_entries.sort_by_key(std::fs::DirEntry::file_name);

            for entry in dir_entries {
                let name = entry.file_name().to_string_lossy().into_owned();
                if !matches_manifest_command_name(&name, base_name) {
                    continue;
                }
                let path = entry.path();
                let meta = std::fs::symlink_metadata(&path)
                    .map_err(|e| format!("Failed to stat '{}': {e}", path.display()))?;
                if meta.file_type().is_symlink() {
                    return Err(format!("Refusing symlink IT binary '{}'", path.display()));
                }
                if meta.is_file() {
                    let bytes = std::fs::read(&path)
                        .map_err(|e| format!("Failed reading '{}': {e}", path.display()))?;
                    return Ok(Some((path, bytes)));
                }
            }
        }
        Ok(None)
    }

    fn resolve_manifest_referenced_binary(
        repo_workspace: &Path,
        manifest_dir: &Path,
        rel_cmd: &Path,
        expected_arch: Option<ExpectedElfArch>,
    ) -> Result<(PathBuf, Vec<u8>), String> {
        for direct in [manifest_dir.join(rel_cmd), repo_workspace.join(rel_cmd)] {
            if let Ok(meta) = std::fs::symlink_metadata(&direct) {
                if meta.file_type().is_symlink() {
                    return Err(format!("Refusing symlink IT binary '{}'", direct.display()));
                }
                if meta.is_file() {
                    let bytes = std::fs::read(&direct)
                        .map_err(|e| format!("Failed reading '{}': {e}", direct.display()))?;
                    return Ok((direct, bytes));
                }
            }
        }

        if let Some(base_name) = rel_cmd.file_name().and_then(|s| s.to_str()) {
            if let Some(found) =
                find_binary_in_cargo_outputs(repo_workspace, base_name, expected_arch)?
            {
                return Ok(found);
            }
        }

        Err(format!(
            "IT manifest references missing binary '{}'",
            rel_cmd.display()
        ))
    }

    fn package_it_manifest_file(
        repo_workspace: &Path,
        manifest_path: &Path,
        raw_manifest: &[u8],
        service_name: &str,
        expected_arch: Option<ExpectedElfArch>,
    ) -> Result<PackagedArtifact, String> {
        let parsed: ItManifestJson = serde_json::from_slice(raw_manifest).map_err(|e| {
            format!(
                "Failed to parse IT manifest '{}': {e}",
                manifest_path.display()
            )
        })?;
        let manifest_dir = manifest_path.parent().unwrap_or(repo_workspace);
        let mut homogeneous_machine = None;
        let mut entries = vec![ArchivedItEntry {
            archive_path: PathBuf::from("manifest.json"),
            bytes: raw_manifest.to_vec(),
            mode: 0o644,
        }];
        let mut packaged_cmds = HashSet::new();

        for test in &parsed.tests {
            let rel_cmd = sanitize_relative_subpath(&test.command)?;
            let (found_path, bytes) = resolve_manifest_referenced_binary(
                repo_workspace,
                manifest_dir,
                &rel_cmd,
                expected_arch,
            )?;
            if bytes.is_empty() {
                return Err(format!(
                    "IT binary '{}' referenced by '{}' is empty",
                    found_path.display(),
                    manifest_path.display()
                ));
            }
            if bytes.len() >= 4 && &bytes[..4] == b"\x7fELF" && parse_elf_machine(&bytes).is_none()
            {
                return Err(format!(
                    "IT binary '{}' has truncated or invalid ELF header",
                    found_path.display()
                ));
            }
            track_homogeneous_elf(&mut homogeneous_machine, &bytes, expected_arch, &found_path)?;
            if packaged_cmds.insert(rel_cmd.clone()) {
                entries.push(ArchivedItEntry {
                    archive_path: rel_cmd,
                    bytes,
                    mode: 0o755,
                });
            }
        }

        let gz_bytes = build_bounded_tar_gz(&entries)?;
        let sha256_hex = compute_sha256_hex(&gz_bytes);
        Ok(PackagedArtifact {
            filename: format!("{service_name}-it.tar.gz"),
            bytes: gz_bytes,
            sha256_hex,
        })
    }

    struct SmokeBinaryCandidate {
        dir_rank: usize,
        arch_matches: bool,
        mtime: SystemTime,
        file_name: String,
        path: PathBuf,
        bytes: Vec<u8>,
    }

    fn collect_smoke_candidates_in_dir(
        abs_dir: &Path,
        dir_rank: usize,
        expected_arch: Option<ExpectedElfArch>,
        by_stem: &mut BTreeMap<String, Vec<SmokeBinaryCandidate>>,
    ) -> Result<(), String> {
        let Ok(dir_meta) = std::fs::symlink_metadata(abs_dir) else {
            return Ok(());
        };
        if dir_meta.file_type().is_symlink() {
            return Err(format!(
                "Refusing symlink Cargo deps directory '{}'",
                abs_dir.display()
            ));
        }
        if !dir_meta.is_dir() {
            return Ok(());
        }

        let mut dir_entries: Vec<_> = std::fs::read_dir(abs_dir)
            .map_err(|e| format!("Failed listing '{}': {e}", abs_dir.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Failed reading entry in '{}': {e}", abs_dir.display()))?;
        dir_entries.sort_by_key(std::fs::DirEntry::file_name);

        for entry in dir_entries {
            let file_name = entry.file_name().to_string_lossy().into_owned();
            let Some(stem) = parse_smoke_binary_stem(&file_name) else {
                continue;
            };
            let path = entry.path();
            let meta = std::fs::symlink_metadata(&path)
                .map_err(|e| format!("Failed to stat '{}': {e}", path.display()))?;
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "Refusing symlink smoke binary '{}'",
                    path.display()
                ));
            }
            if !meta.is_file() {
                continue;
            }
            let bytes = std::fs::read(&path)
                .map_err(|e| format!("Failed reading '{}': {e}", path.display()))?;
            if bytes.len() < 4 || &bytes[..4] != b"\x7fELF" {
                continue;
            }
            let Some((ei_class, e_machine)) = parse_elf_machine(&bytes) else {
                return Err(format!(
                    "Smoke binary '{}' has truncated or invalid ELF header",
                    path.display()
                ));
            };
            if ei_class != 2 {
                return Err(format!(
                    "Smoke binary '{}' is not a 64-bit ELF binary (EI_CLASS={}, expected 2)",
                    path.display(),
                    ei_class
                ));
            }
            if ExpectedElfArch::from_e_machine(e_machine).is_none() {
                return Err(format!(
                    "Smoke binary '{}' has unsupported ELF e_machine=0x{e_machine:04x}",
                    path.display()
                ));
            }
            let arch_matches = expected_arch.is_none_or(|arch| arch.e_machine() == e_machine);
            let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            by_stem.entry(stem).or_default().push(SmokeBinaryCandidate {
                dir_rank,
                arch_matches,
                mtime,
                file_name,
                path,
                bytes,
            });
        }
        Ok(())
    }

    fn discover_and_package_smoke_binaries(
        repo_workspace: &Path,
        summary: &CdManifestSummary,
        expected_arch: Option<ExpectedElfArch>,
        commit_sha: &str,
        artifact_sha256: &str,
    ) -> Result<Option<PackagedArtifact>, String> {
        let mut by_stem: BTreeMap<String, Vec<SmokeBinaryCandidate>> = BTreeMap::new();
        for (rank, rel_dir) in candidate_smoke_deps_dirs(expected_arch)
            .into_iter()
            .enumerate()
        {
            collect_smoke_candidates_in_dir(
                &repo_workspace.join(rel_dir),
                rank,
                expected_arch,
                &mut by_stem,
            )?;
        }

        if by_stem.is_empty() {
            return Ok(None);
        }

        let mut selected: Vec<(String, SmokeBinaryCandidate)> = Vec::new();
        for (stem, mut candidates) in by_stem {
            if expected_arch.is_some() && !candidates.iter().any(|c| c.arch_matches) {
                validate_elf_architecture(
                    &candidates[0].bytes,
                    expected_arch,
                    &candidates[0].path,
                )?;
            }
            candidates.retain(|c| c.arch_matches);
            candidates.sort_by(|a, b| {
                a.dir_rank
                    .cmp(&b.dir_rank)
                    .then_with(|| b.mtime.cmp(&a.mtime))
                    .then_with(|| a.file_name.cmp(&b.file_name))
            });
            if let Some(best) = candidates.into_iter().next() {
                selected.push((stem, best));
            }
        }

        if selected.is_empty() {
            return Ok(None);
        }

        let mut homogeneous_machine = None;
        for (_, cand) in &selected {
            track_homogeneous_elf(
                &mut homogeneous_machine,
                &cand.bytes,
                expected_arch,
                &cand.path,
            )?;
        }

        if !is_static_web_deployment(summary) {
            for requested in &summary.integration_tests {
                let trimmed = requested.trim();
                if trimmed.starts_with("smoke_")
                    && !selected.iter().any(|(stem, _)| stem == trimmed)
                {
                    return Err(format!(
                        "CD manifest for '{}' requires smoke test '{}', but no matching compiled 64-bit ELF binary was found",
                        summary.service_name, trimmed
                    ));
                }
            }
        }

        let resolved_arch =
            expected_arch.or_else(|| homogeneous_machine.and_then(ExpectedElfArch::from_e_machine));

        let mut manifest_tests = Vec::with_capacity(selected.len());
        let mut archive_entries = Vec::with_capacity(selected.len() + 1);
        for (stem, cand) in selected {
            let cmd_rel = format!("bin/{stem}");
            manifest_tests.push(ItManifestEntryJson {
                name: stem,
                command: cmd_rel.clone(),
                args: vec!["--nocapture".to_string()],
                critical: true,
                timeout_secs: Some(30),
            });
            archive_entries.push(ArchivedItEntry {
                archive_path: PathBuf::from(cmd_rel),
                bytes: cand.bytes,
                mode: 0o755,
            });
        }

        let manifest = ItManifestJson {
            schema_version: 1,
            service: summary.service_name.clone(),
            git_commit: commit_sha.to_string(),
            artifact_sha256: artifact_sha256.to_string(),
            target_arch: resolved_arch.map(|a| a.label().to_string()),
            target_triple: resolved_arch.map(|a| a.target_triple().to_string()),
            tests: manifest_tests,
        };
        let manifest_bytes = serde_json::to_vec_pretty(&manifest)
            .map_err(|e| format!("Failed to serialize synthesized IT manifest JSON: {e}"))?;

        let mut full_entries = Vec::with_capacity(archive_entries.len() + 1);
        full_entries.push(ArchivedItEntry {
            archive_path: PathBuf::from("manifest.json"),
            bytes: manifest_bytes,
            mode: 0o644,
        });
        full_entries.extend(archive_entries);

        let gz_bytes = build_bounded_tar_gz(&full_entries)?;
        let sha256_hex = compute_sha256_hex(&gz_bytes);
        Ok(Some(PackagedArtifact {
            filename: format!("{}-it.tar.gz", summary.service_name),
            bytes: gz_bytes,
            sha256_hex,
        }))
    }

    fn build_fallback_it_manifest_tar_gz(
        service_name: &str,
        commit_sha: &str,
        artifact_sha256: &str,
    ) -> Result<Vec<u8>, String> {
        let manifest_bytes = serde_json::to_vec_pretty(&ItManifestJson {
            schema_version: 1,
            service: service_name.to_string(),
            git_commit: commit_sha.to_string(),
            artifact_sha256: artifact_sha256.to_string(),
            target_arch: None,
            target_triple: None,
            tests: Vec::new(),
        })
        .map_err(|e| format!("Failed to serialize IT manifest JSON: {e}"))?;

        build_bounded_tar_gz(&[ArchivedItEntry {
            archive_path: PathBuf::from("manifest.json"),
            bytes: manifest_bytes,
            mode: 0o644,
        }])
    }

    pub(super) fn package_it_archive(
        repo_workspace: &Path,
        summary: &CdManifestSummary,
        commit_sha: &str,
        artifact_sha256: &str,
    ) -> Result<PackagedArtifact, String> {
        let expected_arch = infer_target_arch_from_nodes(&summary.target_nodes);
        const IT_DIR_CANDIDATES: [&str; 6] = [
            ".mucd/it",
            ".mucd/tests",
            ".muconde/it",
            ".muconde/tests",
            "tests/it",
            "it",
        ];
        for rel in IT_DIR_CANDIDATES {
            let dir_path = repo_workspace.join(rel);
            let Ok(meta) = std::fs::symlink_metadata(&dir_path) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "Refusing symlink IT directory '{}'",
                    dir_path.display()
                ));
            }
            if meta.is_dir() {
                if let Some(pkg) =
                    package_it_directory(&dir_path, &summary.service_name, expected_arch)?
                {
                    return Ok(pkg);
                }
            }
        }

        const IT_MANIFEST_FILES: [&str; 3] = [
            ".mucd/it-manifest.json",
            ".mucd/manifest.json",
            "it-manifest.json",
        ];
        for rel in IT_MANIFEST_FILES {
            let file_path = repo_workspace.join(rel);
            let Ok(meta) = std::fs::symlink_metadata(&file_path) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "Refusing symlink IT manifest '{}'",
                    file_path.display()
                ));
            }
            if meta.is_file() {
                let raw = std::fs::read(&file_path)
                    .map_err(|e| format!("Failed to read '{}': {e}", file_path.display()))?;
                return package_it_manifest_file(
                    repo_workspace,
                    &file_path,
                    &raw,
                    &summary.service_name,
                    expected_arch,
                );
            }
        }

        if let Some(pkg) = discover_and_package_smoke_binaries(
            repo_workspace,
            summary,
            expected_arch,
            commit_sha,
            artifact_sha256,
        )? {
            return Ok(pkg);
        }

        let smoke_stems = discover_smoke_test_stems(repo_workspace)?;
        if !smoke_stems.is_empty() && repo_workspace.join("Cargo.toml").is_file() {
            let target_dir = resolve_release_target_dir(repo_workspace);
            let ctx = CompiledSmokePackageCtx {
                checkout_dir: repo_workspace,
                target_dir: &target_dir,
                summary,
                expected_arch,
                commit_sha,
                artifact_sha256,
            };
            return compile_and_package_smoke_tests(&ctx, &smoke_stems);
        }

        let selects_custom_smoke = !is_static_web_deployment(summary)
            && summary
                .integration_tests
                .iter()
                .any(|t| t.trim().starts_with("smoke_"));
        if selects_custom_smoke {
            return Err(format!(
                "CD manifest for '{}' selects custom smoke tests {:?}, but no .mucd/it* files or compiled smoke_* ELF binaries were found",
                summary.service_name, summary.integration_tests
            ));
        }

        tracing::warn!(
            service = %summary.service_name,
            commit = %commit_sha,
            workspace = %repo_workspace.display(),
            "No .mucd/it* directory, it-manifest.json, or compiled smoke_* ELF binaries found; packaging empty IT manifest fallback"
        );

        let gz_bytes =
            build_fallback_it_manifest_tar_gz(&summary.service_name, commit_sha, artifact_sha256)?;
        let sha256_hex = compute_sha256_hex(&gz_bytes);
        Ok(PackagedArtifact {
            filename: format!("{}-it.tar.gz", summary.service_name),
            bytes: gz_bytes,
            sha256_hex,
        })
    }

    struct EphemeralCheckoutDir {
        path: PathBuf,
    }

    impl EphemeralCheckoutDir {
        fn create() -> Result<Self, String> {
            let path = std::env::temp_dir().join(format!("mu-ci-postcd-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&path).map_err(|e| {
                format!(
                    "Failed to create ephemeral post-CI checkout dir '{}': {e}",
                    path.display()
                )
            })?;
            Ok(Self { path })
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for EphemeralCheckoutDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    pub(super) fn resolve_release_target_dir(repo_workspace: &Path) -> PathBuf {
        if let Some(env_dir) = first_non_empty_env(&["MU_CI_CONTROLLER_RELEASE_TARGET_DIR"]) {
            return PathBuf::from(env_dir);
        }
        repo_workspace.join(".post_ci_target")
    }

    pub(super) const fn host_elf_arch() -> Option<ExpectedElfArch> {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            Some(ExpectedElfArch::X86_64)
        }
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        {
            Some(ExpectedElfArch::Aarch64)
        }
        #[cfg(all(target_os = "linux", target_arch = "riscv64"))]
        {
            Some(ExpectedElfArch::Riscv64)
        }
        #[cfg(not(all(
            target_os = "linux",
            any(
                target_arch = "x86_64",
                target_arch = "aarch64",
                target_arch = "riscv64"
            )
        )))]
        {
            None
        }
    }

    pub(super) fn cross_target_triple(
        expected_arch: Option<ExpectedElfArch>,
    ) -> Option<&'static str> {
        let arch = expected_arch?;
        if host_elf_arch() == Some(arch) {
            None
        } else {
            Some(arch.target_triple())
        }
    }

    fn tail_command_output(bytes: &[u8]) -> String {
        let text = String::from_utf8_lossy(bytes);
        let trimmed = text.trim();
        let chars: Vec<char> = trimmed.chars().collect();
        if chars.len() <= 1024 {
            trimmed.to_string()
        } else {
            chars[chars.len() - 1024..].iter().collect()
        }
    }

    /// Safely unpacks an uncompressed tar stream into `dest_dir`, rejecting symlinks,
    /// hardlinks, special files, path traversals (`..`), and absolute/prefixed paths.
    pub(super) fn unpack_tar_bytes_safely(tar_bytes: &[u8], dest_dir: &Path) -> Result<(), String> {
        let mut archive = Archive::new(std::io::Cursor::new(tar_bytes));
        let entries = archive
            .entries()
            .map_err(|e| format!("Failed reading git archive tar stream: {e}"))?;

        for entry_res in entries {
            let mut entry =
                entry_res.map_err(|e| format!("Corrupt entry in git archive tar stream: {e}"))?;
            let entry_type = entry.header().entry_type();
            if matches!(
                entry_type,
                EntryType::XGlobalHeader
                    | EntryType::XHeader
                    | EntryType::GNULongName
                    | EntryType::GNULongLink
            ) {
                continue;
            }
            if matches!(entry_type, EntryType::Symlink | EntryType::Link) {
                return Err("Git archive contains disallowed symlink or hardlink entry".to_string());
            }
            if !entry_type.is_file() && !entry_type.is_dir() {
                return Err(format!(
                    "Git archive contains disallowed special entry type '{entry_type:?}'"
                ));
            }

            let raw_path = entry
                .path()
                .map_err(|e| format!("Invalid path in git archive: {e}"))?
                .into_owned();
            let mut clean_rel = PathBuf::new();
            for comp in raw_path.components() {
                match comp {
                    Component::Normal(part) => clean_rel.push(part),
                    Component::CurDir => {}
                    Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                        return Err(format!(
                            "Git archive contains disallowed traversal or absolute path '{}'",
                            raw_path.display()
                        ));
                    }
                }
            }
            if clean_rel.as_os_str().is_empty() {
                continue;
            }

            let out_path = dest_dir.join(&clean_rel);
            if entry_type.is_dir() {
                std::fs::create_dir_all(&out_path).map_err(|e| {
                    format!(
                        "Failed creating unpacked directory '{}': {e}",
                        out_path.display()
                    )
                })?;
                continue;
            }

            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    format!(
                        "Failed creating parent directory '{}': {e}",
                        parent.display()
                    )
                })?;
            }
            let mode = entry.header().mode().unwrap_or(0o644);
            let mut file = std::fs::File::create(&out_path).map_err(|e| {
                format!(
                    "Failed creating unpacked file '{}': {e}",
                    out_path.display()
                )
            })?;
            std::io::copy(&mut entry, &mut file).map_err(|e| {
                format!("Failed writing unpacked file '{}': {e}", out_path.display())
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if (mode & 0o111) != 0 {
                    let _ =
                        std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o755));
                }
            }
            #[cfg(not(unix))]
            {
                let _ = mode;
            }
        }
        Ok(())
    }

    fn materialize_git_commit_to_dir(
        repo_workspace: &Path,
        commit_sha: &str,
        dest_dir: &Path,
    ) -> Result<(), String> {
        let sha = commit_sha.trim();
        if sha.is_empty()
            || sha.starts_with('-')
            || sha.contains('\0')
            || sha.bytes().any(|b| b.is_ascii_whitespace())
        {
            return Err(format!(
                "Invalid commit_sha '{commit_sha}' for git archive materialization"
            ));
        }

        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(repo_workspace)
            .args(["archive", "--format=tar", sha])
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .map_err(|e| {
                format!(
                    "Failed spawning git archive for '{}' at '{sha}': {e}",
                    repo_workspace.display()
                )
            })?;
        if !output.status.success() {
            return Err(format!(
                "git archive failed for '{}' at '{sha}': {}",
                repo_workspace.display(),
                tail_command_output(&output.stderr)
            ));
        }
        unpack_tar_bytes_safely(&output.stdout, dest_dir)
    }

    fn materialize_static_web_bundle(
        checkout_dir: &Path,
        target_dir: &Path,
        summary: &CdManifestSummary,
    ) -> Result<PackagedArtifact, String> {
        match resolve_static_web_bundle(checkout_dir, summary) {
            Ok(pkg) => Ok(pkg),
            Err(first_err) => {
                if !checkout_dir.join("Trunk.toml").is_file() {
                    return Err(first_err);
                }
                let out = std::process::Command::new("trunk")
                    .current_dir(checkout_dir)
                    .args(["build", "--release"])
                    .env("CARGO_TARGET_DIR", target_dir)
                    .env("CARGO_BUILD_JOBS", "2")
                    .output()
                    .map_err(|e| {
                        format!(
                            "{first_err}; fallback 'trunk build --release' failed to spawn: {e}"
                        )
                    })?;
                if !out.status.success() {
                    return Err(format!(
                        "{first_err}; fallback 'trunk build --release' exited {}: {}",
                        out.status,
                        tail_command_output(&out.stderr)
                    ));
                }
                resolve_static_web_bundle(checkout_dir, summary)
            }
        }
    }

    fn discover_cargo_bin_targets(checkout_dir: &Path) -> (Vec<String>, bool) {
        let Ok(out) = std::process::Command::new("cargo")
            .current_dir(checkout_dir)
            .args(["metadata", "--no-deps", "--format-version", "1"])
            .output()
        else {
            return (Vec::new(), false);
        };
        if !out.status.success() {
            return (Vec::new(), false);
        }
        let Ok(meta) = serde_json::from_slice::<serde_json::Value>(&out.stdout) else {
            return (Vec::new(), false);
        };
        let mut bin_names = Vec::new();
        if let Some(packages) = meta.get("packages").and_then(|v| v.as_array()) {
            for pkg in packages {
                if let Some(targets) = pkg.get("targets").and_then(|v| v.as_array()) {
                    for target in targets {
                        let is_bin = target
                            .get("kind")
                            .and_then(|k| k.as_array())
                            .is_some_and(|kinds| kinds.iter().any(|k| k.as_str() == Some("bin")));
                        if is_bin {
                            if let Some(name) = target.get("name").and_then(|n| n.as_str()) {
                                push_unique_name(&mut bin_names, name);
                            }
                        }
                    }
                }
            }
        }
        let is_virtual_workspace = meta
            .get("resolve")
            .and_then(|r| r.get("root"))
            .is_some_and(serde_json::Value::is_null);
        (bin_names, is_virtual_workspace)
    }

    fn select_cargo_bin_target(
        checkout_dir: &Path,
        candidates: &[String],
    ) -> (Option<String>, bool) {
        let (bin_names, is_virtual_workspace) = discover_cargo_bin_targets(checkout_dir);
        let matched = candidates
            .iter()
            .find(|cand| bin_names.iter().any(|b| b == *cand))
            .cloned()
            .or_else(|| {
                if bin_names.len() == 1 {
                    bin_names.into_iter().next()
                } else {
                    None
                }
            });
        (matched, is_virtual_workspace)
    }

    fn build_and_package_rust_binary(
        checkout_dir: &Path,
        target_dir: &Path,
        repo_name: &str,
        summary: &CdManifestSummary,
        expected_arch: Option<ExpectedElfArch>,
    ) -> Result<PackagedArtifact, String> {
        let candidates = candidate_binary_names(summary, repo_name);
        let (matched_bin, is_virtual_workspace) =
            select_cargo_bin_target(checkout_dir, &candidates);

        let mut cmd = std::process::Command::new("cargo");
        cmd.current_dir(checkout_dir)
            .args(["build", "--release"])
            .env("CARGO_TARGET_DIR", target_dir)
            .env("CARGO_BUILD_JOBS", "2");
        if let Some(triple) = cross_target_triple(expected_arch) {
            cmd.args(["--target", triple]);
        }
        if let Some(bin_name) = matched_bin.as_deref() {
            cmd.args(["--bin", bin_name]);
        } else if is_virtual_workspace {
            cmd.args(["--workspace", "--bins"]);
        } else {
            cmd.arg("--bins");
        }

        let output = cmd.output().map_err(|e| {
            format!(
                "Failed spawning cargo build --release in '{}': {e}",
                checkout_dir.display()
            )
        })?;
        if !output.status.success() {
            return Err(format!(
                "cargo build --release failed in '{}' (status {}): {}",
                checkout_dir.display(),
                output.status,
                tail_command_output(&output.stderr)
            ));
        }

        resolve_binary_artifact_in_dirs(checkout_dir, target_dir, repo_name, summary)
    }

    pub(super) fn discover_smoke_test_stems(checkout_dir: &Path) -> Result<Vec<String>, String> {
        let tests_dir = checkout_dir.join("tests");
        let Ok(dir_meta) = std::fs::symlink_metadata(&tests_dir) else {
            return Ok(Vec::new());
        };
        if dir_meta.file_type().is_symlink() {
            return Err(format!(
                "Refusing symlink tests directory '{}'",
                tests_dir.display()
            ));
        }
        if !dir_meta.is_dir() {
            return Ok(Vec::new());
        }

        let mut entries: Vec<_> = std::fs::read_dir(&tests_dir)
            .map_err(|e| format!("Failed reading '{}': {e}", tests_dir.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Failed listing '{}': {e}", tests_dir.display()))?;
        entries.sort_by_key(std::fs::DirEntry::file_name);

        let mut stems = Vec::new();
        for entry in entries {
            let file_name = entry.file_name().to_string_lossy().into_owned();
            let Some(stem) = file_name.strip_suffix(".rs") else {
                continue;
            };
            if !stem.starts_with("smoke_")
                || stem.len() <= "smoke_".len()
                || !stem.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                continue;
            }
            let path = entry.path();
            let meta = std::fs::symlink_metadata(&path)
                .map_err(|e| format!("Failed to stat '{}': {e}", path.display()))?;
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "Refusing symlink smoke test source '{}'",
                    path.display()
                ));
            }
            if meta.is_file() {
                stems.push(stem.to_string());
            }
        }
        Ok(stems)
    }

    /// Parses Cargo `--message-format=json` lines to locate the compiled test executable
    /// for integration test target `stem`.
    pub(super) fn parse_cargo_test_executable_from_json(
        stdout: &str,
        stem: &str,
    ) -> Option<PathBuf> {
        let mut found = None;
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) else {
                continue;
            };
            if val.get("reason").and_then(|v| v.as_str()) != Some("compiler-artifact") {
                continue;
            }
            let is_test_profile = val
                .get("profile")
                .and_then(|p| p.get("test"))
                .and_then(|t| t.as_bool())
                .unwrap_or(false);
            if !is_test_profile {
                continue;
            }
            let target_matches = val
                .get("target")
                .and_then(|t| t.get("name"))
                .and_then(|n| n.as_str())
                == Some(stem);
            if !target_matches {
                continue;
            }
            if let Some(exec) = val
                .get("executable")
                .and_then(|e| e.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                found = Some(PathBuf::from(exec));
            }
        }
        found
    }

    fn maybe_strip_elf_copy(
        checkout_dir: &Path,
        stem: &str,
        orig_path: &Path,
        orig_bytes: &[u8],
        expected_arch: Option<ExpectedElfArch>,
    ) -> Vec<u8> {
        let Some((_, e_machine)) = parse_elf_machine(orig_bytes) else {
            return orig_bytes.to_vec();
        };
        let strip_candidates: &[&str] = match ExpectedElfArch::from_e_machine(e_machine) {
            Some(arch) if host_elf_arch() == Some(arch) => &["llvm-strip", "strip"],
            Some(ExpectedElfArch::Aarch64) => &["llvm-strip", "aarch64-linux-gnu-strip"],
            Some(ExpectedElfArch::Riscv64) => &["llvm-strip", "riscv64-linux-gnu-strip"],
            Some(ExpectedElfArch::X86_64) => &["llvm-strip", "x86_64-linux-gnu-strip"],
            None => return orig_bytes.to_vec(),
        };

        let out_copy = checkout_dir.join(format!(".post-ci-stripped-{stem}"));
        for strip_bin in strip_candidates {
            let _ = std::fs::remove_file(&out_copy);
            let res = std::process::Command::new(strip_bin)
                .arg("--strip-all")
                .arg("-o")
                .arg(&out_copy)
                .arg(orig_path)
                .output();
            if let Ok(out) = res {
                if out.status.success() {
                    if let Ok(stripped) = std::fs::read(&out_copy) {
                        let _ = std::fs::remove_file(&out_copy);
                        if !stripped.is_empty()
                            && stripped.len() <= orig_bytes.len()
                            && validate_elf_architecture(&stripped, expected_arch, &out_copy)
                                .is_ok()
                        {
                            return stripped;
                        }
                    }
                }
            }
        }
        let _ = std::fs::remove_file(&out_copy);
        orig_bytes.to_vec()
    }

    struct CompiledSmokePackageCtx<'a> {
        checkout_dir: &'a Path,
        target_dir: &'a Path,
        summary: &'a CdManifestSummary,
        expected_arch: Option<ExpectedElfArch>,
        commit_sha: &'a str,
        artifact_sha256: &'a str,
    }

    fn compile_and_package_smoke_tests(
        ctx: &CompiledSmokePackageCtx<'_>,
        stems: &[String],
    ) -> Result<PackagedArtifact, String> {
        let mut homogeneous_machine = None;
        let mut manifest_tests = Vec::with_capacity(stems.len());
        let mut archive_entries = Vec::with_capacity(stems.len());

        for stem in stems {
            let mut cmd = std::process::Command::new("cargo");
            cmd.current_dir(ctx.checkout_dir)
                .args([
                    "test",
                    "--release",
                    "--test",
                    stem,
                    "--no-run",
                    "--message-format=json",
                ])
                .env("CARGO_TARGET_DIR", ctx.target_dir)
                .env("CARGO_BUILD_JOBS", "2");
            if let Some(triple) = cross_target_triple(ctx.expected_arch) {
                cmd.args(["--target", triple]);
            }

            let out = cmd.output().map_err(|e| {
                format!("Failed spawning cargo test --release --test {stem} --no-run: {e}")
            })?;
            if !out.status.success() {
                return Err(format!(
                    "cargo test --release --test {stem} --no-run failed ({}): {}",
                    out.status,
                    tail_command_output(&out.stderr)
                ));
            }

            let stdout = String::from_utf8_lossy(&out.stdout);
            let exec_path =
                parse_cargo_test_executable_from_json(&stdout, stem).ok_or_else(|| {
                    format!(
                        "Cargo JSON output did not report a compiled executable for smoke test '{stem}'"
                    )
                })?;
            let meta = std::fs::symlink_metadata(&exec_path).map_err(|e| {
                format!(
                    "Failed to stat compiled smoke binary '{}': {e}",
                    exec_path.display()
                )
            })?;
            if meta.file_type().is_symlink() || !meta.is_file() {
                return Err(format!(
                    "Compiled smoke test output '{}' is not a regular non-symlink file",
                    exec_path.display()
                ));
            }
            let raw_bytes = std::fs::read(&exec_path).map_err(|e| {
                format!(
                    "Failed reading compiled smoke binary '{}': {e}",
                    exec_path.display()
                )
            })?;
            if raw_bytes.is_empty() {
                return Err(format!(
                    "Compiled smoke binary '{}' is empty",
                    exec_path.display()
                ));
            }
            let bytes = maybe_strip_elf_copy(
                ctx.checkout_dir,
                stem,
                &exec_path,
                &raw_bytes,
                ctx.expected_arch,
            );
            track_homogeneous_elf(
                &mut homogeneous_machine,
                &bytes,
                ctx.expected_arch,
                &exec_path,
            )?;

            let cmd_rel = format!("bin/{stem}");
            manifest_tests.push(ItManifestEntryJson {
                name: stem.clone(),
                command: cmd_rel.clone(),
                args: Vec::new(),
                critical: true,
                timeout_secs: None,
            });
            archive_entries.push(ArchivedItEntry {
                archive_path: PathBuf::from(cmd_rel),
                bytes,
                mode: 0o755,
            });
        }

        if !is_static_web_deployment(ctx.summary) {
            for requested in &ctx.summary.integration_tests {
                let trimmed = requested.trim();
                if trimmed.starts_with("smoke_") && !stems.iter().any(|s| s == trimmed) {
                    return Err(format!(
                        "CD manifest for '{}' requires smoke test '{}', but no matching tests/{}.rs target was found",
                        ctx.summary.service_name, trimmed, trimmed
                    ));
                }
            }
        }

        let resolved_arch = ctx
            .expected_arch
            .or_else(|| homogeneous_machine.and_then(ExpectedElfArch::from_e_machine));

        let manifest = ItManifestJson {
            schema_version: 1,
            service: ctx.summary.service_name.clone(),
            git_commit: ctx.commit_sha.to_string(),
            artifact_sha256: ctx.artifact_sha256.to_string(),
            target_arch: resolved_arch.map(|a| a.label().to_string()),
            target_triple: resolved_arch.map(|a| a.target_triple().to_string()),
            tests: manifest_tests,
        };
        let manifest_bytes = serde_json::to_vec_pretty(&manifest)
            .map_err(|e| format!("Failed to serialize synthesized IT manifest JSON: {e}"))?;

        let mut full_entries = Vec::with_capacity(archive_entries.len() + 1);
        full_entries.push(ArchivedItEntry {
            archive_path: PathBuf::from("manifest.json"),
            bytes: manifest_bytes,
            mode: 0o644,
        });
        full_entries.extend(archive_entries);

        let gz_bytes = build_bounded_tar_gz(&full_entries)?;
        let sha256_hex = compute_sha256_hex(&gz_bytes);
        Ok(PackagedArtifact {
            filename: format!("{}-it.tar.gz", ctx.summary.service_name),
            bytes: gz_bytes,
            sha256_hex,
        })
    }

    fn package_it_archive_for_materialized_checkout(
        ctx: &CompiledSmokePackageCtx<'_>,
    ) -> Result<PackagedArtifact, String> {
        const IT_DIR_CANDIDATES: [&str; 6] = [
            ".mucd/it",
            ".mucd/tests",
            ".muconde/it",
            ".muconde/tests",
            "tests/it",
            "it",
        ];
        for rel in IT_DIR_CANDIDATES {
            let dir_path = ctx.checkout_dir.join(rel);
            let Ok(meta) = std::fs::symlink_metadata(&dir_path) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "Refusing symlink IT directory '{}'",
                    dir_path.display()
                ));
            }
            if meta.is_dir() {
                if let Some(pkg) =
                    package_it_directory(&dir_path, &ctx.summary.service_name, ctx.expected_arch)?
                {
                    return Ok(pkg);
                }
            }
        }

        const IT_MANIFEST_FILES: [&str; 3] = [
            ".mucd/it-manifest.json",
            ".mucd/manifest.json",
            "it-manifest.json",
        ];
        for rel in IT_MANIFEST_FILES {
            let file_path = ctx.checkout_dir.join(rel);
            let Ok(meta) = std::fs::symlink_metadata(&file_path) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "Refusing symlink IT manifest '{}'",
                    file_path.display()
                ));
            }
            if meta.is_file() {
                let raw = std::fs::read(&file_path)
                    .map_err(|e| format!("Failed to read '{}': {e}", file_path.display()))?;
                return package_it_manifest_file(
                    ctx.checkout_dir,
                    &file_path,
                    &raw,
                    &ctx.summary.service_name,
                    ctx.expected_arch,
                );
            }
        }

        let smoke_stems = discover_smoke_test_stems(ctx.checkout_dir)?;
        if !smoke_stems.is_empty() && ctx.checkout_dir.join("Cargo.toml").is_file() {
            return compile_and_package_smoke_tests(ctx, &smoke_stems);
        }

        let selects_custom_smoke = !is_static_web_deployment(ctx.summary)
            && ctx
                .summary
                .integration_tests
                .iter()
                .any(|t| t.trim().starts_with("smoke_"));
        if selects_custom_smoke {
            return Err(format!(
                "CD manifest for '{}' selects custom smoke tests {:?}, but no .mucd/it* files or tests/smoke_*.rs targets were found",
                ctx.summary.service_name, ctx.summary.integration_tests
            ));
        }

        tracing::warn!(
            service = %ctx.summary.service_name,
            commit = %ctx.commit_sha,
            workspace = %ctx.checkout_dir.display(),
            "No .mucd/it* directory, it-manifest.json, or tests/smoke_*.rs targets found; packaging empty IT manifest fallback"
        );

        let gz_bytes = build_fallback_it_manifest_tar_gz(
            &ctx.summary.service_name,
            ctx.commit_sha,
            ctx.artifact_sha256,
        )?;
        let sha256_hex = compute_sha256_hex(&gz_bytes);
        Ok(PackagedArtifact {
            filename: format!("{}-it.tar.gz", ctx.summary.service_name),
            bytes: gz_bytes,
            sha256_hex,
        })
    }

    /// Resolves and packages release + IT artifacts, preserving the prebuilt workspace
    /// fast path and materializing `--no-checkout` Git workspaces via `git archive`.
    pub(super) fn package_post_ci_artifacts(
        repo_workspace: &Path,
        repo_name: &str,
        commit_sha: &str,
        summary: &CdManifestSummary,
    ) -> Result<(PackagedArtifact, PackagedArtifact), String> {
        let direct_err = match resolve_and_package_artifact(repo_workspace, repo_name, summary) {
            Ok(binary) => {
                let it_archive =
                    package_it_archive(repo_workspace, summary, commit_sha, &binary.sha256_hex)?;
                return Ok((binary, it_archive));
            }
            Err(err) => err,
        };

        if !repo_workspace.join(".git").exists() || commit_sha.trim().is_empty() {
            return Err(direct_err);
        }

        let ephemeral = EphemeralCheckoutDir::create()?;
        materialize_git_commit_to_dir(repo_workspace, commit_sha, ephemeral.path())?;
        let target_dir = resolve_release_target_dir(repo_workspace);
        let expected_arch = infer_target_arch_from_nodes(&summary.target_nodes);

        let binary = if is_static_web_deployment(summary) {
            materialize_static_web_bundle(ephemeral.path(), &target_dir, summary)?
        } else if ephemeral.path().join("Cargo.toml").is_file() {
            build_and_package_rust_binary(
                ephemeral.path(),
                &target_dir,
                repo_name,
                summary,
                expected_arch,
            )?
        } else {
            resolve_binary_artifact(ephemeral.path(), repo_name, summary)
                .map_err(|_| direct_err.clone())?
        };

        let smoke_ctx = CompiledSmokePackageCtx {
            checkout_dir: ephemeral.path(),
            target_dir: &target_dir,
            summary,
            expected_arch,
            commit_sha,
            artifact_sha256: &binary.sha256_hex,
        };
        let it_archive = package_it_archive_for_materialized_checkout(&smoke_ctx)?;
        Ok((binary, it_archive))
    }

    pub(super) fn build_cd_http_client(
        tls_ca_path: Option<&str>,
        tls_cert_path: Option<&str>,
        tls_key_path: Option<&str>,
    ) -> Result<(reqwest::Client, Option<String>), String> {
        let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(30));

        if let Some(ca_path) = tls_ca_path.map(str::trim).filter(|s| !s.is_empty()) {
            let ca_bytes = std::fs::read(ca_path)
                .map_err(|e| format!("Failed to read TLS CA bundle '{ca_path}': {e}"))?;
            let ca_certs = reqwest::Certificate::from_pem_bundle(&ca_bytes)
                .map_err(|e| format!("Invalid TLS CA bundle '{ca_path}': {e}"))?;
            for cert in ca_certs {
                builder = builder.add_root_certificate(cert);
            }
        }

        let cert_trimmed = tls_cert_path.map(str::trim).filter(|s| !s.is_empty());
        let key_trimmed = tls_key_path.map(str::trim).filter(|s| !s.is_empty());
        let mut derived_san = None;

        match (cert_trimmed, key_trimmed) {
            (Some(cert_path), Some(key_path)) => {
                let cert_pem = std::fs::read_to_string(cert_path)
                    .map_err(|e| format!("Failed to read TLS client cert '{cert_path}': {e}"))?;
                let key_pem = std::fs::read_to_string(key_path)
                    .map_err(|e| format!("Failed to read TLS client key '{key_path}': {e}"))?;
                let combined_pem = format!("{cert_pem}\n{key_pem}");
                let identity =
                    reqwest::Identity::from_pem(combined_pem.as_bytes()).map_err(|e| {
                        format!("Invalid TLS client identity ('{cert_path}' / '{key_path}'): {e}")
                    })?;
                builder = builder.identity(identity);

                let parsed_certs = crate::tls::load_certs(Path::new(cert_path))
                    .map_err(|e| format!("Failed to parse TLS client cert '{cert_path}': {e}"))?;
                if let Some(first_cert) = parsed_certs.first() {
                    let sans = crate::tls::extract_client_cert_sans(first_cert).map_err(|e| {
                        format!("Failed to extract SANs from TLS client cert '{cert_path}': {e}")
                    })?;
                    derived_san = sans.into_iter().next();
                }
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(
                    "Both TLS client certificate path and private key path must be provided together"
                        .to_string(),
                );
            }
            (None, None) => {}
        }

        let client = builder
            .build()
            .map_err(|e| format!("Failed to build HTTP client for post-CI CD pipeline: {e}"))?;
        Ok((client, derived_san))
    }

    pub(super) struct RegistryUploadRequest<'a> {
        pub(super) client: &'a reqwest::Client,
        pub(super) reg_base: &'a str,
        pub(super) service_name: &'a str,
        pub(super) binary: &'a PackagedArtifact,
        pub(super) it_archive: &'a PackagedArtifact,
        pub(super) muregist_api_token: Option<&'a str>,
        pub(super) client_cert_san: Option<&'a str>,
        pub(super) traceparent: &'a str,
    }

    pub(super) async fn upload_it_bundle_to_registry(
        req_cfg: &RegistryUploadRequest<'_>,
    ) -> Result<Option<String>, String> {
        let reg_url = format!(
            "{}/api/v1/bundles/it",
            req_cfg.reg_base.trim_end_matches('/')
        );
        let binary_part = reqwest::multipart::Part::bytes(req_cfg.binary.bytes.clone())
            .file_name(req_cfg.binary.filename.clone())
            .mime_str("application/octet-stream")
            .map_err(|e| format!("Invalid binary multipart MIME type: {e}"))?;
        let it_part = reqwest::multipart::Part::bytes(req_cfg.it_archive.bytes.clone())
            .file_name(req_cfg.it_archive.filename.clone())
            .mime_str("application/gzip")
            .map_err(|e| format!("Invalid it_archive multipart MIME type: {e}"))?;
        let form = reqwest::multipart::Form::new()
            .text("service_name", req_cfg.service_name.to_string())
            .part("binary", binary_part)
            .part("it_archive", it_part);

        let mut req = req_cfg
            .client
            .post(&reg_url)
            .header("traceparent", req_cfg.traceparent)
            .multipart(form);
        if let Some(token) = req_cfg
            .muregist_api_token
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        if let Some(san) = req_cfg
            .client_cert_san
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            req = req.header("x-client-cert-san", san);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| format!("Failed to contact MuRegist at '{reg_url}': {e}"))?;
        let status = resp.status();
        let body_bytes = resp
            .bytes()
            .await
            .map_err(|e| format!("Failed reading MuRegist response body: {e}"))?;
        if !status.is_success() {
            let body_text = String::from_utf8_lossy(&body_bytes);
            return Err(format!(
                "MuRegist returned HTTP {status} for '{reg_url}': {body_text}"
            ));
        }

        let record: CanaryBundleUploadResponse =
            serde_json::from_slice(&body_bytes).map_err(|e| {
                format!("MuRegist returned invalid JSON bundle record on HTTP {status}: {e}")
            })?;
        if record.binary_digest.trim() != req_cfg.binary.sha256_hex {
            return Err(format!(
                "MuRegist binary_digest mismatch: expected {}, got {}",
                req_cfg.binary.sha256_hex,
                record.binary_digest.trim()
            ));
        }
        if record.it_archive_digest.trim() != req_cfg.it_archive.sha256_hex {
            return Err(format!(
                "MuRegist it_archive_digest mismatch: expected {}, got {}",
                req_cfg.it_archive.sha256_hex,
                record.it_archive_digest.trim()
            ));
        }
        if let Some(returned_service) = record
            .service_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if returned_service != req_cfg.service_name {
                return Err(format!(
                    "MuRegist service_name mismatch: expected '{}', got '{returned_service}'",
                    req_cfg.service_name
                ));
            }
        }
        Ok(clean_opt(record.bundle_id))
    }
}

/// Triggers post-CI Continuous Distribution (`MuRegist`) and Continuous Deployment (`MuConDe`)
/// when a `main` branch `push` or `merge` job succeeds for a repository with a CD manifest
/// or a manifest-free CD-managed service.
pub async fn trigger_post_ci_cd_pipeline(job: &Job, repo_workspace: &Path) -> bool {
    let muregist_url =
        first_non_empty_env(&["MUREGIST_API_URL", "MUREGIST_URL", "MUCONDE_REGISTRY_URL"]);
    let muregist_token = match resolve_env_secret_pairs(&[
        ("MUREGIST_API_TOKEN", "MUREGIST_API_TOKEN_FILE"),
        ("MUREGIST_TOKEN", "MUREGIST_TOKEN_FILE"),
        ("MUCONDE_REGISTRY_TOKEN", "MUCONDE_REGISTRY_TOKEN_FILE"),
    ]) {
        Ok(tok) => tok,
        Err(reason) => {
            warn!(job_id = %job.id, repo = %job.repo_name, error = %reason, "Aborting post-CI CD pipeline due to unreadable registry token");
            return false;
        }
    };
    let muregist_san = first_non_empty_env(&[
        "MUREGIST_CLIENT_CERT_SAN",
        "MU_CI_CONTROLLER_CLIENT_CERT_SAN",
        "ACTION_RUNNER_CLIENT_CERT_SAN",
    ]);
    let tls_ca_path = first_non_empty_env(&[
        "MUREGIST_TLS_CA",
        "MU_CI_CONTROLLER_TLS_CA",
        "ACTION_RUNNER_TLS_CA",
    ]);
    let tls_cert_path = first_non_empty_env(&[
        "MUREGIST_TLS_CERT",
        "MU_CI_CONTROLLER_TLS_CERT",
        "ACTION_RUNNER_TLS_CERT",
    ]);
    let tls_key_path = first_non_empty_env(&[
        "MUREGIST_TLS_KEY",
        "MU_CI_CONTROLLER_TLS_KEY",
        "ACTION_RUNNER_TLS_KEY",
    ]);
    let muconde_url = first_non_empty_env(&[
        "MU_CD_CONTROLLER_API_URL",
        "MU_CD_API_URL",
        "MUCONDE_CD_API_URL",
    ]);
    let cd_token = load_cd_api_token();

    let cfg = PostCiCdEndpointConfig {
        muregist_api_url: muregist_url.as_deref(),
        muregist_api_token: muregist_token.as_deref(),
        muregist_client_cert_san: muregist_san.as_deref(),
        tls_ca_path: tls_ca_path.as_deref(),
        tls_cert_path: tls_cert_path.as_deref(),
        tls_key_path: tls_key_path.as_deref(),
        muconde_cd_api_url: muconde_url.as_deref(),
        cd_api_token: cd_token.as_deref(),
    };
    trigger_post_ci_cd_pipeline_with_config(job, repo_workspace, &cfg).await
}

/// Testable implementation of post-CI `MuRegist` bundle registration and `MuConDe` rollout dispatch.
pub async fn trigger_post_ci_cd_pipeline_with_endpoints(
    job: &Job,
    repo_workspace: &Path,
    muregist_api_url: Option<&str>,
    muconde_cd_api_url: Option<&str>,
    cd_api_token: Option<&str>,
) -> bool {
    let cfg = PostCiCdEndpointConfig {
        muregist_api_url,
        muconde_cd_api_url,
        cd_api_token,
        ..Default::default()
    };
    trigger_post_ci_cd_pipeline_with_config(job, repo_workspace, &cfg).await
}

/// Configurable post-CI `MuRegist` multipart CAS upload and `MuConDe` rollout dispatch.
pub async fn trigger_post_ci_cd_pipeline_with_config(
    job: &Job,
    repo_workspace: &Path,
    endpoints: &PostCiCdEndpointConfig<'_>,
) -> bool {
    if !is_main_push_or_merge(job) {
        return false;
    }

    let reg_base = endpoints
        .muregist_api_url
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let cd_base = endpoints
        .muconde_cd_api_url
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if reg_base.is_none() && cd_base.is_none() {
        return false;
    }

    let summary = if let Some(manifest_yaml) =
        resolve_cd_manifest_yaml(repo_workspace, &job.commit_sha).await
    {
        post_ci_cd::parse_cd_manifest_summary(&manifest_yaml, &job.repo_name)
    } else {
        let muci_yaml = resolve_mu_ci_workflow_yaml(repo_workspace, &job.commit_sha).await;
        let managed_override = std::env::var("MU_CI_CD_MANAGED_SERVICES").ok();
        let has_trunk_toml =
            repo_has_file_at_commit_or_workspace(repo_workspace, &job.commit_sha, "Trunk.toml")
                .await;
        match post_ci_cd::synthesize_cd_manifest_summary(
            &job.repo_name,
            muci_yaml.as_deref(),
            managed_override.as_deref(),
            has_trunk_toml,
        ) {
            Some(synthesized) => {
                info!(
                    job_id = %job.id,
                    repo = %job.repo_name,
                    service = %synthesized.service_name,
                    "Synthesized manifest-free post-CI CD summary for managed service"
                );
                synthesized
            }
            None => return false,
        }
    };
    let (client, cert_san) = match post_ci_cd::build_cd_http_client(
        endpoints.tls_ca_path,
        endpoints.tls_cert_path,
        endpoints.tls_key_path,
    ) {
        Ok(res) => res,
        Err(reason) => {
            warn!(job_id = %job.id, repo = %job.repo_name, error = %reason, "Failed to initialize post-CI CD HTTP client");
            return false;
        }
    };

    let effective_san = endpoints
        .muregist_client_cert_san
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .or(cert_san);

    let workspace = repo_workspace.to_path_buf();
    let repo_name = job.repo_name.clone();
    let commit_sha = job.commit_sha.clone();
    let summary_for_pack = summary.clone();
    let packaged = tokio::task::spawn_blocking(move || {
        post_ci_cd::package_post_ci_artifacts(
            &workspace,
            &repo_name,
            &commit_sha,
            &summary_for_pack,
        )
    })
    .await;

    let (binary, it_archive) = match packaged {
        Ok(Ok(pair)) => pair,
        Ok(Err(reason)) => {
            warn!(
                job_id = %job.id,
                repo = %job.repo_name,
                service = %summary.service_name,
                error = %reason,
                "Failed to resolve or package post-CI CD release artifacts; aborting rollout"
            );
            return false;
        }
        Err(join_err) => {
            warn!(
                job_id = %job.id,
                repo = %job.repo_name,
                error = %join_err,
                "Artifact packaging task panicked; aborting rollout"
            );
            return false;
        }
    };

    let traceparent = crate::storage_backend::job_root_traceparent(&job.id, &job.commit_sha);
    let mut bundle_id = None;

    if let Some(reg_url_base) = reg_base {
        let upload_req = post_ci_cd::RegistryUploadRequest {
            client: &client,
            reg_base: reg_url_base,
            service_name: &summary.service_name,
            binary: &binary,
            it_archive: &it_archive,
            muregist_api_token: endpoints.muregist_api_token,
            client_cert_san: effective_san.as_deref(),
            traceparent: &traceparent,
        };
        match post_ci_cd::upload_it_bundle_to_registry(&upload_req).await {
            Ok(uploaded_id) => {
                bundle_id = uploaded_id;
                info!(
                    job_id = %job.id,
                    repo = %job.repo_name,
                    service = %summary.service_name,
                    commit = %job.commit_sha,
                    binary_digest = %binary.sha256_hex,
                    it_archive_digest = %it_archive.sha256_hex,
                    bundle_id = ?bundle_id,
                    "Uploaded and verified post-CI artifact bundle in MuRegist CAS"
                );
            }
            Err(reason) => {
                warn!(
                    job_id = %job.id,
                    repo = %job.repo_name,
                    service = %summary.service_name,
                    error = %reason,
                    "MuRegist multipart CAS bundle upload failed; aborting CD rollout dispatch"
                );
                return false;
            }
        }
    }

    let cd_url_base = match cd_base {
        Some(u) => u,
        None => return false,
    };
    let token = match endpoints
        .cd_api_token
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(t) => t,
        None => {
            warn!(
                job_id = %job.id,
                repo = %job.repo_name,
                "MUCONDE_CD_API_URL is configured but CD API bearer token is missing or unreadable; skipping rollout dispatch"
            );
            return false;
        }
    };

    let deploy_url = format!("{}/api/cd/deploy", cd_url_base.trim_end_matches('/'));
    let mut deploy_payload = serde_json::json!({
        "repo": job.repo_name,
        "service": summary.service_name,
        "git_commit": job.commit_sha,
        "binary_digest": binary.sha256_hex,
        "it_archive_digest": it_archive.sha256_hex,
        "wait": false,
    });
    if let Some(id) = bundle_id.as_deref() {
        deploy_payload["bundle_id"] = serde_json::Value::String(id.to_string());
    }

    match client
        .post(&deploy_url)
        .header("Authorization", format!("Bearer {token}"))
        .header("traceparent", &traceparent)
        .json(&deploy_payload)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            info!(
                job_id = %job.id,
                repo = %job.repo_name,
                service = %summary.service_name,
                commit = %job.commit_sha,
                binary_digest = %binary.sha256_hex,
                it_archive_digest = %it_archive.sha256_hex,
                "Triggered post-CI MuConDe digest-only rollout notification"
            );
            true
        }
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(
                job_id = %job.id,
                repo = %job.repo_name,
                status = %status,
                body = %body,
                "MuConDe /api/cd/deploy returned non-success status"
            );
            false
        }
        Err(e) => {
            warn!(
                job_id = %job.id,
                repo = %job.repo_name,
                error = %e,
                "Failed to dispatch post-CI rollout to MuConDe controller"
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflow::{ActionRunnerWorkflow, StageConfig, TaskConfig};
    use mu_ci_ipc::SandboxBackendKind;
    use std::collections::HashMap;
    use tempfile::tempdir;

    // --- Sub-task #37: ToolAdapter Dispatch Builder Tests ---

    #[test]
    fn test_build_v3_stage_dispatch_task_cargo_build_and_test() {
        let mut tasks = HashMap::new();
        tasks.insert(
            "task-build".to_string(),
            TaskConfig {
                tool: "cargo-build".to_string(),
                args: vec!["--workspace".to_string(), "--release".to_string()],
                working_dir: None,
                env: HashMap::new(),
                timeout_seconds: Some(600),
                sandbox_profile: None,
                sccache: None,
            },
        );
        tasks.insert(
            "task-test".to_string(),
            TaskConfig {
                tool: "cargo-test".to_string(),
                args: vec!["--workspace".to_string()],
                working_dir: None,
                env: HashMap::new(),
                timeout_seconds: Some(900),
                sandbox_profile: None,
                sccache: None,
            },
        );

        let stage = StageConfig {
            id: "stage-ci".to_string(),
            name: "Build and Test".to_string(),
            tasks: vec!["task-build".to_string(), "task-test".to_string()],
            depends_on: vec![],
            tags: vec!["compute".to_string()],
            threads: 4,
            toolchain: Some("stable".to_string()),
            exclusive: true,
            max_concurrent_per_node: 1,
            sccache: None,
            if_unavailable: None,
        };

        let wf = ActionRunnerWorkflow {
            version: "3".to_string(),
            name: "Test Pipeline".to_string(),
            toolchain: None,
            env: HashMap::from([("CI".to_string(), "true".to_string())]),
            sccache: None,
            tasks,
            stages: vec![stage.clone()],
            on_action: HashMap::from([("push".to_string(), vec!["stage-ci".to_string()])]),
        };

        let dispatch = build_v3_stage_dispatch_task(
            "job-42",
            "test-repo",
            "https://github.com/example/test-repo.git",
            "abcd1234ef",
            &stage,
            &wf,
            1200,
        )
        .expect("Dispatch task should build successfully");

        assert_eq!(dispatch.job_id, "job-42");
        assert_eq!(dispatch.stage_id, "stage-ci");
        assert!(dispatch.exclusive);
        assert_eq!(dispatch.max_concurrent_per_node, 1);
        assert_eq!(dispatch.tasks.len(), 2);
        assert_eq!(dispatch.tasks[0].tool_name, "cargo-build");
        assert_eq!(dispatch.tasks[0].args, vec!["--workspace", "--release"]);
        assert_eq!(dispatch.tasks[1].tool_name, "cargo-test");
        assert_eq!(dispatch.tasks[1].args, vec!["--workspace"]);
        assert_eq!(
            dispatch.sandbox_constraints.backend,
            SandboxBackendKind::Kernel
        );
    }

    // --- Sub-task #38: Reject Unregistered Tool Commands or Shell Scripts ---

    #[test]
    fn test_reject_unapproved_tool_and_shell_injection() {
        // Prohibited shell wrapper: bash
        let mut tasks_bash = HashMap::new();
        tasks_bash.insert(
            "task-bash".to_string(),
            TaskConfig {
                tool: "bash".to_string(),
                args: vec!["-c".to_string(), "echo pwned".to_string()],
                working_dir: None,
                env: HashMap::new(),
                timeout_seconds: None,
                sandbox_profile: None,
                sccache: None,
            },
        );

        let stage_bash = StageConfig {
            id: "stage-bash".to_string(),
            name: "Bash Stage".to_string(),
            tasks: vec!["task-bash".to_string()],
            depends_on: vec![],
            tags: vec![],
            threads: 2,
            toolchain: None,
            exclusive: false,
            max_concurrent_per_node: 1,
            sccache: None,
            if_unavailable: None,
        };

        let wf_bash = ActionRunnerWorkflow {
            version: "3".to_string(),
            name: "Malicious Pipeline".to_string(),
            toolchain: None,
            env: HashMap::new(),
            sccache: None,
            tasks: tasks_bash,
            stages: vec![stage_bash.clone()],
            on_action: HashMap::new(),
        };

        let err_bash = build_v3_stage_dispatch_task(
            "job-bad",
            "malicious-repo",
            "https://example.com",
            "deadbeef",
            &stage_bash,
            &wf_bash,
            600,
        )
        .unwrap_err();

        match err_bash {
            DispatchError::UnapprovedTool(msg) => {
                assert!(msg.contains("prohibited shell wrapper") || msg.contains("bash"));
            }
            other => panic!("Expected UnapprovedTool error, got {:?}", other),
        }

        // Prohibited shell wrapper: sh
        let mut tasks_sh = HashMap::new();
        tasks_sh.insert(
            "task-sh".to_string(),
            TaskConfig {
                tool: "sh".to_string(),
                args: vec!["-c".to_string(), "ls".to_string()],
                working_dir: None,
                env: HashMap::new(),
                timeout_seconds: None,
                sandbox_profile: None,
                sccache: None,
            },
        );
        let stage_sh = StageConfig {
            id: "stage-sh".to_string(),
            name: "Sh Stage".to_string(),
            tasks: vec!["task-sh".to_string()],
            depends_on: vec![],
            tags: vec![],
            threads: 2,
            toolchain: None,
            exclusive: false,
            max_concurrent_per_node: 1,
            sccache: None,
            if_unavailable: None,
        };
        let wf_sh = ActionRunnerWorkflow {
            version: "3".to_string(),
            name: "Sh Pipeline".to_string(),
            toolchain: None,
            env: HashMap::new(),
            sccache: None,
            tasks: tasks_sh,
            stages: vec![stage_sh.clone()],
            on_action: HashMap::new(),
        };
        assert!(matches!(
            build_v3_stage_dispatch_task("job-sh", "r", "c", "s", &stage_sh, &wf_sh, 600),
            Err(DispatchError::UnapprovedTool(_))
        ));

        // Shell metacharacter injection: semicolon
        let mut tasks_semi = HashMap::new();
        tasks_semi.insert(
            "task-semi".to_string(),
            TaskConfig {
                tool: "cargo-test".to_string(),
                args: vec![
                    "--".to_string(),
                    ";".to_string(),
                    "rm".to_string(),
                    "-rf".to_string(),
                ],
                working_dir: None,
                env: HashMap::new(),
                timeout_seconds: None,
                sandbox_profile: None,
                sccache: None,
            },
        );
        let stage_semi = StageConfig {
            id: "stage-semi".to_string(),
            name: "Semi Stage".to_string(),
            tasks: vec!["task-semi".to_string()],
            depends_on: vec![],
            tags: vec![],
            threads: 2,
            toolchain: None,
            exclusive: false,
            max_concurrent_per_node: 1,
            sccache: None,
            if_unavailable: None,
        };
        let wf_semi = ActionRunnerWorkflow {
            version: "3".to_string(),
            name: "Semi Pipeline".to_string(),
            toolchain: None,
            env: HashMap::new(),
            sccache: None,
            tasks: tasks_semi,
            stages: vec![stage_semi.clone()],
            on_action: HashMap::new(),
        };
        assert!(matches!(
            build_v3_stage_dispatch_task("job-semi", "r", "c", "s", &stage_semi, &wf_semi, 600),
            Err(DispatchError::UnapprovedTool(_))
        ));

        // Shell metacharacter injection: subshell $(whoami)
        let mut tasks_sub = HashMap::new();
        tasks_sub.insert(
            "task-sub".to_string(),
            TaskConfig {
                tool: "cargo-test".to_string(),
                args: vec!["$(whoami)".to_string()],
                working_dir: None,
                env: HashMap::new(),
                timeout_seconds: None,
                sandbox_profile: None,
                sccache: None,
            },
        );
        let stage_sub = StageConfig {
            id: "stage-sub".to_string(),
            name: "Subshell Stage".to_string(),
            tasks: vec!["task-sub".to_string()],
            depends_on: vec![],
            tags: vec![],
            threads: 2,
            toolchain: None,
            exclusive: false,
            max_concurrent_per_node: 1,
            sccache: None,
            if_unavailable: None,
        };
        let wf_sub = ActionRunnerWorkflow {
            version: "3".to_string(),
            name: "Subshell Pipeline".to_string(),
            toolchain: None,
            env: HashMap::new(),
            sccache: None,
            tasks: tasks_sub,
            stages: vec![stage_sub.clone()],
            on_action: HashMap::new(),
        };
        assert!(matches!(
            build_v3_stage_dispatch_task("job-sub", "r", "c", "s", &stage_sub, &wf_sub, 600),
            Err(DispatchError::UnapprovedTool(_))
        ));
    }

    // --- Sub-task #27: Declarative ActionRunner.yml Resolution Tests ---

    #[test]
    fn test_resolve_workflow_precedence_and_fallback() {
        let dir = tempdir().unwrap();
        let ar_dir = dir.path().join(".actionrunner");
        std::fs::create_dir_all(&ar_dir).unwrap();

        let v3_content = r#"
version: "3"
name: "Modern Declarative Pipeline"
tasks:
  build-task:
    tool: "cargo-build"
stages:
  - id: build-stage
    name: "Build"
    tasks: ["build-task"]
on_action:
  push: ["build-stage"]
"#;

        let v3_path = ar_dir.join("ActionRunner.yml");

        // 1. Successfully resolve v3 workflow
        std::fs::write(&v3_path, v3_content).unwrap();

        let res = resolve_workflow_for_event(dir.path(), "push", 600)
            .expect("should resolve successfully");
        match res {
            ResolvedWorkflow::V3(wf) => {
                assert_eq!(wf.name, "Modern Declarative Pipeline");
                assert_eq!(wf.stages.len(), 1);
                assert_eq!(wf.stages[0].id, "build-stage");
            }
        }

        // 2. Reject when ActionRunner.yml is absent
        std::fs::remove_file(&v3_path).unwrap();

        let res_missing = resolve_workflow_for_event(dir.path(), "push", 600);
        match res_missing {
            Err(WorkflowResolveError::NotFound { .. }) => {}
            other => panic!(
                "Expected NotFound error when ActionRunner.yml is absent, got {:?}",
                other
            ),
        }

        // 3. Fallback when legacy is disabled
        std::env::set_var("ACTIONRUNNER_DISABLE_LEGACY", "1");
        let res_disabled = resolve_workflow_for_event(dir.path(), "push", 600);
        std::env::remove_var("ACTIONRUNNER_DISABLE_LEGACY");

        match res_disabled {
            Err(WorkflowResolveError::LegacyDisabled) => {}
            other => panic!("Expected LegacyDisabled error, got {:?}", other),
        }
    }

    #[test]
    fn test_muci_workflow_resolution_and_precedence() {
        let dir = tempdir().unwrap();
        let muci_dir = dir.path().join(".muci");
        let ar_dir = dir.path().join(".actionrunner");
        std::fs::create_dir_all(&muci_dir).unwrap();
        std::fs::create_dir_all(&ar_dir).unwrap();

        let muci_content = r#"
version: "3"
name: "MuCI Pipeline"
tasks:
  muci-task:
    tool: "cargo-check"
stages:
  - id: muci-stage
    name: "MuCI Stage"
    tasks: ["muci-task"]
on_action:
  push: ["muci-stage"]
"#;

        let ar_content = r#"
version: "3"
name: "ActionRunner Pipeline"
tasks:
  ar-task:
    tool: "cargo-build"
stages:
  - id: ar-stage
    name: "AR Stage"
    tasks: ["ar-task"]
on_action:
  push: ["ar-stage"]
"#;

        // 1. .muci/mu-ci.yml is resolved when present.
        let muci_path = muci_dir.join("mu-ci.yml");
        std::fs::write(&muci_path, muci_content).unwrap();

        let res =
            resolve_workflow_for_event(dir.path(), "push", 600).expect("should resolve mu-ci.yml");
        match res {
            ResolvedWorkflow::V3(wf) => {
                assert_eq!(wf.name, "MuCI Pipeline");
                assert_eq!(wf.stages[0].id, "muci-stage");
            }
        }

        // 2. .muci/mu-ci.yml takes precedence when both .muci/mu-ci.yml and .actionrunner/ActionRunner.yml exist.
        let ar_path = ar_dir.join("ActionRunner.yml");
        std::fs::write(&ar_path, ar_content).unwrap();

        let res_prec = resolve_workflow_for_event(dir.path(), "push", 600)
            .expect("should resolve mu-ci.yml with precedence");
        match res_prec {
            ResolvedWorkflow::V3(wf) => {
                assert_eq!(wf.name, "MuCI Pipeline");
                assert_eq!(wf.stages[0].id, "muci-stage");
            }
        }

        // 3. .actionrunner/ActionRunner.yml is resolved as a fallback when .muci/ is absent.
        std::fs::remove_file(&muci_path).unwrap();
        let res_fallback = resolve_workflow_for_event(dir.path(), "push", 600)
            .expect("should resolve ActionRunner.yml as fallback");
        match res_fallback {
            ResolvedWorkflow::V3(wf) => {
                assert_eq!(wf.name, "ActionRunner Pipeline");
                assert_eq!(wf.stages[0].id, "ar-stage");
            }
        }
    }

    #[test]
    fn test_muci_security_resolution_and_precedence() {
        let dir = tempdir().unwrap();
        let muci_dir = dir.path().join(".muci");
        let ar_dir = dir.path().join(".actionrunner");
        std::fs::create_dir_all(&muci_dir).unwrap();
        std::fs::create_dir_all(&ar_dir).unwrap();

        let muci_sec = muci_dir.join("security.yml");
        let ar_sec = ar_dir.join("security.yml");

        // 1. None present
        assert_eq!(resolve_security_path(dir.path()), None);

        // 2. .actionrunner/security.yml fallback
        std::fs::write(&ar_sec, "default_profile: ar\n").unwrap();
        assert_eq!(resolve_security_path(dir.path()), Some(ar_sec.clone()));

        // 3. .muci/security.yml takes precedence
        std::fs::write(&muci_sec, "default_profile: muci\n").unwrap();
        assert_eq!(resolve_security_path(dir.path()), Some(muci_sec));
    }

    #[test]
    fn test_build_v3_stage_dispatch_task_sccache_propagation() {
        let yaml = r#"
version: "3"
name: "Sccache Dispatch Propagation"
sccache: true
tasks:
  t-try:
    tool: "cargo-clippy"
    args: ["--workspace"]
  t-off:
    tool: "cargo-test"
    args: ["--workspace"]
    sccache: false
  t-mandatory:
    tool: "cargo-build"
    args: ["--release"]
    sccache: mandatory
stages:
  - id: s-mixed
    name: "Mixed Sccache Tasks"
    tasks: ["t-try", "t-off", "t-mandatory"]
  - id: s-off
    name: "Disabled Stage"
    sccache: false
    tasks: ["t-try"]
on_action:
  push: ["s-mixed", "s-off"]
"#;
        let wf = ActionRunnerWorkflow::from_yaml(yaml).expect("valid workflow");
        let dispatch_mixed = build_v3_stage_dispatch_task(
            "job-sccache-1",
            "LMA1980/ActionRunner-controller",
            "https://github.com/LMA1980/ActionRunner-controller.git",
            "1234567890abcdef",
            &wf.stages[0],
            &wf,
            600,
        )
        .expect("build mixed dispatch");

        assert_eq!(dispatch_mixed.sccache_mode, SccacheMode::Mandatory);
        assert_eq!(dispatch_mixed.tasks[0].sccache_mode, SccacheMode::Try);
        assert_eq!(dispatch_mixed.tasks[1].sccache_mode, SccacheMode::Off);
        assert_eq!(dispatch_mixed.tasks[2].sccache_mode, SccacheMode::Mandatory);

        let dispatch_off = build_v3_stage_dispatch_task(
            "job-sccache-1",
            "LMA1980/ActionRunner-controller",
            "https://github.com/LMA1980/ActionRunner-controller.git",
            "1234567890abcdef",
            &wf.stages[1],
            &wf,
            600,
        )
        .expect("build off dispatch");

        assert_eq!(dispatch_off.sccache_mode, SccacheMode::Off);
        assert_eq!(dispatch_off.tasks[0].sccache_mode, SccacheMode::Off);
    }

    #[test]
    fn test_is_main_push_or_merge_and_service_extraction() {
        let mut job = Job {
            id: "job-cd-1".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/mu-console".to_string(),
            clone_url: "https://github.com/LMA1980/mu-console.git".to_string(),
            commit_sha: "abcdef1234567890".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            pr_number: None,
            queued_at: Utc::now(),
        };
        assert!(is_main_push_or_merge(&job));

        job.ref_name = "refs/heads/feat/test".to_string();
        assert!(!is_main_push_or_merge(&job));

        job.ref_name = "main".to_string();
        job.event_type = "pull_request".to_string();
        assert!(!is_main_push_or_merge(&job));

        job.event_type = "merge".to_string();
        assert!(is_main_push_or_merge(&job));

        assert_eq!(
            extract_cd_service_name(
                "version: \"1\"\nservice: \"muconsole\"\n",
                "LMA1980/mu-console"
            ),
            "muconsole"
        );
        assert_eq!(
            extract_cd_service_name("version: \"1\"\n", "LMA1980/mu-console"),
            "mu-console"
        );
    }

    #[test]
    fn test_load_cd_api_token_from_values_fails_closed_on_missing_file() {
        let dir = tempdir().unwrap();
        let token_path = dir.path().join("cd_token");
        std::fs::write(&token_path, "  secret-cd-token-123 \n").unwrap();

        assert_eq!(
            load_cd_api_token_from_values(token_path.to_str(), None).as_deref(),
            Some("secret-cd-token-123")
        );
        assert_eq!(
            load_cd_api_token_from_values(Some("/nonexistent/cd_api_token_path"), Some("fallback")),
            None
        );
        assert_eq!(
            load_cd_api_token_from_values(None, Some("/nonexistent/cd_api_token_path")),
            None
        );
        assert_eq!(
            load_cd_api_token_from_values(None, Some(" literal-token ")).as_deref(),
            Some("literal-token")
        );
    }

    #[cfg(test)]
    fn parse_multipart_parts(
        content_type: &str,
        body: &[u8],
    ) -> HashMap<String, (Option<String>, Vec<u8>)> {
        let boundary = content_type
            .split(';')
            .find_map(|part| part.trim().strip_prefix("boundary="))
            .map(|b| b.trim_matches('"'))
            .expect("multipart content-type missing boundary");
        let delimiter = format!("--{boundary}").into_bytes();
        let mut parts = HashMap::new();
        let mut pos = 0usize;

        while let Some(rel_start) = body[pos..]
            .windows(delimiter.len())
            .position(|w| w == delimiter.as_slice())
        {
            pos += rel_start + delimiter.len();
            if body[pos..].starts_with(b"--") {
                break;
            }
            if body[pos..].starts_with(b"\r\n") {
                pos += 2;
            }
            let Some(header_end) = body[pos..].windows(4).position(|w| w == b"\r\n\r\n") else {
                break;
            };
            let header_str = std::str::from_utf8(&body[pos..pos + header_end]).unwrap();
            pos += header_end + 4;
            let next_boundary = body[pos..]
                .windows(delimiter.len())
                .position(|w| w == delimiter.as_slice())
                .expect("unterminated multipart part");
            let mut part_bytes = body[pos..pos + next_boundary].to_vec();
            if part_bytes.ends_with(b"\r\n") {
                part_bytes.truncate(part_bytes.len() - 2);
            }
            pos += next_boundary;

            let mut field_name = None;
            let mut filename = None;
            for line in header_str.split("\r\n") {
                if let Some(disp) = line
                    .strip_prefix("Content-Disposition:")
                    .or_else(|| line.strip_prefix("content-disposition:"))
                {
                    for param in disp.split(';') {
                        let p = param.trim();
                        if let Some(val) = p.strip_prefix("name=") {
                            field_name = Some(val.trim_matches('"').to_string());
                        } else if let Some(val) = p.strip_prefix("filename=") {
                            filename = Some(val.trim_matches('"').to_string());
                        }
                    }
                }
            }
            if let Some(name) = field_name {
                parts.insert(name, (filename, part_bytes));
            }
        }
        parts
    }

    fn make_test_elf_header(e_machine: u16) -> Vec<u8> {
        let mut elf = vec![0u8; 64];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2; // ELF64
        elf[5] = 1; // Little endian
        elf[6] = 1; // EV_CURRENT
        elf[18..20].copy_from_slice(&e_machine.to_le_bytes());
        elf
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_trigger_post_ci_cd_pipeline_registers_bundle_and_dispatches_deploy() {
        use axum::{body::Bytes, http::HeaderMap, routing::post, Json, Router};
        use std::sync::Mutex;

        let dir = tempdir().unwrap();
        let muconde_dir = dir.path().join(".muconde");
        std::fs::create_dir_all(&muconde_dir).unwrap();
        let manifest_content =
            "version: \"1\"\nservice: \"muconsole\"\ntarget_nodes:\n  - \"node-a\"\n  - \"node-b\"\n";
        std::fs::write(muconde_dir.join("MuConDe.yml"), manifest_content).unwrap();

        let dist_dir = dir.path().join("dist");
        std::fs::create_dir_all(&dist_dir).unwrap();
        std::fs::write(dist_dir.join("index.html"), b"<html>muconsole</html>").unwrap();
        std::fs::write(dist_dir.join("app.wasm"), b"\x00asm\x01\x00\x00\x00").unwrap();

        type MultipartPartsMap = HashMap<String, (Option<String>, Vec<u8>)>;
        type CapturedRegCall = (String, MultipartPartsMap);
        let captured_reg: Arc<Mutex<Vec<CapturedRegCall>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_deploy: Arc<Mutex<Vec<(String, String, serde_json::Value)>>> =
            Arc::new(Mutex::new(Vec::new()));

        let app = Router::new()
            .route(
                "/api/v1/bundles/it",
                post({
                    let cap = captured_reg.clone();
                    move |headers: HeaderMap, body: Bytes| {
                        let cap = cap.clone();
                        async move {
                            let content_type = headers
                                .get("content-type")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            let traceparent = headers
                                .get("traceparent")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            let parts = parse_multipart_parts(&content_type, &body);
                            let service_name = String::from_utf8(
                                parts.get("service_name").expect("service_name").1.clone(),
                            )
                            .unwrap();
                            let binary_digest = post_ci_cd::compute_sha256_hex(
                                &parts.get("binary").expect("binary").1,
                            );
                            let it_archive_digest = post_ci_cd::compute_sha256_hex(
                                &parts.get("it_archive").expect("it_archive").1,
                            );
                            cap.lock().unwrap().push((traceparent, parts));
                            (
                                axum::http::StatusCode::CREATED,
                                Json(serde_json::json!({
                                    "bundle_id": "bundle-static-001",
                                    "service_name": service_name,
                                    "binary_digest": binary_digest,
                                    "it_archive_digest": it_archive_digest,
                                    "status": "pending_it",
                                })),
                            )
                        }
                    }
                }),
            )
            .route(
                "/api/cd/deploy",
                post({
                    let cap = captured_deploy.clone();
                    move |headers: HeaderMap, Json(body): Json<serde_json::Value>| {
                        let cap = cap.clone();
                        async move {
                            let auth = headers
                                .get("authorization")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            let tp = headers
                                .get("traceparent")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            cap.lock().unwrap().push((auth, tp, body));
                            axum::http::StatusCode::ACCEPTED
                        }
                    }
                }),
            )
            .with_state(());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let base_url = format!("http://{addr}");

        let job = Job {
            id: "job-cd-e2e".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/mu-console".to_string(),
            clone_url: "https://github.com/LMA1980/mu-console.git".to_string(),
            commit_sha: "deadbeefcafe1234".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            pr_number: None,
            queued_at: Utc::now(),
        };

        let triggered = trigger_post_ci_cd_pipeline_with_endpoints(
            &job,
            dir.path(),
            Some(&base_url),
            Some(&base_url),
            Some("test-cd-token"),
        )
        .await;
        assert!(triggered);

        let reg_calls = captured_reg.lock().unwrap().clone();
        assert_eq!(reg_calls.len(), 1);
        assert!(reg_calls[0].0.starts_with("00-"));
        let parts = &reg_calls[0].1;
        assert_eq!(parts["service_name"].1, b"muconsole");

        let binary_part = &parts["binary"];
        assert!(binary_part
            .0
            .as_deref()
            .is_some_and(|n| n.ends_with(".tar.gz")));
        let expected_bin_sha = post_ci_cd::compute_sha256_hex(&binary_part.1);
        let expected_it_sha = post_ci_cd::compute_sha256_hex(&parts["it_archive"].1);

        let mut tar_entries = Vec::new();
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(binary_part.1.as_slice()));
        for entry in archive.entries().unwrap() {
            tar_entries.push(entry.unwrap().path().unwrap().display().to_string());
        }
        assert!(tar_entries.contains(&"dist/index.html".to_string()));
        assert!(tar_entries.contains(&"dist/app.wasm".to_string()));

        let mut it_entries = Vec::new();
        let mut it_archive = tar::Archive::new(flate2::read::GzDecoder::new(
            parts["it_archive"].1.as_slice(),
        ));
        for entry in it_archive.entries().unwrap() {
            it_entries.push(entry.unwrap().path().unwrap().display().to_string());
        }
        assert_eq!(it_entries, vec!["manifest.json".to_string()]);

        let deploy_calls = captured_deploy.lock().unwrap().clone();
        assert_eq!(deploy_calls.len(), 1);
        assert_eq!(deploy_calls[0].0, "Bearer test-cd-token");
        assert_eq!(deploy_calls[0].1, reg_calls[0].0);
        let deploy_body = &deploy_calls[0].2;
        assert_eq!(deploy_body["repo"], "LMA1980/mu-console");
        assert_eq!(deploy_body["service"], "muconsole");
        assert_eq!(deploy_body["git_commit"], "deadbeefcafe1234");
        assert_eq!(deploy_body["binary_digest"], expected_bin_sha);
        assert_ne!(deploy_body["binary_digest"], "deadbeefcafe1234");
        assert_eq!(deploy_body["it_archive_digest"], expected_it_sha);
        assert_eq!(deploy_body["bundle_id"], "bundle-static-001");
        assert_eq!(deploy_body["wait"], false);
        let obj = deploy_body.as_object().expect("deploy JSON object");
        assert!(!obj.contains_key("manifest_yaml"));
        assert!(!obj.contains_key("config"));
        assert!(!obj.contains_key("repo_path"));
        assert!(!obj.contains_key("artifact_sha256"));
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "binary_digest",
                "bundle_id",
                "git_commit",
                "it_archive_digest",
                "repo",
                "service",
                "wait",
            ]
        );
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_trigger_post_ci_cd_pipeline_binary_with_registry_auth_and_it_dir() {
        use axum::{body::Bytes, http::HeaderMap, routing::post, Json, Router};
        use std::sync::Mutex;

        let dir = tempdir().unwrap();
        let mucd_dir = dir.path().join(".mucd");
        let it_dir = mucd_dir.join("it");
        let release_dir = dir.path().join("target/release");
        std::fs::create_dir_all(&it_dir).unwrap();
        std::fs::create_dir_all(&release_dir).unwrap();

        let manifest_content = concat!(
            "version: \"1\"\n",
            "service: \"action-runner-controller\"\n",
            "target_nodes:\n",
            "  - \"node-a\"\n",
            "deployment:\n",
            "  binary: \"custom-ci-bin\"\n",
            "  install_path: \"/usr/local/bin/mu-ci-controller\"\n",
        );
        std::fs::write(mucd_dir.join("mu-cd.yml"), manifest_content).unwrap();
        std::fs::write(it_dir.join("smoke.sh"), b"#!/bin/sh\nexit 0\n").unwrap();

        let custom_bin_bytes = b"\x7fELF-custom-ci-binary-payload-v1".to_vec();
        std::fs::write(release_dir.join("custom-ci-bin"), &custom_bin_bytes).unwrap();
        std::fs::write(release_dir.join("mu-ci-controller"), b"secondary-binary").unwrap();

        #[derive(Clone)]
        struct CapturedAuthCall {
            auth: String,
            san: String,
            service_name: String,
            bin_bytes: Vec<u8>,
            it_bytes: Vec<u8>,
        }
        let reg_headers: Arc<Mutex<Vec<CapturedAuthCall>>> = Arc::new(Mutex::new(Vec::new()));
        let deploy_bodies: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));

        let app = Router::new()
            .route(
                "/api/v1/bundles/it",
                post({
                    let cap = reg_headers.clone();
                    move |headers: HeaderMap, body: Bytes| {
                        let cap = cap.clone();
                        async move {
                            let ct = headers
                                .get("content-type")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("");
                            let auth = headers
                                .get("authorization")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            let san = headers
                                .get("x-client-cert-san")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            let parts = parse_multipart_parts(ct, &body);
                            let service_name =
                                String::from_utf8(parts["service_name"].1.clone()).unwrap();
                            let bin_bytes = parts["binary"].1.clone();
                            let it_bytes = parts["it_archive"].1.clone();
                            let bin_sha = post_ci_cd::compute_sha256_hex(&bin_bytes);
                            let it_sha = post_ci_cd::compute_sha256_hex(&it_bytes);
                            cap.lock().unwrap().push(CapturedAuthCall {
                                auth,
                                san,
                                service_name: service_name.clone(),
                                bin_bytes,
                                it_bytes,
                            });
                            (
                                axum::http::StatusCode::CREATED,
                                Json(serde_json::json!({
                                    "bundle_id": "bundle-bin-002",
                                    "service_name": service_name,
                                    "binary_digest": bin_sha,
                                    "it_archive_digest": it_sha,
                                })),
                            )
                        }
                    }
                }),
            )
            .route(
                "/api/cd/deploy",
                post({
                    let cap = deploy_bodies.clone();
                    move |Json(body): Json<serde_json::Value>| {
                        let cap = cap.clone();
                        async move {
                            cap.lock().unwrap().push(body);
                            axum::http::StatusCode::ACCEPTED
                        }
                    }
                }),
            )
            .with_state(());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let base_url = format!("http://{addr}");

        let job = Job {
            id: "job-cd-bin".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/mu-ci-controller".to_string(),
            clone_url: "https://github.com/LMA1980/mu-ci-controller.git".to_string(),
            commit_sha: "abc123def456".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            pr_number: None,
            queued_at: Utc::now(),
        };

        let cfg = PostCiCdEndpointConfig {
            muregist_api_url: Some(&base_url),
            muregist_api_token: Some("reg-secret-token"),
            muregist_client_cert_san: Some("ci-controller.example.test"),
            muconde_cd_api_url: Some(&base_url),
            cd_api_token: Some("cd-secret-token"),
            ..Default::default()
        };

        assert!(trigger_post_ci_cd_pipeline_with_config(&job, dir.path(), &cfg).await);

        let captured = reg_headers.lock().unwrap().clone();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].auth, "Bearer reg-secret-token");
        assert_eq!(captured[0].san, "ci-controller.example.test");
        assert_eq!(captured[0].service_name, "action-runner-controller");
        assert_eq!(captured[0].bin_bytes, custom_bin_bytes);

        let mut it_archive = tar::Archive::new(flate2::read::GzDecoder::new(
            captured[0].it_bytes.as_slice(),
        ));
        let mut saw_smoke = false;
        for entry in it_archive.entries().unwrap() {
            let e = entry.unwrap();
            if e.path().unwrap().to_str() == Some("smoke.sh") {
                assert_eq!(e.header().mode().unwrap() & 0o777, 0o755);
                saw_smoke = true;
            }
        }
        assert!(saw_smoke);

        let deploys = deploy_bodies.lock().unwrap().clone();
        assert_eq!(deploys.len(), 1);
        let expected_sha = post_ci_cd::compute_sha256_hex(&custom_bin_bytes);
        let expected_it_sha = post_ci_cd::compute_sha256_hex(&captured[0].it_bytes);
        assert_eq!(deploys[0]["repo"], "LMA1980/mu-ci-controller");
        assert_eq!(deploys[0]["service"], "action-runner-controller");
        assert_eq!(deploys[0]["binary_digest"], expected_sha);
        assert_eq!(deploys[0]["it_archive_digest"], expected_it_sha);
        assert_eq!(deploys[0]["git_commit"], "abc123def456");
        assert_ne!(deploys[0]["binary_digest"], deploys[0]["git_commit"]);
        assert_eq!(deploys[0]["bundle_id"], "bundle-bin-002");
        assert_eq!(deploys[0]["wait"], false);
        assert!(deploys[0].get("manifest_yaml").is_none());
        assert!(deploys[0].get("artifact_sha256").is_none());
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_trigger_post_ci_cd_pipeline_canonical_mu_binary_wins_over_legacy() {
        let dir = tempdir().unwrap();
        let mucd_dir = dir.path().join(".mucd");
        let release_dir = dir.path().join("target/release");
        std::fs::create_dir_all(&mucd_dir).unwrap();
        std::fs::create_dir_all(&release_dir).unwrap();
        std::fs::write(
            mucd_dir.join("mu-cd.yml"),
            "version: \"1\"\nservice: \"action-runner-controller\"\n",
        )
        .unwrap();
        std::fs::write(release_dir.join("mu-ci-controller"), b"canonical-mu-bin").unwrap();
        std::fs::write(
            release_dir.join("action-runner-controller"),
            b"legacy-alias-bin",
        )
        .unwrap();

        let summary = post_ci_cd::parse_cd_manifest_summary(
            "version: \"1\"\nservice: \"action-runner-controller\"\n",
            "LMA1980/mu-ci-controller",
        );
        let resolved = post_ci_cd::resolve_and_package_artifact(
            dir.path(),
            "LMA1980/mu-ci-controller",
            &summary,
        )
        .unwrap();
        assert_eq!(resolved.filename, "mu-ci-controller");
        assert_eq!(resolved.bytes, b"canonical-mu-bin");
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_trigger_post_ci_cd_pipeline_fails_closed_on_registry_error_or_digest_mismatch() {
        use axum::{routing::post, Json, Router};
        use std::sync::atomic::{AtomicUsize, Ordering};

        for mode in ["http-500", "digest-mismatch"] {
            let dir = tempdir().unwrap();
            let mucd_dir = dir.path().join(".mucd");
            let release_dir = dir.path().join("target/release");
            std::fs::create_dir_all(&mucd_dir).unwrap();
            std::fs::create_dir_all(&release_dir).unwrap();
            std::fs::write(
                mucd_dir.join("mu-cd.yml"),
                "version: \"1\"\nservice: \"mu-ci-controller\"\n",
            )
            .unwrap();
            std::fs::write(release_dir.join("mu-ci-controller"), b"valid-binary-bytes").unwrap();

            let deploy_count = Arc::new(AtomicUsize::new(0));
            let mode_owned = mode.to_string();
            let app = Router::new()
                .route(
                    "/api/v1/bundles/it",
                    post({
                        move || {
                            let mode_inner = mode_owned.clone();
                            async move {
                                if mode_inner == "http-500" {
                                    (
                                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                        Json(serde_json::json!({ "error": "cas down" })),
                                    )
                                } else {
                                    (
                                        axum::http::StatusCode::CREATED,
                                        Json(serde_json::json!({
                                            "bundle_id": "bad-bundle",
                                            "service_name": "mu-ci-controller",
                                            "binary_digest": "0".repeat(64),
                                            "it_archive_digest": "0".repeat(64),
                                        })),
                                    )
                                }
                            }
                        }
                    }),
                )
                .route(
                    "/api/cd/deploy",
                    post({
                        let count = deploy_count.clone();
                        move || {
                            let count = count.clone();
                            async move {
                                count.fetch_add(1, Ordering::SeqCst);
                                axum::http::StatusCode::ACCEPTED
                            }
                        }
                    }),
                )
                .with_state(());

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                let _ = axum::serve(listener, app).await;
            });
            let base_url = format!("http://{addr}");

            let job = Job {
                id: format!("job-fail-{mode}"),
                event_type: "push".to_string(),
                repo_name: "LMA1980/mu-ci-controller".to_string(),
                clone_url: "https://github.com/LMA1980/mu-ci-controller.git".to_string(),
                commit_sha: "feedface1234".to_string(),
                ref_name: "refs/heads/main".to_string(),
                sender: "LMA1980".to_string(),
                pr_number: None,
                queued_at: Utc::now(),
            };

            let ok = trigger_post_ci_cd_pipeline_with_endpoints(
                &job,
                dir.path(),
                Some(&base_url),
                Some(&base_url),
                Some("cd-token"),
            )
            .await;
            assert!(!ok, "expected fail-closed false for mode {mode}");
            assert_eq!(deploy_count.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_trigger_post_ci_cd_pipeline_fails_closed_on_missing_or_cross_arch_artifact() {
        use axum::{routing::post, Router};
        use std::sync::atomic::{AtomicUsize, Ordering};

        let dir_missing = tempdir().unwrap();
        let mucd_missing = dir_missing.path().join(".mucd");
        std::fs::create_dir_all(&mucd_missing).unwrap();
        std::fs::write(
            mucd_missing.join("mu-cd.yml"),
            "version: \"1\"\nservice: \"mu-ci-controller\"\n",
        )
        .unwrap();

        let dir_xarch = tempdir().unwrap();
        let mucd_xarch = dir_xarch.path().join(".mucd");
        let release_xarch = dir_xarch.path().join("target/release");
        std::fs::create_dir_all(&mucd_xarch).unwrap();
        std::fs::create_dir_all(&release_xarch).unwrap();
        std::fs::write(
            mucd_xarch.join("mu-cd.yml"),
            "version: \"1\"\nservice: \"mu-cd-agent\"\ntarget_nodes:\n  - \"worker-riscv64\"\n",
        )
        .unwrap();
        std::fs::write(
            release_xarch.join("mu-cd-agent"),
            make_test_elf_header(0x003E),
        )
        .unwrap();

        let hits = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route(
                "/api/v1/bundles/it",
                post({
                    let hits = hits.clone();
                    move || {
                        let hits = hits.clone();
                        async move {
                            hits.fetch_add(1, Ordering::SeqCst);
                            axum::http::StatusCode::CREATED
                        }
                    }
                }),
            )
            .route(
                "/api/cd/deploy",
                post({
                    let hits = hits.clone();
                    move || {
                        let hits = hits.clone();
                        async move {
                            hits.fetch_add(1, Ordering::SeqCst);
                            axum::http::StatusCode::ACCEPTED
                        }
                    }
                }),
            )
            .with_state(());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let base_url = format!("http://{addr}");

        let job = Job {
            id: "job-xarch".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/mu-cd-agent".to_string(),
            clone_url: "https://github.com/LMA1980/mu-cd-agent.git".to_string(),
            commit_sha: "cafebabe9999".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            pr_number: None,
            queued_at: Utc::now(),
        };

        assert!(
            !trigger_post_ci_cd_pipeline_with_endpoints(
                &job,
                dir_missing.path(),
                Some(&base_url),
                Some(&base_url),
                Some("cd-token"),
            )
            .await
        );
        assert!(
            !trigger_post_ci_cd_pipeline_with_endpoints(
                &job,
                dir_xarch.path(),
                Some(&base_url),
                Some(&base_url),
                Some("cd-token"),
            )
            .await
        );
        assert_eq!(hits.load(Ordering::SeqCst), 0);

        let riscv_dir = dir_xarch
            .path()
            .join("target/riscv64gc-unknown-linux-gnu/release");
        std::fs::create_dir_all(&riscv_dir).unwrap();
        let riscv_elf = make_test_elf_header(0x00F3);
        std::fs::write(riscv_dir.join("mu-cd-agent"), &riscv_elf).unwrap();

        let summary = post_ci_cd::parse_cd_manifest_summary(
            "version: \"1\"\nservice: \"mu-cd-agent\"\ntarget_nodes:\n  - \"worker-riscv64\"\n",
            "LMA1980/mu-cd-agent",
        );
        let picked = post_ci_cd::resolve_and_package_artifact(
            dir_xarch.path(),
            "LMA1980/mu-cd-agent",
            &summary,
        )
        .unwrap();
        assert_eq!(picked.bytes, riscv_elf);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_build_cd_http_client_mtls_and_fail_closed() {
        use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

        let dir = tempdir().unwrap();
        let kp = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params =
            CertificateParams::new(vec!["mu-ci-controller.example.test".to_string()]).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "mu-ci-controller.example.test");
        params.distinguished_name = dn;
        let cert = params.self_signed(&kp).unwrap();

        let ca_path = dir.path().join("ca.crt");
        let cert_path = dir.path().join("client.crt");
        let key_path = dir.path().join("client.key");
        std::fs::write(&ca_path, cert.pem()).unwrap();
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, kp.serialize_pem()).unwrap();

        let (_client, san) = post_ci_cd::build_cd_http_client(
            Some(ca_path.to_str().unwrap()),
            Some(cert_path.to_str().unwrap()),
            Some(key_path.to_str().unwrap()),
        )
        .unwrap();
        assert_eq!(san.as_deref(), Some("mu-ci-controller.example.test"));

        assert!(post_ci_cd::build_cd_http_client(
            Some(ca_path.to_str().unwrap()),
            Some(cert_path.to_str().unwrap()),
            None,
        )
        .is_err());

        let missing_ca = dir.path().join("missing-ca.crt");
        assert!(
            post_ci_cd::build_cd_http_client(Some(missing_ca.to_str().unwrap()), None, None)
                .is_err()
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_load_registry_api_token_from_values_and_fail_closed() {
        let dir = tempdir().unwrap();
        let tok_path = dir.path().join("reg-token");
        std::fs::write(&tok_path, "  registry-secret-123 \n").unwrap();

        assert_eq!(
            load_registry_api_token_from_values(Some(tok_path.to_str().unwrap()), None).as_deref(),
            Some("registry-secret-123")
        );
        assert_eq!(
            load_registry_api_token_from_values(None, Some("  inline-reg-tok  ")).as_deref(),
            Some("inline-reg-tok")
        );
        let missing = dir.path().join("does-not-exist");
        assert_eq!(
            load_registry_api_token_from_values(Some(missing.to_str().unwrap()), Some("ignored")),
            None
        );
        assert_eq!(
            load_registry_api_token_from_values(None, Some(missing.to_str().unwrap())),
            None
        );
    }

    #[test]
    fn test_parse_cd_manifest_summary_and_arch_inference() {
        let yaml = concat!(
            "version: \"1\"\n",
            "service: \"mu-cd-agent\"\n",
            "target_nodes:\n",
            "  - \"node-a\"\n",
            "deployment:\n",
            "  binary: \"mu-cd-agent\"\n",
            "  install_path: \"/usr/local/bin/mu-cd-agent\"\n",
            "  target_nodes:\n",
            "    - \"worker-riscv64\"\n",
        );
        let summary = post_ci_cd::parse_cd_manifest_summary(yaml, "LMA1980/mu-cd-agent");
        assert_eq!(summary.service_name, "mu-cd-agent");
        assert_eq!(summary.binary.as_deref(), Some("mu-cd-agent"));
        assert_eq!(
            summary.install_path.as_deref(),
            Some("/usr/local/bin/mu-cd-agent")
        );
        assert_eq!(summary.target_nodes, vec!["worker-riscv64".to_string()]);
        assert_eq!(
            post_ci_cd::infer_target_arch_from_nodes(&summary.target_nodes),
            Some(post_ci_cd::ExpectedElfArch::Riscv64)
        );
        assert_eq!(
            post_ci_cd::infer_target_arch_from_nodes(&["worker-aarch64".to_string()]),
            Some(post_ci_cd::ExpectedElfArch::Aarch64)
        );
        assert_eq!(
            post_ci_cd::infer_target_arch_from_nodes(&["node-a".to_string(), "node-b".to_string()]),
            None
        );
        assert_eq!(
            post_ci_cd::infer_target_arch_from_nodes(&[
                "worker-riscv64".to_string(),
                "worker-aarch64".to_string(),
            ]),
            None
        );
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_report_github_commit_status_posts_only_continuous_integration() {
        use axum::{routing::post, Json, Router};
        use std::sync::Mutex;

        let captured: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new().route(
            "/repos/LMA1980/example/statuses/{sha}",
            post({
                let captured = captured.clone();
                move |Json(body): Json<serde_json::Value>| {
                    let captured = captured.clone();
                    async move {
                        captured.lock().unwrap().push(body);
                        axum::http::StatusCode::CREATED
                    }
                }
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let base_url = format!("http://{addr}");
        let config = Config {
            github_token: Some("ghs_mock_token".to_string()),
            ..Config::default()
        };

        report_github_commit_status_with_base_url(
            &base_url,
            &config,
            "LMA1980/example",
            "0123456789abcdef0123456789abcdef01234567",
            "pending",
            "ActionRunner distributed pipeline running...",
            Some("https://hook.lma1980.duckdns.org/web/#/jobs/job-1"),
        )
        .await;

        let calls = captured.lock().unwrap();
        assert_eq!(calls.len(), 1, "expected exactly one status POST");
        assert_eq!(calls[0]["context"], "continuous integration");
        assert_ne!(calls[0]["context"], "k3-ci");
        assert_eq!(calls[0]["state"], "pending");
    }

    #[test]
    fn pipeline_root_span_separates_user_outcomes_from_infra_health() {
        let job = Job {
            id: "job-root-span-1".to_string(),
            event_type: "pull_request".to_string(),
            repo_name: "LMA1980/example".to_string(),
            clone_url: "https://github.com/LMA1980/example.git".to_string(),
            commit_sha: "0123456789abcdef0123456789abcdef01234567".to_string(),
            ref_name: "refs/heads/feat/fix".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: Utc::now(),
            pr_number: Some(12),
        };

        // 1. Completed cleanly -> OK
        let s_ok = build_pipeline_root_span(
            &job,
            &JobStatus::Completed {
                duration_secs: 15,
                exit_code: 0,
            },
            15,
            30_000_000_000,
        );
        assert_eq!(s_ok.status_code, "OK");
        assert_eq!(s_ok.status_message, None);
        let a_ok: serde_json::Value = serde_json::from_str(&s_ok.attributes_json).unwrap();
        assert_eq!(a_ok["ci.outcome"], "passed");

        // 2. Ordinary user lint/coverage exit 101 -> OK with user_failure attributes
        for msg in [
            "Stage 'clippy-check' failed with code 101",
            "Tool 'cargo-llvm-cov' exited with status code Some(101)",
            "RegressionDetected: 1 benchmark regression(s), 0 failing/flaky test(s)",
        ] {
            let s_user = build_pipeline_root_span(
                &job,
                &JobStatus::Failed {
                    error: msg.to_string(),
                },
                20,
                30_000_000_000,
            );
            assert_eq!(s_user.status_code, "OK", "unexpected ERROR for '{msg}'");
            assert_eq!(s_user.status_message, None);
        }

        // 3. Superseded/cancelled -> OK
        let s_skip = build_pipeline_root_span(
            &job,
            &JobStatus::Skipped {
                reason: "Superseded by pull_request event".to_string(),
            },
            5,
            30_000_000_000,
        );
        assert_eq!(s_skip.status_code, "OK");
        let a_skip: serde_json::Value = serde_json::from_str(&s_skip.attributes_json).unwrap();
        assert_eq!(a_skip["ci.outcome"], "superseded");

        // 4. Controller/worker infrastructure faults -> ERROR
        for infra_err in [
            "Failed to serialize stage dispatch frame: ipc codec error",
            "Security grant denied: max_pids exceeded",
            "Failed to spawn tool process 'cargo-test': ENOENT",
            "Stage 'build' missing from resolved workflow configuration",
        ] {
            let s_infra = build_pipeline_root_span(
                &job,
                &JobStatus::Failed {
                    error: infra_err.to_string(),
                },
                5,
                30_000_000_000,
            );
            assert_eq!(
                s_infra.status_code, "ERROR",
                "expected ERROR for '{infra_err}'"
            );
            assert_eq!(s_infra.status_message.as_deref(), Some(infra_err));
            let a_infra: serde_json::Value =
                serde_json::from_str(&s_infra.attributes_json).unwrap();
            assert_eq!(a_infra["ci.outcome"], "infra_failure");
        }
    }

    #[test]
    fn test_canonical_public_binary_candidates_resolution() {
        assert_eq!(
            post_ci_cd::canonical_public_binary_candidates("jero-engine"),
            &["jero-engine", "jero-worker", "k3-worker"]
        );
        assert_eq!(
            post_ci_cd::canonical_public_binary_candidates("jero-worker"),
            &["jero-engine", "jero-worker", "k3-worker"]
        );
        assert_eq!(
            post_ci_cd::canonical_public_binary_candidates("k3-worker"),
            &["jero-engine", "jero-worker", "k3-worker"]
        );

        assert_eq!(
            post_ci_cd::canonical_public_binary_candidates("jero-kv-cache"),
            &["jero-kv-cache", "k3-kv"]
        );
        assert_eq!(
            post_ci_cd::canonical_public_binary_candidates("k3-kv"),
            &["jero-kv-cache", "k3-kv"]
        );

        assert_eq!(
            post_ci_cd::canonical_public_binary_candidates("jero-manager"),
            &["jero-manager", "k3-manager"]
        );
        assert_eq!(
            post_ci_cd::canonical_public_binary_candidates("k3-manager"),
            &["jero-manager", "k3-manager"]
        );

        assert_eq!(
            post_ci_cd::canonical_public_binary_candidates("mu-observable-sentinel"),
            &["mu-observable-sentinel", "musentinel", "muobserve-sentinel"]
        );
        assert_eq!(
            post_ci_cd::canonical_public_binary_candidates("musentinel"),
            &["mu-observable-sentinel", "musentinel", "muobserve-sentinel"]
        );
        assert_eq!(
            post_ci_cd::canonical_public_binary_candidates("muobserve-sentinel"),
            &["mu-observable-sentinel", "musentinel", "muobserve-sentinel"]
        );

        // Verify candidate_binary_names puts canonical public binary first when legacy service name is used
        let summary_mgr = post_ci_cd::parse_cd_manifest_summary(
            "version: \"1\"\nservice: \"k3-manager\"\n",
            "LMA1980/jero-manager",
        );
        let mgr_candidates =
            post_ci_cd::candidate_binary_names(&summary_mgr, "LMA1980/jero-manager");
        assert_eq!(
            mgr_candidates.first().map(String::as_str),
            Some("jero-manager")
        );
        assert!(mgr_candidates.contains(&"k3-manager".to_string()));

        let summary_engine = post_ci_cd::parse_cd_manifest_summary(
            "version: \"1\"\nservice: \"k3-worker\"\n",
            "LMA1980/jero-engine",
        );
        let engine_candidates =
            post_ci_cd::candidate_binary_names(&summary_engine, "LMA1980/jero-engine");
        assert_eq!(
            engine_candidates.first().map(String::as_str),
            Some("jero-engine")
        );
        assert!(engine_candidates.contains(&"jero-worker".to_string()));
        assert!(engine_candidates.contains(&"k3-worker".to_string()));

        let summary_kv = post_ci_cd::parse_cd_manifest_summary(
            "version: \"1\"\nservice: \"k3-kv\"\n",
            "LMA1980/jero-kv-cache",
        );
        let kv_candidates =
            post_ci_cd::candidate_binary_names(&summary_kv, "LMA1980/jero-kv-cache");
        assert_eq!(
            kv_candidates.first().map(String::as_str),
            Some("jero-kv-cache")
        );
        assert!(kv_candidates.contains(&"k3-kv".to_string()));

        let summary_sentinel = post_ci_cd::parse_cd_manifest_summary(
            "version: \"1\"\nservice: \"musentinel\"\n",
            "LMA1980/mu-observable-sentinel",
        );
        let sentinel_candidates =
            post_ci_cd::candidate_binary_names(&summary_sentinel, "LMA1980/mu-observable-sentinel");
        assert_eq!(
            sentinel_candidates.first().map(String::as_str),
            Some("mu-observable-sentinel")
        );
        assert!(sentinel_candidates.contains(&"musentinel".to_string()));
        assert!(sentinel_candidates.contains(&"muobserve-sentinel".to_string()));
    }

    fn make_test_elf32_header(e_machine: u16) -> Vec<u8> {
        let mut elf = vec![0u8; 64];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 1; // ELF32
        elf[5] = 1; // Little endian
        elf[6] = 1; // EV_CURRENT
        elf[18..20].copy_from_slice(&e_machine.to_le_bytes());
        elf
    }

    #[test]
    fn test_smoke_binary_stem_parsing_and_elf_validation_miri_safe() {
        assert_eq!(
            post_ci_cd::parse_smoke_binary_stem("smoke_mu_ci_controller"),
            Some("smoke_mu_ci_controller".to_string())
        );
        assert_eq!(
            post_ci_cd::parse_smoke_binary_stem("smoke_mu_registry-0123456789abcdef"),
            Some("smoke_mu_registry".to_string())
        );
        assert_eq!(post_ci_cd::parse_smoke_binary_stem("smoke_foo.d"), None);
        assert_eq!(
            post_ci_cd::parse_smoke_binary_stem("smoke_foo-0123456789abcdef.d"),
            None
        );
        assert_eq!(post_ci_cd::parse_smoke_binary_stem("smoke_foo.o"), None);
        assert_eq!(
            post_ci_cd::parse_smoke_binary_stem("libsmoke_foo.rlib"),
            None
        );
        assert_eq!(post_ci_cd::parse_smoke_binary_stem("smoke_foo.rmeta"), None);
        assert_eq!(post_ci_cd::parse_smoke_binary_stem("smoke_foo.so"), None);
        assert_eq!(post_ci_cd::parse_smoke_binary_stem("smoke_foo.dylib"), None);
        assert_eq!(post_ci_cd::parse_smoke_binary_stem("smoke_"), None);

        let x86_elf = make_test_elf_header(0x003E);
        let rv_elf = make_test_elf_header(0x00F3);
        let arm_elf = make_test_elf_header(0x00B7);
        let elf32 = make_test_elf32_header(0x003E);

        assert!(post_ci_cd::validate_elf_architecture(
            &x86_elf,
            Some(post_ci_cd::ExpectedElfArch::X86_64),
            Path::new("bin/smoke_x86")
        )
        .is_ok());
        assert!(post_ci_cd::validate_elf_architecture(
            &rv_elf,
            Some(post_ci_cd::ExpectedElfArch::Riscv64),
            Path::new("bin/smoke_rv")
        )
        .is_ok());
        assert!(post_ci_cd::validate_elf_architecture(
            &arm_elf,
            Some(post_ci_cd::ExpectedElfArch::Aarch64),
            Path::new("bin/smoke_arm")
        )
        .is_ok());

        assert!(post_ci_cd::validate_elf_architecture(
            &x86_elf,
            Some(post_ci_cd::ExpectedElfArch::Riscv64),
            Path::new("bin/smoke_bad_rv")
        )
        .is_err());
        assert!(post_ci_cd::validate_elf_architecture(
            &x86_elf,
            Some(post_ci_cd::ExpectedElfArch::Aarch64),
            Path::new("bin/smoke_bad_arm")
        )
        .is_err());
        assert!(
            post_ci_cd::validate_elf_architecture(&elf32, None, Path::new("bin/smoke_32bit"))
                .is_err()
        );

        let summary = post_ci_cd::parse_cd_manifest_summary(
            "version: \"1\"\nservice: \"mu-ci-worker\"\nintegration_tests:\n  - \"smoke_mu_ci_worker\"\n",
            "LMA1980/mu-ci-worker",
        );
        assert_eq!(
            summary.integration_tests,
            vec!["smoke_mu_ci_worker".to_string()]
        );

        let budget_err = post_ci_cd::build_bounded_tar_gz_with_limit(
            &[post_ci_cd::ArchivedItEntry {
                archive_path: std::path::PathBuf::from("bin/smoke_small"),
                bytes: vec![0u8; 128],
                mode: 0o755,
            }],
            64,
        )
        .unwrap_err();
        assert!(budget_err.contains("budget"));
    }

    #[test]
    fn test_package_it_archive_multi_arch_smoke_binaries_round_trip() {
        use std::collections::BTreeMap;
        use std::io::Read as _;

        let cases = [
            (
                "node-x86_64",
                0x003Eu16,
                "x86_64",
                "x86_64-unknown-linux-gnu",
                "target/x86_64-unknown-linux-gnu/release/deps",
            ),
            (
                "worker-riscv64",
                0x00F3u16,
                "riscv64",
                "riscv64gc-unknown-linux-gnu",
                "target/riscv64gc-unknown-linux-gnu/release/deps",
            ),
            (
                "worker-aarch64",
                0x00B7u16,
                "aarch64",
                "aarch64-unknown-linux-gnu",
                "target/aarch64-unknown-linux-gnu/release/deps",
            ),
        ];

        for (target_node, e_machine, expected_label, expected_triple, deps_rel) in cases {
            let dir = tempdir().unwrap();
            let deps_dir = dir.path().join(deps_rel);
            std::fs::create_dir_all(&deps_dir).unwrap();

            // Write matching smoke binary plus ignored Cargo metadata/library artifacts.
            let mut smoke_bin = make_test_elf_header(e_machine);
            smoke_bin.extend_from_slice(target_node.as_bytes());
            std::fs::write(deps_dir.join("smoke_service-0123456789abcdef"), &smoke_bin).unwrap();
            std::fs::write(
                deps_dir.join("smoke_service-0123456789abcdef.d"),
                b"dep-info",
            )
            .unwrap();
            std::fs::write(deps_dir.join("smoke_service.o"), b"obj").unwrap();
            std::fs::write(deps_dir.join("smoke_service.rlib"), b"rlib").unwrap();
            std::fs::write(deps_dir.join("smoke_service.rmeta"), b"rmeta").unwrap();
            std::fs::write(deps_dir.join("smoke_service.so"), b"so").unwrap();
            std::fs::write(deps_dir.join("smoke_service.dylib"), b"dylib").unwrap();

            // Also place a conflicting host-arch binary in target/release/deps to confirm
            // target-arch-prioritized deduplication picks the matching target binary.
            let host_deps = dir.path().join("target/release/deps");
            std::fs::create_dir_all(&host_deps).unwrap();
            let alt_machine = if e_machine == 0x003E { 0x00F3 } else { 0x003E };
            std::fs::write(
                host_deps.join("smoke_service-fedcba9876543210"),
                make_test_elf_header(alt_machine),
            )
            .unwrap();

            let yaml = format!(
                "version: \"1\"\nservice: \"mu-test-svc\"\ntarget_nodes:\n  - \"{target_node}\"\n"
            );
            let summary = post_ci_cd::parse_cd_manifest_summary(&yaml, "LMA1980/mu-test-svc");
            let packaged = post_ci_cd::package_it_archive(
                dir.path(),
                &summary,
                "deadbeef12345678",
                &"a".repeat(64),
            )
            .unwrap();

            assert_eq!(packaged.filename, "mu-test-svc-it.tar.gz");
            assert_eq!(
                packaged.sha256_hex,
                post_ci_cd::compute_sha256_hex(&packaged.bytes)
            );

            let mut archive =
                tar::Archive::new(flate2::read::GzDecoder::new(packaged.bytes.as_slice()));
            let mut extracted: BTreeMap<String, (u32, Vec<u8>)> = BTreeMap::new();
            for entry in archive.entries().unwrap() {
                let mut e = entry.unwrap();
                assert!(e.header().entry_type().is_file());
                let path = e.path().unwrap().display().to_string();
                let mode = e.header().mode().unwrap() & 0o777;
                let mut buf = Vec::new();
                e.read_to_end(&mut buf).unwrap();
                extracted.insert(path, (mode, buf));
            }

            assert_eq!(extracted.len(), 2);
            let (manifest_mode, manifest_bytes) = extracted.get("manifest.json").unwrap();
            assert_eq!(*manifest_mode, 0o644);
            let manifest: post_ci_cd::ItManifestJson =
                serde_json::from_slice(manifest_bytes).unwrap();
            assert_eq!(manifest.schema_version, 1);
            assert_eq!(manifest.service, "mu-test-svc");
            assert_eq!(manifest.git_commit, "deadbeef12345678");
            assert_eq!(manifest.artifact_sha256, "a".repeat(64));
            assert_eq!(manifest.target_arch.as_deref(), Some(expected_label));
            assert_eq!(manifest.target_triple.as_deref(), Some(expected_triple));
            assert_eq!(manifest.tests.len(), 1);
            assert_eq!(manifest.tests[0].name, "smoke_service");
            assert_eq!(manifest.tests[0].command, "bin/smoke_service");
            assert_eq!(manifest.tests[0].args, vec!["--nocapture".to_string()]);
            assert!(manifest.tests[0].critical);
            assert_eq!(manifest.tests[0].timeout_secs, Some(30));

            let (bin_mode, bin_bytes) = extracted.get("bin/smoke_service").unwrap();
            assert_eq!(*bin_mode, 0o755);
            assert_eq!(bin_bytes, &smoke_bin);
        }
    }

    #[test]
    fn test_package_it_archive_manifest_resolution_and_fail_closed_rejections() {
        // 1. Mismatched ELF architecture (x86_64 binary for worker-riscv64 & worker-aarch64)
        for target_node in ["worker-riscv64", "worker-aarch64"] {
            let dir = tempdir().unwrap();
            let deps = dir.path().join("target/release/deps");
            std::fs::create_dir_all(&deps).unwrap();
            std::fs::write(
                deps.join("smoke_probe-1111111111111111"),
                make_test_elf_header(0x003E),
            )
            .unwrap();
            let yaml = format!(
                "version: \"1\"\nservice: \"mu-test-svc\"\ntarget_nodes:\n  - \"{target_node}\"\n"
            );
            let summary = post_ci_cd::parse_cd_manifest_summary(&yaml, "LMA1980/mu-test-svc");
            let err = post_ci_cd::package_it_archive(dir.path(), &summary, "sha1", &"b".repeat(64))
                .unwrap_err();
            assert!(
                err.contains("does not match"),
                "expected ELF arch mismatch for {target_node}, got: {err}"
            );
        }

        // 2. Heterogeneous ELF architectures when target_nodes is generic
        {
            let dir = tempdir().unwrap();
            let deps = dir.path().join("target/release/deps");
            std::fs::create_dir_all(&deps).unwrap();
            std::fs::write(deps.join("smoke_a"), make_test_elf_header(0x003E)).unwrap();
            std::fs::write(deps.join("smoke_b"), make_test_elf_header(0x00F3)).unwrap();
            let summary = post_ci_cd::parse_cd_manifest_summary(
                "version: \"1\"\nservice: \"mu-test-svc\"\n",
                "LMA1980/mu-test-svc",
            );
            let err = post_ci_cd::package_it_archive(dir.path(), &summary, "sha1", &"b".repeat(64))
                .unwrap_err();
            assert!(err.contains("Heterogeneous ELF"));
        }

        // 3. 32-bit EI_CLASS == 1 ELF rejected
        {
            let dir = tempdir().unwrap();
            let deps = dir.path().join("target/release/deps");
            std::fs::create_dir_all(&deps).unwrap();
            std::fs::write(deps.join("smoke_elf32"), make_test_elf32_header(0x003E)).unwrap();
            let summary = post_ci_cd::parse_cd_manifest_summary(
                "version: \"1\"\nservice: \"mu-test-svc\"\n",
                "LMA1980/mu-test-svc",
            );
            let err = post_ci_cd::package_it_archive(dir.path(), &summary, "sha1", &"b".repeat(64))
                .unwrap_err();
            assert!(err.contains("not a 64-bit ELF"));
        }

        // 4. Symlink rejected in deps/
        #[cfg(unix)]
        {
            let dir = tempdir().unwrap();
            let deps = dir.path().join("target/release/deps");
            std::fs::create_dir_all(&deps).unwrap();
            let target_file = dir.path().join("real_bin");
            std::fs::write(&target_file, make_test_elf_header(0x003E)).unwrap();
            std::os::unix::fs::symlink(&target_file, deps.join("smoke_link")).unwrap();
            let summary = post_ci_cd::parse_cd_manifest_summary(
                "version: \"1\"\nservice: \"mu-test-svc\"\n",
                "LMA1980/mu-test-svc",
            );
            let err = post_ci_cd::package_it_archive(dir.path(), &summary, "sha1", &"b".repeat(64))
                .unwrap_err();
            assert!(err.contains("symlink"));
        }

        // 5. Keep 64 MiB allocation in dedicated native test below so Miri runs stay fast.
        let _ = post_ci_cd::MAX_IT_ARCHIVE_UNCOMPRESSED_BYTES;

        // 6. Explicit it-manifest.json missing referenced binary -> fails closed; present -> packages it
        {
            let dir = tempdir().unwrap();
            let mucd = dir.path().join(".mucd");
            std::fs::create_dir_all(&mucd).unwrap();
            std::fs::write(
                mucd.join("it-manifest.json"),
                serde_json::to_vec_pretty(&serde_json::json!({
                    "schema_version": 1,
                    "service": "mu-test-svc",
                    "tests": [{
                        "name": "smoke_missing",
                        "command": "bin/smoke_missing",
                        "args": ["--nocapture"],
                        "critical": true
                    }]
                }))
                .unwrap(),
            )
            .unwrap();
            let summary = post_ci_cd::parse_cd_manifest_summary(
                "version: \"1\"\nservice: \"mu-test-svc\"\ntarget_nodes:\n  - \"worker-riscv64\"\n",
                "LMA1980/mu-test-svc",
            );
            let missing_err =
                post_ci_cd::package_it_archive(dir.path(), &summary, "sha1", &"c".repeat(64))
                    .unwrap_err();
            assert!(missing_err.contains("missing binary"));

            let bin_dir = dir.path().join("bin");
            std::fs::create_dir_all(&bin_dir).unwrap();
            std::fs::write(bin_dir.join("smoke_missing"), make_test_elf_header(0x00F3)).unwrap();
            let ok_pkg =
                post_ci_cd::package_it_archive(dir.path(), &summary, "sha1", &"c".repeat(64))
                    .unwrap();
            let mut archive =
                tar::Archive::new(flate2::read::GzDecoder::new(ok_pkg.bytes.as_slice()));
            let names: Vec<String> = archive
                .entries()
                .unwrap()
                .map(|e| e.unwrap().path().unwrap().display().to_string())
                .collect();
            assert_eq!(
                names,
                vec!["manifest.json".to_string(), "bin/smoke_missing".to_string()]
            );
        }

        // 7. Non-static-web daemon selecting custom smoke_* test with no IT binaries -> fail closed
        {
            let dir = tempdir().unwrap();
            let summary = post_ci_cd::parse_cd_manifest_summary(
                "version: \"1\"\nservice: \"mu-ci-worker\"\nintegration_tests:\n  - \"smoke_mu_ci_worker\"\n",
                "LMA1980/mu-ci-worker",
            );
            let err = post_ci_cd::package_it_archive(dir.path(), &summary, "sha1", &"d".repeat(64))
                .unwrap_err();
            assert!(err.contains("smoke_mu_ci_worker"));
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_package_it_archive_rejects_over_64mib_uncompressed_payload() {
        let dir = tempdir().unwrap();
        let deps = dir.path().join("target/release/deps");
        std::fs::create_dir_all(&deps).unwrap();
        let mut oversized = make_test_elf_header(0x003E);
        oversized.resize((64 * 1024 * 1024) + 128, 0);
        std::fs::write(deps.join("smoke_huge"), &oversized).unwrap();
        let summary = post_ci_cd::parse_cd_manifest_summary(
            "version: \"1\"\nservice: \"mu-test-svc\"\n",
            "LMA1980/mu-test-svc",
        );
        let err = post_ci_cd::package_it_archive(dir.path(), &summary, "sha1", &"b".repeat(64))
            .unwrap_err();
        assert!(err.contains("budget"));
    }

    fn build_raw_tar_with_path(name: &str, typeflag: u8, payload: &[u8]) -> Vec<u8> {
        let mut header = [0u8; 512];
        let name_bytes = name.as_bytes();
        header[..name_bytes.len()].copy_from_slice(name_bytes);
        header[100..108].copy_from_slice(b"0000644\0");
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        let size_octal = format!("{:011o}\0", payload.len());
        header[124..136].copy_from_slice(size_octal.as_bytes());
        header[136..148].copy_from_slice(b"00000000000\0");
        header[148..156].copy_from_slice(b"        ");
        header[156] = typeflag;
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let cksum: u32 = header.iter().map(|&b| u32::from(b)).sum();
        let cksum_octal = format!("{cksum:06o}\0 ");
        header[148..156].copy_from_slice(cksum_octal.as_bytes());

        let mut tar_bytes = Vec::new();
        tar_bytes.extend_from_slice(&header);
        tar_bytes.extend_from_slice(payload);
        let rem = payload.len() % 512;
        if rem != 0 {
            tar_bytes.resize(tar_bytes.len() + (512 - rem), 0);
        }
        tar_bytes.extend_from_slice(&[0u8; 1024]);
        tar_bytes
    }

    #[test]
    fn test_unpack_tar_bytes_safely_rejects_symlinks_traversal_and_absolute_paths() {
        // 1. Valid regular file + PAX global header unpacks cleanly
        let ok_dir = tempdir().unwrap();
        let mut builder = tar::Builder::new(Vec::new());
        let mut hdr = tar::Header::new_gnu();
        let content = b"<html>ok</html>";
        hdr.set_size(content.len() as u64);
        hdr.set_mode(0o755);
        hdr.set_cksum();
        builder
            .append_data(&mut hdr, "dist/index.html", &content[..])
            .unwrap();
        let valid_tar = builder.into_inner().unwrap();
        post_ci_cd::unpack_tar_bytes_safely(&valid_tar, ok_dir.path()).unwrap();
        assert_eq!(
            std::fs::read(ok_dir.path().join("dist/index.html")).unwrap(),
            content
        );

        // 2. Symlink entry rejected
        let sym_dir = tempdir().unwrap();
        let sym_tar = build_raw_tar_with_path("dist/link", b'2', b"");
        let sym_err = post_ci_cd::unpack_tar_bytes_safely(&sym_tar, sym_dir.path()).unwrap_err();
        assert!(sym_err.contains("symlink"), "unexpected error: {sym_err}");

        // 3. Hardlink entry rejected
        let link_dir = tempdir().unwrap();
        let link_tar = build_raw_tar_with_path("dist/hard", b'1', b"");
        let link_err = post_ci_cd::unpack_tar_bytes_safely(&link_tar, link_dir.path()).unwrap_err();
        assert!(
            link_err.contains("hardlink"),
            "unexpected error: {link_err}"
        );

        // 4. Parent directory traversal (..) rejected
        let trav_dir = tempdir().unwrap();
        let trav_tar = build_raw_tar_with_path("../escape.txt", b'0', b"nope");
        let trav_err = post_ci_cd::unpack_tar_bytes_safely(&trav_tar, trav_dir.path()).unwrap_err();
        assert!(
            trav_err.contains("traversal"),
            "unexpected error: {trav_err}"
        );

        // 5. Absolute path rejected
        let abs_dir = tempdir().unwrap();
        let abs_tar = build_raw_tar_with_path("/etc/escape.txt", b'0', b"nope");
        let abs_err = post_ci_cd::unpack_tar_bytes_safely(&abs_tar, abs_dir.path()).unwrap_err();
        assert!(
            abs_err.contains("absolute") || abs_err.contains("traversal"),
            "unexpected error: {abs_err}"
        );
    }

    #[test]
    fn test_parse_cargo_test_executable_from_json_and_target_dir_helpers() {
        let sample = r#"
not-json-line
{"reason":"compiler-message","message":{"message":"ok"}}
{"reason":"compiler-artifact","target":{"name":"demo_lib"},"profile":{"test":false},"executable":null}
{"reason":"compiler-artifact","target":{"name":"smoke_other"},"profile":{"test":true},"executable":"/tmp/target/release/deps/smoke_other-1111111111111111"}
{"reason":"compiler-artifact","target":{"name":"smoke_demo"},"profile":{"test":false},"executable":"/tmp/target/release/smoke_demo"}
{"reason":"compiler-artifact","target":{"name":"smoke_demo"},"profile":{"test":true},"executable":"/tmp/target/release/deps/smoke_demo-0123456789abcdef"}
"#;
        assert_eq!(
            post_ci_cd::parse_cargo_test_executable_from_json(sample, "smoke_demo"),
            Some(std::path::PathBuf::from(
                "/tmp/target/release/deps/smoke_demo-0123456789abcdef"
            ))
        );
        assert_eq!(
            post_ci_cd::parse_cargo_test_executable_from_json(sample, "smoke_missing"),
            None
        );
        assert_eq!(post_ci_cd::cross_target_triple(None), None);
        if std::env::var("MU_CI_CONTROLLER_RELEASE_TARGET_DIR")
            .ok()
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .is_none()
        {
            assert_eq!(
                post_ci_cd::resolve_release_target_dir(Path::new("/tmp/ws")),
                std::path::PathBuf::from("/tmp/ws/.post_ci_target")
            );
        }
    }

    fn run_isolated_git(dir: &Path, args: &[&str]) -> String {
        let out = std::process::Command::new("git")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .expect("spawn isolated git");
        assert!(
            out.status.success(),
            "git {args:?} failed: stdout={}, stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    type MockMultipartPartsMap = HashMap<String, (Option<String>, Vec<u8>)>;
    type MockCapturedRegCall = (String, MockMultipartPartsMap);
    type MockCapturedDeployCall = (String, String, serde_json::Value);

    async fn spawn_mock_post_ci_registry_and_cd_server(
        bundle_id: &'static str,
    ) -> (
        String,
        Arc<std::sync::Mutex<Vec<MockCapturedRegCall>>>,
        Arc<std::sync::Mutex<Vec<MockCapturedDeployCall>>>,
    ) {
        use axum::{body::Bytes, http::HeaderMap, routing::post, Json, Router};

        let captured_reg: Arc<std::sync::Mutex<Vec<MockCapturedRegCall>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured_deploy: Arc<std::sync::Mutex<Vec<MockCapturedDeployCall>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));

        let app = Router::new()
            .route(
                "/api/v1/bundles/it",
                post({
                    let cap = captured_reg.clone();
                    move |headers: HeaderMap, body: Bytes| {
                        let cap = cap.clone();
                        async move {
                            let content_type = headers
                                .get("content-type")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            let traceparent = headers
                                .get("traceparent")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            let parts = parse_multipart_parts(&content_type, &body);
                            let service_name = String::from_utf8(
                                parts.get("service_name").expect("service_name").1.clone(),
                            )
                            .unwrap();
                            let binary_digest = post_ci_cd::compute_sha256_hex(
                                &parts.get("binary").expect("binary").1,
                            );
                            let it_archive_digest = post_ci_cd::compute_sha256_hex(
                                &parts.get("it_archive").expect("it_archive").1,
                            );
                            cap.lock().unwrap().push((traceparent, parts));
                            (
                                axum::http::StatusCode::CREATED,
                                Json(serde_json::json!({
                                    "bundle_id": bundle_id,
                                    "service_name": service_name,
                                    "binary_digest": binary_digest,
                                    "it_archive_digest": it_archive_digest,
                                    "status": "pending_it",
                                })),
                            )
                        }
                    }
                }),
            )
            .route(
                "/api/cd/deploy",
                post({
                    let cap = captured_deploy.clone();
                    move |headers: HeaderMap, Json(body): Json<serde_json::Value>| {
                        let cap = cap.clone();
                        async move {
                            let auth = headers
                                .get("authorization")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            let tp = headers
                                .get("traceparent")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            cap.lock().unwrap().push((auth, tp, body));
                            axum::http::StatusCode::ACCEPTED
                        }
                    }
                }),
            )
            .with_state(());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{addr}"), captured_reg, captured_deploy)
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_trigger_post_ci_cd_pipeline_no_checkout_static_dist_materialization() {
        let root = tempdir().unwrap();
        let src_repo = root.path().join("src-web");
        std::fs::create_dir_all(src_repo.join(".mucd")).unwrap();
        std::fs::create_dir_all(src_repo.join("dist")).unwrap();
        std::fs::write(
            src_repo.join(".mucd/mu-cd.yml"),
            "version: \"1\"\nservice: \"mu-ci-web\"\ntarget_nodes:\n  - \"node-a\"\n",
        )
        .unwrap();
        std::fs::write(
            src_repo.join("dist/index.html"),
            b"<html>no-checkout-web</html>",
        )
        .unwrap();
        std::fs::write(src_repo.join("dist/app.wasm"), b"\x00asm\x01\x00\x00\x00").unwrap();

        run_isolated_git(&src_repo, &["init", "-b", "main"]);
        run_isolated_git(&src_repo, &["config", "user.name", "CI Test"]);
        run_isolated_git(&src_repo, &["config", "user.email", "ci@example.invalid"]);
        run_isolated_git(&src_repo, &["add", "."]);
        run_isolated_git(&src_repo, &["commit", "-m", "initial web dist"]);
        let sha = run_isolated_git(&src_repo, &["rev-parse", "HEAD"]);

        let no_checkout_ws = root.path().join("no-checkout-web");
        let clone_out = std::process::Command::new("git")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .args([
                "clone",
                "--no-checkout",
                src_repo.to_str().unwrap(),
                no_checkout_ws.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(clone_out.status.success());
        assert!(no_checkout_ws.join(".git").exists());
        assert!(!no_checkout_ws.join("dist").exists());

        let (base_url, captured_reg, captured_deploy) =
            spawn_mock_post_ci_registry_and_cd_server("bundle-no-checkout-web").await;

        let job = Job {
            id: "job-no-checkout-web".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/mu-ci-web".to_string(),
            clone_url: src_repo.display().to_string(),
            commit_sha: sha.clone(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            pr_number: None,
            queued_at: Utc::now(),
        };

        let ok = trigger_post_ci_cd_pipeline_with_endpoints(
            &job,
            &no_checkout_ws,
            Some(&base_url),
            Some(&base_url),
            Some("test-cd-token"),
        )
        .await;
        assert!(
            ok,
            "expected --no-checkout static dist packaging to succeed"
        );

        let reg_calls = captured_reg.lock().unwrap().clone();
        assert_eq!(reg_calls.len(), 1);
        let parts = &reg_calls[0].1;
        assert_eq!(parts["service_name"].1, b"mu-ci-web");
        let bin_sha = post_ci_cd::compute_sha256_hex(&parts["binary"].1);
        let it_sha = post_ci_cd::compute_sha256_hex(&parts["it_archive"].1);

        let mut tar_entries = Vec::new();
        let mut archive =
            tar::Archive::new(flate2::read::GzDecoder::new(parts["binary"].1.as_slice()));
        for entry in archive.entries().unwrap() {
            tar_entries.push(entry.unwrap().path().unwrap().display().to_string());
        }
        assert!(tar_entries.contains(&"dist/index.html".to_string()));
        assert!(tar_entries.contains(&"dist/app.wasm".to_string()));

        let deploy_calls = captured_deploy.lock().unwrap().clone();
        assert_eq!(deploy_calls.len(), 1);
        let body = &deploy_calls[0].2;
        assert_eq!(body["repo"], "LMA1980/mu-ci-web");
        assert_eq!(body["service"], "mu-ci-web");
        assert_eq!(body["git_commit"], sha);
        assert_eq!(body["binary_digest"], bin_sha);
        assert_eq!(body["it_archive_digest"], it_sha);
        assert_eq!(body["bundle_id"], "bundle-no-checkout-web");
        assert_eq!(body["wait"], false);
        let mut keys: Vec<&str> = body
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "binary_digest",
                "bundle_id",
                "git_commit",
                "it_archive_digest",
                "repo",
                "service",
                "wait",
            ]
        );
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_trigger_post_ci_cd_pipeline_no_checkout_rust_binary_and_smoke_it() {
        use std::collections::BTreeMap;
        use std::io::Read as _;

        let root = tempdir().unwrap();
        let src_repo = root.path().join("src-rust");
        std::fs::create_dir_all(src_repo.join(".mucd")).unwrap();
        std::fs::create_dir_all(src_repo.join("src")).unwrap();
        std::fs::create_dir_all(src_repo.join("tests")).unwrap();
        std::fs::write(
            src_repo.join(".mucd/mu-cd.yml"),
            "version: \"1\"\nservice: \"demo-svc\"\ntarget_nodes:\n  - \"node-a\"\nintegration_tests:\n  - \"smoke_demo\"\n",
        )
        .unwrap();
        std::fs::write(
            src_repo.join("Cargo.toml"),
            "[package]\nname = \"demo-svc\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::write(
            src_repo.join("src/main.rs"),
            "fn main() {\n    println!(\"demo-svc ok\");\n}\n",
        )
        .unwrap();
        std::fs::write(
            src_repo.join("tests/smoke_demo.rs"),
            "#[test]\nfn smoke_ok() {\n    assert_eq!(2 + 2, 4);\n}\n",
        )
        .unwrap();

        run_isolated_git(&src_repo, &["init", "-b", "main"]);
        run_isolated_git(&src_repo, &["config", "user.name", "CI Test"]);
        run_isolated_git(&src_repo, &["config", "user.email", "ci@example.invalid"]);
        run_isolated_git(&src_repo, &["add", "."]);
        run_isolated_git(&src_repo, &["commit", "-m", "initial demo-svc"]);
        let sha = run_isolated_git(&src_repo, &["rev-parse", "HEAD"]);

        let no_checkout_ws = root.path().join("no-checkout-rust");
        let clone_out = std::process::Command::new("git")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .args([
                "clone",
                "--no-checkout",
                src_repo.to_str().unwrap(),
                no_checkout_ws.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(clone_out.status.success());
        assert!(no_checkout_ws.join(".git").exists());
        assert!(!no_checkout_ws.join("Cargo.toml").exists());
        assert!(!no_checkout_ws.join("target").exists());

        let (base_url, captured_reg, captured_deploy) =
            spawn_mock_post_ci_registry_and_cd_server("bundle-no-checkout-rust").await;

        let job = Job {
            id: "job-no-checkout-rust".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/demo-svc".to_string(),
            clone_url: src_repo.display().to_string(),
            commit_sha: sha.clone(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            pr_number: None,
            queued_at: Utc::now(),
        };

        let ok = trigger_post_ci_cd_pipeline_with_endpoints(
            &job,
            &no_checkout_ws,
            Some(&base_url),
            Some(&base_url),
            Some("test-cd-token"),
        )
        .await;
        assert!(
            ok,
            "expected --no-checkout Rust release binary + smoke_demo packaging to succeed"
        );

        let reg_calls = captured_reg.lock().unwrap().clone();
        assert_eq!(reg_calls.len(), 1);
        let parts = &reg_calls[0].1;
        assert_eq!(parts["service_name"].1, b"demo-svc");
        assert_eq!(parts["binary"].0.as_deref(), Some("demo-svc"));
        assert!(!parts["binary"].1.is_empty());
        let bin_sha = post_ci_cd::compute_sha256_hex(&parts["binary"].1);
        let it_sha = post_ci_cd::compute_sha256_hex(&parts["it_archive"].1);

        let mut it_entries: BTreeMap<String, (u32, Vec<u8>)> = BTreeMap::new();
        let mut it_archive = tar::Archive::new(flate2::read::GzDecoder::new(
            parts["it_archive"].1.as_slice(),
        ));
        for entry in it_archive.entries().unwrap() {
            let mut e = entry.unwrap();
            let path = e.path().unwrap().display().to_string();
            let mode = e.header().mode().unwrap() & 0o777;
            let mut buf = Vec::new();
            e.read_to_end(&mut buf).unwrap();
            it_entries.insert(path, (mode, buf));
        }

        assert_eq!(it_entries.len(), 2);
        let (manifest_mode, manifest_bytes) = it_entries.get("manifest.json").unwrap();
        assert_eq!(*manifest_mode, 0o644);
        let manifest: post_ci_cd::ItManifestJson = serde_json::from_slice(manifest_bytes).unwrap();
        assert_eq!(manifest.schema_version, 1);
        assert_eq!(manifest.service, "demo-svc");
        assert_eq!(manifest.git_commit, sha);
        assert_eq!(manifest.artifact_sha256, bin_sha);
        assert_eq!(manifest.tests.len(), 1);
        assert_eq!(manifest.tests[0].name, "smoke_demo");
        assert_eq!(manifest.tests[0].command, "bin/smoke_demo");
        assert!(manifest.tests[0].args.is_empty());
        assert!(manifest.tests[0].critical);

        let (smoke_mode, smoke_bytes) = it_entries.get("bin/smoke_demo").unwrap();
        assert_eq!(*smoke_mode, 0o755);
        assert!(!smoke_bytes.is_empty());

        let deploy_calls = captured_deploy.lock().unwrap().clone();
        assert_eq!(deploy_calls.len(), 1);
        let body = &deploy_calls[0].2;
        assert_eq!(body["repo"], "LMA1980/demo-svc");
        assert_eq!(body["service"], "demo-svc");
        assert_eq!(body["git_commit"], sha);
        assert_eq!(body["binary_digest"], bin_sha);
        assert_eq!(body["it_archive_digest"], it_sha);
        assert_eq!(body["bundle_id"], "bundle-no-checkout-rust");
        assert_eq!(body["wait"], false);
        let mut keys: Vec<&str> = body
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "binary_digest",
                "bundle_id",
                "git_commit",
                "it_archive_digest",
                "repo",
                "service",
                "wait",
            ]
        );
    }

    #[test]
    fn test_synthesize_cd_manifest_summary_managed_vs_non_managed() {
        for svc in DEFAULT_CD_MANAGED_SERVICES {
            let repo = format!("LMA1980/{svc}");
            let summary = post_ci_cd::synthesize_cd_manifest_summary(&repo, None, None, false)
                .unwrap_or_else(|| panic!("expected {svc} to be CD-managed"));
            assert_eq!(summary.service_name, *svc);
            assert!(summary.target_nodes.is_empty());
            if *svc == "mu-ci-web" || *svc == "mu-console" {
                assert_eq!(summary.artifact.as_deref(), Some("dist"));
                assert!(post_ci_cd::is_static_web_deployment(&summary));
            } else {
                assert!(!post_ci_cd::is_static_web_deployment(&summary));
            }
        }

        for non_service in [
            "mu-ci",
            "mu-cd",
            "mu-observable",
            "mu-ci-ipc",
            "mu-cd-ipc",
            "mu-observable-ipc",
            "mu-deploy",
            "lma1980.github.io",
            "arbitrary-non-service",
        ] {
            let repo = format!("LMA1980/{non_service}");
            assert!(
                post_ci_cd::synthesize_cd_manifest_summary(&repo, None, None, true).is_none(),
                "expected {non_service} without .muci cd metadata to return None"
            );
        }

        // MU_CI_CD_MANAGED_SERVICES override replaces the default managed set.
        let custom_summary = post_ci_cd::synthesize_cd_manifest_summary(
            "LMA1980/custom-svc",
            None,
            Some("custom-svc, another-svc"),
            false,
        )
        .expect("custom-svc should match override");
        assert_eq!(custom_summary.service_name, "custom-svc");
        assert!(post_ci_cd::synthesize_cd_manifest_summary(
            "LMA1980/mu-ci-controller",
            None,
            Some("custom-svc, another-svc"),
            false,
        )
        .is_none());

        // Optional .muci/mu-ci.yml cd metadata enables/configures custom repos and supports opt-out.
        let muci_opt_in = "version: \"3\"\nname: \"spa\"\ncd:\n  enabled: true\n  service: \"custom-spa\"\ntasks: {}\nstages: []\non_action: {}\n";
        let spa_summary = post_ci_cd::synthesize_cd_manifest_summary(
            "LMA1980/custom-spa-repo",
            Some(muci_opt_in),
            None,
            true,
        )
        .expect("cd.enabled: true should enable manifest-free CD");
        assert_eq!(spa_summary.service_name, "custom-spa");
        assert_eq!(spa_summary.artifact.as_deref(), Some("dist"));
        assert!(post_ci_cd::is_static_web_deployment(&spa_summary));

        let muci_opt_out = "version: \"3\"\nname: \"disabled\"\ncd:\n  enabled: false\n";
        assert!(post_ci_cd::synthesize_cd_manifest_summary(
            "LMA1980/mu-ci-controller",
            Some(muci_opt_out),
            None,
            false,
        )
        .is_none());
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_trigger_post_ci_cd_pipeline_manifest_free_rust_binary_and_smoke_it() {
        use std::collections::BTreeMap;
        use std::io::Read as _;

        // Case 1: Canonical managed service in --no-checkout workspace without .mucd/ or .muconde/
        let root = tempdir().unwrap();
        let src_repo = root.path().join("src-managed-rust");
        std::fs::create_dir_all(src_repo.join("src")).unwrap();
        std::fs::create_dir_all(src_repo.join("tests")).unwrap();
        std::fs::write(
            src_repo.join("Cargo.toml"),
            "[package]\nname = \"mu-ci-controller\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::write(
            src_repo.join("src/main.rs"),
            "fn main() {\n    println!(\"mu-ci-controller ok\");\n}\n",
        )
        .unwrap();
        std::fs::write(
            src_repo.join("tests/smoke_mu_ci_controller.rs"),
            "#[test]\nfn smoke_ok() {\n    assert_eq!(1 + 1, 2);\n}\n",
        )
        .unwrap();

        run_isolated_git(&src_repo, &["init", "-b", "main"]);
        run_isolated_git(&src_repo, &["config", "user.name", "CI Test"]);
        run_isolated_git(&src_repo, &["config", "user.email", "ci@example.invalid"]);
        run_isolated_git(&src_repo, &["add", "."]);
        run_isolated_git(&src_repo, &["commit", "-m", "manifest-free rust service"]);
        let sha = run_isolated_git(&src_repo, &["rev-parse", "HEAD"]);

        let no_checkout_ws = root.path().join("no-checkout-managed-rust");
        let clone_out = std::process::Command::new("git")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .args([
                "clone",
                "--no-checkout",
                src_repo.to_str().unwrap(),
                no_checkout_ws.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(clone_out.status.success());

        let (base_url, captured_reg, captured_deploy) =
            spawn_mock_post_ci_registry_and_cd_server("bundle-mf-rust-001").await;

        let job = Job {
            id: "job-mf-rust".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/mu-ci-controller".to_string(),
            clone_url: src_repo.display().to_string(),
            commit_sha: sha.clone(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            pr_number: None,
            queued_at: Utc::now(),
        };

        let cfg = PostCiCdEndpointConfig {
            muregist_api_url: Some(&base_url),
            muregist_api_token: None,
            muregist_client_cert_san: None,
            tls_ca_path: None,
            tls_cert_path: None,
            tls_key_path: None,
            muconde_cd_api_url: Some(&base_url),
            cd_api_token: Some("test-cd-token"),
        };
        assert!(trigger_post_ci_cd_pipeline_with_config(&job, &no_checkout_ws, &cfg).await);

        let reg_calls = captured_reg.lock().unwrap().clone();
        assert_eq!(reg_calls.len(), 1);
        let parts = &reg_calls[0].1;
        assert_eq!(parts["service_name"].1, b"mu-ci-controller");
        assert_eq!(parts["binary"].0.as_deref(), Some("mu-ci-controller"));
        let bin_sha = post_ci_cd::compute_sha256_hex(&parts["binary"].1);
        let it_sha = post_ci_cd::compute_sha256_hex(&parts["it_archive"].1);

        let mut it_entries: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut it_archive = tar::Archive::new(flate2::read::GzDecoder::new(
            parts["it_archive"].1.as_slice(),
        ));
        for entry in it_archive.entries().unwrap() {
            let mut e = entry.unwrap();
            let path = e.path().unwrap().display().to_string();
            let mut buf = Vec::new();
            e.read_to_end(&mut buf).unwrap();
            it_entries.insert(path, buf);
        }
        let manifest: post_ci_cd::ItManifestJson =
            serde_json::from_slice(it_entries.get("manifest.json").unwrap()).unwrap();
        assert_eq!(manifest.service, "mu-ci-controller");
        assert_eq!(manifest.tests.len(), 1);
        assert_eq!(manifest.tests[0].name, "smoke_mu_ci_controller");
        assert!(it_entries.contains_key("bin/smoke_mu_ci_controller"));

        let deploy_calls = captured_deploy.lock().unwrap().clone();
        assert_eq!(deploy_calls.len(), 1);
        let body = &deploy_calls[0].2;
        assert_eq!(body["repo"], "LMA1980/mu-ci-controller");
        assert_eq!(body["service"], "mu-ci-controller");
        assert_eq!(body["git_commit"], sha);
        assert_eq!(body["binary_digest"], bin_sha);
        assert_eq!(body["it_archive_digest"], it_sha);
        assert_eq!(body["bundle_id"], "bundle-mf-rust-001");
        assert!(body.get("manifest_yaml").is_none());
        assert!(body.get("config").is_none());
        assert!(body.get("repo_path").is_none());

        // Case 2: Checked-out repo with .muci/mu-ci.yml cd metadata, custom Cargo.toml [[bin]] target
        // in target/<triple>/release/<bin>, empty target_nodes, and tests/smoke_custom.rs
        let checked_out = root.path().join("checked-out-custom-bin");
        std::fs::create_dir_all(checked_out.join(".muci")).unwrap();
        std::fs::create_dir_all(checked_out.join("src")).unwrap();
        std::fs::create_dir_all(checked_out.join("tests")).unwrap();
        let triple_release = checked_out.join("target/x86_64-unknown-linux-gnu/release");
        std::fs::create_dir_all(&triple_release).unwrap();
        std::fs::write(
            checked_out.join(".muci/mu-ci.yml"),
            "version: \"3\"\nname: \"custom-svc\"\ncd:\n  enabled: true\ntasks: {}\nstages: []\non_action: {}\n",
        )
        .unwrap();
        std::fs::write(
            checked_out.join("Cargo.toml"),
            "[package]\nname = \"custom-pkg\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[[bin]]\nname = \"custom-daemon\"\npath = \"src/main.rs\"\n",
        )
        .unwrap();
        std::fs::write(checked_out.join("src/main.rs"), "fn main() {}\n").unwrap();
        std::fs::write(
            checked_out.join("tests/smoke_custom.rs"),
            "#[test]\nfn smoke_custom_ok() {\n    assert!(true);\n}\n",
        )
        .unwrap();
        let elf_bytes = make_test_elf_header(0x003E);
        std::fs::write(triple_release.join("custom-daemon"), &elf_bytes).unwrap();

        let (base_url2, captured_reg2, captured_deploy2) =
            spawn_mock_post_ci_registry_and_cd_server("bundle-mf-rust-002").await;
        let job2 = Job {
            id: "job-mf-custom-bin".to_string(),
            event_type: "merge".to_string(),
            repo_name: "LMA1980/custom-svc".to_string(),
            clone_url: "https://github.com/LMA1980/custom-svc.git".to_string(),
            commit_sha: "feedface12345678".to_string(),
            ref_name: "main".to_string(),
            sender: "LMA1980".to_string(),
            pr_number: None,
            queued_at: Utc::now(),
        };
        let cfg2 = PostCiCdEndpointConfig {
            muregist_api_url: Some(&base_url2),
            muregist_api_token: None,
            muregist_client_cert_san: None,
            tls_ca_path: None,
            tls_cert_path: None,
            tls_key_path: None,
            muconde_cd_api_url: Some(&base_url2),
            cd_api_token: Some("test-cd-token"),
        };
        assert!(trigger_post_ci_cd_pipeline_with_config(&job2, &checked_out, &cfg2).await);

        let reg2 = captured_reg2.lock().unwrap().clone();
        assert_eq!(reg2.len(), 1);
        assert_eq!(reg2[0].1["service_name"].1, b"custom-svc");
        assert_eq!(reg2[0].1["binary"].0.as_deref(), Some("custom-daemon"));
        assert_eq!(reg2[0].1["binary"].1, elf_bytes);

        let dep2 = captured_deploy2.lock().unwrap().clone();
        assert_eq!(dep2.len(), 1);
        let body2 = &dep2[0].2;
        assert_eq!(body2["repo"], "LMA1980/custom-svc");
        assert_eq!(body2["service"], "custom-svc");
        assert_eq!(body2["bundle_id"], "bundle-mf-rust-002");
        assert!(body2.get("manifest_yaml").is_none());
        assert!(body2.get("config").is_none());
        assert!(body2.get("repo_path").is_none());
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_trigger_post_ci_cd_pipeline_manifest_free_static_web_spa() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("dist")).unwrap();
        std::fs::write(
            dir.path().join("Trunk.toml"),
            "[build]\ntarget = \"index.html\"\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("dist/index.html"),
            b"<html>mu-ci-web</html>",
        )
        .unwrap();

        let (base_url, captured_reg, captured_deploy) =
            spawn_mock_post_ci_registry_and_cd_server("bundle-mf-spa-001").await;

        let job = Job {
            id: "job-mf-spa".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/mu-ci-web".to_string(),
            clone_url: "https://github.com/LMA1980/mu-ci-web.git".to_string(),
            commit_sha: "abc987654321".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            pr_number: None,
            queued_at: Utc::now(),
        };

        let cfg = PostCiCdEndpointConfig {
            muregist_api_url: Some(&base_url),
            muregist_api_token: None,
            muregist_client_cert_san: None,
            tls_ca_path: None,
            tls_cert_path: None,
            tls_key_path: None,
            muconde_cd_api_url: Some(&base_url),
            cd_api_token: Some("test-cd-token"),
        };
        assert!(trigger_post_ci_cd_pipeline_with_config(&job, dir.path(), &cfg).await);

        let reg_calls = captured_reg.lock().unwrap().clone();
        assert_eq!(reg_calls.len(), 1);
        let parts = &reg_calls[0].1;
        assert_eq!(parts["service_name"].1, b"mu-ci-web");
        assert_eq!(parts["binary"].0.as_deref(), Some("mu-ci-web-dist.tar.gz"));
        let bin_sha = post_ci_cd::compute_sha256_hex(&parts["binary"].1);
        let it_sha = post_ci_cd::compute_sha256_hex(&parts["it_archive"].1);

        let mut tar_entries = Vec::new();
        let mut archive =
            tar::Archive::new(flate2::read::GzDecoder::new(parts["binary"].1.as_slice()));
        for entry in archive.entries().unwrap() {
            tar_entries.push(entry.unwrap().path().unwrap().display().to_string());
        }
        assert!(tar_entries.contains(&"dist/index.html".to_string()));

        let deploy_calls = captured_deploy.lock().unwrap().clone();
        assert_eq!(deploy_calls.len(), 1);
        let body = &deploy_calls[0].2;
        assert_eq!(body["repo"], "LMA1980/mu-ci-web");
        assert_eq!(body["service"], "mu-ci-web");
        assert_eq!(body["git_commit"], "abc987654321");
        assert_eq!(body["binary_digest"], bin_sha);
        assert_eq!(body["it_archive_digest"], it_sha);
        assert_eq!(body["bundle_id"], "bundle-mf-spa-001");
        assert_eq!(body["wait"], false);
        assert!(body.get("manifest_yaml").is_none());
        assert!(body.get("config").is_none());
        assert!(body.get("repo_path").is_none());
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_trigger_post_ci_cd_pipeline_manifest_free_non_managed_returns_false() {
        use axum::{routing::post, Router};
        use std::sync::atomic::{AtomicUsize, Ordering};

        let hits = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route(
                "/api/v1/bundles/it",
                post({
                    let hits = hits.clone();
                    move || {
                        let hits = hits.clone();
                        async move {
                            hits.fetch_add(1, Ordering::SeqCst);
                            axum::http::StatusCode::CREATED
                        }
                    }
                }),
            )
            .route(
                "/api/cd/deploy",
                post({
                    let hits = hits.clone();
                    move || {
                        let hits = hits.clone();
                        async move {
                            hits.fetch_add(1, Ordering::SeqCst);
                            axum::http::StatusCode::ACCEPTED
                        }
                    }
                }),
            )
            .with_state(());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let base_url = format!("http://{addr}");

        let cfg = PostCiCdEndpointConfig {
            muregist_api_url: Some(&base_url),
            muregist_api_token: None,
            muregist_client_cert_san: None,
            tls_ca_path: None,
            tls_cert_path: None,
            tls_key_path: None,
            muconde_cd_api_url: Some(&base_url),
            cd_api_token: Some("test-cd-token"),
        };

        for non_managed in [
            "LMA1980/mu-ci",
            "LMA1980/mu-cd",
            "LMA1980/mu-observable",
            "LMA1980/mu-ci-ipc",
            "LMA1980/mu-deploy",
            "LMA1980/lma1980.github.io",
            "LMA1980/arbitrary-non-service",
        ] {
            let dir = tempdir().unwrap();
            let slug = non_managed.rsplit('/').next().unwrap();
            std::fs::create_dir_all(dir.path().join(".muci")).unwrap();
            std::fs::create_dir_all(dir.path().join("target/release")).unwrap();
            std::fs::create_dir_all(dir.path().join("dist")).unwrap();
            std::fs::write(
                dir.path().join(".muci/mu-ci.yml"),
                "version: \"3\"\nname: \"ci-only\"\ntasks: {}\nstages: []\non_action: {}\n",
            )
            .unwrap();
            std::fs::write(dir.path().join("Trunk.toml"), "[build]\n").unwrap();
            std::fs::write(dir.path().join("dist/index.html"), b"<html>docs</html>").unwrap();
            std::fs::write(
                dir.path().join("target/release").join(slug),
                make_test_elf_header(0x003E),
            )
            .unwrap();

            let job = Job {
                id: format!("job-non-{slug}"),
                event_type: "push".to_string(),
                repo_name: non_managed.to_string(),
                clone_url: format!("https://github.com/{non_managed}.git"),
                commit_sha: "deadbeef0001".to_string(),
                ref_name: "refs/heads/main".to_string(),
                sender: "LMA1980".to_string(),
                pr_number: None,
                queued_at: Utc::now(),
            };
            assert!(
                !trigger_post_ci_cd_pipeline_with_config(&job, dir.path(), &cfg).await,
                "expected non-managed repo {non_managed} to return false"
            );
        }

        // Canonical repo with explicit cd.enabled: false opt-out in .muci/mu-ci.yml also returns false.
        let opt_out_dir = tempdir().unwrap();
        std::fs::create_dir_all(opt_out_dir.path().join(".muci")).unwrap();
        std::fs::create_dir_all(opt_out_dir.path().join("target/release")).unwrap();
        std::fs::write(
            opt_out_dir.path().join(".muci/mu-ci.yml"),
            "version: \"3\"\nname: \"opt-out\"\ncd:\n  enabled: false\ntasks: {}\nstages: []\non_action: {}\n",
        )
        .unwrap();
        std::fs::write(
            opt_out_dir.path().join("target/release/mu-ci-controller"),
            make_test_elf_header(0x003E),
        )
        .unwrap();
        let opt_out_job = Job {
            id: "job-opt-out".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/mu-ci-controller".to_string(),
            clone_url: "https://github.com/LMA1980/mu-ci-controller.git".to_string(),
            commit_sha: "deadbeef0002".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            pr_number: None,
            queued_at: Utc::now(),
        };
        assert!(
            !trigger_post_ci_cd_pipeline_with_config(&opt_out_job, opt_out_dir.path(), &cfg).await
        );
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }
}
