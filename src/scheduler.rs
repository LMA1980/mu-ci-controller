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
                        let _ = trigger_post_ci_cd_pipeline(&job, &repo_workspace).await;
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

/// Returns `true` when `job` represents a `push` or `merge` event on the `main` branch.
#[must_use]
pub fn is_main_push_or_merge(job: &Job) -> bool {
    !job.commit_sha.trim().is_empty()
        && (job.event_type == "push" || job.event_type == "merge")
        && (job.ref_name == "refs/heads/main" || job.ref_name == "main")
}

/// Resolves the raw YAML content of a repository's CD manifest from either `git show <sha>:<cand>`
/// or the local `repo_workspace` checkout.
pub async fn resolve_cd_manifest_yaml(repo_workspace: &Path, commit_sha: &str) -> Option<String> {
    if !commit_sha.trim().is_empty() && repo_workspace.join(".git").exists() {
        for cand in CD_MANIFEST_CANDIDATES {
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

    for cand in CD_MANIFEST_CANDIDATES {
        let p = repo_workspace.join(cand);
        if let Ok(content) = tokio::fs::read_to_string(&p).await {
            if !content.trim().is_empty() {
                return Some(content);
            }
        }
    }
    None
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
    repo_name
        .rsplit('/')
        .next()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(repo_name)
        .to_string()
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

/// Loads the `MuConDe` CD API bearer token from `MUCONDE_CD_API_TOKEN_FILE` or `MUCONDE_CD_API_TOKEN`.
#[must_use]
pub fn load_cd_api_token() -> Option<String> {
    let token_file = std::env::var("MUCONDE_CD_API_TOKEN_FILE").ok();
    let token_val = std::env::var("MUCONDE_CD_API_TOKEN").ok();
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
    use super::extract_cd_service_name;
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

    fn is_static_web_deployment(summary: &CdManifestSummary) -> bool {
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

    fn candidate_release_dirs(expected_arch: Option<ExpectedElfArch>) -> Vec<PathBuf> {
        match expected_arch {
            Some(arch) => vec![
                PathBuf::from("target")
                    .join(arch.target_triple())
                    .join("release"),
                PathBuf::from("target/release"),
            ],
            None => vec![
                PathBuf::from("target/release"),
                PathBuf::from("target")
                    .join(ExpectedElfArch::Riscv64.target_triple())
                    .join("release"),
                PathBuf::from("target")
                    .join(ExpectedElfArch::X86_64.target_triple())
                    .join("release"),
                PathBuf::from("target")
                    .join(ExpectedElfArch::Aarch64.target_triple())
                    .join("release"),
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

    fn resolve_binary_artifact(
        repo_workspace: &Path,
        repo_name: &str,
        summary: &CdManifestSummary,
    ) -> Result<PackagedArtifact, String> {
        let expected_arch = infer_target_arch_from_nodes(&summary.target_nodes);
        let candidates = candidate_binary_names(summary, repo_name);

        if let Some(raw_art) = summary.artifact.as_deref() {
            let rel_art = sanitize_relative_subpath(art_or_raw(raw_art))?;
            let art_path = repo_workspace.join(&rel_art);
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
                let bin_path = repo_workspace.join(&rel_bin);
                if let Some(pkg) = read_validated_binary(&bin_path, expected_arch)? {
                    return Ok(pkg);
                }
            }
        }

        for rel_dir in candidate_release_dirs(expected_arch) {
            let abs_dir = repo_workspace.join(&rel_dir);
            for bin_name in &candidates {
                let bin_path = abs_dir.join(bin_name);
                if let Some(pkg) = read_validated_binary(&bin_path, expected_arch)? {
                    return Ok(pkg);
                }
            }
        }

        Err(format!(
            "No release binary found in '{}' matching candidates {:?}",
            repo_workspace.display(),
            candidates
        ))
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
        #[serde(default)]
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
/// when a `main` branch `push` or `merge` job succeeds and the repository defines a CD manifest.
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
    let muconde_url = first_non_empty_env(&["MUCONDE_CD_API_URL"]);
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

    let manifest_yaml = match resolve_cd_manifest_yaml(repo_workspace, &job.commit_sha).await {
        Some(yaml) => yaml,
        None => return false,
    };

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

    let summary = post_ci_cd::parse_cd_manifest_summary(&manifest_yaml, &job.repo_name);
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
        let binary =
            post_ci_cd::resolve_and_package_artifact(&workspace, &repo_name, &summary_for_pack)?;
        let it_archive = post_ci_cd::package_it_archive(
            &workspace,
            &summary_for_pack,
            &commit_sha,
            &binary.sha256_hex,
        )?;
        Ok::<_, String>((binary, it_archive))
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
        "artifact_sha256": binary.sha256_hex,
        "git_commit": job.commit_sha,
        "binary_digest": binary.sha256_hex,
        "it_archive_digest": it_archive.sha256_hex,
        "manifest_yaml": manifest_yaml,
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
                artifact_sha256 = %binary.sha256_hex,
                "Triggered post-CI MuConDe rollout deployment"
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
        assert_eq!(deploy_body["artifact_sha256"], expected_bin_sha);
        assert_ne!(deploy_body["artifact_sha256"], "deadbeefcafe1234");
        assert_eq!(deploy_body["git_commit"], "deadbeefcafe1234");
        assert_eq!(deploy_body["binary_digest"], expected_bin_sha);
        assert_eq!(deploy_body["it_archive_digest"], expected_it_sha);
        assert_eq!(deploy_body["bundle_id"], "bundle-static-001");
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
        assert_eq!(deploys[0]["artifact_sha256"], expected_sha);
        assert_eq!(deploys[0]["git_commit"], "abc123def456");
        assert_ne!(deploys[0]["artifact_sha256"], deploys[0]["git_commit"]);
        assert_eq!(deploys[0]["bundle_id"], "bundle-bin-002");
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
}
