use mu_ci_controller::workflow::ActionRunnerWorkflow;

#[test]
fn test_workflow_dag_validation_valid() {
    let yaml = r#"
version: "3"
name: "Test Pipeline"
tasks:
  t-fmt:
    tool: "cargo-fmt"
  t-clippy:
    tool: "cargo-clippy"
  t-test:
    tool: "cargo-test"
stages:
  - id: fmt
    name: "Format"
    tasks: ["t-fmt"]
    tags: ["fmt"]
    threads: 2
  - id: clippy
    name: "Clippy"
    tasks: ["t-clippy"]
    tags: ["clippy"]
    threads: 4
  - id: test-native
    name: "Native Test"
    tasks: ["t-test"]
    tags: ["k3"]
    depends_on: ["fmt", "clippy"]
on_action:
  push: ["test-native"]
"#;
    let wf = ActionRunnerWorkflow::from_yaml(yaml).expect("valid workflow");
    assert_eq!(wf.stages.len(), 3);
    assert_eq!(wf.stages[2].depends_on, vec!["fmt", "clippy"]);
}

#[test]
fn test_workflow_dag_cycle_detection() {
    let yaml = r#"
version: "3"
name: "Cyclic Pipeline"
tasks:
  t1:
    tool: "cargo-build"
stages:
  - id: stage-a
    name: "A"
    tasks: ["t1"]
    depends_on: ["stage-b"]
  - id: stage-b
    name: "B"
    tasks: ["t1"]
    depends_on: ["stage-a"]
on_action:
  push: ["stage-a"]
"#;
    let err = ActionRunnerWorkflow::from_yaml(yaml).unwrap_err();
    assert!(err.contains("Cyclic dependency detected"));
}

#[test]
fn test_workflow_v3_subgraph_event_filtering() {
    let yaml = r#"
version: "3"
name: "Event Filtering Pipeline"
tasks:
  t1:
    tool: "cargo-fmt"
stages:
  - id: stage-1
    name: "Step 1"
    tasks: ["t1"]
on_action:
  push: ["stage-1"]
"#;
    let wf = ActionRunnerWorkflow::from_yaml(yaml).expect("valid v3");
    let push_sub = wf.subgraph_for_event("push").expect("push subgraph");
    assert_eq!(push_sub.stages.len(), 1);
    assert_eq!(push_sub.stages[0].id, "stage-1");
}

#[tokio::test]
async fn test_job_card_svg_route_and_headers() {
    use axum::http::{Request, StatusCode};
    use chrono::Utc;
    use mu_ci_controller::app::create_router;
    use mu_ci_controller::cluster::ClusterRegistry;
    use mu_ci_controller::config::Config;
    use mu_ci_controller::job::{Job, JobStatus, JobStore};
    use mu_ci_controller::scheduler::DAGScheduler;
    use mu_ci_controller::webhook::AppState;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use tower::ServiceExt;

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let ws_path = temp_dir.path().join("ws");
    let config = Config {
        bind_addr: "127.0.0.1:0".to_string(),
        workspace_dir: ws_path.clone(),
        allowed_repositories: vec!["*".to_string()],
        allowed_actors: vec![],
        allow_fork_prs: true,
        allowed_pr_authors: vec![],
        log_api_key: None,
        webhook_secret: None,
        cluster_token: "token".to_string(),
        job_timeout_seconds: 30,
        allow_insecure_no_secret: true,
        max_concurrent_jobs: 2,
        github_token: None,
        ..Config::default()
    };

    let job_store = JobStore::new(100, None);
    let cluster = ClusterRegistry::new();
    let (tx, _rx) = mpsc::channel(32);
    let _scheduler = Arc::new(DAGScheduler::new(
        config.clone(),
        job_store.clone(),
        cluster.clone(),
    ));

    let (log_broadcaster, _) = tokio::sync::broadcast::channel(128);

    let state = Arc::new(AppState {
        config,
        job_store: job_store.clone(),
        cluster,
        tx,
        log_broadcaster,

        console: mu_ci_controller::console::ConsoleState::default(),
    });

    let job = Job {
        id: "job-test-123".to_string(),
        event_type: "pull_request".to_string(),
        repo_name: "LMA1980/ActionRunner-web".to_string(),
        clone_url: String::new(),
        commit_sha: "9ca1c51a8e62c3950dde184046fa4613298b539c".to_string(),
        ref_name: "feat/first-view-host-attribution".to_string(),
        sender: "LMA1980".to_string(),
        queued_at: Utc::now(),
        pr_number: None,
    };
    job_store
        .enqueue_job(job, PathBuf::from("logs/test.log"))
        .await;
    job_store
        .update_status(
            "job-test-123",
            JobStatus::Completed {
                duration_secs: 143,
                exit_code: 0,
            },
        )
        .await;

    let app = create_router(state);

    let req = Request::builder()
        .uri("/api/jobs/job-test-123/card.svg")
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let cache_control = resp
        .headers()
        .get("cache-control")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(cache_control.contains("no-cache"));
    assert!(cache_control.contains("no-store"));

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let svg_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(svg_str.contains("LMA1980/ActionRunner-web"));
    assert!(svg_str.contains("9ca1c51a"));
    assert!(svg_str.contains("✓ PASSING"));
}

#[tokio::test]
async fn test_sse_dashboard_and_job_events_push() {
    use axum::http::{Request, StatusCode};
    use chrono::Utc;
    use futures_util::StreamExt;
    use mu_ci_controller::app::create_router;
    use mu_ci_controller::cluster::ClusterRegistry;
    use mu_ci_controller::config::Config;
    use mu_ci_controller::job::{Job, JobStore};
    use mu_ci_controller::webhook::AppState;
    use std::sync::Arc;
    use tower::ServiceExt;

    let tmp_ws = tempfile::tempdir().unwrap();
    let config = Config {
        bind_addr: "127.0.0.1:0".to_string(),
        webhook_secret: None,
        allow_insecure_no_secret: true,
        workspace_dir: tmp_ws.path().to_path_buf(),
        allowed_repositories: vec!["*".to_string()],
        allowed_actors: vec![],
        allow_fork_prs: true,
        allowed_pr_authors: vec![],
        cluster_token: "test".to_string(),
        job_timeout_seconds: 60,
        log_api_key: None,
        max_concurrent_jobs: 2,
        github_token: None,
        ..Config::default()
    };

    let job_store = JobStore::new(10, Some(tmp_ws.path()));
    let cluster = ClusterRegistry::new();
    let (tx, _rx) = tokio::sync::mpsc::channel(16);
    let (log_broadcaster, _) = tokio::sync::broadcast::channel(128);

    let state = Arc::new(AppState {
        config: config.clone(),
        job_store: job_store.clone(),
        cluster,
        tx,
        log_broadcaster,

        console: mu_ci_controller::console::ConsoleState::default(),
    });

    let job_id = "job-sse-456".to_string();
    let log_file = std::path::PathBuf::from("logs/sample_sse.log");
    let full_log_path = tmp_ws.path().join(&log_file);
    if let Some(parent) = full_log_path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(
        &full_log_path,
        "[2026-10-24T12:00:00Z] Initial SSE test log line\n",
    )
    .unwrap();

    let job = Job {
        id: job_id.clone(),
        event_type: "push".to_string(),
        repo_name: "LMA1980/ActionRunner-web".to_string(),
        clone_url: String::new(),
        commit_sha: "abcd1234abcd1234".to_string(),
        ref_name: "refs/heads/feat/sse-test".to_string(),
        sender: "LMA1980".to_string(),
        queued_at: Utc::now(),
        pr_number: None,
    };
    job_store.enqueue_job(job, log_file).await;

    let app = create_router(state.clone());

    // 1. Test Dashboard Events SSE Endpoint (/api/events)
    let req = Request::builder()
        .uri("/api/events")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-accel-buffering")
            .unwrap()
            .to_str()
            .unwrap(),
        "no"
    );

    let mut body_stream = resp.into_body().into_data_stream();
    let first_chunk = body_stream.next().await.unwrap().unwrap();
    let sse_text = String::from_utf8(first_chunk.to_vec()).unwrap();
    assert!(
        sse_text.contains("event: queue")
            || sse_text.contains("event: jobs")
            || sse_text.contains("event: cluster")
    );

    // 2. Test Job-Specific Events SSE Endpoint (/api/jobs/{id}/events)
    let req = Request::builder()
        .uri(format!("/api/jobs/{}/events", job_id))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-accel-buffering")
            .unwrap()
            .to_str()
            .unwrap(),
        "no"
    );

    let mut job_body_stream = resp.into_body().into_data_stream();
    let first_job_chunk = job_body_stream.next().await.unwrap().unwrap();
    let sse_job_text = String::from_utf8(first_job_chunk.to_vec()).unwrap();
    assert!(sse_job_text.contains("event: job") || sse_job_text.contains("event: log_init"));
    assert!(
        sse_job_text.contains("job-sse-456") || sse_job_text.contains("Initial SSE test log line")
    );
}

#[test]
fn test_workflow_exclusive_true_parsing() {
    let yaml = r#"
version: "3"
name: "Exclusive Test Pipeline"
tasks:
  bench-task:
    tool: "cargo-bench"
stages:
  - id: bench-run
    name: "Benchmark"
    tasks: ["bench-task"]
    tags: ["bench"]
    exclusive: true
on_action:
  push: ["bench-run"]
"#;
    let wf = ActionRunnerWorkflow::from_yaml(yaml).expect("valid exclusive");
    assert_eq!(wf.stages.len(), 1);
    assert!(wf.stages[0].exclusive, "exclusive: true was not parsed");
}

#[test]
fn test_workflow_isolate_node_alias_parsing() {
    let yaml = r#"
version: "3"
name: "Isolate Node Pipeline"
tasks:
  bench-task:
    tool: "cargo-bench"
stages:
  - id: bench-run
    name: "Benchmark"
    tasks: ["bench-task"]
    tags: ["bench"]
    isolate_node: true
on_action:
  push: ["bench-run"]
"#;
    let wf = ActionRunnerWorkflow::from_yaml(yaml).expect("valid isolate_node");
    assert_eq!(wf.stages.len(), 1);
    assert!(
        wf.stages[0].exclusive,
        "isolate_node: true was not aliased to exclusive: true"
    );
}

#[test]
fn test_workflow_exclusive_default_false() {
    let yaml = r#"
version: "3"
name: "Standard Pipeline"
tasks:
  test-task:
    tool: "cargo-test"
stages:
  - id: test-stage
    name: "Test"
    tasks: ["test-task"]
    tags: ["test"]
on_action:
  push: ["test-stage"]
"#;
    let wf = ActionRunnerWorkflow::from_yaml(yaml).expect("valid default");
    assert_eq!(wf.stages.len(), 1);
    assert!(
        !wf.stages[0].exclusive,
        "exclusive did not default to false"
    );
}

#[test]
fn test_config_resolve_secret_fail_closed_on_missing_path() {
    use mu_ci_controller::config::Config;

    // 1. Nonexistent absolute path must fail closed to None
    let missing_path = "/tmp/actionrunner_missing_secret_test.key";
    assert_eq!(
        Config::resolve_secret_value(missing_path),
        None,
        "Must fail closed to None when secret path does not exist"
    );

    // 2. Nonexistent relative path must fail closed to None
    assert_eq!(
        Config::resolve_secret_value("./missing_secret.txt"),
        None,
        "Missing relative secret file must fail closed to None"
    );

    // 3. Existing empty file must fail closed to None
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let empty_file = temp_dir.path().join("empty.key");
    std::fs::write(&empty_file, "   \n\t  \n").unwrap();
    assert_eq!(
        Config::resolve_secret_value(empty_file.to_str().unwrap()),
        None,
        "Empty secret file must return None"
    );

    // 4. Existing valid file with trailing whitespace returns trimmed content
    let valid_file = temp_dir.path().join("valid.key");
    std::fs::write(&valid_file, "  super_secret_payload_token_xyz  \n").unwrap();
    assert_eq!(
        Config::resolve_secret_value(valid_file.to_str().unwrap()),
        Some("super_secret_payload_token_xyz".to_string()),
        "Valid secret file must return trimmed content"
    );

    // 5. Literal string secret should be preserved
    let literal_secret = "my-literal-api-key";
    assert_eq!(
        Config::resolve_secret_value(literal_secret),
        Some(literal_secret.to_string()),
        "Literal string secret should be preserved"
    );

    // 6. Environment variable pointing to nonexistent file fails closed
    let env_key = "TEST_SECRET_FAIL_CLOSED_ENV_VAR_M2";
    std::env::set_var(env_key, "/nonexistent/secret_env_file.key");
    assert_eq!(Config::resolve_secret(env_key), None);
    std::env::remove_var(env_key);
}

#[tokio::test]
async fn test_startup_health_ready_before_async_log_backfill_and_preserves_live_jobs() {
    use chrono::Utc;
    use mu_ci_controller::app::create_router;
    use mu_ci_controller::cluster::ClusterRegistry;
    use mu_ci_controller::config::Config;
    use mu_ci_controller::job::{Job, JobStore};
    use mu_ci_controller::webhook::AppState;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc;

    let tmp_ws = tempfile::tempdir().expect("tempdir");
    let repo_logs = tmp_ws
        .path()
        .join("logs")
        .join("LMA1980")
        .join("example-service");
    std::fs::create_dir_all(&repo_logs).expect("create repo logs dir");

    // Seed two historical workspace log files: one purely historical and one colliding with a live job.
    std::fs::write(
        repo_logs.join("job-1729500000-deadbeef.log"),
        "2026-10-21T10:00:00Z [worker-x86] [test] [stdout] running 5 tests\n2026-10-21T10:00:02Z [worker-x86] [test] [stdout] test result: ok. 5 passed; 0 failed; 0 ignored\n",
    )
    .expect("write historical log");
    std::fs::write(
        repo_logs.join("job-1729500099-cafebabe.log"),
        "2026-10-21T10:05:00Z [worker-x86] [test] [stdout] running 1 tests\n2026-10-21T10:05:01Z [worker-x86] [test] [stdout] test result: ok. 1 passed; 0 failed; 0 ignored\n",
    )
    .expect("write colliding historical log");

    let mut cfg = Config::load();
    cfg.workspace_dir = tmp_ws.path().to_path_buf();
    cfg.ha_role = mu_ci_controller::config::HaRoleConfig::Leader;
    cfg.node_id = "node-a".to_string();

    // 1. JobStore::from_config must NOT synchronously block on disk log backfill.
    let job_store = JobStore::from_config(100, &cfg);
    assert!(
        job_store
            .find_latest_job("LMA1980/example-service", None)
            .await
            .is_none(),
        "JobStore::from_config must defer workspace log backfill off the startup critical path"
    );

    let cluster = ClusterRegistry::new();
    let (tx, _rx) = mpsc::channel(8);
    let (log_broadcaster, _) = tokio::sync::broadcast::channel(32);
    let state = Arc::new(AppState {
        config: cfg.clone(),
        job_store: job_store.clone(),
        cluster,
        tx,
        log_broadcaster,
        console: mu_ci_controller::console::ConsoleState::default(),
    });
    let app = create_router(state.clone());

    // 2. Bind HTTP listener and verify /health responds 200 OK immediately before backfill runs.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral listener");
    let addr = listener.local_addr().expect("local_addr");
    let server_handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to controller HTTP listener");
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write GET /health");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .await
        .expect("read /health response");
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "expected immediate 200 OK from /health, got: {response}"
    );

    // 3. Enqueue a live Queued job sharing the colliding job_id before spawning background backfill.
    let live_job = Job {
        id: "job-1729500099-cafebabe".to_string(),
        event_type: "push".to_string(),
        repo_name: "LMA1980/example-service".to_string(),
        clone_url: String::new(),
        commit_sha: "livefeed12345678".to_string(),
        ref_name: "refs/heads/main".to_string(),
        sender: "LMA1980".to_string(),
        queued_at: Utc::now(),
        pr_number: None,
    };
    job_store
        .enqueue_job(
            live_job,
            std::path::PathBuf::from("logs/LMA1980/example-service/job-1729500099-cafebabe.log"),
        )
        .await;

    // 4. Spawn background log backfill and await completion.
    let backfill_handle = job_store
        .spawn_background_log_backfill(cfg.workspace_dir.clone())
        .expect("InMemoryStorage must spawn background backfill");
    let recovered_count = backfill_handle.await.expect("backfill join");
    assert_eq!(
        recovered_count, 1,
        "only the non-colliding historical log should be backfilled"
    );

    // 5. Historical record is recovered cleanly in both CatalogStore and in-memory list_jobs.
    let historical = job_store
        .find_latest_job("LMA1980/example-service", None)
        .await
        .expect("historical job reconstructed by background backfill");
    assert_eq!(historical.job.id, "job-1729500000-deadbeef");
    assert_eq!(historical.job.commit_sha, "deadbeef");
    assert_eq!(
        historical
            .metrics
            .expect("reconstructed metrics")
            .tests_passed,
        5
    );

    // 6. Live job was NEVER clobbered in either storage or in-memory queue.
    let jobs = job_store.list_jobs().await;
    let got_live = jobs
        .iter()
        .find(|j| j.job.id == "job-1729500099-cafebabe")
        .expect("live job must remain in list_jobs");
    assert!(matches!(
        got_live.status,
        mu_ci_controller::job::JobStatus::Queued
    ));
    assert_eq!(got_live.job.commit_sha, "livefeed12345678");
    assert!(
        jobs.iter().any(|j| j.job.id == "job-1729500000-deadbeef"),
        "recovered historical job must be merged into list_jobs"
    );

    server_handle.abort();
}
