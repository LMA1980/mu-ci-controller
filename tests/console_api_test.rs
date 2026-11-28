//! Integration tests for the read-only console API (`/api/repos`, `/summary`,
//! `/topology`) and the additive SSE kinds on `/api/events` (#50).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{Duration as ChronoDuration, Utc};
use futures_util::StreamExt;
use mu_ci_controller::app::create_router;
use mu_ci_controller::cluster::ClusterRegistry;
use mu_ci_controller::config::Config;
use mu_ci_controller::console::{ConsoleConfig, ConsoleState};
use mu_ci_controller::job::{Job, JobMetrics, JobStatus, JobStore, StageRecord, StageStatus};
use mu_ci_controller::webhook::AppState;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use serde_cbor_2::Value as CborValue;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;
use webauthn_rs_core::proto::{
    AuthenticatorAssertionResponseRaw, AuthenticatorAttestationResponseRaw, PublicKeyCredential,
    RegisterPublicKeyCredential,
};

const API_KEY: &str = "console-test-key";
const SHA_CORE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA_SECRET: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SHA_CHILD: &str = "cccccccccccccccccccccccccccccccccccccccc";

fn test_config(log_api_key: Option<&str>) -> Config {
    Config {
        bind_addr: "127.0.0.1:0".to_string(),
        workspace_dir: PathBuf::from("/nonexistent-console-ws"),
        allowed_repositories: vec!["LMA1980/*".to_string()],
        allowed_actors: vec![],
        allow_fork_prs: false,
        allowed_pr_authors: vec!["OWNER".to_string()],
        log_api_key: log_api_key.map(str::to_string),
        webhook_secret: None,
        cluster_token: "token".to_string(),
        job_timeout_seconds: 30,
        allow_insecure_no_secret: true,
        max_concurrent_jobs: 2,
        github_token: None,
        ..Config::default()
    }
}

fn make_state(log_api_key: Option<&str>, console: ConsoleState) -> Arc<AppState> {
    let (tx, _rx) = tokio::sync::mpsc::channel(64);
    let (log_broadcaster, _) = tokio::sync::broadcast::channel(128);
    Arc::new(AppState {
        config: test_config(log_api_key),
        job_store: JobStore::new(100, None),
        cluster: ClusterRegistry::new(),
        tx,
        log_broadcaster,
        console,
    })
}

/// Minimal GitHub REST mock: `/repos/{o}/{r}` and `/repos/{o}/{r}/contents/{path}`.
async fn spawn_github_mock() -> String {
    let mut repos: BTreeMap<&'static str, Value> = BTreeMap::new();
    repos.insert(
        "LMA1980/parent",
        json!({"private": false, "visibility": "public", "default_branch": "main"}),
    );
    repos.insert(
        "LMA1980/child",
        json!({"private": false, "visibility": "public", "default_branch": "main"}),
    );
    repos.insert(
        "LMA1980/secret-lib",
        json!({"private": true, "visibility": "private", "default_branch": "main"}),
    );
    repos.insert(
        "LMA1980/private-parent",
        json!({"private": true, "visibility": "private", "default_branch": "trunk"}),
    );
    let repos = Arc::new(repos);

    let mut files: BTreeMap<String, String> = BTreeMap::new();
    files.insert(
        "LMA1980/parent/.gitmodules".into(),
        "[submodule \"code/core\"]\n\tpath = code/core\n\turl = https://github.com/LMA1980/child.git\n[submodule \"code/secret\"]\n\tpath = code/secret\n\turl = ../secret-lib.git\n".into(),
    );
    files.insert(
        "LMA1980/parent/code/core".into(),
        json!({"type": "submodule", "sha": SHA_CORE}).to_string(),
    );
    files.insert(
        "LMA1980/parent/code/secret".into(),
        json!({"type": "submodule", "sha": SHA_SECRET}).to_string(),
    );
    files.insert(
        "LMA1980/parent/.actionrunner/ActionRunner.yml".into(),
        r#"
version: "3"
name: "Parent Pipeline"
tasks:
  fmt:
    tool: "cargo-fmt"
  clippy:
    tool: "cargo-clippy"
  test:
    tool: "cargo-test"
stages:
  - id: fmt
    name: "FMT"
    tasks: ["fmt"]
  - id: clippy
    name: "CLIPPY"
    tasks: ["clippy"]
    depends_on: ["fmt"]
  - id: test
    name: "TEST"
    tasks: ["test"]
    depends_on: ["clippy"]
on_action:
  push: ["fmt", "clippy", "test"]
"#
        .into(),
    );
    files.insert(
        "LMA1980/private-parent/.gitmodules".into(),
        "[submodule \"code/child\"]\n\tpath = code/child\n\turl = git@github.com:LMA1980/child.git\n"
            .into(),
    );
    files.insert(
        "LMA1980/private-parent/code/child".into(),
        json!({"type": "submodule", "sha": SHA_CHILD}).to_string(),
    );
    let files = Arc::new(files);

    let app = Router::new()
        .route(
            "/repos/{owner}/{repo}",
            get({
                let repos = repos.clone();
                move |axum::extract::Path((o, r)): axum::extract::Path<(String, String)>| {
                    let repos = repos.clone();
                    async move {
                        match repos.get(format!("{o}/{r}").as_str()) {
                            Some(v) => (StatusCode::OK, v.to_string()),
                            None => (StatusCode::NOT_FOUND, "{}".to_string()),
                        }
                    }
                }
            }),
        )
        .route(
            "/repos/{owner}/{repo}/contents/{*path}",
            get({
                let files = files.clone();
                move |axum::extract::Path((o, r, p)): axum::extract::Path<(
                    String,
                    String,
                    String,
                )>| {
                    let files = files.clone();
                    async move {
                        match files.get(&format!("{o}/{r}/{p}")) {
                            Some(v) => (StatusCode::OK, v.clone()),
                            None => (StatusCode::NOT_FOUND, "{}".to_string()),
                        }
                    }
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

async fn get_json(app: &Router, uri: &str, bearer: Option<&str>) -> (StatusCode, Value) {
    let mut req = Request::builder().uri(uri);
    if let Some(b) = bearer {
        req = req.header("Authorization", format!("Bearer {b}"));
    }
    let resp = app
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let val = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, val)
}

async fn post_webhook(app: &Router, event: &str, payload: Value) -> StatusCode {
    let req = Request::builder()
        .method("POST")
        .uri("/webhook")
        .header("x-github-event", event)
        .header("content-type", "application/json")
        .body(Body::from(payload.to_string()))
        .unwrap();
    app.clone().oneshot(req).await.unwrap().status()
}

fn repo_obj(full: &str, private: bool) -> Value {
    json!({
        "full_name": full,
        "private": private,
        "default_branch": "main",
        "clone_url": format!("https://github.com/{full}.git"),
    })
}

/// Enqueues and completes a job with metrics on `ref_name`.
async fn completed_job(
    store: &JobStore,
    id: &str,
    repo: &str,
    ref_name: &str,
    sha: &str,
    age_mins: i64,
    metrics: Option<JobMetrics>,
) {
    let job = Job {
        id: id.to_string(),
        event_type: "push".to_string(),
        repo_name: repo.to_string(),
        clone_url: String::new(),
        commit_sha: sha.to_string(),
        ref_name: ref_name.to_string(),
        sender: "LMA1980".to_string(),
        queued_at: Utc::now() - ChronoDuration::minutes(age_mins),
        pr_number: None,
    };
    store
        .enqueue_job(job, PathBuf::from(format!("logs/{id}.log")))
        .await;
    if let Some(m) = metrics {
        store.update_metrics(id, m).await;
    }
    store
        .update_status(
            id,
            JobStatus::Completed {
                duration_secs: 10,
                exit_code: 0,
            },
        )
        .await;
}

fn metrics(score: u32, coverage: f64, bench: &str) -> JobMetrics {
    JobMetrics {
        quality_score: score,
        letter_grade: "A".to_string(),
        coverage_pct: Some(coverage),
        benchmark_summary: Some(bench.to_string()),
        tests_passed: 10,
        tests_total: 10,
        advisories_count: 0,
        clippy_warnings: 0,
        submodules: BTreeMap::new(),
    }
}

fn find_repo<'a>(list: &'a Value, name: &str) -> Option<&'a Value> {
    list["repos"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["repo"] == name)
}

async fn seeded_state() -> Arc<AppState> {
    let api = spawn_github_mock().await;
    let console = ConsoleState::new(ConsoleConfig {
        github_api_url: Some(api),
        ..ConsoleConfig::default()
    });
    for r in ["parent", "child", "secret-lib", "private-parent"] {
        console.refresh_repo("LMA1980", r, None).await;
    }
    make_state(Some(API_KEY), console)
}

#[tokio::test]
async fn repos_filter_private_and_expose_submodule_graph() {
    let state = seeded_state().await;
    // A repository known only from job history with unknown visibility.
    completed_job(
        &state.job_store,
        "job-hist-1",
        "LMA1980/history-only",
        "refs/heads/main",
        "1111111111111111111111111111111111111111",
        5,
        None,
    )
    .await;
    let app = create_router(state.clone());

    // Anonymous: only public repositories.
    let (status, anon) = get_json(&app, "/api/repos", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(anon["authenticated"], false);
    let names: Vec<&str> = anon["repos"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["repo"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"parent") && names.contains(&"child"));
    assert!(!names.contains(&"secret-lib"), "private repo leaked");
    assert!(!names.contains(&"private-parent"), "private repo leaked");
    assert!(
        !names.contains(&"history-only"),
        "unknown visibility must fail closed"
    );

    let parent = find_repo(&anon, "parent").unwrap();
    assert_eq!(parent["visibility"], "public");
    assert_eq!(parent["default_branch"], "main");
    assert_eq!(
        parent["submodules"],
        json!([
            {"path": "code/core", "owner": "LMA1980", "repo": "child", "pinned_sha": SHA_CORE},
            {"path": "code/secret", "owner": "LMA1980", "repo": "secret-lib", "pinned_sha": SHA_SECRET},
        ])
    );
    let child = find_repo(&anon, "child").unwrap();
    assert_eq!(
        child["parents"],
        json!([{"owner": "LMA1980", "repo": "parent", "path": "code/core"}]),
        "private parent must be hidden from anonymous sessions"
    );

    // Wrong key behaves as anonymous.
    let (_, wrong) = get_json(&app, "/api/repos", Some("nope")).await;
    assert_eq!(wrong["authenticated"], false);
    assert!(find_repo(&wrong, "secret-lib").is_none());

    // Authenticated: everything, including parents from private superprojects.
    let (_, authed) = get_json(&app, "/api/repos", Some(API_KEY)).await;
    assert_eq!(authed["authenticated"], true);
    assert_eq!(
        find_repo(&authed, "secret-lib").unwrap()["visibility"],
        "private"
    );
    let pp = find_repo(&authed, "private-parent").unwrap();
    assert_eq!(pp["default_branch"], "trunk");
    let hist = find_repo(&authed, "history-only").unwrap();
    assert_eq!(hist["visibility"], Value::Null);
    assert_eq!(hist["latest_job_id"], "job-hist-1");
    assert_eq!(hist["status"], "passing");
    let child = find_repo(&authed, "child").unwrap();
    assert_eq!(child["parents"].as_array().unwrap().len(), 2);
    assert!(authed["fabric_rev"].as_u64().unwrap() >= 1);
}

#[tokio::test]
async fn submodules_refresh_on_default_branch_push_touching_gitmodules() {
    let api = spawn_github_mock().await;
    let console = ConsoleState::new(ConsoleConfig {
        github_api_url: Some(api),
        ..ConsoleConfig::default()
    });
    let state = make_state(Some(API_KEY), console);
    let app = create_router(state.clone());

    let status = post_webhook(
        &app,
        "push",
        json!({
            "ref": "refs/heads/main",
            "after": "2222222222222222222222222222222222222222",
            "repository": repo_obj("LMA1980/parent", false),
            "sender": {"login": "LMA1980"},
            "commits": [{"added": [], "modified": [".gitmodules"], "removed": []}],
        }),
    )
    .await;
    assert!(status.is_success());

    let mut subs = Value::Null;
    for _ in 0..50 {
        let (_, list) = get_json(&app, "/api/repos", None).await;
        if let Some(p) = find_repo(&list, "parent") {
            if p["submodules"].as_array().map(|a| a.len()) == Some(2) {
                subs = p["submodules"].clone();
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(subs[0]["repo"], "child");
    assert_eq!(subs[0]["pinned_sha"], SHA_CORE);
}

#[tokio::test]
async fn summary_scorecard_and_visibility() {
    let state = seeded_state().await;
    let store = &state.job_store;
    completed_job(
        store,
        "job-p-1",
        "LMA1980/parent",
        "refs/heads/main",
        "3333333333333333333333333333333333333333",
        20,
        Some(metrics(88, 80.0, "1 benches (10.0 µs/iter)")),
    )
    .await;
    completed_job(
        store,
        "job-p-2",
        "LMA1980/parent",
        "refs/heads/main",
        "4444444444444444444444444444444444444444",
        10,
        Some(metrics(92, 87.5, "1 benches (11.0 µs/iter)")),
    )
    .await;
    completed_job(
        store,
        "job-s-1",
        "LMA1980/secret-lib",
        "refs/heads/main",
        "5555555555555555555555555555555555555555",
        5,
        Some(metrics(70, 50.0, "")),
    )
    .await;
    let app = create_router(state.clone());

    let (status, s) = get_json(&app, "/api/repos/LMA1980/parent/summary", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(s["status"], "passing");
    assert_eq!(s["branch"], "main");
    assert_eq!(s["latest_completed_job_id"], "job-p-2");
    assert_eq!(s["score"], 92);
    assert_eq!(s["coverage"], 87.5);
    assert_eq!(s["coverage_bp"], 8750);
    assert_eq!(s["bench_delta"], 10.0);
    let hist: Vec<&str> = s["history"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["job_id"].as_str().unwrap())
        .collect();
    assert_eq!(hist, vec!["job-p-1", "job-p-2"], "history is oldest-first");
    assert_eq!(s["submodules"].as_array().unwrap().len(), 2);

    // The list carries the same CI numbers.
    let (_, list) = get_json(&app, "/api/repos", None).await;
    let p = find_repo(&list, "parent").unwrap();
    assert_eq!(p["latest_job_id"], "job-p-2");
    assert_eq!(p["score"], 92);
    assert_eq!(p["bench_delta"], 10.0);

    // Unknown -> 404; private + anonymous -> 404 (not 403); private + key -> 200.
    let (status, _) = get_json(&app, "/api/repos/LMA1980/does-not-exist/summary", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = get_json(&app, "/api/repos/LMA1980/secret-lib/summary", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, s) = get_json(&app, "/api/repos/LMA1980/secret-lib/summary", Some(API_KEY)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(s["score"], 70);
    let (status, _) = get_json(&app, "/api/repos/LMA1980/secret-lib/topology", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn topology_tracks_simulated_webhooks() {
    let state = make_state(None, ConsoleState::default());
    let app = create_router(state.clone());
    let full = "LMA1980/railway";

    // Branch created (feat/**) and an unrelated non-feat branch.
    assert!(post_webhook(
        &app,
        "create",
        json!({"ref": "feat/rail", "ref_type": "branch", "master_branch": "main",
               "repository": repo_obj(full, false), "sender": {"login": "LMA1980"}}),
    )
    .await
    .is_success());
    assert!(post_webhook(
        &app,
        "create",
        json!({"ref": "experiment", "ref_type": "branch",
               "repository": repo_obj(full, false), "sender": {"login": "LMA1980"}}),
    )
    .await
    .is_success());

    let (status, t0) = get_json(&app, "/api/repos/LMA1980/railway/topology", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(t0["stations_source"], "default");
    let ids: Vec<&str> = t0["stations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["fmt-check", "clippy-check", "native-k3"]);
    let refs: Vec<&str> = t0["branches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["ref"].as_str().unwrap())
        .collect();
    assert_eq!(
        refs,
        vec!["feat/rail"],
        "non-feat branch without PR is hidden"
    );
    let rev0 = t0["fabric_rev"].as_u64().unwrap();

    // Push to the branch (queues a train) and open PRs on feat/rail and fix/bug.
    assert!(post_webhook(
        &app,
        "push",
        json!({"ref": "refs/heads/feat/rail", "after": "6666666666666666666666666666666666666666",
               "repository": repo_obj(full, false), "sender": {"login": "LMA1980"}}),
    )
    .await
    .is_success());
    for (number, head, draft) in [(7, "feat/rail", false), (8, "fix/bug", true)] {
        assert!(post_webhook(
            &app,
            "pull_request",
            json!({"action": "opened", "number": number,
                   "repository": repo_obj(full, false), "sender": {"login": "LMA1980"},
                   "pull_request": {"number": number, "draft": draft, "author_association": "OWNER",
                       "head": {"ref": head, "sha": "7777777777777777777777777777777777777777",
                                "repo": {"full_name": full}},
                       "base": {"ref": "main", "repo": {"full_name": full}}}}),
        )
        .await
        .is_success());
    }

    // Give the queued train stages, one running on a node.
    let jobs = state.job_store.list_jobs().await;
    let train_job = jobs
        .iter()
        .filter(|j| j.job.repo_name == full && j.job.ref_name.ends_with("feat/rail"))
        .max_by_key(|j| j.job.queued_at)
        .expect("push / PR queued a job");
    let job_id = train_job.job.id.clone();
    let stage = |id: &str| StageRecord {
        id: id.to_string(),
        name: id.to_uppercase(),
        tags: vec![],
        threads: 2,
        toolchain: None,
        depends_on: vec![],
        status: StageStatus::Pending,
        assigned_node: None,
        exclusive: false,
        skip_if_unavailable: false,
        skip_reason_code: None,
        skip_capability: None,
    };
    state
        .job_store
        .set_stages(&job_id, vec![stage("fmt"), stage("clippy"), stage("test")])
        .await;
    state
        .job_store
        .update_stage_status(
            &job_id,
            "fmt",
            StageStatus::Completed {
                duration_secs: 1,
                exit_code: 0,
            },
        )
        .await;
    state
        .job_store
        .update_stage_status(
            &job_id,
            "clippy",
            StageStatus::Running {
                node_id: "node-a".to_string(),
                started_at: Utc::now(),
                pid: None,
            },
        )
        .await;

    let (_, t1) = get_json(&app, "/api/repos/LMA1980/railway/topology", None).await;
    assert!(t1["fabric_rev"].as_u64().unwrap() > rev0);
    assert_eq!(t1["stations_source"], "job");
    let branches = t1["branches"].as_array().unwrap();
    let rail = branches.iter().find(|b| b["ref"] == "feat/rail").unwrap();
    assert_eq!(rail["pr_state"], "open");
    assert_eq!(rail["pr_number"], 7);
    assert_eq!(rail["base_ref"], "main");
    assert_eq!(rail["last_job"]["job_id"], job_id.as_str());
    assert_eq!(rail["last_job"]["stage"], "clippy");
    let bug = branches.iter().find(|b| b["ref"] == "fix/bug").unwrap();
    assert_eq!(bug["pr_state"], "draft", "open-PR branch listed");

    let train = t1["trains"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["job_id"] == job_id.as_str())
        .unwrap();
    assert_eq!(train["ref"], "feat/rail");
    assert_eq!(train["stage"], "clippy");
    assert_eq!(train["node_id"], "node-a");
    assert_eq!(
        train["stage_states"],
        json!([
            {"station": "fmt", "state": "passed", "node_id": null},
            {"station": "clippy", "state": "running", "node_id": "node-a"},
            {"station": "test", "state": "pending", "node_id": null},
        ])
    );

    // PR merged, then branch deleted: siding leaves the topology.
    assert!(post_webhook(
        &app,
        "pull_request",
        json!({"action": "closed", "number": 7,
               "repository": repo_obj(full, false), "sender": {"login": "LMA1980"},
               "pull_request": {"number": 7, "merged": true, "author_association": "OWNER",
                   "merge_commit_sha": "8888888888888888888888888888888888888888",
                   "head": {"ref": "feat/rail", "sha": "7777777777777777777777777777777777777777",
                            "repo": {"full_name": full}},
                   "base": {"ref": "main", "repo": {"full_name": full}}}}),
    )
    .await
    .is_success());
    let (_, t2) = get_json(&app, "/api/repos/LMA1980/railway/topology", None).await;
    let rail = t2["branches"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["ref"] == "feat/rail")
        .unwrap();
    assert_eq!(rail["pr_state"], "merged");

    assert!(post_webhook(
        &app,
        "delete",
        json!({"ref": "feat/rail", "ref_type": "branch",
               "repository": repo_obj(full, false), "sender": {"login": "LMA1980"}}),
    )
    .await
    .is_success());
    let (_, t3) = get_json(&app, "/api/repos/LMA1980/railway/topology", None).await;
    assert!(t3["branches"]
        .as_array()
        .unwrap()
        .iter()
        .all(|b| b["ref"] != "feat/rail"));
    assert!(t3["fabric_rev"].as_u64().unwrap() > t2["fabric_rev"].as_u64().unwrap());
}

/// Reads SSE frames until one with `event: <kind>` arrives; returns the accumulated text.
async fn read_until<S>(stream: &mut S, kind: &str) -> String
where
    S: futures_util::Stream<Item = Result<axum::body::Bytes, axum::Error>> + Unpin,
{
    let mut acc = String::new();
    let needle = format!("event: {kind}\n");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !acc.contains(&needle) {
        let chunk = tokio::time::timeout_at(deadline, stream.next())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {kind}; got:\n{acc}"))
            .expect("stream ended")
            .expect("stream error");
        acc.push_str(&String::from_utf8_lossy(&chunk));
    }
    acc
}

fn frame_data(acc: &str, kind: &str) -> Value {
    let needle = format!("event: {kind}\n");
    let start = acc.rfind(&needle).unwrap() + needle.len();
    let line = acc[start..]
        .lines()
        .find(|l| l.starts_with("data: "))
        .unwrap();
    serde_json::from_str(&line["data: ".len()..]).unwrap()
}

#[tokio::test]
async fn sse_emits_additive_console_kinds_and_filters_private() {
    // No API key configured: the stream is open and anonymous.
    let state = make_state(None, ConsoleState::default());
    let app = create_router(state.clone());
    state
        .console
        .reconcile(&state.job_store, &state.cluster)
        .await; // baseline

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut stream = resp.into_body().into_data_stream();
    let initial = read_until(&mut stream, "cluster").await;
    assert!(initial.contains("event: queue\n") && initial.contains("event: jobs\n"));

    // Private repository events never reach anonymous subscribers.
    post_webhook(
        &app,
        "create",
        json!({"ref": "feat/hidden", "ref_type": "branch",
               "repository": repo_obj("LMA1980/top-secret", true), "sender": {"login": "LMA1980"}}),
    )
    .await;
    let full = "LMA1980/sse-public";
    post_webhook(
        &app,
        "create",
        json!({"ref": "feat/sse", "ref_type": "branch",
               "repository": repo_obj(full, false), "sender": {"login": "LMA1980"}}),
    )
    .await;
    let acc = read_until(&mut stream, "branch_created").await;
    assert!(!acc.contains("top-secret"), "private event leaked: {acc}");
    let created = frame_data(&acc, "branch_created");
    assert_eq!(created["repo"], "sse-public");
    assert_eq!(created["ref"], "feat/sse");
    let rev1 = created["fabric_rev"].as_u64().unwrap();

    post_webhook(
        &app,
        "pull_request",
        json!({"action": "opened", "number": 11,
               "repository": repo_obj(full, false), "sender": {"login": "LMA1980"},
               "pull_request": {"number": 11, "author_association": "OWNER",
                   "head": {"ref": "feat/sse", "sha": "9999999999999999999999999999999999999999",
                            "repo": {"full_name": full}},
                   "base": {"ref": "main", "repo": {"full_name": full}}}}),
    )
    .await;
    let acc = read_until(&mut stream, "pr_state_changed").await;
    let pr = frame_data(&acc, "pr_state_changed");
    assert_eq!(pr["pr_state"], "open");
    assert_eq!(pr["previous_state"], "none");
    assert_eq!(pr["pr_number"], 11);
    assert!(pr["fabric_rev"].as_u64().unwrap() > rev1);

    post_webhook(
        &app,
        "delete",
        json!({"ref": "feat/sse", "ref_type": "branch",
               "repository": repo_obj(full, false), "sender": {"login": "LMA1980"}}),
    )
    .await;
    let acc = read_until(&mut stream, "branch_deleted").await;
    assert_eq!(frame_data(&acc, "branch_deleted")["ref"], "feat/sse");

    // job_stage_changed from the reconciler.
    completed_job(
        &state.job_store,
        "job-sse-stage",
        full,
        "refs/heads/main",
        "abababababababababababababababababababab",
        1,
        None,
    )
    .await;
    state
        .job_store
        .set_stages(
            "job-sse-stage",
            vec![StageRecord {
                id: "fmt".to_string(),
                name: "FMT".to_string(),
                tags: vec![],
                threads: 2,
                toolchain: None,
                depends_on: vec![],
                status: StageStatus::Pending,
                assigned_node: None,
                exclusive: false,
                skip_if_unavailable: false,
                skip_reason_code: None,
                skip_capability: None,
            }],
        )
        .await;
    state
        .console
        .reconcile(&state.job_store, &state.cluster)
        .await;
    state
        .job_store
        .update_stage_status(
            "job-sse-stage",
            "fmt",
            StageStatus::Running {
                node_id: "node-a".to_string(),
                started_at: Utc::now(),
                pid: None,
            },
        )
        .await;
    state
        .console
        .reconcile(&state.job_store, &state.cluster)
        .await;
    let acc = read_until(&mut stream, "job_stage_changed").await;
    let st = frame_data(&acc, "job_stage_changed");
    assert_eq!(st["job_id"], "job-sse-stage");
    assert_eq!(st["stage"], "fmt");
    assert_eq!(st["state"], "running");
    assert_eq!(st["previous_state"], "pending");
    assert_eq!(st["node_id"], "node-a");

    // node_membership_changed on worker join.
    let (cmd_tx, _cmd_rx) = tokio::sync::mpsc::channel(4);
    state
        .cluster
        .register(
            mu_ci_ipc::WorkerRegistration {
                node_id: "worker-riscv64".to_string(),
                arch: "riscv64".to_string(),
                tags: vec!["k3".to_string()],
                max_slots: 1,
                ram_total_mb: 1024,
                btrfs_enabled: false,
                toolchains: vec!["system".to_string()],
                rust_semver: None,
            },
            cmd_tx,
        )
        .await;
    state
        .console
        .reconcile(&state.job_store, &state.cluster)
        .await;
    let acc = read_until(&mut stream, "node_membership_changed").await;
    let nm = frame_data(&acc, "node_membership_changed");
    assert_eq!(nm["node_id"], "worker-riscv64");
    assert_eq!(nm["change"], "joined");
    assert_eq!(nm["online_nodes"], json!(["worker-riscv64"]));
}

#[tokio::test]
async fn sse_private_events_reach_authenticated_streams() {
    let state = make_state(Some(API_KEY), ConsoleState::default());
    let app = create_router(state.clone());
    // Existing behaviour unchanged: a configured key is required for the stream.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/events?token={API_KEY}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut stream = resp.into_body().into_data_stream();
    read_until(&mut stream, "cluster").await;
    post_webhook(
        &app,
        "create",
        json!({"ref": "feat/hidden", "ref_type": "branch",
               "repository": repo_obj("LMA1980/top-secret", true), "sender": {"login": "LMA1980"}}),
    )
    .await;
    let acc = read_until(&mut stream, "branch_created").await;
    assert_eq!(frame_data(&acc, "branch_created")["repo"], "top-secret");
}

#[tokio::test]
async fn registry_cache_survives_restart_and_keeps_fabric_rev_monotonic() {
    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("console_registry.json");
    let cfg = || ConsoleConfig {
        cache_file: Some(cache.clone()),
        ..ConsoleConfig::default()
    };
    let store = JobStore::new(10, None);
    let console = ConsoleState::new(cfg());
    console
        .observe_webhook(
            "create",
            &json!({"ref": "feat/persist", "ref_type": "branch",
                    "repository": repo_obj("LMA1980/cached", false)}),
            &store,
        )
        .await;
    let rev = console.fabric_rev().await;
    assert!(rev >= 1);

    let restarted = ConsoleState::new(cfg());
    assert_eq!(restarted.fabric_rev().await, rev);
    let entry = restarted.entry("LMA1980", "cached").await.unwrap();
    assert!(entry.branches.contains_key("feat/persist"));
}

// ============================================================================
// Milestone 7 (#89-#100): Invite-Only GitHub Operator Auth & Route Gating Tests
// ============================================================================

const PROXY_SECRET: &str = "trusted-proxy-secret-m7";
const INVITE_KEY: &str = "invite-hmac-signing-key-m7";

async fn seeded_auth_state() -> (Arc<AppState>, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let api = spawn_github_mock().await;
    let console = ConsoleState::new(ConsoleConfig {
        github_api_url: Some(api),
        ..ConsoleConfig::default()
    });
    for r in ["parent", "child", "secret-lib", "private-parent"] {
        console.refresh_repo("LMA1980", r, None).await;
    }

    let mut cfg = test_config(Some(API_KEY));
    cfg.workspace_dir = tmp.path().to_path_buf();
    cfg.proxy_secret = Some(PROXY_SECRET.to_string());
    cfg.invite_signing_key = Some(INVITE_KEY.to_string());
    cfg.bootstrap_admins = vec!["LMA1980".to_string()];

    let job_store = JobStore::from_config(100, &cfg);
    let (tx, _rx) = tokio::sync::mpsc::channel(64);
    let (log_broadcaster, _) = tokio::sync::broadcast::channel(128);
    let state = Arc::new(AppState {
        config: cfg,
        job_store,
        cluster: ClusterRegistry::new(),
        tx,
        log_broadcaster,
        console,
    });
    (state, tmp)
}

async fn send_req_with_cookie(
    app: &Router,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> (StatusCode, Value, String, Option<String>) {
    let mut builder = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let req_body = match body {
        Some(v) => {
            builder = builder.header("content-type", "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    let resp = app
        .clone()
        .oneshot(builder.body(req_body).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let elevated_cookie = resp
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|raw| {
            let pair = raw.split(';').next()?.trim();
            pair.starts_with("__Host-mu_elevated=")
                .then(|| pair.to_string())
        });
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&bytes).to_string();
    let json_val = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json_val, text, elevated_cookie)
}

async fn send_req(
    app: &Router,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> (StatusCode, Value, String) {
    let (st, j, text, _) = send_req_with_cookie(app, method, uri, headers, body).await;
    (st, j, text)
}

struct TestVirtualAuthenticator {
    rp_id: String,
    origin: String,
    cred_id: Vec<u8>,
    signing_key: P256SigningKey,
    pub_x: Vec<u8>,
    pub_y: Vec<u8>,
    backup_eligible: bool,
    backup_state: bool,
    sign_count: u32,
}

impl TestVirtualAuthenticator {
    fn new_synced(seed_byte: u8, cred_tag: &[u8]) -> Self {
        let mut secret = [0u8; 32];
        for (idx, b) in secret.iter_mut().enumerate() {
            *b = seed_byte.wrapping_add((idx as u8).wrapping_mul(17)).max(1);
        }
        let signing_key = P256SigningKey::from_slice(&secret).expect("valid p256 seed");
        let point = signing_key.verifying_key().to_sec1_point(false);
        let pub_x = point.x().expect("x coord").to_vec();
        let pub_y = point.y().expect("y coord").to_vec();
        Self {
            rp_id: "localhost".to_string(),
            origin: "http://localhost".to_string(),
            cred_id: cred_tag.to_vec(),
            signing_key,
            pub_x,
            pub_y,
            backup_eligible: true,
            backup_state: true,
            sign_count: 0,
        }
    }

    fn create_registration_response(&self, challenge_bytes: &[u8]) -> RegisterPublicKeyCredential {
        let mut flags: u8 = 0x01 | 0x04 | 0x40; // UP | UV | AT
        if self.backup_eligible {
            flags |= 0x08;
        }
        if self.backup_state {
            flags |= 0x10;
        }

        let rp_id_hash = Sha256::digest(self.rp_id.as_bytes());
        let mut cose_map = BTreeMap::new();
        cose_map.insert(CborValue::Integer(1), CborValue::Integer(2)); // kty = EC2
        cose_map.insert(CborValue::Integer(3), CborValue::Integer(-7)); // alg = ES256
        cose_map.insert(CborValue::Integer(-1), CborValue::Integer(1)); // crv = P-256
        cose_map.insert(CborValue::Integer(-2), CborValue::Bytes(self.pub_x.clone()));
        cose_map.insert(CborValue::Integer(-3), CborValue::Bytes(self.pub_y.clone()));
        let cose_cbor = serde_cbor_2::to_vec(&CborValue::Map(cose_map)).unwrap();

        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&rp_id_hash);
        auth_data.push(flags);
        auth_data.extend_from_slice(&self.sign_count.to_be_bytes());
        auth_data.extend_from_slice(&[0u8; 16]);
        auth_data.extend_from_slice(&(self.cred_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&self.cred_id);
        auth_data.extend_from_slice(&cose_cbor);

        let mut att_obj = BTreeMap::new();
        att_obj.insert(
            CborValue::Text("fmt".into()),
            CborValue::Text("none".into()),
        );
        att_obj.insert(
            CborValue::Text("attStmt".into()),
            CborValue::Map(BTreeMap::new()),
        );
        att_obj.insert(
            CborValue::Text("authData".into()),
            CborValue::Bytes(auth_data),
        );
        let attestation_object = serde_cbor_2::to_vec(&CborValue::Map(att_obj)).unwrap();

        let client_data = json!({
            "type": "webauthn.create",
            "challenge": URL_SAFE_NO_PAD.encode(challenge_bytes),
            "origin": self.origin,
            "crossOrigin": false,
        });
        let client_data_json = serde_json::to_vec(&client_data).unwrap();

        RegisterPublicKeyCredential {
            id: URL_SAFE_NO_PAD.encode(&self.cred_id),
            raw_id: self.cred_id.clone(),
            response: AuthenticatorAttestationResponseRaw {
                attestation_object,
                client_data_json,
                transports: None,
            },
            type_: "public-key".into(),
            extensions: Default::default(),
        }
    }

    fn create_assertion_response(
        &self,
        challenge_bytes: &[u8],
        sign_count: u32,
    ) -> PublicKeyCredential {
        let mut flags: u8 = 0x01 | 0x04; // UP | UV
        if self.backup_eligible {
            flags |= 0x08;
        }
        if self.backup_state {
            flags |= 0x10;
        }

        let rp_id_hash = Sha256::digest(self.rp_id.as_bytes());
        let mut auth_data = Vec::with_capacity(37);
        auth_data.extend_from_slice(&rp_id_hash);
        auth_data.push(flags);
        auth_data.extend_from_slice(&sign_count.to_be_bytes());

        let client_data = json!({
            "type": "webauthn.get",
            "challenge": URL_SAFE_NO_PAD.encode(challenge_bytes),
            "origin": self.origin,
            "crossOrigin": false,
        });
        let client_data_json = serde_json::to_vec(&client_data).unwrap();
        let client_data_hash = Sha256::digest(&client_data_json);

        let mut signed_msg = Vec::with_capacity(auth_data.len() + client_data_hash.len());
        signed_msg.extend_from_slice(&auth_data);
        signed_msg.extend_from_slice(&client_data_hash);

        let sig: P256Signature = self.signing_key.sign(&signed_msg);
        let der_sig = sig.to_der().as_ref().to_vec();

        PublicKeyCredential {
            id: URL_SAFE_NO_PAD.encode(&self.cred_id),
            raw_id: self.cred_id.clone(),
            response: AuthenticatorAssertionResponseRaw {
                authenticator_data: auth_data,
                client_data_json,
                signature: der_sig,
                user_handle: None,
            },
            extensions: Default::default(),
            type_: "public-key".into(),
        }
    }
}

async fn enroll_first_passkey(
    app: &Router,
    hdrs: &[(&str, &str)],
    auth: &TestVirtualAuthenticator,
    label: &str,
) {
    let (st_start, start_json, start_text) = send_req(
        app,
        "POST",
        "/api/auth/passkeys/register/start",
        hdrs,
        Some(json!({ "label": label })),
    )
    .await;
    assert_eq!(
        st_start,
        StatusCode::OK,
        "register/start failed: {st_start} {start_text}"
    );
    let challenge_id = start_json["challenge_id"].as_str().unwrap().to_string();
    let challenge_b64 = start_json["options"]["publicKey"]["challenge"]
        .as_str()
        .unwrap();
    let challenge_bytes = URL_SAFE_NO_PAD.decode(challenge_b64).unwrap();
    let cred = auth.create_registration_response(&challenge_bytes);

    let (st_fin, fin_json, fin_text) = send_req(
        app,
        "POST",
        "/api/auth/passkeys/register/finish",
        hdrs,
        Some(json!({
            "challenge_id": challenge_id,
            "credential": cred,
            "label": label,
        })),
    )
    .await;
    assert_eq!(
        st_fin,
        StatusCode::OK,
        "register/finish failed: {st_fin} {fin_text}"
    );
    assert_eq!(fin_json["session"]["passkey_enrollment_required"], false);
    assert_eq!(fin_json["session"]["role"], "operator");
}

async fn elevate_admin_with_passkey(
    app: &Router,
    hdrs: &[(&str, &str)],
    auth: &TestVirtualAuthenticator,
) -> String {
    let (st_start, start_json, start_text) = send_req(
        app,
        "POST",
        "/api/auth/elevate/start",
        hdrs,
        Some(json!({ "role_id": "platform-admin" })),
    )
    .await;
    assert_eq!(
        st_start,
        StatusCode::OK,
        "elevate/start failed: {st_start} {start_text}"
    );
    let challenge_id = start_json["challenge_id"].as_str().unwrap().to_string();
    let challenge_b64 = start_json["options"]["publicKey"]["challenge"]
        .as_str()
        .unwrap();
    let challenge_bytes = URL_SAFE_NO_PAD.decode(challenge_b64).unwrap();
    let cred = auth.create_assertion_response(&challenge_bytes, auth.sign_count);

    let (st_fin, fin_json, fin_text, cookie_opt) = send_req_with_cookie(
        app,
        "POST",
        "/api/auth/elevate/finish",
        hdrs,
        Some(json!({
            "challenge_id": challenge_id,
            "credential": cred,
            "role_id": "platform-admin",
        })),
    )
    .await;
    assert_eq!(
        st_fin,
        StatusCode::OK,
        "elevate/finish failed: {st_fin} {fin_text}"
    );
    assert_eq!(fin_json["elevated"], true);
    assert_eq!(fin_json["session"]["role"], "platform-admin");
    cookie_opt.expect("elevate/finish must set __Host-mu_elevated cookie")
}

#[tokio::test]
async fn invite_lifecycle_single_use_redemption_replay_expiry_and_revocation() {
    let (state, _tmp) = seeded_auth_state().await;
    completed_job(
        &state.job_store,
        "job-m7-1",
        "LMA1980/parent",
        "refs/heads/main",
        "1234567890abcdef1234567890abcdef12345678",
        5,
        None,
    )
    .await;
    state
        .job_store
        .append_job_log("job-m7-1", "[stdout] cargo test passed\n");
    let app = create_router(state.clone());

    // 1. Header spoofing without X-Proxy-Secret is rejected as Anonymous (401 on /log and /restart)
    let (st, j, _) = send_req(
        &app,
        "GET",
        "/api/auth/session",
        &[("X-Forwarded-User", "LMA1980")],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(j["authenticated"], false);
    assert_eq!(j["github_login"], Value::Null);
    assert_eq!(j["invite_bound"], false);

    let (st, _, _) = send_req(
        &app,
        "GET",
        "/api/jobs/job-m7-1/log",
        &[("X-Forwarded-User", "LMA1980")],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    let (st, _, _) = send_req(
        &app,
        "POST",
        "/api/jobs/job-m7-1/restart",
        &[("X-Forwarded-User", "LMA1980")],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    // 2. Uninvited GitHub user with valid X-Proxy-Secret gets 200 (invite_bound: false) on /api/auth/session,
    //    and 403 Forbidden with generic AuthorizationDenied (zero invite hints) on protected endpoints.
    let uninvited_hdrs = [
        ("X-Proxy-Secret", PROXY_SECRET),
        ("X-Forwarded-User", "random-github-user"),
    ];
    let (st, j, _) = send_req(&app, "GET", "/api/auth/session", &uninvited_hdrs, None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(j["authenticated"], false);
    assert_eq!(j["github_login"], "random-github-user");
    assert_eq!(j["invite_bound"], false);
    assert_eq!(j["role"], Value::Null);
    assert_eq!(j["reason_code"], "authorization_denied");

    for (method, path) in [
        ("GET", "/api/jobs/job-m7-1/log"),
        ("GET", "/jobs/job-m7-1/logs"),
        ("GET", "/api/jobs/job-m7-1/events"),
        ("POST", "/api/jobs/job-m7-1/restart"),
        ("POST", "/api/jobs/job-m7-1/resume"),
        ("POST", "/api/ha/promote"),
        ("POST", "/api/ha/demote"),
    ] {
        let (st, j, body_text) = send_req(&app, method, path, &uninvited_hdrs, None).await;
        assert_eq!(st, StatusCode::FORBIDDEN, "expected 403 on {method} {path}");
        assert_eq!(j["reason_code"], "authorization_denied");
        assert!(
            !body_text.to_ascii_lowercase().contains("invite"),
            "protected denial must not leak invite onboarding hints: {body_text}"
        );
    }

    // Uninvited user cannot create invites (403)
    let (st, _, _) = send_req(
        &app,
        "POST",
        "/api/auth/invites",
        &uninvited_hdrs,
        Some(json!({"note": "attempt"})),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // 3. Bootstrap admin ("LMA1980") starts at 0 Passkeys (withheld baseline console access until enrolled),
    //    enrolls Passkey to become active baseline "operator", and steps up to timed "platform-admin" to issue invites.
    let admin_hdrs = [
        ("X-Proxy-Secret", PROXY_SECRET),
        ("X-Forwarded-User", "LMA1980"),
    ];
    let (st, j, _) = send_req(&app, "GET", "/api/auth/session", &admin_hdrs, None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(j["authenticated"], true);
    assert_eq!(j["github_login"], "LMA1980");
    assert_eq!(j["invite_bound"], true);
    assert_eq!(j["passkey_enrollment_required"], true);
    assert_eq!(j["passkey_count"], 0);
    assert_eq!(j["role"], Value::Null);

    let admin_auth = TestVirtualAuthenticator::new_synced(11, b"cred-admin-lma");
    enroll_first_passkey(&app, &admin_hdrs, &admin_auth, "Admin 1Password").await;

    // Dormant platform-admin cannot create invites until step-up elevation completes
    let (st_pre_elev, _, _) = send_req(
        &app,
        "POST",
        "/api/auth/invites",
        &admin_hdrs,
        Some(json!({ "note": "pre-elevation" })),
    )
    .await;
    assert_eq!(st_pre_elev, StatusCode::FORBIDDEN);

    let admin_cookie = elevate_admin_with_passkey(&app, &admin_hdrs, &admin_auth).await;
    let admin_elevated_hdrs = [
        ("X-Proxy-Secret", PROXY_SECRET),
        ("X-Forwarded-User", "LMA1980"),
        ("Cookie", admin_cookie.as_str()),
    ];

    let (st, inv_resp, _) = send_req(
        &app,
        "POST",
        "/api/auth/invites",
        &admin_elevated_hdrs,
        Some(json!({
            "ttl_seconds": 3600,
            "note": "Operator onboarding",
            "base_url": "https://console.lma1980.duckdns.org"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let invite_id = inv_resp["invite_id"].as_str().unwrap().to_string();
    let invite_token = inv_resp["invite_token"].as_str().unwrap().to_string();
    let invite_url = inv_resp["invite_url"].as_str().unwrap().to_string();
    assert!(invite_token.starts_with(&format!("inv_{invite_id}.")));
    assert_eq!(
        invite_url,
        format!("https://console.lma1980.duckdns.org/#redeem={invite_token}")
    );
    assert_eq!(inv_resp["granted_role"], "operator");

    // 4. Tampered HMAC signature on /api/auth/redeem is rejected with 401
    let tampered_token =
        format!("inv_{invite_id}.ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    let (st, _, _) = send_req(
        &app,
        "POST",
        "/api/auth/redeem",
        &uninvited_hdrs,
        Some(json!({ "invite_token": tampered_token })),
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    // 5. Valid single-use redemption binds "random-github-user" strictly as PinnedBaseline ("operator") at 0 Passkeys
    let (st, redeem_json, _) = send_req(
        &app,
        "POST",
        "/api/auth/redeem",
        &uninvited_hdrs,
        Some(json!({ "invite_token": invite_token })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(redeem_json["authenticated"], true);
    assert_eq!(redeem_json["github_login"], "random-github-user");
    assert_eq!(redeem_json["invite_bound"], true);
    assert_eq!(redeem_json["baseline_role"], "operator");
    assert_eq!(redeem_json["passkey_enrollment_required"], true);
    assert_eq!(redeem_json["passkey_count"], 0);
    assert_eq!(redeem_json["role"], Value::Null);

    // 6. Replay of the already-used invite token returns 409 Conflict
    let second_user_hdrs = [
        ("X-Proxy-Secret", PROXY_SECRET),
        ("X-Forwarded-User", "second-user"),
    ];
    let (st, replay_json, _) = send_req(
        &app,
        "POST",
        "/api/auth/redeem",
        &second_user_hdrs,
        Some(json!({ "invite_token": invite_token })),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT);
    assert!(replay_json["error"]
        .as_str()
        .unwrap_or("")
        .contains("already been used"));

    // 7. At 0 Passkeys, baseline /log is withheld with 403 passkey_enrollment_required.
    let (st_0pk, j_0pk, _) =
        send_req(&app, "GET", "/api/jobs/job-m7-1/log", &uninvited_hdrs, None).await;
    assert_eq!(st_0pk, StatusCode::FORBIDDEN);
    assert_eq!(j_0pk["reason_code"], "passkey_enrollment_required");

    // Once enrolled, bound "operator" accesses /log and private repos, while job /restart requires "ci-operator"
    let user_auth = TestVirtualAuthenticator::new_synced(22, b"cred-random-operator");
    enroll_first_passkey(&app, &uninvited_hdrs, &user_auth, "User Passkey").await;

    let (st, _, log_text) =
        send_req(&app, "GET", "/api/jobs/job-m7-1/log", &uninvited_hdrs, None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(log_text.contains("cargo test passed"));

    let (st_pre_ci, j_pre_ci, _) = send_req(
        &app,
        "POST",
        "/api/jobs/job-m7-1/restart",
        &uninvited_hdrs,
        None,
    )
    .await;
    assert_eq!(st_pre_ci, StatusCode::FORBIDDEN);
    assert_eq!(j_pre_ci["reason_code"], "authorization_denied");

    // Elevated platform-admin binds elective "ci-operator", user enables it -> /restart -> 200 OK
    let (st_grant, _, grant_text) = send_req(
        &app,
        "PUT",
        "/api/auth/users/random-github-user/roles",
        &admin_elevated_hdrs,
        Some(json!({ "bound_roles": ["operator", "ci-operator"] })),
    )
    .await;
    assert_eq!(st_grant, StatusCode::OK, "role grant failed: {grant_text}");

    let (st_enable, _, enable_text) = send_req(
        &app,
        "POST",
        "/api/auth/roles/ci-operator/enable",
        &uninvited_hdrs,
        Some(json!({})),
    )
    .await;
    assert_eq!(st_enable, StatusCode::OK, "enable failed: {enable_text}");

    let (st, restart_json, _) = send_req(
        &app,
        "POST",
        "/api/jobs/job-m7-1/restart",
        &uninvited_hdrs,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(restart_json["status"], "ok");

    let (st, repos_json, _) = send_req(&app, "GET", "/api/repos", &uninvited_hdrs, None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(repos_json["authenticated"], true);
    assert!(
        find_repo(&repos_json, "secret-lib").is_some(),
        "bound operator must see private repos"
    );

    // 8. Expired invite token rejection (410 Gone)
    let (st, exp_inv, _) = send_req(
        &app,
        "POST",
        "/api/auth/invites",
        &[("Authorization", &format!("Bearer {API_KEY}"))],
        Some(json!({ "ttl_seconds": 0, "note": "expired-immediately" })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let exp_token = exp_inv["invite_token"].as_str().unwrap().to_string();
    let (st, exp_err, _) = send_req(
        &app,
        "POST",
        "/api/auth/redeem",
        &second_user_hdrs,
        Some(json!({ "invite_token": exp_token })),
    )
    .await;
    assert_eq!(st, StatusCode::GONE);
    assert!(exp_err["error"].as_str().unwrap_or("").contains("expired"));

    // 9. GET /api/auth/invites lists invites without raw tokens + bound users
    let (st, list_inv, _) =
        send_req(&app, "GET", "/api/auth/invites", &admin_elevated_hdrs, None).await;
    assert_eq!(st, StatusCode::OK);
    let invites_arr = list_inv["invites"].as_array().unwrap();
    assert_eq!(invites_arr.len(), 2);
    assert!(invites_arr[0].get("invite_token").is_none());
    assert!(invites_arr[0].get("token_hmac").is_none());
    let used_entry = invites_arr
        .iter()
        .find(|i| i["invite_id"] == invite_id)
        .unwrap();
    assert_eq!(used_entry["used_by_github_login"], "random-github-user");

    // 10. Revoke user via DELETE /api/auth/users/{github_login} -> subsequent requests return 403
    let (st, rev_json, _) = send_req(
        &app,
        "DELETE",
        "/api/auth/users/random-github-user",
        &admin_elevated_hdrs,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(rev_json["revoked"], true);

    let (st, sess_after, _) =
        send_req(&app, "GET", "/api/auth/session", &uninvited_hdrs, None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(sess_after["authenticated"], false);
    assert_eq!(sess_after["invite_bound"], false);
    assert_eq!(sess_after["reason_code"], "authorization_denied");

    let (st, _, _) = send_req(&app, "GET", "/api/jobs/job-m7-1/log", &uninvited_hdrs, None).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn invite_redemption_payload_token_compatibility() {
    let (state, _tmp) = seeded_auth_state().await;
    let app = create_router(state.clone());

    let bearer_auth = format!("Bearer {API_KEY}");
    let api_hdrs = [("Authorization", bearer_auth.as_str())];

    // Mint three invite tokens:
    // 1) For redemption using {"token": ...} (MuConsole web worker format)
    // 2) For redemption using {"invite_token": ...} (standard controller format)
    // 3) For redemption using {"token": ..., "invite_token": ...} (dual-field format)
    let (st1, inv_resp1, _) = send_req(
        &app,
        "POST",
        "/api/auth/invites",
        &api_hdrs,
        Some(json!({
            "ttl_seconds": 3600,
            "note": "MuConsole web worker invite (token field)",
            "base_url": "https://console.lma1980.duckdns.org"
        })),
    )
    .await;
    assert_eq!(st1, StatusCode::CREATED);
    let token1 = inv_resp1["invite_token"].as_str().unwrap().to_string();

    let (st2, inv_resp2, _) = send_req(
        &app,
        "POST",
        "/api/auth/invites",
        &api_hdrs,
        Some(json!({
            "ttl_seconds": 3600,
            "note": "Standard invite (invite_token field)",
            "base_url": "https://console.lma1980.duckdns.org"
        })),
    )
    .await;
    assert_eq!(st2, StatusCode::CREATED);
    let token2 = inv_resp2["invite_token"].as_str().unwrap().to_string();

    let (st3, inv_resp3, _) = send_req(
        &app,
        "POST",
        "/api/auth/invites",
        &api_hdrs,
        Some(json!({
            "ttl_seconds": 3600,
            "note": "Dual field invite (both token and invite_token)",
            "base_url": "https://console.lma1980.duckdns.org"
        })),
    )
    .await;
    assert_eq!(st3, StatusCode::CREATED);
    let token3 = inv_resp3["invite_token"].as_str().unwrap().to_string();

    // 1. Redeem using MuConsole payload format: {"token": token1}
    let user1_hdrs = [
        ("X-Proxy-Secret", PROXY_SECRET),
        ("X-Forwarded-User", "muconsole-user"),
    ];
    let (st_token, redeem_token_json, body_text) = send_req(
        &app,
        "POST",
        "/api/auth/redeem",
        &user1_hdrs,
        Some(json!({ "token": token1 })),
    )
    .await;
    assert_eq!(
        st_token,
        StatusCode::OK,
        "POST /api/auth/redeem must accept {{\"token\": ...}} payload matching MuConsole; got status {st_token}: {body_text}"
    );
    assert_eq!(redeem_token_json["authenticated"], true);
    assert_eq!(redeem_token_json["github_login"], "muconsole-user");
    assert_eq!(redeem_token_json["invite_bound"], true);
    assert_eq!(redeem_token_json["baseline_role"], "operator");
    assert_eq!(redeem_token_json["passkey_enrollment_required"], true);
    assert_eq!(redeem_token_json["passkey_count"], 0);

    // 2. Redeem using controller standard payload format: {"invite_token": token2}
    let user2_hdrs = [
        ("X-Proxy-Secret", PROXY_SECRET),
        ("X-Forwarded-User", "standard-user"),
    ];
    let (st_invite, redeem_invite_json, body_invite_text) = send_req(
        &app,
        "POST",
        "/api/auth/redeem",
        &user2_hdrs,
        Some(json!({ "invite_token": token2 })),
    )
    .await;
    assert_eq!(
        st_invite,
        StatusCode::OK,
        "POST /api/auth/redeem must accept {{\"invite_token\": ...}} payload; got status {st_invite}: {body_invite_text}"
    );
    assert_eq!(redeem_invite_json["authenticated"], true);
    assert_eq!(redeem_invite_json["github_login"], "standard-user");
    assert_eq!(redeem_invite_json["invite_bound"], true);
    assert_eq!(redeem_invite_json["baseline_role"], "operator");
    assert_eq!(redeem_invite_json["passkey_enrollment_required"], true);

    // 3. Redeem using dual field payload format: {"token": token3, "invite_token": token3}
    let user3_hdrs = [
        ("X-Proxy-Secret", PROXY_SECRET),
        ("X-Forwarded-User", "dual-user"),
    ];
    let (st_dual, redeem_dual_json, body_dual_text) = send_req(
        &app,
        "POST",
        "/api/auth/redeem",
        &user3_hdrs,
        Some(json!({
            "token": token3,
            "invite_token": token3,
        })),
    )
    .await;
    assert_eq!(
        st_dual,
        StatusCode::OK,
        "POST /api/auth/redeem must accept dual {{\"token\": ..., \"invite_token\": ...}} payload; got status {st_dual}: {body_dual_text}"
    );
    assert_eq!(redeem_dual_json["authenticated"], true);
    assert_eq!(redeem_dual_json["github_login"], "dual-user");
    assert_eq!(redeem_dual_json["invite_bound"], true);
    assert_eq!(redeem_dual_json["baseline_role"], "operator");
    assert_eq!(redeem_dual_json["passkey_enrollment_required"], true);

    // 4. Missing both fields produces 422 Unprocessable Entity
    let user4_hdrs = [
        ("X-Proxy-Secret", PROXY_SECRET),
        ("X-Forwarded-User", "missing-user"),
    ];
    let (st_missing, _, _) = send_req(
        &app,
        "POST",
        "/api/auth/redeem",
        &user4_hdrs,
        Some(json!({})),
    )
    .await;
    assert_eq!(
        st_missing,
        StatusCode::UNPROCESSABLE_ENTITY,
        "POST /api/auth/redeem without token or invite_token must return 422 Unprocessable Entity"
    );
}

#[tokio::test]
async fn session_resolution_anonymous_untrusted_uninvited_and_bound_operator() {
    let (state, _tmp) = seeded_auth_state().await;
    let app = create_router(state.clone());

    // 1. Anonymous caller with no headers -> unauthenticated anonymous
    let (st_anon, j_anon, _) = send_req(&app, "GET", "/api/auth/session", &[], None).await;
    assert_eq!(st_anon, StatusCode::OK);
    assert_eq!(j_anon["authenticated"], false);
    assert_eq!(j_anon["github_login"], Value::Null);
    assert_eq!(j_anon["invite_bound"], false);
    assert_eq!(j_anon["role"], Value::Null);

    // 2. Caller with X-Forwarded-User but WITHOUT X-Proxy-Secret -> unauthenticated anonymous (fails closed)
    let (st_spoof, j_spoof, _) = send_req(
        &app,
        "GET",
        "/api/auth/session",
        &[("X-Forwarded-User", "malicious-actor")],
        None,
    )
    .await;
    assert_eq!(st_spoof, StatusCode::OK);
    assert_eq!(j_spoof["authenticated"], false);
    assert_eq!(j_spoof["github_login"], Value::Null);
    assert_eq!(j_spoof["invite_bound"], false);
    assert_eq!(j_spoof["role"], Value::Null);

    // 3. Caller with INVALID X-Proxy-Secret -> unauthenticated anonymous (fails closed)
    let (st_wrong, j_wrong, _) = send_req(
        &app,
        "GET",
        "/api/auth/session",
        &[
            ("X-Proxy-Secret", "wrong-secret"),
            ("X-Forwarded-User", "malicious-actor"),
        ],
        None,
    )
    .await;
    assert_eq!(st_wrong, StatusCode::OK);
    assert_eq!(j_wrong["authenticated"], false);
    assert_eq!(j_wrong["github_login"], Value::Null);
    assert_eq!(j_wrong["invite_bound"], false);
    assert_eq!(j_wrong["role"], Value::Null);

    // 4. Caller with valid X-Proxy-Secret but EMPTY / whitespace X-Forwarded-User -> unauthenticated anonymous
    for empty_user in ["", "   ", "\t"] {
        let (st_empty, j_empty, _) = send_req(
            &app,
            "GET",
            "/api/auth/session",
            &[
                ("X-Proxy-Secret", PROXY_SECRET),
                ("X-Forwarded-User", empty_user),
            ],
            None,
        )
        .await;
        assert_eq!(st_empty, StatusCode::OK);
        assert_eq!(j_empty["authenticated"], false);
        assert_eq!(j_empty["github_login"], Value::Null);
        assert_eq!(j_empty["invite_bound"], false);
        assert_eq!(j_empty["role"], Value::Null);
    }

    // 5. Caller with valid X-Proxy-Secret + X-Forwarded-User NOT in auth_users -> UninvitedUser (generic denial)
    let (st_uninv, j_uninv, _) = send_req(
        &app,
        "GET",
        "/api/auth/session",
        &[
            ("X-Proxy-Secret", PROXY_SECRET),
            ("X-Forwarded-User", "uninvited-guest"),
        ],
        None,
    )
    .await;
    assert_eq!(st_uninv, StatusCode::OK);
    assert_eq!(j_uninv["authenticated"], false);
    assert_eq!(j_uninv["github_login"], "uninvited-guest");
    assert_eq!(j_uninv["invite_bound"], false);
    assert_eq!(j_uninv["role"], Value::Null);
    assert_eq!(j_uninv["reason_code"], "authorization_denied");

    // 6. Bootstrap admin ("LMA1980") starts with passkey_enrollment_required=true, becomes "operator" after enrollment,
    //    and elevates to timed "platform-admin" after Passkey assertion.
    let admin_hdrs = [
        ("X-Proxy-Secret", PROXY_SECRET),
        ("X-Forwarded-User", "LMA1980"),
    ];
    let (st_admin0, j_admin0, _) =
        send_req(&app, "GET", "/api/auth/session", &admin_hdrs, None).await;
    assert_eq!(st_admin0, StatusCode::OK);
    assert_eq!(j_admin0["authenticated"], true);
    assert_eq!(j_admin0["github_login"], "LMA1980");
    assert_eq!(j_admin0["invite_bound"], true);
    assert_eq!(j_admin0["passkey_enrollment_required"], true);
    assert_eq!(j_admin0["role"], Value::Null);

    let admin_auth = TestVirtualAuthenticator::new_synced(33, b"cred-sess-admin");
    enroll_first_passkey(&app, &admin_hdrs, &admin_auth, "Admin Passkey").await;
    let admin_cookie = elevate_admin_with_passkey(&app, &admin_hdrs, &admin_auth).await;
    let admin_elevated_hdrs = [
        ("X-Proxy-Secret", PROXY_SECRET),
        ("X-Forwarded-User", "LMA1980"),
        ("Cookie", admin_cookie.as_str()),
    ];

    let (st_admin, j_admin, _) =
        send_req(&app, "GET", "/api/auth/session", &admin_elevated_hdrs, None).await;
    assert_eq!(st_admin, StatusCode::OK);
    assert_eq!(j_admin["authenticated"], true);
    assert_eq!(j_admin["github_login"], "LMA1980");
    assert_eq!(j_admin["invite_bound"], true);
    assert_eq!(j_admin["role"], "platform-admin");

    // 7. Bound user via invite -> passkey enrollment required until Passkey enrolled -> active "operator"
    let (st_inv, inv_resp, _) = send_req(
        &app,
        "POST",
        "/api/auth/invites",
        &admin_elevated_hdrs,
        Some(json!({ "ttl_seconds": 3600, "note": "session resolution test" })),
    )
    .await;
    assert_eq!(st_inv, StatusCode::CREATED);
    let token = inv_resp["invite_token"].as_str().unwrap();

    let op_hdrs = [
        ("X-Proxy-Secret", PROXY_SECRET),
        ("X-Forwarded-User", "verified-operator"),
    ];
    let (st_red, j_red, _) = send_req(
        &app,
        "POST",
        "/api/auth/redeem",
        &op_hdrs,
        Some(json!({ "invite_token": token })),
    )
    .await;
    assert_eq!(st_red, StatusCode::OK);
    assert_eq!(j_red["passkey_enrollment_required"], true);

    let op_auth = TestVirtualAuthenticator::new_synced(44, b"cred-verified-op");
    enroll_first_passkey(&app, &op_hdrs, &op_auth, "Verified Operator Passkey").await;

    let (st_op, j_op, _) = send_req(&app, "GET", "/api/auth/session", &op_hdrs, None).await;
    assert_eq!(st_op, StatusCode::OK);
    assert_eq!(j_op["authenticated"], true);
    assert_eq!(j_op["github_login"], "verified-operator");
    assert_eq!(j_op["invite_bound"], true);
    assert_eq!(j_op["passkey_enrollment_required"], false);
    assert_eq!(j_op["passkey_count"], 1);
    assert_eq!(j_op["role"], "operator");
}

#[tokio::test]
async fn redeem_invite_unauthorized_when_anonymous_spoofed_or_empty_forwarded_user() {
    let (state, _tmp) = seeded_auth_state().await;
    let app = create_router(state.clone());

    let bearer_auth = format!("Bearer {API_KEY}");
    // Mint a valid invite token via configured admin API key
    let (st_inv, inv_resp, _) = send_req(
        &app,
        "POST",
        "/api/auth/invites",
        &[("Authorization", bearer_auth.as_str())],
        Some(json!({ "ttl_seconds": 3600, "note": "unauthorized redemption test" })),
    )
    .await;
    assert_eq!(st_inv, StatusCode::CREATED);
    let valid_token = inv_resp["invite_token"].as_str().unwrap();
    let redeem_body = json!({ "invite_token": valid_token });

    // 1. Anonymous caller (no headers) -> 401 Unauthorized
    let (st, body, text) = send_req(
        &app,
        "POST",
        "/api/auth/redeem",
        &[],
        Some(redeem_body.clone()),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::UNAUTHORIZED,
        "Anonymous caller must receive 401; got {st}: {text}"
    );
    assert!(
        body["error"]
            .as_str()
            .unwrap_or("")
            .contains("valid X-Proxy-Secret and X-Forwarded-User headers required"),
        "error message must cite required proxy headers: {text}"
    );

    // 2. Caller with X-Forwarded-User but NO X-Proxy-Secret (spoofed header) -> 401 Unauthorized
    let (st, body, text) = send_req(
        &app,
        "POST",
        "/api/auth/redeem",
        &[("X-Forwarded-User", "attacker")],
        Some(redeem_body.clone()),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::UNAUTHORIZED,
        "Spoofed header without proxy secret must receive 401; got {st}: {text}"
    );
    assert!(body["error"]
        .as_str()
        .unwrap_or("")
        .contains("valid X-Proxy-Secret and X-Forwarded-User headers required"));

    // 3. Caller with INVALID X-Proxy-Secret -> 401 Unauthorized
    let (st, body, text) = send_req(
        &app,
        "POST",
        "/api/auth/redeem",
        &[
            ("X-Proxy-Secret", "wrong-secret-token"),
            ("X-Forwarded-User", "attacker"),
        ],
        Some(redeem_body.clone()),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::UNAUTHORIZED,
        "Invalid proxy secret must receive 401; got {st}: {text}"
    );
    assert!(body["error"]
        .as_str()
        .unwrap_or("")
        .contains("valid X-Proxy-Secret and X-Forwarded-User headers required"));

    // 4. Caller with valid X-Proxy-Secret but MISSING X-Forwarded-User -> 401 Unauthorized
    let (st, body, text) = send_req(
        &app,
        "POST",
        "/api/auth/redeem",
        &[("X-Proxy-Secret", PROXY_SECRET)],
        Some(redeem_body.clone()),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::UNAUTHORIZED,
        "Missing X-Forwarded-User must receive 401; got {st}: {text}"
    );
    assert!(body["error"]
        .as_str()
        .unwrap_or("")
        .contains("valid X-Proxy-Secret and X-Forwarded-User headers required"));

    // 5. Caller with valid X-Proxy-Secret but EMPTY X-Forwarded-User -> 401 Unauthorized
    let (st, body, text) = send_req(
        &app,
        "POST",
        "/api/auth/redeem",
        &[("X-Proxy-Secret", PROXY_SECRET), ("X-Forwarded-User", "")],
        Some(redeem_body.clone()),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::UNAUTHORIZED,
        "Empty X-Forwarded-User must receive 401; got {st}: {text}"
    );
    assert!(body["error"]
        .as_str()
        .unwrap_or("")
        .contains("valid X-Proxy-Secret and X-Forwarded-User headers required"));

    // 6. Caller with valid X-Proxy-Secret but whitespace-only X-Forwarded-User -> 401 Unauthorized
    let (st, body, text) = send_req(
        &app,
        "POST",
        "/api/auth/redeem",
        &[
            ("X-Proxy-Secret", PROXY_SECRET),
            ("X-Forwarded-User", "   \t  "),
        ],
        Some(redeem_body.clone()),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::UNAUTHORIZED,
        "Whitespace X-Forwarded-User must receive 401; got {st}: {text}"
    );
    assert!(body["error"]
        .as_str()
        .unwrap_or("")
        .contains("valid X-Proxy-Secret and X-Forwarded-User headers required"));

    // 7. Caller with admin API key in Bearer token (no proxy headers) -> 401 Unauthorized
    let (st, body, text) = send_req(
        &app,
        "POST",
        "/api/auth/redeem",
        &[("Authorization", &format!("Bearer {API_KEY}"))],
        Some(redeem_body.clone()),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::UNAUTHORIZED,
        "Admin API key without proxy headers must receive 401; got {st}: {text}"
    );
    assert!(body["error"]
        .as_str()
        .unwrap_or("")
        .contains("valid X-Proxy-Secret and X-Forwarded-User headers required"));
}

#[tokio::test]
async fn redeem_invite_valid_token_binds_user_and_grants_operator_role() {
    let (state, _tmp) = seeded_auth_state().await;
    let app = create_router(state.clone());

    let bearer_auth = format!("Bearer {API_KEY}");
    // 1. Issue a valid invite
    let (st_inv, inv_resp, _) = send_req(
        &app,
        "POST",
        "/api/auth/invites",
        &[("Authorization", bearer_auth.as_str())],
        Some(json!({
            "ttl_seconds": 3600,
            "note": "Onboarding test candidate",
            "base_url": "https://console.lma1980.duckdns.org"
        })),
    )
    .await;
    assert_eq!(st_inv, StatusCode::CREATED);
    let invite_token = inv_resp["invite_token"].as_str().unwrap().to_string();

    let candidate_hdrs = [
        ("X-Proxy-Secret", PROXY_SECRET),
        ("X-Forwarded-User", "new-operator-alice"),
    ];

    // 2. Pre-condition: Candidate is currently UninvitedUser (authenticated: false, invite_bound: false)
    let (st_pre, j_pre, _) =
        send_req(&app, "GET", "/api/auth/session", &candidate_hdrs, None).await;
    assert_eq!(st_pre, StatusCode::OK);
    assert_eq!(j_pre["authenticated"], false);
    assert_eq!(j_pre["github_login"], "new-operator-alice");
    assert_eq!(j_pre["invite_bound"], false);
    assert_eq!(j_pre["role"], Value::Null);

    // 3. Redeem the valid invite token -> 200 OK binding PinnedBaseline ("operator") with 0-Passkey enrollment gate
    let (st_redeem, j_redeem, text_redeem) = send_req(
        &app,
        "POST",
        "/api/auth/redeem",
        &candidate_hdrs,
        Some(json!({ "invite_token": invite_token })),
    )
    .await;
    assert_eq!(
        st_redeem,
        StatusCode::OK,
        "Expected 200 OK on redemption; got {st_redeem}: {text_redeem}"
    );
    assert_eq!(j_redeem["authenticated"], true);
    assert_eq!(j_redeem["github_login"], "new-operator-alice");
    assert_eq!(j_redeem["invite_bound"], true);
    assert_eq!(j_redeem["baseline_role"], "operator");
    assert_eq!(j_redeem["passkey_enrollment_required"], true);
    assert_eq!(j_redeem["passkey_count"], 0);

    // 4. After enrolling a Passkey, candidate session resolution activates BoundUser ("operator")
    let alice_auth = TestVirtualAuthenticator::new_synced(55, b"cred-new-op-alice");
    enroll_first_passkey(&app, &candidate_hdrs, &alice_auth, "Alice Passkey").await;

    let (st_post, j_post, _) =
        send_req(&app, "GET", "/api/auth/session", &candidate_hdrs, None).await;
    assert_eq!(st_post, StatusCode::OK);
    assert_eq!(j_post["authenticated"], true);
    assert_eq!(j_post["github_login"], "new-operator-alice");
    assert_eq!(j_post["invite_bound"], true);
    assert_eq!(j_post["passkey_enrollment_required"], false);
    assert_eq!(j_post["role"], "operator");

    // 5. Replay attempt with same token fails with 409 Conflict
    let (st_replay, j_replay, text_replay) = send_req(
        &app,
        "POST",
        "/api/auth/redeem",
        &candidate_hdrs,
        Some(json!({ "invite_token": invite_token })),
    )
    .await;
    assert_eq!(
        st_replay,
        StatusCode::CONFLICT,
        "Replay must return 409 Conflict; got {st_replay}: {text_replay}"
    );
    assert!(j_replay["error"]
        .as_str()
        .unwrap_or("")
        .contains("already been used"));
}

#[tokio::test]
async fn anonymous_job_sse_streams_sanitized_log_init_and_shared_storage_deltas() {
    let state = seeded_state().await;
    let job_id = "job-live-sse-131";
    let job = Job {
        id: job_id.to_string(),
        event_type: "push".to_string(),
        repo_name: "LMA1980/parent".to_string(),
        clone_url: "https://github.com/LMA1980/parent.git".to_string(),
        commit_sha: SHA_CORE.to_string(),
        ref_name: "refs/heads/main".to_string(),
        sender: "LMA1980".to_string(),
        queued_at: Utc::now(),
        pr_number: None,
    };
    state
        .job_store
        .enqueue_job(job, PathBuf::from(format!("logs/{job_id}.log")))
        .await;
    state
        .job_store
        .update_status(
            job_id,
            JobStatus::Running {
                started_at: Utc::now(),
            },
        )
        .await;
    state.job_store.append_job_log(
        job_id,
        "[fmt] connected to worker-a.internal.local (192.0.2.42) with token ghp_secret12345\n",
    );

    let app = create_router(state.clone());
    // Anonymous caller (even though API_KEY is configured on `state`) must receive 200 OK SSE.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/jobs/{job_id}/events"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut stream = resp.into_body().into_data_stream();

    let init_acc = read_until(&mut stream, "log_init").await;
    assert!(
        init_acc.contains("event: job\n"),
        "expected initial job frame before log_init: {init_acc}"
    );
    let init_text = frame_data(&init_acc, "log_init")
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        init_text.contains("worker-a"),
        "expected hostname prefix preserved: {init_text}"
    );
    assert!(
        !init_text.contains(".internal.local"),
        "internal domain suffix must be stripped: {init_text}"
    );
    assert!(
        init_text.contains("192.0.###.42"),
        "private IPv4 third octet must be masked: {init_text}"
    );
    assert!(
        !init_text.contains("ghp_secret12345") && init_text.contains("[REDACTED]"),
        "GitHub token must be redacted for anonymous viewers: {init_text}"
    );

    // Append a delta solely via shared storage (`job_store.append_job_log`) without local file
    // or `log_broadcaster` emission, simulating cross-controller HA log tailing.
    state.job_store.append_job_log(
        job_id,
        "[clippy] finished on 10.20.30.40 Bearer secret-jwt-token\n",
    );

    let chunk_acc = read_until(&mut stream, "log_chunk").await;
    let chunk_text = frame_data(&chunk_acc, "log_chunk")
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        chunk_text.contains("[clippy] finished on 10.20.###.40 Bearer [REDACTED]"),
        "expected sanitized delta chunk from shared storage poll, got: {chunk_text}"
    );
}

// ============================================================================
// Repository Retirement & NotFound Auto-Retirement Tests
// ============================================================================

async fn spawn_retirement_github_mock(active_repos: Vec<&'static str>) -> String {
    let mut repos: BTreeMap<&'static str, Value> = BTreeMap::new();
    for name in active_repos {
        repos.insert(
            name,
            json!({"private": false, "visibility": "public", "default_branch": "main"}),
        );
    }
    let repos = Arc::new(repos);

    let app = Router::new()
        .route(
            "/repos/{owner}/{repo}",
            get({
                let repos = repos.clone();
                move |axum::extract::Path((o, r)): axum::extract::Path<(String, String)>| {
                    let repos = repos.clone();
                    async move {
                        match repos.get(format!("{o}/{r}").as_str()) {
                            Some(v) => (StatusCode::OK, v.to_string()),
                            None => (StatusCode::NOT_FOUND, "{}".to_string()),
                        }
                    }
                }
            }),
        )
        .route(
            "/repos/{owner}/{repo}/contents/{*path}",
            get(|| async { (StatusCode::NOT_FOUND, "{}".to_string()) }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn authenticated_github_not_found_auto_retires_stale_local_clone_preserving_job_history() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path().to_path_buf();
    let cache_file = ws.join("logs").join("console_registry.json");
    // Create a stale local git clone on disk that previously caused local_clone fallback.
    let stale_git_dir = ws
        .join("repos")
        .join("LMA1980")
        .join("stale-local")
        .join(".git");
    std::fs::create_dir_all(&stale_git_dir).unwrap();
    std::fs::write(stale_git_dir.join("HEAD"), "ref: refs/heads/main\n").unwrap();

    let api = spawn_retirement_github_mock(vec!["LMA1980/active-repo"]).await;
    let console = ConsoleState::new(ConsoleConfig {
        github_api_url: Some(api),
        github_token: Some("ghp_test_token".to_string()),
        workspace_dir: Some(ws.clone()),
        cache_file: Some(cache_file.clone()),
        ..ConsoleConfig::default()
    });

    let mut cfg = test_config(Some(API_KEY));
    cfg.workspace_dir = ws;
    cfg.github_token = Some("ghp_test_token".to_string());
    let job_store = JobStore::new(100, None);
    console.attach_storage(Arc::clone(job_store.storage()));

    completed_job(
        &job_store,
        "job-stale-1",
        "LMA1980/stale-local",
        "refs/heads/main",
        SHA_CORE,
        5,
        None,
    )
    .await;
    completed_job(
        &job_store,
        "job-active-1",
        "LMA1980/active-repo",
        "refs/heads/main",
        SHA_CHILD,
        3,
        None,
    )
    .await;

    console.refresh_repo("LMA1980", "active-repo", None).await;
    console.refresh_repo("LMA1980", "stale-local", None).await;

    assert!(console.is_retired("LMA1980", "stale-local").await);
    assert!(console.entry("LMA1980", "stale-local").await.is_none());
    assert!(!console.is_retired("LMA1980", "active-repo").await);
    assert!(console.entry("LMA1980", "active-repo").await.is_some());

    // Calling refresh_repo again returns early without resurrecting from local_clone.
    console.refresh_repo("LMA1980", "stale-local", None).await;
    assert!(console.entry("LMA1980", "stale-local").await.is_none());

    // Persisted in console_registry.json AND mirrored into ControllerStorage (__ar_console_registry__).
    let disk_json: mu_ci_controller::console::Registry =
        serde_json::from_str(&std::fs::read_to_string(&cache_file).unwrap()).unwrap();
    assert!(disk_json.retired_repos.contains_key("lma1980/stale-local"));
    let stored_json: mu_ci_controller::console::Registry = serde_json::from_str(
        &job_store
            .storage()
            .load_console_registry()
            .expect("mirrored registry"),
    )
    .unwrap();
    assert!(stored_json
        .retired_repos
        .contains_key("lma1980/stale-local"));

    // Historical jobs in JobStore remain untouched (Decision A1).
    let all_jobs = job_store.list_jobs().await;
    assert!(
        all_jobs
            .iter()
            .any(|j| j.job.repo_name == "LMA1980/stale-local"),
        "historical jobs in JobStore must remain intact"
    );

    let (tx, _rx) = tokio::sync::mpsc::channel(64);
    let (log_broadcaster, _) = tokio::sync::broadcast::channel(128);
    let state = Arc::new(AppState {
        config: cfg,
        job_store,
        cluster: ClusterRegistry::new(),
        tx,
        log_broadcaster,
        console,
    });
    let app = create_router(state);

    let (st_repos, repos_json) = get_json(&app, "/api/repos", Some(API_KEY)).await;
    assert_eq!(st_repos, StatusCode::OK);
    assert!(find_repo(&repos_json, "active-repo").is_some());
    assert!(find_repo(&repos_json, "stale-local").is_none());

    let (st_sum, _) = get_json(
        &app,
        "/api/repos/LMA1980/stale-local/summary",
        Some(API_KEY),
    )
    .await;
    assert_eq!(st_sum, StatusCode::NOT_FOUND);
    let (st_top, _) = get_json(
        &app,
        "/api/repos/LMA1980/stale-local/topology",
        Some(API_KEY),
    )
    .await;
    assert_eq!(st_top, StatusCode::NOT_FOUND);

    // Both /api/queue and /api/ci/queue exclude retired repos from recent_jobs.
    for queue_uri in ["/api/queue", "/api/ci/queue"] {
        let (st_q, q_json) = get_json(&app, queue_uri, Some(API_KEY)).await;
        assert_eq!(st_q, StatusCode::OK);
        let recent = q_json["recent_jobs"].as_array().unwrap();
        assert!(recent
            .iter()
            .any(|r| r["job"]["repo_name"] == "LMA1980/active-repo"));
        assert!(!recent
            .iter()
            .any(|r| r["job"]["repo_name"] == "LMA1980/stale-local"));
    }
}

#[tokio::test]
async fn sync_from_storage_does_not_resurrect_retired_repos_from_snapshots_or_jobs() {
    let storage: Arc<dyn mu_ci_controller::storage_backend::ControllerStorage> =
        Arc::new(mu_ci_controller::storage_backend::InMemoryStorage::open());
    let leader_store = JobStore::with_storage(100, None, Arc::clone(&storage));

    completed_job(
        &leader_store,
        "job-sync-ret-1",
        "LMA1980/deleted-legacy",
        "refs/heads/feat/old-branch",
        SHA_CORE,
        10,
        None,
    )
    .await;
    completed_job(
        &leader_store,
        "job-sync-act-1",
        "LMA1980/parent",
        "refs/heads/main",
        SHA_CHILD,
        5,
        None,
    )
    .await;

    let leader_console = ConsoleState::default();
    leader_console.attach_storage(Arc::clone(&storage));
    assert!(
        leader_console
            .retire_repo("LMA1980", "deleted-legacy")
            .await
    );

    // Standby hydrates from shared storage where branch_snapshots and jobs_history still hold
    // historical records for LMA1980/deleted-legacy.
    let standby_store = JobStore::with_storage(100, None, Arc::clone(&storage));
    let _ = standby_store.rehydrate_from_storage(false).await;
    let standby_console = ConsoleState::default();
    standby_console
        .sync_from_storage(&standby_store, true)
        .await;

    assert!(
        standby_console
            .is_retired("LMA1980", "deleted-legacy")
            .await
    );
    assert!(standby_console
        .entry("LMA1980", "deleted-legacy")
        .await
        .is_none());
    assert!(standby_console.entry("LMA1980", "parent").await.is_some());

    let (entries, retired) = (
        standby_console.entries().await,
        standby_console.retired_repos().await,
    );
    let known =
        mu_ci_controller::console::api::known_repo_names(&standby_store, &entries, &retired).await;
    assert!(!known.contains_key("lma1980/deleted-legacy"));
    assert!(known.contains_key("lma1980/parent"));

    // Underlying branch_snapshots and jobs_history remain untouched.
    assert!(storage
        .load_branch_snapshots(Some("LMA1980/deleted-legacy"), None)
        .iter()
        .any(|s| s.repo_name == "LMA1980/deleted-legacy"));
    assert!(standby_store
        .list_jobs()
        .await
        .iter()
        .any(|j| j.job.repo_name == "LMA1980/deleted-legacy"));
}

#[tokio::test]
async fn admin_delete_prune_and_repository_lifecycle_webhooks() {
    let tmp = tempfile::tempdir().unwrap();
    let api = spawn_retirement_github_mock(vec![
        "LMA1980/parent",
        "LMA1980/child",
        "LMA1980/parent-renamed",
    ])
    .await;
    let console = ConsoleState::new(ConsoleConfig {
        github_api_url: Some(api),
        github_token: Some("ghp_test_token".to_string()),
        retired_repos: vec!["LMA1980/startup-retired".to_string()],
        ..ConsoleConfig::default()
    });
    console.refresh_repo("LMA1980", "parent", None).await;
    console.refresh_repo("LMA1980", "child", None).await;

    let mut cfg = test_config(Some(API_KEY));
    cfg.workspace_dir = tmp.path().to_path_buf();
    cfg.proxy_secret = Some(PROXY_SECRET.to_string());
    cfg.invite_signing_key = Some(INVITE_KEY.to_string());
    cfg.bootstrap_admins = vec!["LMA1980".to_string()];
    cfg.github_token = Some("ghp_test_token".to_string());

    let job_store = JobStore::from_config(100, &cfg);
    completed_job(
        &job_store,
        "job-miss-a",
        "LMA1980/missing-a",
        "refs/heads/main",
        SHA_CORE,
        5,
        None,
    )
    .await;
    completed_job(
        &job_store,
        "job-miss-b",
        "LMA1980/missing-b",
        "refs/heads/main",
        SHA_SECRET,
        4,
        None,
    )
    .await;
    completed_job(
        &job_store,
        "job-startup-ret",
        "LMA1980/startup-retired",
        "refs/heads/main",
        SHA_CHILD,
        3,
        None,
    )
    .await;

    let (tx, _rx) = tokio::sync::mpsc::channel(64);
    let (log_broadcaster, _) = tokio::sync::broadcast::channel(128);
    let state = Arc::new(AppState {
        config: cfg,
        job_store,
        cluster: ClusterRegistry::new(),
        tx,
        log_broadcaster,
        console,
    });
    let app = create_router(state.clone());

    assert!(state.console.is_retired("LMA1980", "startup-retired").await);

    // 1. Auth gating on DELETE /api/repos/{owner}/{repo} & POST /api/repos/prune
    let (st_anon_del, _, _) =
        send_req(&app, "DELETE", "/api/repos/LMA1980/missing-a", &[], None).await;
    assert_eq!(st_anon_del, StatusCode::UNAUTHORIZED);
    let (st_anon_prune, _, _) = send_req(&app, "POST", "/api/repos/prune", &[], None).await;
    assert_eq!(st_anon_prune, StatusCode::UNAUTHORIZED);

    // Non-admin baseline operator (enrolled passkey, not elevated to platform-admin) -> 403
    let bearer_auth = format!("Bearer {API_KEY}");
    let api_hdrs = [("Authorization", bearer_auth.as_str())];
    let (st_inv, inv_json, _) = send_req(
        &app,
        "POST",
        "/api/auth/invites",
        &api_hdrs,
        Some(json!({ "ttl_seconds": 3600, "note": "baseline operator" })),
    )
    .await;
    assert_eq!(st_inv, StatusCode::CREATED);
    let inv_tok = inv_json["invite_token"].as_str().unwrap();
    let op_hdrs = [
        ("X-Proxy-Secret", PROXY_SECRET),
        ("X-Forwarded-User", "baseline-op"),
    ];
    let (st_red, _, _) = send_req(
        &app,
        "POST",
        "/api/auth/redeem",
        &op_hdrs,
        Some(json!({ "invite_token": inv_tok })),
    )
    .await;
    assert_eq!(st_red, StatusCode::OK);
    let op_auth = TestVirtualAuthenticator::new_synced(77, b"cred-baseline-op");
    enroll_first_passkey(&app, &op_hdrs, &op_auth, "Op Passkey").await;

    let (st_op_del, _, _) = send_req(
        &app,
        "DELETE",
        "/api/repos/LMA1980/missing-a",
        &op_hdrs,
        None,
    )
    .await;
    assert_eq!(st_op_del, StatusCode::FORBIDDEN);
    let (st_op_prune, _, _) = send_req(&app, "POST", "/api/repos/prune", &op_hdrs, None).await;
    assert_eq!(st_op_prune, StatusCode::FORBIDDEN);

    // 2. Elevated platform-admin DELETE /api/repos/{owner}/{repo} -> 200 OK
    let admin_hdrs = [
        ("X-Proxy-Secret", PROXY_SECRET),
        ("X-Forwarded-User", "LMA1980"),
    ];
    let admin_auth = TestVirtualAuthenticator::new_synced(78, b"cred-admin-retire");
    enroll_first_passkey(&app, &admin_hdrs, &admin_auth, "Admin Passkey").await;
    let admin_cookie = elevate_admin_with_passkey(&app, &admin_hdrs, &admin_auth).await;
    let admin_elevated_hdrs = [
        ("X-Proxy-Secret", PROXY_SECRET),
        ("X-Forwarded-User", "LMA1980"),
        ("Cookie", admin_cookie.as_str()),
    ];

    let (st_del, del_json, del_txt) = send_req(
        &app,
        "DELETE",
        "/api/repos/LMA1980/missing-a",
        &admin_elevated_hdrs,
        None,
    )
    .await;
    assert_eq!(st_del, StatusCode::OK, "DELETE failed: {del_txt}");
    assert_eq!(del_json["retired"], "LMA1980/missing-a");
    assert!(del_json["fabric_rev"].as_u64().unwrap() >= 1);
    assert!(state.console.is_retired("LMA1980", "missing-a").await);

    let (st_sum, _) = get_json(&app, "/api/repos/LMA1980/missing-a/summary", Some(API_KEY)).await;
    assert_eq!(st_sum, StatusCode::NOT_FOUND);

    // 3. AdminApiKey POST /api/repos/prune with empty body probes known repos and retires 404s
    let (st_prune, prune_json, prune_txt) =
        send_req(&app, "POST", "/api/repos/prune", &api_hdrs, None).await;
    assert_eq!(st_prune, StatusCode::OK, "prune failed: {prune_txt}");
    let pruned: Vec<&str> = prune_json["retired"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(pruned, vec!["LMA1980/missing-b"]);
    assert!(state.console.is_retired("LMA1980", "missing-b").await);
    assert!(!state.console.is_retired("LMA1980", "parent").await);

    // Explicit repos in JSON body are also retired; subsequent empty prune returns [].
    let (st_prune_exp, prune_exp_json, _) = send_req(
        &app,
        "POST",
        "/api/repos/prune",
        &api_hdrs,
        Some(json!({ "repos": ["LMA1980/explicit-old"] })),
    )
    .await;
    assert_eq!(st_prune_exp, StatusCode::OK);
    assert_eq!(prune_exp_json["retired"], json!(["LMA1980/explicit-old"]));
    assert!(state.console.is_retired("LMA1980", "explicit-old").await);

    let (st_prune_idem, prune_idem_json, _) =
        send_req(&app, "POST", "/api/repos/prune", &api_hdrs, None).await;
    assert_eq!(st_prune_idem, StatusCode::OK);
    assert_eq!(prune_idem_json["retired"], json!([]));

    // 4. repository "deleted" and "renamed" webhooks + un-retire on "unarchived"/"push"
    let st_wh_del = post_webhook(
        &app,
        "repository",
        json!({
            "action": "deleted",
            "repository": repo_obj("LMA1980/child", false),
        }),
    )
    .await;
    assert_eq!(st_wh_del, StatusCode::OK);
    assert!(state.console.is_retired("LMA1980", "child").await);

    let st_wh_ren = post_webhook(
        &app,
        "repository",
        json!({
            "action": "renamed",
            "repository": repo_obj("LMA1980/parent-renamed", false),
            "changes": {
                "repository": {
                    "name": { "from": "parent" }
                }
            }
        }),
    )
    .await;
    assert_eq!(st_wh_ren, StatusCode::OK);
    assert!(state.console.is_retired("LMA1980", "parent").await);
    assert!(!state.console.is_retired("LMA1980", "parent-renamed").await);

    let (_, after_ren) = get_json(&app, "/api/repos", Some(API_KEY)).await;
    assert!(find_repo(&after_ren, "parent").is_none());
    assert!(find_repo(&after_ren, "child").is_none());
    assert!(find_repo(&after_ren, "parent-renamed").is_some());

    // Valid repository "unarchived" webhook un-retires LMA1980/child
    let st_wh_unarch = post_webhook(
        &app,
        "repository",
        json!({
            "action": "unarchived",
            "repository": repo_obj("LMA1980/child", false),
        }),
    )
    .await;
    assert_eq!(st_wh_unarch, StatusCode::OK);
    assert!(!state.console.is_retired("LMA1980", "child").await);
    let (_, after_unarch) = get_json(&app, "/api/repos", Some(API_KEY)).await;
    assert!(find_repo(&after_unarch, "child").is_some());

    // Retire LMA1980/child again, verify "archived" does NOT un-retire, then verify valid "push" un-retires
    assert!(state.console.retire_repo("LMA1980", "child").await);
    let st_wh_arch = post_webhook(
        &app,
        "repository",
        json!({
            "action": "archived",
            "repository": repo_obj("LMA1980/child", false),
        }),
    )
    .await;
    assert_eq!(st_wh_arch, StatusCode::OK);
    assert!(state.console.is_retired("LMA1980", "child").await);

    let st_wh_push = post_webhook(
        &app,
        "push",
        json!({
            "ref": "refs/heads/main",
            "after": SHA_CHILD,
            "repository": repo_obj("LMA1980/child", false),
        }),
    )
    .await;
    assert_eq!(st_wh_push, StatusCode::ACCEPTED);
    assert!(!state.console.is_retired("LMA1980", "child").await);

    // 5. Elevated super-operator role can also DELETE /api/repos/{owner}/{repo}
    let (st_elev_so_start, so_start_json, _) = send_req(
        &app,
        "POST",
        "/api/auth/elevate/start",
        &admin_hdrs,
        Some(json!({ "role_id": "super-operator" })),
    )
    .await;
    assert_eq!(st_elev_so_start, StatusCode::OK);
    let so_challenge_id = so_start_json["challenge_id"].as_str().unwrap().to_string();
    let so_challenge_b64 = so_start_json["options"]["publicKey"]["challenge"]
        .as_str()
        .unwrap();
    let so_challenge_bytes = URL_SAFE_NO_PAD.decode(so_challenge_b64).unwrap();
    let so_cred =
        admin_auth.create_assertion_response(&so_challenge_bytes, admin_auth.sign_count + 1);
    let (st_elev_so_fin, _, so_fin_text, so_cookie_opt) = send_req_with_cookie(
        &app,
        "POST",
        "/api/auth/elevate/finish",
        &admin_hdrs,
        Some(json!({
            "challenge_id": so_challenge_id,
            "credential": so_cred,
            "role_id": "super-operator",
        })),
    )
    .await;
    assert_eq!(
        st_elev_so_fin,
        StatusCode::OK,
        "super-operator elevate failed: {so_fin_text}"
    );
    let so_cookie = so_cookie_opt.expect("super-operator cookie");
    let so_elevated_hdrs = [
        ("X-Proxy-Secret", PROXY_SECRET),
        ("X-Forwarded-User", "LMA1980"),
        ("Cookie", so_cookie.as_str()),
    ];
    let (st_so_del, so_del_json, so_del_txt) = send_req(
        &app,
        "DELETE",
        "/api/repos/LMA1980/child",
        &so_elevated_hdrs,
        None,
    )
    .await;
    assert_eq!(
        st_so_del,
        StatusCode::OK,
        "super-operator DELETE failed: {so_del_txt}"
    );
    assert_eq!(so_del_json["retired"], "LMA1980/child");
    assert!(state.console.is_retired("LMA1980", "child").await);
}

#[test]
fn env_retired_repos_seeds_console_state_on_startup() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = test_config(None);
    cfg.workspace_dir = tmp.path().to_path_buf();
    std::env::set_var(
        "ACTION_RUNNER_RETIRED_REPOS",
        "LMA1980/env-seeded-retired-repo, LMA1980/env-seeded-retired-two",
    );
    let console_cfg = ConsoleConfig::from_config(&cfg);
    std::env::remove_var("ACTION_RUNNER_RETIRED_REPOS");
    let console = ConsoleState::new(console_cfg);
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        assert!(
            console
                .is_retired("LMA1980", "env-seeded-retired-repo")
                .await
        );
        assert!(
            console
                .is_retired("LMA1980", "env-seeded-retired-two")
                .await
        );
    });
}

#[tokio::test]
async fn unauthenticated_github_client_preserves_history_only_behavior() {
    let api = spawn_retirement_github_mock(vec!["LMA1980/parent"]).await;
    let console = ConsoleState::new(ConsoleConfig {
        github_api_url: Some(api),
        github_token: None,
        ..ConsoleConfig::default()
    });
    let state = make_state(Some(API_KEY), console.clone());
    completed_job(
        &state.job_store,
        "job-hist-preserve",
        "LMA1980/history-only",
        "refs/heads/main",
        SHA_CORE,
        5,
        None,
    )
    .await;

    console.refresh_repo("LMA1980", "history-only", None).await;
    assert!(
        !console.is_retired("LMA1980", "history-only").await,
        "unauthenticated GitHubClient (github_token: None) must not auto-retire on 404"
    );
    let entry = console
        .entry("LMA1980", "history-only")
        .await
        .expect("history-only entry must remain cached");
    assert_eq!(entry.visibility, None);

    let app = create_router(state);
    let (st, authed) = get_json(&app, "/api/repos", Some(API_KEY)).await;
    assert_eq!(st, StatusCode::OK);
    let hist = find_repo(&authed, "history-only").expect("history-only visible to authed callers");
    assert_eq!(hist["visibility"], Value::Null);
}

#[tokio::test]
async fn redirected_renamed_github_repo_full_name_mismatch_auto_retires_in_refresh_and_prune() {
    // Mock GitHub returns 200 OK with canonical `"full_name": "LMA1980/mu-ci-controller"`
    // when queried for the legacy pre-rename path `GET /repos/LMA1980/ActionRunner-controller`,
    // simulating reqwest following GitHub's HTTP 301 redirect.
    let mut repos: BTreeMap<&'static str, Value> = BTreeMap::new();
    repos.insert(
        "LMA1980/ActionRunner-controller",
        json!({
            "full_name": "LMA1980/mu-ci-controller",
            "private": false,
            "visibility": "public",
            "default_branch": "main"
        }),
    );
    repos.insert(
        "LMA1980/mu-ci-controller",
        json!({
            "full_name": "LMA1980/mu-ci-controller",
            "private": false,
            "visibility": "public",
            "default_branch": "main"
        }),
    );
    let repos = Arc::new(repos);

    let mock_app = Router::new()
        .route(
            "/repos/{owner}/{repo}",
            get({
                let repos = repos.clone();
                move |axum::extract::Path((o, r)): axum::extract::Path<(String, String)>| {
                    let repos = repos.clone();
                    async move {
                        match repos.get(format!("{o}/{r}").as_str()) {
                            Some(v) => (StatusCode::OK, v.to_string()),
                            None => (StatusCode::NOT_FOUND, "{}".to_string()),
                        }
                    }
                }
            }),
        )
        .route(
            "/repos/{owner}/{repo}/contents/{*path}",
            get(|| async { (StatusCode::NOT_FOUND, "{}".to_string()) }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, mock_app).await.unwrap();
    });
    let api_url = format!("http://{addr}");

    // 1. Authenticated refresh_repo detects the full_name mismatch and auto-retires the legacy name.
    let console_refresh = ConsoleState::new(ConsoleConfig {
        github_api_url: Some(api_url.clone()),
        github_token: Some("ghp_test_token".to_string()),
        ..ConsoleConfig::default()
    });
    console_refresh
        .refresh_repo("LMA1980", "ActionRunner-controller", None)
        .await;
    assert!(
        console_refresh
            .is_retired("LMA1980", "ActionRunner-controller")
            .await
    );
    assert!(console_refresh
        .entry("LMA1980", "ActionRunner-controller")
        .await
        .is_none());

    console_refresh
        .refresh_repo("LMA1980", "mu-ci-controller", None)
        .await;
    assert!(
        !console_refresh
            .is_retired("LMA1980", "mu-ci-controller")
            .await
    );
    assert!(console_refresh
        .entry("LMA1980", "mu-ci-controller")
        .await
        .is_some());

    // 2. POST /api/repos/prune with `{}` probes known repos, detects the redirect mismatch on
    //    `LMA1980/ActionRunner-controller`, retires it, and leaves `LMA1980/mu-ci-controller` active.
    let console_prune = ConsoleState::new(ConsoleConfig {
        github_api_url: Some(api_url),
        github_token: Some("ghp_test_token".to_string()),
        ..ConsoleConfig::default()
    });
    let mut cfg = test_config(Some(API_KEY));
    cfg.github_token = Some("ghp_test_token".to_string());
    let job_store = JobStore::new(100, None);
    completed_job(
        &job_store,
        "job-legacy-redirect-1",
        "LMA1980/ActionRunner-controller",
        "refs/heads/main",
        SHA_CORE,
        5,
        None,
    )
    .await;
    completed_job(
        &job_store,
        "job-canonical-1",
        "LMA1980/mu-ci-controller",
        "refs/heads/main",
        SHA_CHILD,
        3,
        None,
    )
    .await;

    let (tx, _rx) = tokio::sync::mpsc::channel(64);
    let (log_broadcaster, _) = tokio::sync::broadcast::channel(128);
    let state = Arc::new(AppState {
        config: cfg,
        job_store,
        cluster: ClusterRegistry::new(),
        tx,
        log_broadcaster,
        console: console_prune,
    });
    let app = create_router(state.clone());

    let bearer_auth = format!("Bearer {API_KEY}");
    let (st_prune, prune_json, prune_txt) = send_req(
        &app,
        "POST",
        "/api/repos/prune",
        &[("Authorization", bearer_auth.as_str())],
        Some(json!({})),
    )
    .await;
    assert_eq!(st_prune, StatusCode::OK, "prune failed: {prune_txt}");
    assert_eq!(
        prune_json["retired"],
        json!(["LMA1980/ActionRunner-controller"])
    );
    assert!(
        state
            .console
            .is_retired("LMA1980", "ActionRunner-controller")
            .await
    );
    assert!(
        !state
            .console
            .is_retired("LMA1980", "mu-ci-controller")
            .await
    );

    let (_, repos_json) = get_json(&app, "/api/repos", Some(API_KEY)).await;
    assert!(find_repo(&repos_json, "ActionRunner-controller").is_none());
    assert!(find_repo(&repos_json, "mu-ci-controller").is_some());
}

fn all_frame_data(acc: &str, kind: &str) -> Vec<Value> {
    let needle = format!("event: {kind}\n");
    let mut out = Vec::new();
    let mut offset = 0;
    while let Some(pos) = acc[offset..].find(&needle) {
        let start = offset + pos + needle.len();
        if let Some(line) = acc[start..].lines().find(|l| l.starts_with("data: ")) {
            if let Ok(val) = serde_json::from_str::<Value>(&line["data: ".len()..]) {
                out.push(val);
            }
        }
        offset = start;
    }
    out
}

async fn read_until_count<S>(stream: &mut S, kind: &str, count: usize) -> String
where
    S: futures_util::Stream<Item = Result<axum::body::Bytes, axum::Error>> + Unpin,
{
    let mut acc = String::new();
    let needle = format!("event: {kind}\n");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while acc.matches(&needle).count() < count {
        let chunk = tokio::time::timeout_at(deadline, stream.next())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "timed out waiting for {count} `{kind}` frames (got {}):\n{acc}",
                    acc.matches(&needle).count()
                )
            })
            .expect("stream ended")
            .expect("stream error");
        acc.push_str(&String::from_utf8_lossy(&chunk));
    }
    acc
}

#[tokio::test]
async fn sse_repos_changed_on_catalog_mutations_and_private_confidentiality() {
    let mut initial_repos: BTreeMap<String, Value> = BTreeMap::new();
    for (name, private) in [
        ("LMA1980/priv-created", true),
        ("LMA1980/pub-created", false),
        ("LMA1980/priv-renamed", true),
        ("LMA1980/pub-from-priv", false),
        ("LMA1980/pub-renamed", false),
        ("LMA1980/priv-after-pub", true),
        ("LMA1980/priv-push", true),
        ("LMA1980/pub-push", false),
        ("LMA1980/refreshed-pub", false),
        ("LMA1980/pub-404-gone", false),
        ("LMA1980/priv-404-gone", true),
        ("LMA1980/pub-redirect-old", false),
        ("LMA1980/priv-batch-prune", true),
    ] {
        initial_repos.insert(
            name.to_string(),
            json!({
                "private": private,
                "visibility": if private { "private" } else { "public" },
                "default_branch": "main"
            }),
        );
    }
    let mock_repos = Arc::new(tokio::sync::RwLock::new(initial_repos));
    let mock_app = Router::new()
        .route(
            "/repos/{owner}/{repo}",
            get({
                let repos = mock_repos.clone();
                move |axum::extract::Path((o, r)): axum::extract::Path<(String, String)>| {
                    let repos = repos.clone();
                    async move {
                        let guard = repos.read().await;
                        match guard.get(&format!("{o}/{r}")) {
                            Some(v) => (StatusCode::OK, v.to_string()),
                            None => (StatusCode::NOT_FOUND, "{}".to_string()),
                        }
                    }
                }
            }),
        )
        .route(
            "/repos/{owner}/{repo}/contents/{*path}",
            get(|| async { (StatusCode::NOT_FOUND, "{}".to_string()) }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, mock_app).await.unwrap();
    });
    let api_url = format!("http://{addr}");

    let console = ConsoleState::new(ConsoleConfig {
        github_api_url: Some(api_url),
        github_token: Some("ghp_test_token".to_string()),
        ..ConsoleConfig::default()
    });
    let mut cfg = test_config(Some(API_KEY));
    cfg.proxy_secret = Some(PROXY_SECRET.to_string());
    cfg.github_token = Some("ghp_test_token".to_string());
    let job_store = JobStore::new(100, None);
    let (tx, _rx) = tokio::sync::mpsc::channel(64);
    let (log_broadcaster, _) = tokio::sync::broadcast::channel(128);
    let state = Arc::new(AppState {
        config: cfg,
        job_store,
        cluster: ClusterRegistry::new(),
        tx,
        log_broadcaster,
        console,
    });
    let app = create_router(state.clone());

    // Connect both anonymous and authenticated /api/events streams simultaneously.
    let anon_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(anon_resp.status(), StatusCode::OK);
    let mut anon_stream = anon_resp.into_body().into_data_stream();
    read_until(&mut anon_stream, "cluster").await;

    let auth_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/events?token={API_KEY}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(auth_resp.status(), StatusCode::OK);
    let mut auth_stream = auth_resp.into_body().into_data_stream();
    read_until(&mut auth_stream, "cluster").await;

    let bearer_auth = format!("Bearer {API_KEY}");
    let api_hdrs = [("Authorization", bearer_auth.as_str())];

    // 1. repository created (private then public)
    assert_eq!(
        post_webhook(
            &app,
            "repository",
            json!({"action": "created", "repository": repo_obj("LMA1980/priv-created", true)}),
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(
        post_webhook(
            &app,
            "repository",
            json!({"action": "created", "repository": repo_obj("LMA1980/pub-created", false)}),
        )
        .await,
        StatusCode::OK
    );

    // 2. repository renamed:
    //    - private -> private
    //    - private -> public
    //    - public -> public
    //    - public -> private
    assert_eq!(
        post_webhook(
            &app,
            "repository",
            json!({
                "action": "renamed",
                "repository": repo_obj("LMA1980/priv-renamed", true),
                "changes": {"repository": {"name": {"from": "priv-created"}}}
            }),
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(
        post_webhook(
            &app,
            "repository",
            json!({
                "action": "renamed",
                "repository": repo_obj("LMA1980/pub-from-priv", false),
                "changes": {"repository": {"name": {"from": "priv-renamed"}}}
            }),
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(
        post_webhook(
            &app,
            "repository",
            json!({
                "action": "renamed",
                "repository": repo_obj("LMA1980/pub-renamed", false),
                "changes": {"repository": {"name": {"from": "pub-created"}}}
            }),
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(
        post_webhook(
            &app,
            "repository",
            json!({
                "action": "renamed",
                "repository": repo_obj("LMA1980/priv-after-pub", true),
                "changes": {"repository": {"name": {"from": "pub-renamed"}}}
            }),
        )
        .await,
        StatusCode::OK
    );

    // 3. DELETE /api/repos/{owner}/{repo} (private, public, and idempotent repeat)
    let (st, _, _) = send_req(
        &app,
        "DELETE",
        "/api/repos/LMA1980/priv-after-pub",
        &api_hdrs,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (st, _, _) = send_req(
        &app,
        "DELETE",
        "/api/repos/LMA1980/pub-from-priv",
        &api_hdrs,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let rev_before_noop = state.console.fabric_rev().await;
    let (st, _, _) = send_req(
        &app,
        "DELETE",
        "/api/repos/LMA1980/pub-from-priv",
        &api_hdrs,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(state.console.fabric_rev().await, rev_before_noop);

    // 4. repository unarchived + repository deleted (private then public)
    assert_eq!(
        post_webhook(
            &app,
            "repository",
            json!({"action": "unarchived", "repository": repo_obj("LMA1980/priv-after-pub", true)}),
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(
        post_webhook(
            &app,
            "repository",
            json!({"action": "unarchived", "repository": repo_obj("LMA1980/pub-from-priv", false)}),
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(
        post_webhook(
            &app,
            "repository",
            json!({"action": "deleted", "repository": repo_obj("LMA1980/priv-after-pub", true)}),
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(
        post_webhook(
            &app,
            "repository",
            json!({"action": "deleted", "repository": repo_obj("LMA1980/pub-from-priv", false)}),
        )
        .await,
        StatusCode::OK
    );

    // 5. First-seen push discovery (private, public, and repeat public push which must NOT emit)
    assert_eq!(
        post_webhook(
            &app,
            "push",
            json!({
                "ref": "refs/heads/main",
                "after": SHA_SECRET,
                "repository": repo_obj("LMA1980/priv-push", true),
            }),
        )
        .await,
        StatusCode::ACCEPTED
    );
    assert_eq!(
        post_webhook(
            &app,
            "push",
            json!({
                "ref": "refs/heads/main",
                "after": SHA_CHILD,
                "repository": repo_obj("LMA1980/pub-push", false),
            }),
        )
        .await,
        StatusCode::ACCEPTED
    );
    assert_eq!(
        post_webhook(
            &app,
            "push",
            json!({
                "ref": "refs/heads/main",
                "after": SHA_CORE,
                "repository": repo_obj("LMA1980/pub-push", false),
            }),
        )
        .await,
        StatusCode::ACCEPTED
    );

    // 6. refresh_repo discovery + repeat refresh (no spam) + authenticated 404 & #236 redirect auto-retirement
    state
        .console
        .refresh_repo("LMA1980", "refreshed-pub", None)
        .await;
    state
        .console
        .refresh_repo("LMA1980", "refreshed-pub", None)
        .await;

    // Seed repos via refresh_repo while active in mock GitHub, then delete/redirect them.
    state
        .console
        .refresh_repo("LMA1980", "pub-404-gone", None)
        .await;
    state
        .console
        .refresh_repo("LMA1980", "priv-404-gone", None)
        .await;
    state
        .console
        .refresh_repo("LMA1980", "pub-redirect-old", None)
        .await;
    {
        let mut guard = mock_repos.write().await;
        guard.remove("LMA1980/pub-404-gone");
        guard.remove("LMA1980/priv-404-gone");
        guard.insert(
            "LMA1980/pub-redirect-old".to_string(),
            json!({"full_name": "LMA1980/refreshed-pub", "private": false, "visibility": "public", "default_branch": "main"}),
        );
    }
    state
        .console
        .refresh_repo("LMA1980", "pub-404-gone", None)
        .await;
    state
        .console
        .refresh_repo("LMA1980", "priv-404-gone", None)
        .await;
    state
        .console
        .refresh_repo("LMA1980", "pub-redirect-old", None)
        .await;

    // 7. POST /api/repos/prune: empty, private-only, and mixed (public + private)
    let rev_before_empty_prune = state.console.fabric_rev().await;
    let (st, empty_prune, _) =
        send_req(&app, "POST", "/api/repos/prune", &api_hdrs, Some(json!({}))).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(empty_prune["retired"], json!([]));
    assert_eq!(state.console.fabric_rev().await, rev_before_empty_prune);

    let (st, priv_prune, _) = send_req(
        &app,
        "POST",
        "/api/repos/prune",
        &api_hdrs,
        Some(json!({"repos": ["LMA1980/priv-push"]})),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(priv_prune["retired"], json!(["LMA1980/priv-push"]));

    // Ensure priv-batch-prune is cached as private in console registry before mixed prune
    state
        .console
        .refresh_repo("LMA1980", "priv-batch-prune", None)
        .await;

    let (st, mixed_prune, _) = send_req(
        &app,
        "POST",
        "/api/repos/prune",
        &api_hdrs,
        Some(json!({"repos": ["LMA1980/pub-push", "LMA1980/priv-batch-prune"]})),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        mixed_prune["retired"],
        json!(["LMA1980/priv-batch-prune", "LMA1980/pub-push"])
    );

    // Expected authenticated repos_changed count:
    // 1: created priv-created
    // 2: created pub-created
    // 3: renamed priv-created -> priv-renamed
    // 4: renamed priv-renamed -> pub-from-priv
    // 5: renamed pub-created -> pub-renamed
    // 6: renamed pub-renamed -> priv-after-pub
    // 7: retired priv-after-pub (DELETE)
    // 8: retired pub-from-priv (DELETE)
    // 9: unarchived priv-after-pub
    // 10: unarchived pub-from-priv
    // 11: deleted priv-after-pub
    // 12: deleted pub-from-priv
    // 13: discovered priv-push (push)
    // 14: discovered pub-push (push)
    // 15: discovered refreshed-pub (refresh_repo)
    // 16: discovered pub-404-gone (refresh_repo)
    // 17: discovered priv-404-gone (refresh_repo)
    // 18: discovered pub-redirect-old (refresh_repo)
    // 19: retired pub-404-gone (refresh_repo 404)
    // 20: retired priv-404-gone (refresh_repo 404)
    // 21: retired pub-redirect-old (refresh_repo #236 redirect)
    // 22: pruned priv-push
    // 23: discovered priv-batch-prune (refresh_repo)
    // 24: pruned mixed (priv-batch-prune + pub-push)
    let auth_acc = read_until_count(&mut auth_stream, "repos_changed", 24).await;
    let auth_events = all_frame_data(&auth_acc, "repos_changed");
    assert_eq!(auth_events.len(), 24);

    let mut prev_rev = 0;
    for ev in &auth_events {
        let rev = ev["fabric_rev"].as_u64().unwrap();
        assert!(rev > prev_rev, "non-monotonic fabric_rev in auth: {ev}");
        prev_rev = rev;
    }

    assert_eq!(auth_events[0]["reason"], "created");
    assert_eq!(auth_events[0]["repo"], "priv-created");
    assert_eq!(auth_events[2]["reason"], "renamed");
    assert_eq!(auth_events[2]["repo"], "priv-renamed");
    assert_eq!(auth_events[2]["previous_repo"], "priv-created");
    assert_eq!(auth_events[3]["reason"], "renamed");
    assert_eq!(auth_events[3]["repo"], "pub-from-priv");
    assert_eq!(auth_events[3]["previous_repo"], "priv-renamed");
    assert_eq!(auth_events[6]["reason"], "retired");
    assert_eq!(auth_events[6]["repo"], "priv-after-pub");
    assert_eq!(auth_events[8]["reason"], "unarchived");
    assert_eq!(auth_events[10]["reason"], "deleted");
    assert_eq!(auth_events[10]["repo"], "priv-after-pub");
    assert_eq!(auth_events[12]["reason"], "discovered");
    assert_eq!(auth_events[12]["repo"], "priv-push");
    assert_eq!(auth_events[19]["reason"], "retired");
    assert_eq!(auth_events[19]["repo"], "priv-404-gone");
    assert_eq!(auth_events[20]["reason"], "retired");
    assert_eq!(auth_events[20]["repo"], "pub-redirect-old");
    assert_eq!(auth_events[21]["reason"], "pruned");
    assert_eq!(auth_events[21]["pruned_count"], 1);
    assert_eq!(auth_events[23]["reason"], "pruned");
    assert_eq!(auth_events[23]["pruned_count"], 2);
    assert_eq!(
        auth_events[23]["repos"],
        json!(["LMA1980/priv-batch-prune", "LMA1980/pub-push"])
    );

    // Expected anonymous repos_changed count (only public / redacted cross-boundary events):
    // 1: created pub-created
    // 2: renamed pub-from-priv (previous_repo stripped!)
    // 3: renamed pub-renamed (previous_repo = pub-created)
    // 4: catalog_updated (pub-renamed -> priv-after-pub, redacted!)
    // 5: retired pub-from-priv (DELETE)
    // 6: unarchived pub-from-priv
    // 7: deleted pub-from-priv
    // 8: discovered pub-push
    // 9: discovered refreshed-pub
    // 10: created pub-404-gone
    // 11: created pub-redirect-old
    // 12: retired pub-404-gone
    // 13: retired pub-redirect-old
    // 14: pruned mixed (filtered strictly to pub-push, pruned_count = 1!)
    let anon_acc = read_until_count(&mut anon_stream, "repos_changed", 14).await;
    for private_repo in [
        "priv-created",
        "priv-renamed",
        "priv-after-pub",
        "priv-push",
        "priv-404-gone",
        "priv-batch-prune",
    ] {
        assert!(
            !anon_acc.contains(private_repo),
            "unexpected private repository identifier in anonymous SSE stream"
        );
    }
    let anon_events = all_frame_data(&anon_acc, "repos_changed");
    assert_eq!(anon_events.len(), 14);

    let mut anon_prev_rev = 0;
    for ev in &anon_events {
        let rev = ev["fabric_rev"].as_u64().unwrap();
        assert!(
            rev > anon_prev_rev,
            "non-monotonic fabric_rev in anon: {ev}"
        );
        anon_prev_rev = rev;
    }

    assert_eq!(anon_events[0]["reason"], "created");
    assert_eq!(anon_events[0]["repo"], "pub-created");
    assert_eq!(anon_events[1]["reason"], "renamed");
    assert_eq!(anon_events[1]["repo"], "pub-from-priv");
    assert!(anon_events[1].get("previous_repo").is_none());
    assert_eq!(anon_events[2]["reason"], "renamed");
    assert_eq!(anon_events[2]["repo"], "pub-renamed");
    assert_eq!(anon_events[2]["previous_repo"], "pub-created");
    assert_eq!(anon_events[3]["reason"], "catalog_updated");
    assert!(anon_events[3].get("repo").is_none());
    assert!(anon_events[3].get("previous_repo").is_none());
    assert_eq!(anon_events[4]["reason"], "retired");
    assert_eq!(anon_events[4]["repo"], "pub-from-priv");
    assert_eq!(anon_events[5]["reason"], "unarchived");
    assert_eq!(anon_events[6]["reason"], "deleted");
    assert_eq!(anon_events[7]["reason"], "discovered");
    assert_eq!(anon_events[7]["repo"], "pub-push");
    assert_eq!(anon_events[8]["reason"], "discovered");
    assert_eq!(anon_events[8]["repo"], "refreshed-pub");
    assert_eq!(anon_events[11]["reason"], "retired");
    assert_eq!(anon_events[11]["repo"], "pub-404-gone");
    assert_eq!(anon_events[12]["reason"], "retired");
    assert_eq!(anon_events[12]["repo"], "pub-redirect-old");
    assert_eq!(anon_events[13]["reason"], "pruned");
    assert_eq!(anon_events[13]["pruned_count"], 1);
    assert_eq!(anon_events[13]["repos"], json!(["LMA1980/pub-push"]));
}
