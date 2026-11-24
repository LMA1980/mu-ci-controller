#![deny(unsafe_code)]

//! HTTP integration tests for the dedicated read-only service bearer token slot
//! (`MU_CI_CONTROLLER_READONLY_TOKEN_FILE` / `MU_CI_READONLY_TOKEN_FILE`, `#262`).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use chrono::Utc;
use mu_ci_controller::app::create_router;
use mu_ci_controller::cluster::ClusterRegistry;
use mu_ci_controller::config::{Config, HaRoleConfig};
use mu_ci_controller::console::{ConsoleConfig, ConsoleState};
use mu_ci_controller::job::{Job, JobStore};
use mu_ci_controller::webhook::AppState;
use mu_ci_ipc::WorkerRegistration;
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::sync::{broadcast, mpsc};
use tower::ServiceExt;

const ADMIN_TOKEN: &str = "admin-service-bearer-token-9999";
const READONLY_TOKEN: &str = "ro-service-bearer-token-1111";
const INVALID_TOKEN: &str = "invalid-service-bearer-token-0000";
const PROXY_SECRET: &str = "edge-proxy-secret-test";
const INVITE_SIGNING_KEY: &str = "invite-signing-key-test";

struct TestFixture {
    app: Router,
    job_id: String,
    _tmp: TempDir,
}

async fn build_fixture(include_admin_key: bool, include_proxy_secret: bool) -> TestFixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ro_file = tmp.path().join("ci-readonly.token");
    std::fs::write(&ro_file, format!("  {READONLY_TOKEN}\n")).expect("write ro token file");

    let mut env_map: HashMap<&str, String> = HashMap::new();
    env_map.insert("MU_CI_CONTROLLER_BIND", "127.0.0.1:0".to_string());
    env_map.insert(
        "MU_CI_CONTROLLER_WORKSPACE",
        tmp.path().to_str().unwrap().to_string(),
    );
    env_map.insert(
        "MU_CI_CONTROLLER_READONLY_TOKEN_FILE",
        ro_file.to_str().unwrap().to_string(),
    );
    env_map.insert("MU_CI_CONTROLLER_NODE_ID", "node-a".to_string());
    env_map.insert("MU_CI_CONTROLLER_HA_ROLE", "leader".to_string());
    env_map.insert(
        "MU_CI_CONTROLLER_INVITE_SIGNING_KEY",
        INVITE_SIGNING_KEY.to_string(),
    );
    env_map.insert("MU_CI_CONTROLLER_BOOTSTRAP_ADMINS", "LMA1980".to_string());
    if include_admin_key {
        env_map.insert("MU_CI_CONTROLLER_LOG_API_KEY", ADMIN_TOKEN.to_string());
    }
    if include_proxy_secret {
        env_map.insert("MU_CI_CONTROLLER_PROXY_SECRET", PROXY_SECRET.to_string());
    }

    let mut config = Config::load_with_env(|k| env_map.get(k).cloned());
    config.ha_role = HaRoleConfig::Leader;
    config.auth_state_file = Some(tmp.path().join("logs").join("platform_auth.json"));
    assert_eq!(config.readonly_api_token.as_deref(), Some(READONLY_TOKEN));

    let job_store = JobStore::from_config(50, &config);
    let job_id = "job-ro-test-001".to_string();
    let rel_log = PathBuf::from("logs/LMA1980/demo-public/job-ro-test-001.log");
    let full_log = tmp.path().join(&rel_log);
    std::fs::create_dir_all(full_log.parent().unwrap()).expect("create log dir");
    std::fs::write(&full_log, "stage build ok\n").expect("write job log");

    let job = Job {
        id: job_id.clone(),
        event_type: "push".to_string(),
        repo_name: "LMA1980/demo-public".to_string(),
        clone_url: "https://github.com/LMA1980/demo-public.git".to_string(),
        commit_sha: "abcdef1234567890abcdef1234567890abcdef12".to_string(),
        ref_name: "refs/heads/main".to_string(),
        sender: "LMA1980".to_string(),
        pr_number: None,
        queued_at: Utc::now(),
    };
    let _ = job_store.enqueue_job(job, rel_log).await;

    let cluster = ClusterRegistry::new();
    let (cmd_tx, _cmd_rx) = mpsc::channel(8);
    cluster
        .register(
            WorkerRegistration {
                node_id: "worker-riscv64".to_string(),
                arch: "riscv64".to_string(),
                tags: vec!["riscv64".to_string()],
                max_slots: 1,
                ram_total_mb: 32_768,
                btrfs_enabled: true,
                toolchains: vec!["system".to_string()],
                rust_semver: Some("1.90.0".to_string()),
            },
            cmd_tx,
        )
        .await;

    let console = ConsoleState::new(ConsoleConfig {
        github_api_url: None,
        cache_file: None,
        ..ConsoleConfig::default()
    });
    console
        .observe_webhook(
            "push",
            &json!({
                "repository": {
                    "full_name": "LMA1980/demo-public",
                    "private": false,
                    "visibility": "public",
                    "default_branch": "main"
                },
                "ref": "refs/heads/main",
                "after": "abcdef1234567890abcdef1234567890abcdef12"
            }),
            &job_store,
        )
        .await;
    console
        .observe_webhook(
            "push",
            &json!({
                "repository": {
                    "full_name": "LMA1980/demo-private",
                    "private": true,
                    "visibility": "private",
                    "default_branch": "main"
                },
                "ref": "refs/heads/main",
                "after": "1111111111111111111111111111111111111111"
            }),
            &job_store,
        )
        .await;

    let (tx, _rx) = mpsc::channel(16);
    let (log_broadcaster, _) = broadcast::channel(64);
    let state = Arc::new(AppState {
        config,
        job_store,
        cluster,
        tx,
        log_broadcaster,
        console,
    });
    let app = create_router(state);

    TestFixture {
        app,
        job_id,
        _tmp: tmp,
    }
}

fn assert_no_secret_leak(
    status: StatusCode,
    headers: &axum::http::HeaderMap,
    body: &str,
    ctx: &str,
) {
    for secret in [READONLY_TOKEN, ADMIN_TOKEN, INVALID_TOKEN] {
        assert!(
            !body.contains(secret),
            "Secret '{secret}' leaked into response body ({status}) for {ctx}: {body}"
        );
        for (name, val) in headers {
            if let Ok(s) = val.to_str() {
                assert!(
                    !s.contains(secret),
                    "Secret '{secret}' leaked into header '{name}' ({status}) for {ctx}"
                );
            }
        }
    }
}

async fn send(
    app: &Router,
    method: Method,
    uri: &str,
    headers: &[(&str, &str)],
    json_body: Option<Value>,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let mut builder = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let body = match json_body {
        Some(v) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    let resp = app
        .clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let resp_headers = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&bytes).into_owned();
    assert_no_secret_leak(status, &resp_headers, &text, uri);
    (status, resp_headers, text)
}

#[tokio::test]
async fn readonly_token_allows_strictly_readonly_inspection_routes() {
    let fx = build_fixture(true, true).await;
    let bearer_hdr = format!("Bearer {READONLY_TOKEN}");
    let lower_bearer_hdr = format!("bearer {READONLY_TOKEN}");

    let readonly_get_routes = [
        "/",
        "/health",
        "/api/health",
        "/ha/status",
        "/api/ha/status",
        "/api/cluster/nodes",
        "/cluster/status",
        "/api/cluster/status",
        "/queue",
        "/api/queue",
        "/api/ci/queue",
        "/jobs",
        "/api/jobs",
        "/api/repos",
        "/api/repos/LMA1980/demo-public/summary",
        "/api/repos/LMA1980/demo-public/topology",
        "/api/auth/folios",
        "/api/auth/session",
    ];

    for route in readonly_get_routes {
        let (st, _, body) = send(
            &fx.app,
            Method::GET,
            route,
            &[("Authorization", &bearer_hdr)],
            None,
        )
        .await;
        assert_eq!(
            st,
            StatusCode::OK,
            "GET {route} with RO Bearer token must return 200 OK; body={body}"
        );
    }

    // Also verify lowercase `bearer` and `X-Api-Key` header delivery
    for headers in [
        vec![("Authorization", lower_bearer_hdr.as_str())],
        vec![("X-Api-Key", READONLY_TOKEN)],
    ] {
        let (st, _, body) = send(&fx.app, Method::GET, "/api/auth/folios", &headers, None).await;
        assert_eq!(st, StatusCode::OK, "GET /api/auth/folios body={body}");
        let v: Value = serde_json::from_str(&body).unwrap();
        assert!(v["folios"].is_array());
        assert!(v["policies"].is_array());
    }

    // Verify job detail & log inspection endpoints succeed (and missing log returns 404, not 401/403)
    for route in [
        format!("/jobs/{}", fx.job_id),
        format!("/api/jobs/{}", fx.job_id),
        format!("/jobs/{}/log", fx.job_id),
        format!("/api/jobs/{}/log", fx.job_id),
        format!("/jobs/{}/logs", fx.job_id),
        format!("/api/jobs/{}/logs", fx.job_id),
    ] {
        let (st, _, body) = send(
            &fx.app,
            Method::GET,
            &route,
            &[("Authorization", &bearer_hdr)],
            None,
        )
        .await;
        assert_eq!(
            st,
            StatusCode::OK,
            "GET {route} with RO token must return 200 OK; body={body}"
        );
    }

    let (st_missing, _, _) = send(
        &fx.app,
        Method::GET,
        "/jobs/nonexistent-canary-probe/log",
        &[("Authorization", &bearer_hdr)],
        None,
    )
    .await;
    assert_eq!(st_missing, StatusCode::NOT_FOUND);

    // Verify /api/auth/session reports restricted readonly-service scope (never admin)
    let (_, _, sess_body) = send(
        &fx.app,
        Method::GET,
        "/api/auth/session",
        &[("Authorization", &bearer_hdr)],
        None,
    )
    .await;
    let sess: Value = serde_json::from_str(&sess_body).unwrap();
    assert_eq!(sess["authenticated"], true);
    assert_eq!(sess["role"], "readonly-service");
    let policies = sess["active_policies"].as_array().unwrap();
    assert!(policies.iter().any(|p| p == "platform:folios.read"));
    assert!(!policies.iter().any(|p| p == "platform:folios.write"));
    assert!(!policies.iter().any(|p| p == "ci:ha.write"));

    // Verify SSE /api/events accepts RO token and returns text/event-stream
    let sse_resp = fx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/events")
                .header(header::AUTHORIZATION, &bearer_hdr)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sse_resp.status(), StatusCode::OK);
    let ct = sse_resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.starts_with("text/event-stream"), "unexpected ct: {ct}");
}

#[tokio::test]
async fn readonly_token_rejects_all_mutating_and_admin_routes_with_403_forbidden() {
    let fx = build_fixture(true, true).await;
    let bearer_hdr = format!("Bearer {READONLY_TOKEN}");
    let admin_hdr = format!("Bearer {ADMIN_TOKEN}");

    let mutating_and_admin_cases: Vec<(Method, String, Option<Value>)> = vec![
        // HA failover mutations
        (Method::POST, "/ha/promote".to_string(), None),
        (Method::POST, "/api/ha/promote".to_string(), None),
        (Method::POST, "/ha/demote".to_string(), None),
        (Method::POST, "/api/ha/demote".to_string(), None),
        // Job control mutations (resume / retry / restart)
        (Method::POST, format!("/jobs/{}/resume", fx.job_id), None),
        (
            Method::POST,
            format!("/api/jobs/{}/resume", fx.job_id),
            None,
        ),
        (Method::POST, format!("/jobs/{}/retry", fx.job_id), None),
        (Method::POST, format!("/api/jobs/{}/retry", fx.job_id), None),
        (Method::POST, format!("/jobs/{}/restart", fx.job_id), None),
        (
            Method::POST,
            format!("/api/jobs/{}/restart", fx.job_id),
            None,
        ),
        // Webhook trigger
        (Method::POST, "/webhook".to_string(), Some(json!({}))),
        // Repository admin mutations
        (
            Method::POST,
            "/api/repos/prune".to_string(),
            Some(json!({ "repos": ["LMA1980/demo-public"] })),
        ),
        (
            Method::DELETE,
            "/api/repos/LMA1980/demo-public".to_string(),
            None,
        ),
        // Auth folio / role / index / user / invite mutations (both with JSON and without body!)
        (Method::POST, "/api/auth/folios".to_string(), None),
        (
            Method::POST,
            "/api/auth/folios".to_string(),
            Some(json!({ "id": "folio:op:evil" })),
        ),
        (
            Method::PUT,
            "/api/auth/folios".to_string(),
            Some(json!({ "id": "folio:op:evil" })),
        ),
        (
            Method::PUT,
            "/api/auth/folios/folio:op:evil".to_string(),
            Some(json!({})),
        ),
        (
            Method::DELETE,
            "/api/auth/folios/folio:op:evil".to_string(),
            None,
        ),
        (Method::POST, "/api/auth/roles".to_string(), Some(json!({}))),
        (Method::PUT, "/api/auth/roles".to_string(), Some(json!({}))),
        (
            Method::PUT,
            "/api/auth/roles/custom".to_string(),
            Some(json!({})),
        ),
        (Method::DELETE, "/api/auth/roles/custom".to_string(), None),
        (
            Method::PUT,
            "/api/auth/role-folio-index".to_string(),
            Some(json!({ "anonymous": [] })),
        ),
        (
            Method::POST,
            "/api/auth/role-folio-index".to_string(),
            Some(json!({ "anonymous": [] })),
        ),
        (Method::DELETE, "/api/auth/users/LMA1980".to_string(), None),
        (
            Method::PUT,
            "/api/auth/users/LMA1980/roles".to_string(),
            Some(json!({ "bound_roles": ["operator"] })),
        ),
        (
            Method::POST,
            "/api/auth/users/LMA1980/roles".to_string(),
            Some(json!({ "bound_roles": ["operator"] })),
        ),
        (
            Method::DELETE,
            "/api/auth/users/LMA1980/passkeys".to_string(),
            None,
        ),
        (
            Method::POST,
            "/api/auth/users/LMA1980/passkeys/reset".to_string(),
            None,
        ),
        (
            Method::DELETE,
            "/api/auth/users/LMA1980/passkeys/reset".to_string(),
            None,
        ),
        (
            Method::POST,
            "/api/auth/invites".to_string(),
            Some(json!({})),
        ),
        (
            Method::DELETE,
            "/api/auth/invites/inv-123".to_string(),
            None,
        ),
        // Interactive / self-service auth mutations
        (
            Method::POST,
            "/api/auth/redeem".to_string(),
            Some(json!({ "token": "inv_abc.123" })),
        ),
        (
            Method::PUT,
            "/api/auth/profile".to_string(),
            Some(json!({ "display_name": "Evil" })),
        ),
        (
            Method::PATCH,
            "/api/auth/profile".to_string(),
            Some(json!({ "display_name": "Evil" })),
        ),
        (
            Method::POST,
            "/api/auth/passkeys/register/start".to_string(),
            Some(json!({})),
        ),
        (
            Method::POST,
            "/api/auth/passkeys/assert/start".to_string(),
            None,
        ),
        (
            Method::DELETE,
            "/api/auth/passkeys/cred-1".to_string(),
            None,
        ),
        (
            Method::POST,
            "/api/auth/elevate/start".to_string(),
            Some(json!({})),
        ),
        (Method::POST, "/api/auth/elevate/lock-all".to_string(), None),
        (Method::POST, "/api/auth/roles/lock".to_string(), None),
        (
            Method::POST,
            "/api/auth/roles/ci-operator/enable".to_string(),
            None,
        ),
        (
            Method::POST,
            "/api/auth/roles/ci-operator/disable".to_string(),
            None,
        ),
        (Method::POST, "/api/auth/activity".to_string(), None),
        // Privileged / administrative / non-allowlisted GET routes
        (Method::GET, "/api/auth/users".to_string(), None),
        (Method::GET, "/api/auth/invites".to_string(), None),
        (Method::GET, "/api/auth/roles".to_string(), None),
        (Method::GET, "/api/auth/role-folio-index".to_string(), None),
        (Method::GET, "/api/auth/profile".to_string(), None),
        (Method::GET, "/api/auth/passkeys".to_string(), None),
        (Method::GET, "/api/internal/auth/snapshot".to_string(), None),
        (Method::GET, "/api/cluster/tunnel".to_string(), None),
    ];

    for (method, path, body) in &mutating_and_admin_cases {
        // Test with Authorization: Bearer <ro-token>
        let (st_bearer, _, resp_body) = send(
            &fx.app,
            method.clone(),
            path,
            &[("Authorization", &bearer_hdr)],
            body.clone(),
        )
        .await;
        assert_eq!(
            st_bearer,
            StatusCode::FORBIDDEN,
            "{method} {path} with RO Bearer token must return 403 Forbidden (not 401); got {st_bearer}: {resp_body}"
        );

        // Test with X-Api-Key: <ro-token>
        let (st_xkey, _, resp_body_x) = send(
            &fx.app,
            method.clone(),
            path,
            &[("X-Api-Key", READONLY_TOKEN)],
            body.clone(),
        )
        .await;
        assert_eq!(
            st_xkey,
            StatusCode::FORBIDDEN,
            "{method} {path} with RO X-Api-Key must return 403 Forbidden; got {st_xkey}: {resp_body_x}"
        );
    }

    // Query-string RO token on privileged cluster tunnel must also return 403
    let (st_qs_tunnel, _, _) = send(
        &fx.app,
        Method::GET,
        &format!("/api/cluster/tunnel?token={READONLY_TOKEN}"),
        &[],
        None,
    )
    .await;
    assert_eq!(st_qs_tunnel, StatusCode::FORBIDDEN);

    // Combined admin + RO headers OR RO + edge proxy headers monotonically attenuate to 403
    let (st_combined_admin_ro, _, _) = send(
        &fx.app,
        Method::POST,
        "/api/ha/promote",
        &[("X-Api-Key", ADMIN_TOKEN), ("Authorization", &bearer_hdr)],
        None,
    )
    .await;
    assert_eq!(st_combined_admin_ro, StatusCode::FORBIDDEN);

    let (st_combined_proxy_ro, _, _) = send(
        &fx.app,
        Method::POST,
        "/api/ha/promote",
        &[
            ("Authorization", &bearer_hdr),
            ("X-Proxy-Secret", PROXY_SECRET),
            ("X-Forwarded-User", "LMA1980"),
        ],
        None,
    )
    .await;
    assert_eq!(st_combined_proxy_ro, StatusCode::FORBIDDEN);

    // Full admin API key retains full administrative & mutating privileges
    let (st_admin_promote, _, _) = send(
        &fx.app,
        Method::POST,
        "/api/ha/promote",
        &[("Authorization", &admin_hdr)],
        None,
    )
    .await;
    assert_eq!(st_admin_promote, StatusCode::OK);

    let (st_admin_users, _, _) = send(
        &fx.app,
        Method::GET,
        "/api/auth/users",
        &[("Authorization", &admin_hdr)],
        None,
    )
    .await;
    assert_eq!(st_admin_users, StatusCode::OK);

    let (st_admin_snap, _, _) = send(
        &fx.app,
        Method::GET,
        "/api/internal/auth/snapshot",
        &[("Authorization", &admin_hdr)],
        None,
    )
    .await;
    assert_eq!(st_admin_snap, StatusCode::OK);
}

#[tokio::test]
async fn invalid_token_returns_401_and_lockdown_allows_readonly_token() {
    let fx = build_fixture(true, false).await;
    let invalid_hdr = format!("Bearer {INVALID_TOKEN}");
    let ro_hdr = format!("Bearer {READONLY_TOKEN}");
    let admin_hdr = format!("Bearer {ADMIN_TOKEN}");

    let protected_routes = [
        (Method::GET, "/api/auth/folios".to_string()),
        (Method::GET, format!("/jobs/{}/log", fx.job_id)),
        (Method::GET, "/api/auth/users".to_string()),
        (Method::GET, "/api/internal/auth/snapshot".to_string()),
        (Method::GET, "/api/events".to_string()),
        (Method::POST, "/api/ha/promote".to_string()),
        (Method::POST, format!("/api/jobs/{}/resume", fx.job_id)),
        (Method::POST, "/api/repos/prune".to_string()),
        (Method::DELETE, "/api/repos/LMA1980/demo-public".to_string()),
    ];

    for (method, path) in &protected_routes {
        let (st_invalid, _, body) = send(
            &fx.app,
            method.clone(),
            path,
            &[("Authorization", &invalid_hdr)],
            None,
        )
        .await;
        assert_eq!(
            st_invalid,
            StatusCode::UNAUTHORIZED,
            "{method} {path} with invalid token must return 401; got {st_invalid}: {body}"
        );
    }

    // Enable anonymous lockdown (anonymous = []) using admin key
    let (st_lock, _, body_lock) = send(
        &fx.app,
        Method::PUT,
        "/api/auth/role-folio-index",
        &[("Authorization", &admin_hdr)],
        Some(json!({ "anonymous": [] })),
    )
    .await;
    assert_eq!(st_lock, StatusCode::OK, "lockdown failed: {body_lock}");

    // Under anonymous lockdown: invalid token gets 401 on inspection routes, RO token gets 200 OK
    for path in [
        "/api/ha/status",
        "/api/cluster/nodes",
        "/api/queue",
        "/api/repos",
        "/api/jobs",
    ] {
        let (st_inv, _, _) = send(
            &fx.app,
            Method::GET,
            path,
            &[("Authorization", &invalid_hdr)],
            None,
        )
        .await;
        assert_eq!(
            st_inv,
            StatusCode::UNAUTHORIZED,
            "GET {path} under lockdown with invalid token must return 401"
        );

        let (st_ro, _, body_ro) = send(
            &fx.app,
            Method::GET,
            path,
            &[("Authorization", &ro_hdr)],
            None,
        )
        .await;
        assert_eq!(
            st_ro,
            StatusCode::OK,
            "GET {path} under lockdown with RO token must return 200 OK: {body_ro}"
        );
    }
}

#[tokio::test]
async fn readonly_token_only_config_fails_closed_on_invalid_and_allows_readonly() {
    // Configure ONLY readonly_api_token (no log_api_key, no proxy_secret)
    let fx = build_fixture(false, false).await;
    let ro_hdr = format!("Bearer {READONLY_TOKEN}");
    let invalid_hdr = format!("Bearer {INVALID_TOKEN}");

    let (st_unauth, _, _) = send(&fx.app, Method::GET, "/api/auth/folios", &[], None).await;
    assert_eq!(st_unauth, StatusCode::UNAUTHORIZED);

    let (st_invalid, _, _) = send(
        &fx.app,
        Method::GET,
        "/api/auth/folios",
        &[("Authorization", &invalid_hdr)],
        None,
    )
    .await;
    assert_eq!(st_invalid, StatusCode::UNAUTHORIZED);

    let (st_ro_get, _, _) = send(
        &fx.app,
        Method::GET,
        "/api/auth/folios",
        &[("Authorization", &ro_hdr)],
        None,
    )
    .await;
    assert_eq!(st_ro_get, StatusCode::OK);

    let (st_ro_post, _, _) = send(
        &fx.app,
        Method::POST,
        "/api/ha/promote",
        &[("Authorization", &ro_hdr)],
        None,
    )
    .await;
    assert_eq!(st_ro_post, StatusCode::FORBIDDEN);
}
