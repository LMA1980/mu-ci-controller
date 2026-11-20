#![deny(unsafe_code)]

use mu_ci_controller::app::create_router;
use mu_ci_controller::cluster::ClusterRegistry;
use mu_ci_controller::config::{Config, HaRoleConfig};
use mu_ci_controller::console::ConsoleState;
use mu_ci_controller::job::JobStore;
use mu_ci_controller::tls::{
    build_mtls_server_config, load_certs, load_private_key, load_root_cert_store,
};
use mu_ci_controller::webhook::AppState;
use mu_ci_ipc::WorkerRegistration;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use reqwest::Client;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio_rustls::TlsAcceptor;

#[derive(Debug, Clone)]
struct SmokeConfig {
    target_url: Option<String>,
    bearer_token: Option<String>,
    tls_ca_pem: Option<Vec<u8>>,
    tls_cert_pem: Option<Vec<u8>>,
    tls_key_pem: Option<Vec<u8>>,
    timeout: Duration,
}

fn read_trimmed_secret_file(var_name: &str, path_raw: &str) -> Result<String, String> {
    let path = path_raw.trim();
    if path.is_empty() {
        return Err(format!("{var_name} was set to an empty path"));
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {var_name} at '{path}': {e}"))?;
    let trimmed = raw.trim().to_string();
    if trimmed.is_empty() {
        return Err(format!("{var_name} at '{path}' is empty"));
    }
    Ok(trimmed)
}

fn read_non_empty_file_bytes(var_name: &str, path_raw: &str) -> Result<Vec<u8>, String> {
    let path = path_raw.trim();
    if path.is_empty() {
        return Err(format!("{var_name} was set to an empty path"));
    }
    let bytes =
        std::fs::read(path).map_err(|e| format!("Failed to read {var_name} at '{path}': {e}"))?;
    if bytes.is_empty() {
        return Err(format!("{var_name} at '{path}' is empty"));
    }
    Ok(bytes)
}

fn load_smoke_config_with<F>(get_env: F) -> Result<SmokeConfig, String>
where
    F: Fn(&str) -> Option<String>,
{
    let target_url = get_env("MU_SMOKE_TARGET_URL")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let bearer_token = match get_env("MU_SMOKE_BEARER_TOKEN_FILE")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        Some(path) => Some(read_trimmed_secret_file(
            "MU_SMOKE_BEARER_TOKEN_FILE",
            &path,
        )?),
        None => None,
    };

    let tls_ca_pem = match get_env("MU_SMOKE_TLS_CA_FILE")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        Some(path) => Some(read_non_empty_file_bytes("MU_SMOKE_TLS_CA_FILE", &path)?),
        None => None,
    };

    let cert_path = get_env("MU_SMOKE_TLS_CERT_FILE")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let key_path = get_env("MU_SMOKE_TLS_KEY_FILE")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let (tls_cert_pem, tls_key_pem) = match (cert_path, key_path) {
        (Some(cert), Some(key)) => (
            Some(read_non_empty_file_bytes("MU_SMOKE_TLS_CERT_FILE", &cert)?),
            Some(read_non_empty_file_bytes("MU_SMOKE_TLS_KEY_FILE", &key)?),
        ),
        (Some(_), None) | (None, Some(_)) => {
            return Err(
                "MU_SMOKE_TLS_CERT_FILE and MU_SMOKE_TLS_KEY_FILE must both be set together"
                    .to_string(),
            );
        }
        (None, None) => (None, None),
    };

    let timeout_secs = match get_env("MU_SMOKE_TIMEOUT_SECS")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        Some(raw) => {
            let secs = raw.parse::<u64>().map_err(|e| {
                format!("Invalid MU_SMOKE_TIMEOUT_SECS '{raw}': expected positive integer ({e})")
            })?;
            if secs == 0 {
                return Err("MU_SMOKE_TIMEOUT_SECS must be greater than zero".to_string());
            }
            secs
        }
        None => 10,
    };

    Ok(SmokeConfig {
        target_url,
        bearer_token,
        tls_ca_pem,
        tls_cert_pem,
        tls_key_pem,
        timeout: Duration::from_secs(timeout_secs),
    })
}

fn load_smoke_config() -> Result<SmokeConfig, String> {
    load_smoke_config_with(|k| std::env::var(k).ok())
}

fn build_http_client(cfg: &SmokeConfig) -> Result<Client, String> {
    let mut builder = Client::builder().timeout(cfg.timeout);
    if let Some(ref ca_pem) = cfg.tls_ca_pem {
        let certs = reqwest::Certificate::from_pem_bundle(ca_pem)
            .map_err(|e| format!("Invalid MU_SMOKE_TLS_CA_FILE PEM: {e}"))?;
        for cert in certs {
            builder = builder.add_root_certificate(cert);
        }
    }
    if let (Some(cert_pem), Some(key_pem)) = (&cfg.tls_cert_pem, &cfg.tls_key_pem) {
        let mut combined = cert_pem.clone();
        if !combined.ends_with(b"\n") {
            combined.push(b'\n');
        }
        combined.extend_from_slice(key_pem);
        let identity = reqwest::Identity::from_pem(&combined)
            .map_err(|e| format!("Invalid MU_SMOKE_TLS_CERT_FILE/KEY_FILE identity: {e}"))?;
        builder = builder.identity(identity);
    }
    builder
        .build()
        .map_err(|e| format!("Failed building smoke HTTP client: {e}"))
}

fn assert_cluster_node_schema(node: &serde_json::Value) {
    assert!(
        node["node_id"].is_string(),
        "node_id must be string: {node}"
    );
    assert!(node["arch"].is_string(), "arch must be string: {node}");
    assert!(node["tags"].is_array(), "tags must be array: {node}");
    assert!(
        node["max_slots"].is_u64(),
        "max_slots must be integer: {node}"
    );
    assert!(
        node["active_slots"].is_u64(),
        "active_slots must be integer: {node}"
    );
    assert!(
        node["exclusive_locked"].is_boolean(),
        "exclusive_locked must be bool: {node}"
    );
    assert!(
        node["ram_total_mb"].is_u64(),
        "ram_total_mb must be integer: {node}"
    );
    assert!(
        node["ram_used_mb"].is_u64(),
        "ram_used_mb must be integer: {node}"
    );
    assert!(
        node["cpu_load_pct"].is_number(),
        "cpu_load_pct must be number: {node}"
    );
    assert!(
        node["btrfs_enabled"].is_boolean(),
        "btrfs_enabled must be bool: {node}"
    );
    assert!(
        node["toolchains"].is_array(),
        "toolchains must be array: {node}"
    );
    assert!(
        node["last_seen_secs_ago"].is_u64(),
        "last_seen_secs_ago must be integer: {node}"
    );
    assert!(
        node["is_online"].is_boolean(),
        "is_online must be bool: {node}"
    );
}

async fn run_controller_readonly_checks(
    client: &Client,
    base_url: &str,
    bearer_token: Option<&str>,
    expect_ephemeral_node: bool,
) {
    let base = base_url.trim_end_matches('/');

    // 1. /health (200 OK, status == "ok")
    let health_resp = client
        .get(format!("{base}/health"))
        .send()
        .await
        .expect("GET /health request must succeed");
    assert_eq!(health_resp.status(), 200);
    let health_json: serde_json::Value = health_resp.json().await.unwrap();
    assert_eq!(health_json["status"], "ok");
    assert!(health_json["controller_id"].is_string());
    assert!(health_json["ha_role"].is_string());

    // 2. /api/ha/status
    let mut ha_req = client.get(format!("{base}/api/ha/status"));
    if let Some(tok) = bearer_token {
        ha_req = ha_req.bearer_auth(tok);
    }
    let ha_resp = ha_req
        .send()
        .await
        .expect("GET /api/ha/status must succeed");
    assert_eq!(ha_resp.status(), 200);
    let ha_json: serde_json::Value = ha_resp.json().await.unwrap();
    assert_eq!(ha_json["status"], "ok");
    assert!(ha_json["ha_role"].is_string());
    assert!(ha_json["ha_policy"].is_string());
    assert!(ha_json["lease_ttl_seconds"].is_u64());
    assert!(ha_json["standby_sync_seconds"].is_u64());

    // 3. /api/cluster/nodes schema check
    let mut nodes_req = client.get(format!("{base}/api/cluster/nodes"));
    if let Some(tok) = bearer_token {
        nodes_req = nodes_req.bearer_auth(tok);
    }
    let nodes_resp = nodes_req
        .send()
        .await
        .expect("GET /api/cluster/nodes must succeed");
    assert_eq!(nodes_resp.status(), 200);
    let nodes_json: serde_json::Value = nodes_resp.json().await.unwrap();
    let nodes = nodes_json
        .as_array()
        .expect("/api/cluster/nodes must return a JSON array");
    if expect_ephemeral_node {
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0]["node_id"], "worker-riscv64");
        assert_eq!(nodes[0]["arch"], "riscv64");
        assert_eq!(nodes[0]["is_online"], true);
    }
    for node in nodes {
        assert_cluster_node_schema(node);
    }

    // 4. Unauthenticated 401 vs valid Bearer / x-api-key 200 (and 404 for unknown read-only job log)
    let unauth_folios = client
        .get(format!("{base}/api/auth/folios"))
        .send()
        .await
        .expect("Unauthenticated GET /api/auth/folios must connect");
    assert_eq!(
        unauth_folios.status(),
        401,
        "Unauthenticated /api/auth/folios must fail closed with 401"
    );

    let unauth_log = client
        .get(format!("{base}/jobs/nonexistent-smoke-probe/log"))
        .send()
        .await
        .expect("Unauthenticated GET /jobs/.../log must connect");
    assert_eq!(
        unauth_log.status(),
        401,
        "Unauthenticated /jobs/.../log must fail closed with 401"
    );

    if let Some(tok) = bearer_token {
        let auth_folios = client
            .get(format!("{base}/api/auth/folios"))
            .bearer_auth(tok)
            .send()
            .await
            .expect("Bearer GET /api/auth/folios must succeed");
        assert_eq!(auth_folios.status(), 200);
        let folios_json: serde_json::Value = auth_folios.json().await.unwrap();
        assert!(folios_json["folios"].is_array());
        assert!(folios_json["policies"].is_array());

        let api_key_folios = client
            .get(format!("{base}/api/auth/folios"))
            .header("x-api-key", tok)
            .send()
            .await
            .expect("x-api-key GET /api/auth/folios must succeed");
        assert_eq!(api_key_folios.status(), 200);

        let auth_missing_log = client
            .get(format!("{base}/jobs/nonexistent-smoke-probe/log"))
            .bearer_auth(tok)
            .send()
            .await
            .expect("Authenticated missing job log probe must succeed");
        assert_eq!(auth_missing_log.status(), 404);
    }
}

#[tokio::test]
#[cfg_attr(miri, ignore)]
async fn smoke_mu_ci_controller_endpoints_and_auth() {
    let cfg = load_smoke_config().expect("Smoke environment configuration must be valid");
    let client = build_http_client(&cfg).expect("HTTP client initialization must succeed");

    if let Some(ref target_url) = cfg.target_url {
        run_controller_readonly_checks(&client, target_url, cfg.bearer_token.as_deref(), false)
            .await;
        return;
    }

    let tmp_ws = tempdir().unwrap();
    let api_key = "ephemeral-controller-smoke-key".to_string();
    let config = Config {
        bind_addr: "127.0.0.1:0".to_string(),
        workspace_dir: tmp_ws.path().to_path_buf(),
        allowed_repositories: vec!["LMA1980/*".to_string()],
        allowed_actors: vec!["*".to_string()],
        allow_fork_prs: false,
        allowed_pr_authors: vec!["OWNER".to_string()],
        log_api_key: Some(api_key.clone()),
        webhook_secret: None,
        cluster_token: "ephemeral-cluster-token".to_string(),
        job_timeout_seconds: 30,
        allow_insecure_no_secret: true,
        max_concurrent_jobs: 2,
        node_id: "node-a".to_string(),
        ha_role: HaRoleConfig::Leader,
        ..Config::default()
    };

    let cluster = ClusterRegistry::new();
    let (cmd_tx, _cmd_rx) = mpsc::channel(8);
    cluster
        .register(
            WorkerRegistration {
                node_id: "worker-riscv64".to_string(),
                arch: "riscv64".to_string(),
                tags: vec!["riscv64".to_string(), "rvv".to_string()],
                max_slots: 1,
                ram_total_mb: 32_768,
                btrfs_enabled: true,
                toolchains: vec!["system".to_string()],
                rust_semver: Some("1.90.0".to_string()),
            },
            cmd_tx,
        )
        .await;

    let (tx, _rx) = mpsc::channel(16);
    let (log_broadcaster, _) = tokio::sync::broadcast::channel(32);
    let state = Arc::new(AppState {
        config,
        job_store: JobStore::new(50, None),
        cluster,
        tx,
        log_broadcaster,
        console: ConsoleState::default(),
    });
    let app = create_router(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let srv_task = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = stop_rx.await;
            })
            .await;
    });

    run_controller_readonly_checks(&client, &format!("http://{addr}"), Some(&api_key), true).await;

    let _ = stop_tx.send(());
    let _ = srv_task.await;
}

#[tokio::test]
#[cfg_attr(miri, ignore)]
async fn smoke_mu_ci_controller_mtls_client_and_fail_closed_files() {
    // 1. Fail-closed credential file checks
    let missing_tok = load_smoke_config_with(|k| match k {
        "MU_SMOKE_BEARER_TOKEN_FILE" => Some("/nonexistent/controller-smoke-token".to_string()),
        _ => None,
    })
    .unwrap_err();
    assert!(missing_tok.contains("MU_SMOKE_BEARER_TOKEN_FILE"));

    let missing_ca = load_smoke_config_with(|k| match k {
        "MU_SMOKE_TLS_CA_FILE" => Some("/nonexistent/controller-smoke-ca.crt".to_string()),
        _ => None,
    })
    .unwrap_err();
    assert!(missing_ca.contains("MU_SMOKE_TLS_CA_FILE"));

    let partial_mtls = load_smoke_config_with(|k| match k {
        "MU_SMOKE_TLS_CERT_FILE" => Some("/tmp/only-cert.crt".to_string()),
        _ => None,
    })
    .unwrap_err();
    assert!(partial_mtls.contains("MU_SMOKE_TLS_KEY_FILE"));

    // 2. Ephemeral mTLS listener verifying SmokeConfig CA + client cert/key loading end-to-end
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tmp = tempdir().unwrap();

    let mut ca_params = CertificateParams::default();
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "Jero-Mu Controller Smoke CA");
    ca_params.distinguished_name = ca_dn;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

    let mut srv_params =
        CertificateParams::new(vec!["127.0.0.1".to_string(), "localhost".to_string()]).unwrap();
    srv_params.is_ca = IsCa::NoCa;
    srv_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let srv_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let srv_cert = srv_params.signed_by(&srv_key, &ca).unwrap();

    let mut cli_params = CertificateParams::new(vec!["node-a.example".to_string()]).unwrap();
    cli_params.is_ca = IsCa::NoCa;
    cli_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let cli_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cli_cert = cli_params.signed_by(&cli_key, &ca).unwrap();

    let ca_path = tmp.path().join("ca.crt");
    let srv_cert_path = tmp.path().join("srv.crt");
    let srv_key_path = tmp.path().join("srv.key");
    let cli_cert_path = tmp.path().join("cli.crt");
    let cli_key_path = tmp.path().join("cli.key");
    let tok_path = tmp.path().join("bearer.token");

    std::fs::write(&ca_path, ca.pem()).unwrap();
    std::fs::write(&srv_cert_path, srv_cert.pem()).unwrap();
    std::fs::write(&srv_key_path, srv_key.serialize_pem()).unwrap();
    std::fs::write(&cli_cert_path, cli_cert.pem()).unwrap();
    std::fs::write(&cli_key_path, cli_key.serialize_pem()).unwrap();
    std::fs::write(&tok_path, "  mtls-smoke-bearer  \n").unwrap();

    let server_tls = build_mtls_server_config(
        load_certs(&srv_cert_path).unwrap(),
        load_private_key(&srv_key_path).unwrap(),
        load_root_cert_store(&ca_path).unwrap(),
    )
    .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_tls));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let srv_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.unwrap();
        let mut raw = Vec::new();
        let mut buf = [0u8; 2048];
        while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = tls.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..n]);
        }
        let req = String::from_utf8_lossy(&raw).to_ascii_lowercase();
        assert!(
            req.contains("authorization: bearer mtls-smoke-bearer"),
            "missing bearer header in mTLS request: {req}"
        );
        let body = r#"{"status":"ok"}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        tls.write_all(resp.as_bytes()).await.unwrap();
        tls.flush().await.unwrap();
        tls.shutdown().await.unwrap();
    });

    let smoke_cfg = load_smoke_config_with(|k| match k {
        "MU_SMOKE_TARGET_URL" => Some(format!("https://{addr}")),
        "MU_SMOKE_TLS_CA_FILE" => Some(ca_path.to_string_lossy().into_owned()),
        "MU_SMOKE_TLS_CERT_FILE" => Some(cli_cert_path.to_string_lossy().into_owned()),
        "MU_SMOKE_TLS_KEY_FILE" => Some(cli_key_path.to_string_lossy().into_owned()),
        "MU_SMOKE_BEARER_TOKEN_FILE" => Some(tok_path.to_string_lossy().into_owned()),
        _ => None,
    })
    .unwrap();
    let client = build_http_client(&smoke_cfg).unwrap();
    let resp = client
        .get(format!("https://{addr}/health"))
        .bearer_auth(smoke_cfg.bearer_token.as_deref().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    let _ = srv_task.await;
}
