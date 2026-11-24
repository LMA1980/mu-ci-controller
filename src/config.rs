use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};
use tracing::{error, info, warn};

/// Configured High-Availability role policy for a controller instance (`#78`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum HaRoleConfig {
    /// Automatically acquires or renews the single-leader lease in `ControllerStorage`;
    /// starts in `standby` if another node holds a valid lease, and promotes to `leader`
    /// when the primary lease expires.
    Auto,
    /// Explicitly starts as the active `leader`.
    #[default]
    Leader,
    /// Explicitly starts as a hot `standby` replica (does not claim jobs until promoted).
    Standby,
}

impl HaRoleConfig {
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "auto" => Self::Auto,
            "standby" | "follower" | "backup" => Self::Standby,
            _ => Self::Leader,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Leader => "leader",
            Self::Standby => "standby",
        }
    }
}

/// Runtime High-Availability role of a controller instance (`#78`–`#80`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum HaRole {
    #[default]
    Leader,
    Standby,
}

impl HaRole {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Leader => "leader",
            Self::Standby => "standby",
        }
    }

    #[must_use]
    pub const fn is_leader(self) -> bool {
        matches!(self, Self::Leader)
    }
}

#[derive(Clone)]
pub struct Config {
    pub bind_addr: String,
    pub workspace_dir: PathBuf,
    pub allowed_repositories: Vec<String>,
    pub allowed_actors: Vec<String>,
    pub allow_fork_prs: bool,
    pub allowed_pr_authors: Vec<String>,
    pub log_api_key: Option<String>,
    /// Optional dedicated read-only service bearer token for least-privilege
    /// inspection probes (resolved strictly fail-closed from a file path).
    pub readonly_api_token: Option<String>,
    pub webhook_secret: Option<String>,
    pub cluster_token: String,
    pub job_timeout_seconds: u64,
    pub allow_insecure_no_secret: bool,
    pub max_concurrent_jobs: usize,
    pub github_token: Option<String>,
    pub node_id: String,
    pub ha_role: HaRoleConfig,
    pub lease_ttl_seconds: u64,
    pub standby_sync_seconds: u64,
    pub proxy_secret: Option<String>,
    pub invite_signing_key: Option<String>,
    pub bootstrap_admins: Vec<String>,
    pub quic_bind_addr: Option<String>,
    pub quic_alt_svc_port: Option<u16>,
    pub quic_alt_svc_max_age: Option<u64>,
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
    pub tls_ca_path: Option<PathBuf>,
    /// WebAuthn Relying Party ID (domain, e.g., `localhost` or `console.example.org`).
    pub webauthn_rp_id: String,
    /// WebAuthn Relying Party human-readable display name.
    pub webauthn_rp_name: String,
    /// WebAuthn expected origin (`http://localhost` or `https://console.example.org`).
    pub webauthn_rp_origin: String,
    /// Dedicated HMAC secret for `__Host-mu_elevated` cookies (falls back to `invite_signing_key`).
    pub host_elevation_secret: Option<String>,
    /// Optional explicit path for persistent platform auth state JSON.
    pub auth_state_file: Option<PathBuf>,
}

fn redacted_opt(opt: &Option<String>) -> &'static str {
    if opt.is_some() {
        "<redacted>"
    } else {
        "<unset>"
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("bind_addr", &self.bind_addr)
            .field("workspace_dir", &self.workspace_dir)
            .field("allowed_repositories", &self.allowed_repositories)
            .field("allowed_actors", &self.allowed_actors)
            .field("allow_fork_prs", &self.allow_fork_prs)
            .field("allowed_pr_authors", &self.allowed_pr_authors)
            .field("log_api_key", &redacted_opt(&self.log_api_key))
            .field(
                "readonly_api_token",
                &redacted_opt(&self.readonly_api_token),
            )
            .field("webhook_secret", &redacted_opt(&self.webhook_secret))
            .field("cluster_token", &"<redacted>")
            .field("job_timeout_seconds", &self.job_timeout_seconds)
            .field("allow_insecure_no_secret", &self.allow_insecure_no_secret)
            .field("max_concurrent_jobs", &self.max_concurrent_jobs)
            .field("github_token", &redacted_opt(&self.github_token))
            .field("node_id", &self.node_id)
            .field("ha_role", &self.ha_role)
            .field("lease_ttl_seconds", &self.lease_ttl_seconds)
            .field("standby_sync_seconds", &self.standby_sync_seconds)
            .field("proxy_secret", &redacted_opt(&self.proxy_secret))
            .field(
                "invite_signing_key",
                &redacted_opt(&self.invite_signing_key),
            )
            .field("bootstrap_admins", &self.bootstrap_admins)
            .field("quic_bind_addr", &self.quic_bind_addr)
            .field("quic_alt_svc_port", &self.quic_alt_svc_port)
            .field("quic_alt_svc_max_age", &self.quic_alt_svc_max_age)
            .field("tls_cert_path", &self.tls_cert_path)
            .field("tls_key_path", &self.tls_key_path)
            .field("tls_ca_path", &self.tls_ca_path)
            .field("webauthn_rp_id", &self.webauthn_rp_id)
            .field("webauthn_rp_name", &self.webauthn_rp_name)
            .field("webauthn_rp_origin", &self.webauthn_rp_origin)
            .field(
                "host_elevation_secret",
                &redacted_opt(&self.host_elevation_secret),
            )
            .field("auth_state_file", &self.auth_state_file)
            .finish()
    }
}

/// Returns the first non-empty trimmed value among `vars` using a custom env lookup.
pub(crate) fn first_non_empty_in<F>(vars: &[&str], get_env: &F) -> Option<String>
where
    F: Fn(&str) -> Option<String>,
{
    for var in vars {
        if let Some(val) = get_env(var) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// Parses the first valid value of `T` among `vars` using a custom env lookup.
pub(crate) fn first_parsed_in<T, F>(vars: &[&str], get_env: &F) -> Option<T>
where
    T: std::str::FromStr,
    F: Fn(&str) -> Option<String>,
{
    for var in vars {
        if let Some(val) = get_env(var) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                if let Ok(parsed) = trimmed.parse::<T>() {
                    return Some(parsed);
                }
            }
        }
    }
    None
}

/// Returns the first non-empty trimmed value among `vars`.
pub(crate) fn first_non_empty_env(vars: &[&str]) -> Option<String> {
    first_non_empty_in(vars, &|k| std::env::var(k).ok())
}

/// Parses the first valid value of `T` among `vars`.
pub(crate) fn first_parsed_env<T: std::str::FromStr>(vars: &[&str]) -> Option<T> {
    first_parsed_in(vars, &|k| std::env::var(k).ok())
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:8000".to_string(),
            workspace_dir: PathBuf::from("/var/lib/mu-ci-controller/workspace"),
            allowed_repositories: vec!["LMA1980/*".to_string()],
            allowed_actors: vec!["*".to_string()],
            allow_fork_prs: false,
            allowed_pr_authors: vec![
                "OWNER".to_string(),
                "MEMBER".to_string(),
                "COLLABORATOR".to_string(),
            ],
            log_api_key: None,
            readonly_api_token: None,
            webhook_secret: None,
            cluster_token: "actionrunner_default_cluster_token".to_string(),
            job_timeout_seconds: 1800,
            allow_insecure_no_secret: false,
            max_concurrent_jobs: 3,
            github_token: None,
            node_id: "node-a".to_string(),
            ha_role: HaRoleConfig::Leader,
            lease_ttl_seconds: 15,
            standby_sync_seconds: 5,
            proxy_secret: None,
            invite_signing_key: None,
            bootstrap_admins: Vec::new(),
            quic_bind_addr: None,
            quic_alt_svc_port: None,
            quic_alt_svc_max_age: None,
            tls_cert_path: None,
            tls_key_path: None,
            tls_ca_path: None,
            webauthn_rp_id: "localhost".to_string(),
            webauthn_rp_name: "MuConsole Platform".to_string(),
            webauthn_rp_origin: "http://localhost".to_string(),
            host_elevation_secret: None,
            auth_state_file: None,
        }
    }
}

impl Config {
    /// Resolve the default workspace directory, preferring `mu_root/workspace` unless only
    /// `legacy_root` exists on disk.
    #[must_use]
    pub fn resolve_default_workspace_dir(mu_root: &Path, legacy_root: &Path) -> PathBuf {
        if mu_root.is_dir() {
            mu_root.join("workspace")
        } else if legacy_root.is_dir() {
            legacy_root.join("workspace")
        } else {
            mu_root.join("workspace")
        }
    }

    pub fn load() -> Self {
        Self::load_with_env(|k| std::env::var(k).ok())
    }

    pub fn load_with_env<F>(get_env: F) -> Self
    where
        F: Fn(&str) -> Option<String>,
    {
        let bind_addr =
            first_non_empty_in(&["MU_CI_CONTROLLER_BIND", "ACTION_RUNNER_BIND"], &get_env)
                .unwrap_or_else(|| "127.0.0.1:8000".to_string());

        let workspace_dir = first_non_empty_in(
            &["MU_CI_CONTROLLER_WORKSPACE", "ACTION_RUNNER_WORKSPACE"],
            &get_env,
        )
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Self::resolve_default_workspace_dir(
                Path::new("/var/lib/mu-ci-controller"),
                Path::new("/var/lib/action-runner"),
            )
        });

        let allowed_repositories = first_non_empty_in(
            &[
                "MU_CI_CONTROLLER_ALLOWED_REPOS",
                "ACTION_RUNNER_ALLOWED_REPOS",
            ],
            &get_env,
        )
        .unwrap_or_else(|| "LMA1980/*".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

        let allowed_actors = first_non_empty_in(
            &[
                "MU_CI_CONTROLLER_ALLOWED_ACTORS",
                "ACTION_RUNNER_ALLOWED_ACTORS",
            ],
            &get_env,
        )
        .unwrap_or_else(|| "*".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

        let allow_fork_prs = first_non_empty_in(
            &[
                "MU_CI_CONTROLLER_ALLOW_FORK_PRS",
                "ACTION_RUNNER_ALLOW_FORK_PRS",
            ],
            &get_env,
        )
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false);

        let allowed_pr_authors = first_non_empty_in(
            &[
                "MU_CI_CONTROLLER_ALLOWED_PR_AUTHORS",
                "ACTION_RUNNER_ALLOWED_PR_AUTHORS",
            ],
            &get_env,
        )
        .unwrap_or_else(|| "OWNER,MEMBER,COLLABORATOR".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

        let log_api_key = Self::resolve_secret_first_with_env(
            &["MU_CI_CONTROLLER_LOG_API_KEY", "ACTION_RUNNER_LOG_API_KEY"],
            &get_env,
        );

        let readonly_api_token = Self::resolve_strict_token_file_first_with_env(
            &[
                "MU_CI_CONTROLLER_READONLY_TOKEN_FILE",
                "MU_CI_READONLY_TOKEN_FILE",
            ],
            &get_env,
        );

        let allow_insecure_no_secret = first_non_empty_in(
            &[
                "MU_CI_CONTROLLER_ALLOW_INSECURE_NO_SECRET",
                "ACTION_RUNNER_ALLOW_INSECURE_NO_SECRET",
            ],
            &get_env,
        )
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false);

        let webhook_secret =
            Self::resolve_secret_first_with_env(&["GITHUB_WEBHOOK_SECRET"], &get_env);
        let cluster_token = Self::resolve_secret_first_with_env(
            &[
                "MU_CI_CONTROLLER_CLUSTER_TOKEN",
                "ACTION_RUNNER_CLUSTER_TOKEN",
            ],
            &get_env,
        )
        .unwrap_or_else(|| "actionrunner_default_cluster_token".to_string());

        let job_timeout_seconds = first_parsed_in::<u64, _>(
            &[
                "MU_CI_CONTROLLER_TIMEOUT_SECS",
                "ACTION_RUNNER_TIMEOUT_SECS",
            ],
            &get_env,
        )
        .unwrap_or(1800);

        let max_concurrent_jobs = first_parsed_in::<usize, _>(
            &[
                "MU_CI_CONTROLLER_MAX_CONCURRENT_JOBS",
                "ACTION_RUNNER_MAX_CONCURRENT_JOBS",
            ],
            &get_env,
        )
        .unwrap_or(3);

        let github_token = Self::resolve_secret_first_with_env(&["GITHUB_TOKEN"], &get_env);

        let node_id = first_non_empty_in(
            &["MU_CI_CONTROLLER_NODE_ID", "ACTION_RUNNER_NODE_ID"],
            &get_env,
        )
        .unwrap_or_else(|| "node-a".to_string());

        let ha_role = first_non_empty_in(
            &["MU_CI_CONTROLLER_HA_ROLE", "ACTION_RUNNER_HA_ROLE"],
            &get_env,
        )
        .map(|s| HaRoleConfig::parse(&s))
        .unwrap_or(HaRoleConfig::Leader);

        let lease_ttl_seconds = first_parsed_in::<u64, _>(
            &[
                "MU_CI_CONTROLLER_LEASE_TTL_SECS",
                "ACTION_RUNNER_LEASE_TTL_SECS",
            ],
            &get_env,
        )
        .filter(|&v| v > 0)
        .unwrap_or(15);

        let standby_sync_seconds = first_parsed_in::<u64, _>(
            &[
                "MU_CI_CONTROLLER_STANDBY_SYNC_SECS",
                "ACTION_RUNNER_STANDBY_SYNC_SECS",
            ],
            &get_env,
        )
        .filter(|&v| v > 0)
        .unwrap_or(5);

        let proxy_secret = Self::resolve_secret_pairs_with_env(
            &[
                (
                    "MU_CI_CONTROLLER_PROXY_SECRET",
                    "MU_CI_CONTROLLER_PROXY_SECRET_FILE",
                ),
                (
                    "ACTION_RUNNER_PROXY_SECRET",
                    "ACTION_RUNNER_PROXY_SECRET_FILE",
                ),
            ],
            &get_env,
        );

        let invite_signing_key = Self::resolve_secret_pairs_with_env(
            &[
                (
                    "MU_CI_CONTROLLER_INVITE_SIGNING_KEY",
                    "MU_CI_CONTROLLER_INVITE_SIGNING_KEY_FILE",
                ),
                (
                    "ACTION_RUNNER_INVITE_SIGNING_KEY",
                    "ACTION_RUNNER_INVITE_SIGNING_KEY_FILE",
                ),
            ],
            &get_env,
        );

        let bootstrap_admins = first_non_empty_in(
            &[
                "MU_CI_CONTROLLER_BOOTSTRAP_ADMINS",
                "ACTION_RUNNER_BOOTSTRAP_ADMINS",
            ],
            &get_env,
        )
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

        let quic_bind_addr = first_non_empty_in(
            &["MU_CI_CONTROLLER_QUIC_BIND", "ACTION_RUNNER_QUIC_BIND"],
            &get_env,
        );
        let quic_alt_svc_port = first_parsed_in::<u16, _>(
            &[
                "MU_CI_CONTROLLER_QUIC_ALT_SVC_PORT",
                "ACTION_RUNNER_QUIC_ALT_SVC_PORT",
            ],
            &get_env,
        );
        let quic_alt_svc_max_age = first_parsed_in::<u64, _>(
            &[
                "MU_CI_CONTROLLER_QUIC_ALT_SVC_MAX_AGE",
                "ACTION_RUNNER_QUIC_ALT_SVC_MAX_AGE",
            ],
            &get_env,
        );
        let tls_cert_path = first_non_empty_in(
            &["MU_CI_CONTROLLER_TLS_CERT", "ACTION_RUNNER_TLS_CERT"],
            &get_env,
        )
        .map(PathBuf::from);
        let tls_key_path = first_non_empty_in(
            &["MU_CI_CONTROLLER_TLS_KEY", "ACTION_RUNNER_TLS_KEY"],
            &get_env,
        )
        .map(PathBuf::from);
        let tls_ca_path = first_non_empty_in(
            &["MU_CI_CONTROLLER_TLS_CA", "ACTION_RUNNER_TLS_CA"],
            &get_env,
        )
        .map(PathBuf::from);

        Self {
            bind_addr,
            workspace_dir,
            allowed_repositories,
            allowed_actors,
            allow_fork_prs,
            allowed_pr_authors,
            log_api_key,
            readonly_api_token,
            webhook_secret,
            cluster_token,
            job_timeout_seconds,
            allow_insecure_no_secret,
            max_concurrent_jobs,
            github_token,
            node_id,
            ha_role,
            lease_ttl_seconds,
            standby_sync_seconds,
            proxy_secret,
            invite_signing_key,
            bootstrap_admins,
            quic_bind_addr,
            quic_alt_svc_port,
            quic_alt_svc_max_age,
            tls_cert_path,
            tls_key_path,
            tls_ca_path,
            webauthn_rp_id: first_non_empty_in(
                &[
                    "MU_CI_CONTROLLER_WEBAUTHN_RP_ID",
                    "ACTION_RUNNER_WEBAUTHN_RP_ID",
                ],
                &get_env,
            )
            .unwrap_or_else(|| "localhost".to_string()),
            webauthn_rp_name: first_non_empty_in(
                &[
                    "MU_CI_CONTROLLER_WEBAUTHN_RP_NAME",
                    "ACTION_RUNNER_WEBAUTHN_RP_NAME",
                ],
                &get_env,
            )
            .unwrap_or_else(|| "MuConsole Platform".to_string()),
            webauthn_rp_origin: first_non_empty_in(
                &[
                    "MU_CI_CONTROLLER_WEBAUTHN_ORIGIN",
                    "ACTION_RUNNER_WEBAUTHN_ORIGIN",
                ],
                &get_env,
            )
            .unwrap_or_else(|| "http://localhost".to_string()),
            host_elevation_secret: Self::resolve_secret_pairs_with_env(
                &[
                    (
                        "MU_CI_CONTROLLER_HOST_ELEVATION_SECRET",
                        "MU_CI_CONTROLLER_HOST_ELEVATION_SECRET_FILE",
                    ),
                    (
                        "ACTION_RUNNER_HOST_ELEVATION_SECRET",
                        "ACTION_RUNNER_HOST_ELEVATION_SECRET_FILE",
                    ),
                ],
                &get_env,
            ),
            auth_state_file: first_non_empty_in(
                &[
                    "MU_CI_CONTROLLER_AUTH_STATE_FILE",
                    "ACTION_RUNNER_AUTH_STATE_FILE",
                ],
                &get_env,
            )
            .map(PathBuf::from),
        }
    }

    /// Returns the HMAC secret used to sign `__Host-mu_elevated` session cookies.
    /// Prefers `MU_CI_CONTROLLER_HOST_ELEVATION_SECRET` (or `ACTION_RUNNER_HOST_ELEVATION_SECRET`),
    /// falls back to `invite_signing_key`, or generates an ephemeral per-process secret if neither
    /// is configured.
    #[must_use]
    pub fn elevation_signing_key(&self) -> String {
        static EPHEMERAL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        if let Some(ref s) = self.host_elevation_secret {
            return format!("elev:{s}");
        }
        if let Some(ref s) = self.invite_signing_key {
            return format!("elev:{s}");
        }
        EPHEMERAL
            .get_or_init(|| format!("ephemeral:{}", uuid::Uuid::new_v4()))
            .clone()
    }

    pub fn is_repo_allowed(&self, repo: &str) -> bool {
        if !is_safe_repo_name(repo) {
            return false;
        }

        for pattern in &self.allowed_repositories {
            if pattern == "*" {
                return true;
            }
            if let Some(prefix) = pattern.strip_suffix("/*") {
                if let Some((owner, _)) = repo.split_once('/') {
                    if owner.eq_ignore_ascii_case(prefix) {
                        return true;
                    }
                }
            } else if pattern.eq_ignore_ascii_case(repo) {
                return true;
            }
        }
        false
    }

    pub fn is_actor_allowed(&self, actor: &str) -> bool {
        if self.allowed_actors.is_empty() {
            return true;
        }
        self.allowed_actors
            .iter()
            .any(|a| a == "*" || a.eq_ignore_ascii_case(actor))
    }

    pub fn is_pr_author_allowed(&self, association: &str) -> bool {
        self.allowed_pr_authors
            .iter()
            .any(|a| a.eq_ignore_ascii_case(association))
    }

    pub fn resolve_secret(env_var: &str) -> Option<String> {
        let val = std::env::var(env_var).ok()?;
        Self::resolve_secret_value(&val)
    }

    /// Resolve a secret from the first non-empty environment variable in `vars`.
    /// Fails closed (`None`) if the selected variable points to an unreadable or empty path.
    pub fn resolve_secret_first(vars: &[&str]) -> Option<String> {
        Self::resolve_secret_first_with_env(vars, |k| std::env::var(k).ok())
    }

    pub fn resolve_secret_first_with_env<F>(vars: &[&str], get_env: F) -> Option<String>
    where
        F: Fn(&str) -> Option<String>,
    {
        for var in vars {
            if let Some(val) = get_env(var) {
                if !val.trim().is_empty() {
                    return Self::resolve_secret_value(&val);
                }
            }
        }
        None
    }

    pub fn resolve_secret_with_file_var(env_var: &str, file_env_var: &str) -> Option<String> {
        Self::resolve_secret_pairs(&[(env_var, file_env_var)])
    }

    /// Resolve a secret across ordered `(value_var, file_var)` pairs.
    /// Commits to the first pair with a non-empty variable and fails closed if a configured file
    /// path cannot be read.
    pub fn resolve_secret_pairs(pairs: &[(&str, &str)]) -> Option<String> {
        Self::resolve_secret_pairs_with_env(pairs, |k| std::env::var(k).ok())
    }

    pub fn resolve_secret_pairs_with_env<F>(pairs: &[(&str, &str)], get_env: F) -> Option<String>
    where
        F: Fn(&str) -> Option<String>,
    {
        for (env_var, file_env_var) in pairs {
            if let Some(file_val) = get_env(file_env_var) {
                let trimmed = file_val.trim();
                if !trimmed.is_empty() {
                    return Self::resolve_secret_file(trimmed);
                }
            }
            if let Some(val) = get_env(env_var) {
                if !val.trim().is_empty() {
                    return Self::resolve_secret_value(&val);
                }
            }
        }
        None
    }

    pub fn resolve_secret_file(path_str: &str) -> Option<String> {
        let trimmed = path_str.trim();
        if trimmed.is_empty() {
            return None;
        }
        let path = Path::new(trimmed);
        if !path.is_file() {
            warn!(
                "Secret file '{}' does not exist or is not a readable file; failing closed",
                path.display()
            );
            return None;
        }
        match std::fs::read_to_string(path) {
            Ok(content) => {
                let secret = content.trim().to_string();
                if secret.is_empty() {
                    warn!("Secret file at {} is empty; failing closed", path.display());
                    None
                } else {
                    info!("Loaded secret from {}", path.display());
                    Some(secret)
                }
            }
            Err(err) => {
                warn!("Failed to read secret file at {}: {}", path.display(), err);
                None
            }
        }
    }

    /// Resolves a secret strictly from the first configured file-path environment variable in
    /// `vars`. Never falls back to treating the environment variable value as a literal token,
    /// and fails closed (`None`) with an `error!` log if the configured file path is empty,
    /// missing, unreadable, not a regular file, or empty after trimming.
    pub fn resolve_strict_token_file_first_with_env<F>(vars: &[&str], get_env: F) -> Option<String>
    where
        F: Fn(&str) -> Option<String>,
    {
        let mut saw_empty_var: Option<&str> = None;
        for var in vars {
            if let Some(raw_path) = get_env(var) {
                let trimmed = raw_path.trim();
                if trimmed.is_empty() {
                    saw_empty_var.get_or_insert(var);
                    continue;
                }
                return Self::resolve_strict_token_file(var, trimmed);
            }
        }
        if let Some(var) = saw_empty_var {
            error!(
                env_var = var,
                "Configured read-only service token file path is empty; failing closed"
            );
        }
        None
    }

    /// Reads and trims a token strictly from `path_str`, failing closed (`None`) with an `error!`
    /// log if the path is empty, missing, non-regular, unreadable, or empty after trimming.
    /// Never logs the token value or falls back to returning `path_str`.
    pub fn resolve_strict_token_file(env_var: &str, path_str: &str) -> Option<String> {
        let trimmed = path_str.trim();
        if trimmed.is_empty() {
            error!(
                env_var = env_var,
                "Configured read-only service token file path is empty; failing closed"
            );
            return None;
        }
        let path = Path::new(trimmed);
        if !path.is_file() {
            error!(
                env_var = env_var,
                "Configured read-only service token file does not exist or is not a regular file; failing closed"
            );
            return None;
        }
        match std::fs::read_to_string(path) {
            Ok(content) => {
                let secret = content.trim().to_string();
                if secret.is_empty() {
                    error!(
                        env_var = env_var,
                        "Configured read-only service token file is empty; failing closed"
                    );
                    None
                } else {
                    info!(
                        env_var = env_var,
                        "Loaded read-only service bearer token from configured file"
                    );
                    Some(secret)
                }
            }
            Err(err) => {
                error!(
                    env_var = env_var,
                    error_kind = ?err.kind(),
                    "Failed to read configured read-only service token file; failing closed"
                );
                None
            }
        }
    }

    pub fn resolve_secret_value(val: &str) -> Option<String> {
        let val = val.trim();
        if val.is_empty() {
            return None;
        }

        let is_path = val.starts_with('/')
            || val.starts_with("./")
            || val.starts_with("../")
            || val.contains('/')
            || val.contains('\\');

        let path = Path::new(val);
        if path.is_file() {
            match std::fs::read_to_string(path) {
                Ok(content) => {
                    let secret = content.trim().to_string();
                    if secret.is_empty() {
                        warn!("Secret file at {} is empty", path.display());
                        None
                    } else {
                        info!("Loaded secret from {}", path.display());
                        Some(secret)
                    }
                }
                Err(err) => {
                    warn!("Failed to read secret file at {}: {}", path.display(), err);
                    None
                }
            }
        } else if is_path {
            warn!(
                "Secret path '{}' does not exist or is not a readable file; failing closed",
                val
            );
            None
        } else {
            Some(val.to_string())
        }
    }
}

pub fn is_safe_repo_name(repo: &str) -> bool {
    let parts: Vec<&str> = repo.split('/').collect();
    if parts.len() != 2 {
        return false;
    }
    let owner = parts[0];
    let name = parts[1];
    if owner.is_empty() || name.is_empty() {
        return false;
    }
    if owner.contains("..") || name.contains("..") {
        return false;
    }
    let is_valid_char = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.';
    owner.chars().all(is_valid_char) && name.chars().all(is_valid_char)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_secret_value_literal() {
        let literal = "ghp_super_secret_token_12345";
        assert_eq!(
            Config::resolve_secret_value(literal),
            Some(literal.to_string())
        );
    }

    #[test]
    fn test_resolve_secret_value_from_valid_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("secret.key");
        std::fs::write(&file_path, "  my-secret-from-disk \n\t").unwrap();

        assert_eq!(
            Config::resolve_secret_value(file_path.to_str().unwrap()),
            Some("my-secret-from-disk".to_string())
        );
    }

    #[test]
    fn test_resolve_secret_value_missing_path_fail_closed() {
        // Absolute path missing
        assert_eq!(
            Config::resolve_secret_value("/nonexistent/secrets/webhook.key"),
            None,
            "Missing absolute secret file must fail closed to None, never returning path string"
        );

        // Relative path missing
        assert_eq!(
            Config::resolve_secret_value("./missing_secret.txt"),
            None,
            "Missing relative secret file must fail closed to None"
        );
    }

    #[test]
    fn test_resolve_secret_value_empty_file_fail_closed() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("empty.key");
        std::fs::write(&file_path, "   \n\t").unwrap();

        assert_eq!(
            Config::resolve_secret_value(file_path.to_str().unwrap()),
            None,
            "Empty secret file must fail closed to None"
        );
    }

    #[test]
    fn test_resolve_secret_env_var_fail_closed() {
        let var_name = "TEST_CONTROLLER_SECRET_FAIL_CLOSED_VAR";
        std::env::set_var(var_name, "/nonexistent/path/to/token.secret");
        assert_eq!(
            Config::resolve_secret(var_name),
            None,
            "Environment variable pointing to nonexistent path must fail closed"
        );
        std::env::remove_var(var_name);
    }

    #[test]
    fn test_ha_role_config_parse_and_defaults() {
        assert_eq!(HaRoleConfig::parse("auto"), HaRoleConfig::Auto);
        assert_eq!(HaRoleConfig::parse("AUTO"), HaRoleConfig::Auto);
        assert_eq!(HaRoleConfig::parse("standby"), HaRoleConfig::Standby);
        assert_eq!(HaRoleConfig::parse("follower"), HaRoleConfig::Standby);
        assert_eq!(HaRoleConfig::parse("backup"), HaRoleConfig::Standby);
        assert_eq!(HaRoleConfig::parse("leader"), HaRoleConfig::Leader);
        assert_eq!(HaRoleConfig::parse("unknown"), HaRoleConfig::Leader);

        assert_eq!(HaRoleConfig::Auto.as_str(), "auto");
        assert_eq!(HaRoleConfig::Leader.as_str(), "leader");
        assert_eq!(HaRoleConfig::Standby.as_str(), "standby");

        assert!(HaRole::Leader.is_leader());
        assert!(!HaRole::Standby.is_leader());
        assert_eq!(HaRole::Leader.as_str(), "leader");
        assert_eq!(HaRole::Standby.as_str(), "standby");

        let default_cfg = Config::default();
        assert_eq!(default_cfg.node_id, "node-a");
        assert_eq!(default_cfg.ha_role, HaRoleConfig::Leader);
        assert_eq!(default_cfg.lease_ttl_seconds, 15);
        assert_eq!(default_cfg.standby_sync_seconds, 5);
        assert_eq!(default_cfg.proxy_secret, None);
        assert_eq!(default_cfg.invite_signing_key, None);
        assert!(default_cfg.bootstrap_admins.is_empty());
    }

    #[test]
    fn test_resolve_secret_with_file_var_and_fail_closed() {
        let temp_dir = tempfile::tempdir().unwrap();
        let valid_file = temp_dir.path().join("proxy.secret");
        std::fs::write(&valid_file, "  proxy-secret-from-file \n").unwrap();

        let env_lit = "TEST_PROXY_SECRET_LIT_92";
        let env_file = "TEST_PROXY_SECRET_FILE_92";

        std::env::set_var(env_file, valid_file.to_str().unwrap());
        assert_eq!(
            Config::resolve_secret_with_file_var(env_lit, env_file),
            Some("proxy-secret-from-file".to_string())
        );

        // Missing file in *_FILE must fail closed to None even if literal var is set
        std::env::set_var(env_lit, "fallback-literal");
        std::env::set_var(env_file, "/nonexistent/proxy.secret");
        assert_eq!(
            Config::resolve_secret_with_file_var(env_lit, env_file),
            None
        );

        // When *_FILE is unset, falls back to env_lit
        std::env::remove_var(env_file);
        assert_eq!(
            Config::resolve_secret_with_file_var(env_lit, env_file),
            Some("fallback-literal".to_string())
        );
        std::env::remove_var(env_lit);
    }

    static CONTROLLER_ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct EnvGuard {
        saved: Vec<(String, Option<std::ffi::OsString>)>,
    }

    impl EnvGuard {
        fn capture(keys: &[&str]) -> Self {
            let saved = keys
                .iter()
                .map(|k| ((*k).to_string(), std::env::var_os(k)))
                .collect();
            Self { saved }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, v) in &self.saved {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    #[test]
    fn test_resolve_default_workspace_dir_precedence() {
        let dir = tempfile::tempdir().unwrap();
        let mu_root = dir.path().join("mu-ci-controller");
        let legacy_root = dir.path().join("action-runner");

        // Neither exists -> canonical mu_root/workspace
        assert_eq!(
            Config::resolve_default_workspace_dir(&mu_root, &legacy_root),
            mu_root.join("workspace")
        );

        // Only legacy exists -> legacy_root/workspace
        std::fs::create_dir_all(&legacy_root).unwrap();
        assert_eq!(
            Config::resolve_default_workspace_dir(&mu_root, &legacy_root),
            legacy_root.join("workspace")
        );

        // Both exist -> canonical mu_root/workspace
        std::fs::create_dir_all(&mu_root).unwrap();
        assert_eq!(
            Config::resolve_default_workspace_dir(&mu_root, &legacy_root),
            mu_root.join("workspace")
        );
    }

    #[test]
    fn test_controller_config_load_mu_ci_controller_precedence_and_fallback() {
        let mut env_map: std::collections::HashMap<&str, String> = Default::default();

        // 1. Legacy ACTION_RUNNER_* fallback when MU_CI_CONTROLLER_* unset
        env_map.insert("ACTION_RUNNER_BIND", "127.0.0.1:9100".to_string());
        env_map.insert("ACTION_RUNNER_WORKSPACE", "/tmp/legacy-ctrl-ws".to_string());
        env_map.insert("ACTION_RUNNER_ALLOWED_REPOS", "org/legacy".to_string());
        env_map.insert("ACTION_RUNNER_ALLOWED_ACTORS", "alice".to_string());
        env_map.insert("ACTION_RUNNER_ALLOW_FORK_PRS", "true".to_string());
        env_map.insert("ACTION_RUNNER_ALLOWED_PR_AUTHORS", "OWNER".to_string());
        env_map.insert("ACTION_RUNNER_LOG_API_KEY", "legacy-log-key".to_string());
        env_map.insert("ACTION_RUNNER_ALLOW_INSECURE_NO_SECRET", "1".to_string());
        env_map.insert(
            "ACTION_RUNNER_CLUSTER_TOKEN",
            "legacy-cluster-tok".to_string(),
        );
        env_map.insert("ACTION_RUNNER_TIMEOUT_SECS", "900".to_string());
        env_map.insert("ACTION_RUNNER_MAX_CONCURRENT_JOBS", "5".to_string());
        env_map.insert("ACTION_RUNNER_NODE_ID", "node-legacy".to_string());
        env_map.insert("ACTION_RUNNER_HA_ROLE", "standby".to_string());
        env_map.insert("ACTION_RUNNER_LEASE_TTL_SECS", "25".to_string());
        env_map.insert("ACTION_RUNNER_STANDBY_SYNC_SECS", "9".to_string());
        env_map.insert("ACTION_RUNNER_PROXY_SECRET", "legacy-proxy".to_string());
        env_map.insert(
            "ACTION_RUNNER_INVITE_SIGNING_KEY",
            "legacy-invite".to_string(),
        );
        env_map.insert("ACTION_RUNNER_BOOTSTRAP_ADMINS", "admin1".to_string());
        env_map.insert("ACTION_RUNNER_QUIC_BIND", "127.0.0.1:9443".to_string());
        env_map.insert("ACTION_RUNNER_QUIC_ALT_SVC_PORT", "9443".to_string());
        env_map.insert("ACTION_RUNNER_QUIC_ALT_SVC_MAX_AGE", "120".to_string());
        env_map.insert("ACTION_RUNNER_TLS_CERT", "/tmp/legacy.crt".to_string());
        env_map.insert("ACTION_RUNNER_TLS_KEY", "/tmp/legacy.key".to_string());
        env_map.insert("ACTION_RUNNER_TLS_CA", "/tmp/legacy-ca.crt".to_string());
        env_map.insert(
            "ACTION_RUNNER_WEBAUTHN_RP_ID",
            "legacy.example.org".to_string(),
        );
        env_map.insert("ACTION_RUNNER_WEBAUTHN_RP_NAME", "Legacy".to_string());
        env_map.insert(
            "ACTION_RUNNER_WEBAUTHN_ORIGIN",
            "https://legacy.example.org".to_string(),
        );
        env_map.insert(
            "ACTION_RUNNER_HOST_ELEVATION_SECRET",
            "legacy-elev".to_string(),
        );
        env_map.insert(
            "ACTION_RUNNER_AUTH_STATE_FILE",
            "/tmp/legacy-auth.json".to_string(),
        );

        let legacy_cfg = Config::load_with_env(|k| env_map.get(k).cloned());
        assert_eq!(legacy_cfg.bind_addr, "127.0.0.1:9100");
        assert_eq!(
            legacy_cfg.workspace_dir,
            PathBuf::from("/tmp/legacy-ctrl-ws")
        );
        assert_eq!(legacy_cfg.allowed_repositories, vec!["org/legacy"]);
        assert_eq!(legacy_cfg.allowed_actors, vec!["alice"]);
        assert!(legacy_cfg.allow_fork_prs);
        assert_eq!(legacy_cfg.allowed_pr_authors, vec!["OWNER"]);
        assert_eq!(legacy_cfg.log_api_key.as_deref(), Some("legacy-log-key"));
        assert!(legacy_cfg.allow_insecure_no_secret);
        assert_eq!(legacy_cfg.cluster_token, "legacy-cluster-tok");
        assert_eq!(legacy_cfg.job_timeout_seconds, 900);
        assert_eq!(legacy_cfg.max_concurrent_jobs, 5);
        assert_eq!(legacy_cfg.node_id, "node-legacy");
        assert_eq!(legacy_cfg.ha_role, HaRoleConfig::Standby);
        assert_eq!(legacy_cfg.lease_ttl_seconds, 25);
        assert_eq!(legacy_cfg.standby_sync_seconds, 9);
        assert_eq!(legacy_cfg.proxy_secret.as_deref(), Some("legacy-proxy"));
        assert_eq!(
            legacy_cfg.invite_signing_key.as_deref(),
            Some("legacy-invite")
        );
        assert_eq!(legacy_cfg.bootstrap_admins, vec!["admin1"]);
        assert_eq!(legacy_cfg.quic_bind_addr.as_deref(), Some("127.0.0.1:9443"));
        assert_eq!(legacy_cfg.quic_alt_svc_port, Some(9443));
        assert_eq!(legacy_cfg.quic_alt_svc_max_age, Some(120));
        assert_eq!(
            legacy_cfg.tls_cert_path,
            Some(PathBuf::from("/tmp/legacy.crt"))
        );
        assert_eq!(
            legacy_cfg.tls_key_path,
            Some(PathBuf::from("/tmp/legacy.key"))
        );
        assert_eq!(
            legacy_cfg.tls_ca_path,
            Some(PathBuf::from("/tmp/legacy-ca.crt"))
        );
        assert_eq!(legacy_cfg.webauthn_rp_id, "legacy.example.org");
        assert_eq!(legacy_cfg.webauthn_rp_name, "Legacy");
        assert_eq!(legacy_cfg.webauthn_rp_origin, "https://legacy.example.org");
        assert_eq!(
            legacy_cfg.host_elevation_secret.as_deref(),
            Some("legacy-elev")
        );
        assert_eq!(
            legacy_cfg.auth_state_file,
            Some(PathBuf::from("/tmp/legacy-auth.json"))
        );

        // 2. Canonical MU_CI_CONTROLLER_* values override ACTION_RUNNER_*
        let dir = tempfile::tempdir().unwrap();
        let elev_file = dir.path().join("elev.secret");
        std::fs::write(&elev_file, "canonical-elev-from-file\n").unwrap();

        env_map.insert("MU_CI_CONTROLLER_BIND", "0.0.0.0:8080".to_string());
        env_map.insert(
            "MU_CI_CONTROLLER_WORKSPACE",
            "/tmp/canonical-ctrl-ws".to_string(),
        );
        env_map.insert("MU_CI_CONTROLLER_ALLOWED_REPOS", "LMA1980/*".to_string());
        env_map.insert("MU_CI_CONTROLLER_ALLOWED_ACTORS", "bob".to_string());
        env_map.insert("MU_CI_CONTROLLER_ALLOW_FORK_PRS", "false".to_string());
        env_map.insert("MU_CI_CONTROLLER_ALLOWED_PR_AUTHORS", "MEMBER".to_string());
        env_map.insert(
            "MU_CI_CONTROLLER_LOG_API_KEY",
            "canonical-log-key".to_string(),
        );
        env_map.insert(
            "MU_CI_CONTROLLER_ALLOW_INSECURE_NO_SECRET",
            "false".to_string(),
        );
        env_map.insert(
            "MU_CI_CONTROLLER_CLUSTER_TOKEN",
            "canonical-cluster-tok".to_string(),
        );
        env_map.insert("MU_CI_CONTROLLER_TIMEOUT_SECS", "1200".to_string());
        env_map.insert("MU_CI_CONTROLLER_MAX_CONCURRENT_JOBS", "8".to_string());
        env_map.insert("MU_CI_CONTROLLER_NODE_ID", "node-b".to_string());
        env_map.insert("MU_CI_CONTROLLER_HA_ROLE", "auto".to_string());
        env_map.insert("MU_CI_CONTROLLER_LEASE_TTL_SECS", "30".to_string());
        env_map.insert("MU_CI_CONTROLLER_STANDBY_SYNC_SECS", "12".to_string());
        env_map.insert(
            "MU_CI_CONTROLLER_PROXY_SECRET",
            "canonical-proxy".to_string(),
        );
        env_map.insert(
            "MU_CI_CONTROLLER_INVITE_SIGNING_KEY",
            "canonical-invite".to_string(),
        );
        env_map.insert(
            "MU_CI_CONTROLLER_BOOTSTRAP_ADMINS",
            "admin2,admin3".to_string(),
        );
        env_map.insert("MU_CI_CONTROLLER_QUIC_BIND", "0.0.0.0:8443".to_string());
        env_map.insert("MU_CI_CONTROLLER_QUIC_ALT_SVC_PORT", "8443".to_string());
        env_map.insert("MU_CI_CONTROLLER_QUIC_ALT_SVC_MAX_AGE", "300".to_string());
        env_map.insert(
            "MU_CI_CONTROLLER_TLS_CERT",
            "/tmp/canonical.crt".to_string(),
        );
        env_map.insert("MU_CI_CONTROLLER_TLS_KEY", "/tmp/canonical.key".to_string());
        env_map.insert(
            "MU_CI_CONTROLLER_TLS_CA",
            "/tmp/canonical-ca.crt".to_string(),
        );
        env_map.insert(
            "MU_CI_CONTROLLER_WEBAUTHN_RP_ID",
            "mu.example.org".to_string(),
        );
        env_map.insert("MU_CI_CONTROLLER_WEBAUTHN_RP_NAME", "MuCI".to_string());
        env_map.insert(
            "MU_CI_CONTROLLER_WEBAUTHN_ORIGIN",
            "https://mu.example.org".to_string(),
        );
        env_map.insert(
            "MU_CI_CONTROLLER_HOST_ELEVATION_SECRET_FILE",
            elev_file.to_str().unwrap().to_string(),
        );
        env_map.insert(
            "MU_CI_CONTROLLER_AUTH_STATE_FILE",
            "/tmp/canonical-auth.json".to_string(),
        );

        let mu_cfg = Config::load_with_env(|k| env_map.get(k).cloned());
        assert_eq!(mu_cfg.bind_addr, "0.0.0.0:8080");
        assert_eq!(
            mu_cfg.workspace_dir,
            PathBuf::from("/tmp/canonical-ctrl-ws")
        );
        assert_eq!(mu_cfg.allowed_repositories, vec!["LMA1980/*"]);
        assert_eq!(mu_cfg.allowed_actors, vec!["bob"]);
        assert!(!mu_cfg.allow_fork_prs);
        assert_eq!(mu_cfg.allowed_pr_authors, vec!["MEMBER"]);
        assert_eq!(mu_cfg.log_api_key.as_deref(), Some("canonical-log-key"));
        assert!(!mu_cfg.allow_insecure_no_secret);
        assert_eq!(mu_cfg.cluster_token, "canonical-cluster-tok");
        assert_eq!(mu_cfg.job_timeout_seconds, 1200);
        assert_eq!(mu_cfg.max_concurrent_jobs, 8);
        assert_eq!(mu_cfg.node_id, "node-b");
        assert_eq!(mu_cfg.ha_role, HaRoleConfig::Auto);
        assert_eq!(mu_cfg.lease_ttl_seconds, 30);
        assert_eq!(mu_cfg.standby_sync_seconds, 12);
        assert_eq!(mu_cfg.proxy_secret.as_deref(), Some("canonical-proxy"));
        assert_eq!(
            mu_cfg.invite_signing_key.as_deref(),
            Some("canonical-invite")
        );
        assert_eq!(mu_cfg.bootstrap_admins, vec!["admin2", "admin3"]);
        assert_eq!(mu_cfg.quic_bind_addr.as_deref(), Some("0.0.0.0:8443"));
        assert_eq!(mu_cfg.quic_alt_svc_port, Some(8443));
        assert_eq!(mu_cfg.quic_alt_svc_max_age, Some(300));
        assert_eq!(
            mu_cfg.tls_cert_path,
            Some(PathBuf::from("/tmp/canonical.crt"))
        );
        assert_eq!(
            mu_cfg.tls_key_path,
            Some(PathBuf::from("/tmp/canonical.key"))
        );
        assert_eq!(
            mu_cfg.tls_ca_path,
            Some(PathBuf::from("/tmp/canonical-ca.crt"))
        );
        assert_eq!(mu_cfg.webauthn_rp_id, "mu.example.org");
        assert_eq!(mu_cfg.webauthn_rp_name, "MuCI");
        assert_eq!(mu_cfg.webauthn_rp_origin, "https://mu.example.org");
        assert_eq!(
            mu_cfg.host_elevation_secret.as_deref(),
            Some("canonical-elev-from-file")
        );
        assert_eq!(
            mu_cfg.auth_state_file,
            Some(PathBuf::from("/tmp/canonical-auth.json"))
        );

        // 3. Unreadable canonical secret file fails closed instead of falling back to legacy secret
        env_map.insert(
            "MU_CI_CONTROLLER_PROXY_SECRET_FILE",
            "/nonexistent/canonical-proxy.secret".to_string(),
        );
        let fail_closed_cfg = Config::load_with_env(|k| env_map.get(k).cloned());
        assert_eq!(fail_closed_cfg.proxy_secret, None);

        // 4. Verify process env helpers using unique test-only keys
        let _lock = CONTROLLER_ENV_TEST_LOCK.lock().unwrap();
        let test_keys = [
            "TEST_MU_CI_CONTROLLER_ENV_PRIMARY",
            "TEST_ACTION_RUNNER_ENV_FALLBACK",
        ];
        let _guard = EnvGuard::capture(&test_keys);
        std::env::remove_var(test_keys[0]);
        std::env::set_var(test_keys[1], "77");
        assert_eq!(first_non_empty_env(&test_keys).as_deref(), Some("77"));
        assert_eq!(first_parsed_env::<usize>(&test_keys), Some(77));
        std::env::set_var(test_keys[0], "88");
        assert_eq!(first_non_empty_env(&test_keys).as_deref(), Some("88"));
        assert_eq!(first_parsed_env::<usize>(&test_keys), Some(88));
    }

    #[test]
    fn test_readonly_api_token_precedence_and_trimming() {
        let dir = tempfile::tempdir().unwrap();
        let primary_file = dir.path().join("primary-ro.token");
        let fallback_file = dir.path().join("fallback-ro.token");
        std::fs::write(&primary_file, "  primary-ro-secret-token \r\n\t").unwrap();
        std::fs::write(&fallback_file, "\n  fallback-ro-secret-token  \n").unwrap();

        // Unset -> None
        let empty_cfg = Config::load_with_env(|_| None);
        assert_eq!(empty_cfg.readonly_api_token, None);

        // Fallback MU_CI_READONLY_TOKEN_FILE used when primary unset
        let mut env_map: std::collections::HashMap<&str, String> = Default::default();
        env_map.insert(
            "MU_CI_READONLY_TOKEN_FILE",
            fallback_file.to_str().unwrap().to_string(),
        );
        let fallback_cfg = Config::load_with_env(|k| env_map.get(k).cloned());
        assert_eq!(
            fallback_cfg.readonly_api_token.as_deref(),
            Some("fallback-ro-secret-token")
        );

        // Canonical MU_CI_CONTROLLER_READONLY_TOKEN_FILE overrides MU_CI_READONLY_TOKEN_FILE
        env_map.insert(
            "MU_CI_CONTROLLER_READONLY_TOKEN_FILE",
            primary_file.to_str().unwrap().to_string(),
        );
        let primary_cfg = Config::load_with_env(|k| env_map.get(k).cloned());
        assert_eq!(
            primary_cfg.readonly_api_token.as_deref(),
            Some("primary-ro-secret-token")
        );
    }

    #[test]
    fn test_readonly_api_token_fail_closed_missing_empty_dir_and_literal() {
        let dir = tempfile::tempdir().unwrap();
        let valid_file = dir.path().join("valid-ro.token");
        let empty_file = dir.path().join("empty-ro.token");
        std::fs::write(&valid_file, "valid-fallback-token\n").unwrap();
        std::fs::write(&empty_file, "   \n\t  ").unwrap();

        // 1. Missing primary file fails closed even when fallback is valid
        let mut env_map: std::collections::HashMap<&str, String> = Default::default();
        env_map.insert(
            "MU_CI_CONTROLLER_READONLY_TOKEN_FILE",
            "/nonexistent/path/to/ci-readonly.token".to_string(),
        );
        env_map.insert(
            "MU_CI_READONLY_TOKEN_FILE",
            valid_file.to_str().unwrap().to_string(),
        );
        assert_eq!(
            Config::load_with_env(|k| env_map.get(k).cloned()).readonly_api_token,
            None,
            "Missing primary read-only token file must fail closed without falling back"
        );

        // 2. Empty file fails closed
        env_map.insert(
            "MU_CI_CONTROLLER_READONLY_TOKEN_FILE",
            empty_file.to_str().unwrap().to_string(),
        );
        assert_eq!(
            Config::load_with_env(|k| env_map.get(k).cloned()).readonly_api_token,
            None,
            "Empty read-only token file must fail closed"
        );

        // 3. Directory path fails closed
        env_map.insert(
            "MU_CI_CONTROLLER_READONLY_TOKEN_FILE",
            dir.path().to_str().unwrap().to_string(),
        );
        assert_eq!(
            Config::load_with_env(|k| env_map.get(k).cloned()).readonly_api_token,
            None,
            "Directory path must fail closed"
        );

        // 4. Literal token value (not a file path) must NEVER be accepted as a literal secret
        env_map.insert(
            "MU_CI_CONTROLLER_READONLY_TOKEN_FILE",
            "literal-secret-that-must-not-load".to_string(),
        );
        assert_eq!(
            Config::load_with_env(|k| env_map.get(k).cloned()).readonly_api_token,
            None,
            "Non-file literal value in *_READONLY_TOKEN_FILE must fail closed"
        );

        // 5. Fallback missing file & empty env var both fail closed
        env_map.clear();
        env_map.insert(
            "MU_CI_READONLY_TOKEN_FILE",
            "/nonexistent/fallback-readonly.token".to_string(),
        );
        assert_eq!(
            Config::load_with_env(|k| env_map.get(k).cloned()).readonly_api_token,
            None
        );

        env_map.clear();
        env_map.insert("MU_CI_CONTROLLER_READONLY_TOKEN_FILE", "   ".to_string());
        assert_eq!(
            Config::load_with_env(|k| env_map.get(k).cloned()).readonly_api_token,
            None
        );

        // 6. Unreadable file (0o000) fails closed when not running as root
        #[cfg(all(unix, not(miri)))]
        {
            use std::os::unix::fs::PermissionsExt;
            let unreadable = dir.path().join("unreadable-ro.token");
            std::fs::write(&unreadable, "unreadable-secret\n").unwrap();
            std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();
            let res = Config::resolve_strict_token_file(
                "MU_CI_CONTROLLER_READONLY_TOKEN_FILE",
                unreadable.to_str().unwrap(),
            );
            // Restore permissions so tempdir cleanup always succeeds
            let _ = std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o600));
            // Only assert None when the OS actually enforced 0o000 (non-root)
            if std::fs::OpenOptions::new()
                .read(true)
                .open(&unreadable)
                .is_ok()
            {
                // Re-check with 0o000 probe to determine if running unprivileged
                let _ =
                    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000));
                let readable_as_000 = std::fs::read_to_string(&unreadable).is_ok();
                let _ =
                    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o600));
                if !readable_as_000 {
                    assert_eq!(res, None, "Unreadable 0o000 token file must fail closed");
                }
            }
        }
    }

    #[test]
    fn test_readonly_api_token_error_logging_and_zero_leakage() {
        use std::io::Write;
        use std::sync::{Arc, Mutex};

        #[derive(Clone, Default)]
        struct BufWriter(Arc<Mutex<Vec<u8>>>);

        impl Write for BufWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let secret_val = "ro_super_secret_token_9f8e7d6c5b4a";
        let admin_val = "admin_super_secret_key_1a2b3c4d5e";
        let literal_val = "accidental_literal_secret_must_not_log";
        let valid_file = dir.path().join("ro.token");
        let empty_file = dir.path().join("empty.token");
        std::fs::write(&valid_file, format!("{secret_val}\n")).unwrap();
        std::fs::write(&empty_file, "  \n").unwrap();

        let shared_buf = Arc::new(Mutex::new(Vec::<u8>::new()));
        let writer_handle = Arc::clone(&shared_buf);
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(move || BufWriter(Arc::clone(&writer_handle)))
            .finish();

        let loaded_cfg = tracing::subscriber::with_default(subscriber, || {
            assert_eq!(
                Config::resolve_strict_token_file(
                    "MU_CI_CONTROLLER_READONLY_TOKEN_FILE",
                    "/nonexistent/missing-ro.token"
                ),
                None
            );
            assert_eq!(
                Config::resolve_strict_token_file(
                    "MU_CI_CONTROLLER_READONLY_TOKEN_FILE",
                    empty_file.to_str().unwrap()
                ),
                None
            );
            assert_eq!(
                Config::resolve_strict_token_file(
                    "MU_CI_CONTROLLER_READONLY_TOKEN_FILE",
                    literal_val
                ),
                None
            );
            assert_eq!(
                Config::resolve_strict_token_file_first_with_env(
                    &["MU_CI_CONTROLLER_READONLY_TOKEN_FILE"],
                    |_| Some("   ".to_string())
                ),
                None
            );

            let mut env_map: std::collections::HashMap<&str, String> = Default::default();
            env_map.insert("MU_CI_CONTROLLER_LOG_API_KEY", admin_val.to_string());
            env_map.insert(
                "MU_CI_CONTROLLER_READONLY_TOKEN_FILE",
                valid_file.to_str().unwrap().to_string(),
            );
            Config::load_with_env(|k| env_map.get(k).cloned())
        });

        assert_eq!(loaded_cfg.readonly_api_token.as_deref(), Some(secret_val));
        assert_eq!(loaded_cfg.log_api_key.as_deref(), Some(admin_val));

        let logs = String::from_utf8(shared_buf.lock().unwrap().clone()).unwrap();
        assert!(
            logs.contains("ERROR") && logs.contains("failing closed"),
            "Expected fail-closed ERROR logs, got: {logs}"
        );
        assert!(
            !logs.contains(secret_val),
            "Read-only token leaked into tracing logs: {logs}"
        );
        assert!(
            !logs.contains(literal_val),
            "Accidental literal value leaked into tracing logs: {logs}"
        );
        assert!(
            !logs.contains(admin_val),
            "Admin log API key leaked into tracing logs: {logs}"
        );

        let debug_repr = format!("{loaded_cfg:?}");
        assert!(debug_repr.contains("<redacted>"));
        assert!(
            !debug_repr.contains(secret_val),
            "Read-only token leaked into Config Debug output"
        );
        assert!(
            !debug_repr.contains(admin_val),
            "Admin log API key leaked into Config Debug output"
        );
    }
}
