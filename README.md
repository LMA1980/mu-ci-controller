# mu-ci-controller

<p align="center">
  <a href="https://hook.lma1980.duckdns.org/jobs">
    <img src="https://hook.lma1980.duckdns.org/cards/LMA1980/mu-ci-controller/card.svg" alt="mu-ci-controller Factory Scorecard" width="520"/>
  </a>
</p>

<p align="center">
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/mu-ci-controller/status.svg" alt="CI Status"/></a>
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/mu-ci-controller/score.svg" alt="Quality Score"/></a>
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/mu-ci-controller/coverage.svg" alt="Coverage"/></a>
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/mu-ci-controller/benchmark.svg" alt="Benchmark"/></a>
</p>

______________________________________________________________________

WebAPI, Ingress Gateway, DAG Stage Scheduler, Auth Authority Host, and SVG Scorecard Controller for the distributed [`mu-ci`](https://github.com/LMA1980/mu-ci) platform, coordinating [`mu-ci-worker`](https://github.com/LMA1980/mu-ci-worker) nodes over [`mu-ci-ipc`](https://github.com/LMA1980/mu-ci-ipc) and validating typed tool pipelines from [`mu-ci-tools`](https://github.com/LMA1980/mu-ci-tools).

## Architecture

- **Ingress & Webhook Verification**: GitHub webhook receiver (`POST /webhook`) with constant-time HMAC-SHA256 payload verification and anti-RCE fork PR validation.
- **Coalescing FIFO Queue & Remote `ControllerStorage` (`mu-observable-hub`)**: Serializes builds and persists execution history, branch snapshots, submodule snapshots, HA leader leases, console repository catalog state, and platform auth state through the `ControllerStorage` trait. In production (`StorageBackendMode::MuObserveRemote`, controlled by `ACTION_RUNNER_STORAGE_MODE` and `MUOBSERVE_CONTROL_ADDR`), `MuObserveRemoteStorage` communicates via Apache Fory RPC (`MUOB` framing over `step-ca` mTLS) with [`mu-observable-hub`](https://github.com/LMA1980/mu-observable-hub) via [`mu-observable-ipc`](https://github.com/LMA1980/mu-observable-ipc), reconstructing historical logs from `v_logs` without local DuckDB files; standalone test harnesses use `InMemoryStorage`.
- **DAG Stage Scheduler & Concurrency Invariants**: Evaluates stage dependencies (`depends_on`), matches required stage tags and toolchains (including `version: "4"` `toolchain.min_version` checks against worker `rust_semver`, and `if_unavailable` skip handling for optional hardware capabilities such as `KVA23`) against worker node capabilities, enforces per-job in-flight deduplication (`InFlightJobGuard`) and `JobStatus::Running` stage invariants, reserves pending worker slots during claim before `git fetch` (`sync_and_try_reserve_for_claim`), respects `exclusive: true` ("Drain Before Dispatch"), and preserves priority during yield-and-requeue and HA leader rehydration (`should_preserve_local_record`).
- **Zero-Copy IPC Cluster Tunnel & Telemetry Streaming**: Coordinates with distributed [`mu-ci-worker`](https://github.com/LMA1980/mu-ci-worker) daemons over WebSocket (`/api/cluster/tunnel`) using [`mu-ci-ipc`](https://github.com/LMA1980/mu-ci-ipc) (`zerocopy` framing, Apache Fory control envelopes, and Apache Arrow columnar log/metric streaming), forwarding deduplicated `OtelLogEntry` deltas (`MSG_TYPE_ARROW_OTEL_LOGS`) to [`mu-observable-hub`](https://github.com/LMA1980/mu-observable-hub) / [`mu-observable-collector`](https://github.com/LMA1980/mu-observable-collector).
- **HTTP/3 QUIC & HA Failover**: Optionally binds a dual-stack UDP QUIC endpoint (`ALPN h3`, `ACTION_RUNNER_QUIC_BIND`) with `step-ca` mTLS alongside HTTP/1.1, and coordinates single-leader HA leases with `/ha/status`, `/ha/promote`, and `/ha/demote` (also under `/api/ha/*`) plus disk- and leadership-aware `GET /health` probes (`503 Service Unavailable` when storage I/O hangs or a configured leader demotes to standby). See [`specs/gray-failure-health-and-delta-log-streaming.md`](specs/gray-failure-health-and-delta-log-streaming.md).
- **Platform Auth Authority (`mu-auth`) & [`mu-console`](https://github.com/LMA1980/mu-console) API**: Integrates [`mu-auth`](https://github.com/LMA1980/mu-auth) (`PolicyFolio`s, `RoleLeases`, `super-operator` WebAuthn Passkey elevation with final-2-minute single renewal, `GithubEdgeAuthAdapter`, HMAC invites, and `__Host-mu_elevated` cookies) across `/api/auth/*` (`session`, `redeem`, `profile`, `passkeys/*`, `roles/*`, `elevate/*`, `activity`, `folios/*`, `role-folio-index`, `users/*`, `invites/*`, and `/api/internal/auth/snapshot`), plus a break-glass host CLI subcommand (`mu-ci-controller reset-passkeys <github_login>`). Also serves the Console API (`GET /api/repos`, `POST /api/repos/prune`, `DELETE /api/repos/{owner}/{repo}` alongside `ACTION_RUNNER_RETIRED_REPOS` startup retirement, `GET /api/repos/{owner}/{repo}/summary`, `GET /api/repos/{owner}/{repo}/topology`, and SSE `/api/events`) consumed by [`mu-console`](https://github.com/LMA1980/mu-console). See [docs/console-api.md](docs/console-api.md).
- **Post-CI `mu-registry` CAS Upload & `mu-cd-controller` Rollout Trigger**: On successful `main`-branch `push` or `merge` jobs for CD-managed services (resolved via `DEFAULT_CD_MANAGED_SERVICES` / `MU_CI_CD_MANAGED_SERVICES`, optional `.muci/mu-ci.yml` `cd` metadata, or legacy manifest fallback), packages the release binary (or static SPA `dist/` bundle) and `tests/smoke_*.rs` integration-test (IT) archive, uploads the multipart CAS bundle to [`mu-registry`](https://github.com/LMA1980/mu-registry), and dispatches a digest-only `POST /api/cd/deploy` notification to [`mu-cd-controller`](https://github.com/LMA1980/mu-cd-controller) (whose deployment targets and rollback policy live in the signature-verified deployment policy repository).
- **Factory Pipeline Quality Scoring & SVG Rendering**: Computes letter grade (`A+` to `F`), pass ratios, coverage summaries, advisories, and micro-benchmarks across submodules, serving dynamic SVG badges (`/badges/*`) and live multi-metric scorecard cards (`/cards/*`).

## Declarative Workflow & `sccache` Configuration (`.muci/mu-ci.yml` / `.actionrunner/ActionRunner.yml`)

`mu-ci-controller` parses declarative workflows (`version: "3"` and `version: "4"`) from `.muci/mu-ci.yml` (with `.actionrunner/ActionRunner.yml` fallback) and enforces [`sccache`](https://github.com/mozilla/sccache) compiler cache policies at the **workflow**, **stage**, and **task** levels.

> **Complete Operator & Workflow Portal Guide**: See [**Operator & Workflow Guide: Distributed `sccache` Compilation Caching**](https://github.com/LMA1980/lma1980.github.io/blob/main/content/docs/sccache-guide.md) for a walkthrough of `sccache` build timings, `CARGO_INCREMENTAL=0`, cross-node toolchain alignment, and worker setup.

### 1. Policy Modes (`SccacheMode`) & Scheduling Behavior

| Policy Value          | Accepted YAML Literals                | Scheduling & Runtime Behavior                                                                                                                                                                                                                                                                                                                                                                                           |
| :-------------------- | :------------------------------------ | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`try`** *(default)* | `try`, `true`, `auto`, `yes`, `1`     | **Default when `sccache:` is omitted.** Dispatches to any worker matching the stage's `tags`. Uses `sccache` (`RUSTC_WRAPPER` + `CARGO_INCREMENTAL=0` + `SCCACHE_IDLE_TIMEOUT=0`) on eligible compiler tasks when `sccache` is installed and healthy on the assigned worker; falls back cleanly to uncached `rustc` compilation if `sccache` is absent or the cache backend is unreachable.                             |
| **`mandatory`**       | `mandatory`, `required`, `strict`     | Strictly requires `sccache` for compilation. The DAG scheduler automatically appends `"sccache"` to the stage's required worker capability tags (both during pre-claim slot reservation and `lease_slot`—if no matching online worker advertises `"sccache"`, the stage remains `Queued`), and the worker fails closed (`exit_code = 126`) if `sccache` is missing or fails its pre-flight `--show-stats` health check. |
| **`false`**           | `false`, `off`, `disabled`, `no`, `0` | Disables `sccache` and strips `RUSTC_WRAPPER` / `CARGO_BUILD_RUSTC_WRAPPER` from the task environment.                                                                                                                                                                                                                                                                                                                  |

### 2. Hierarchical Inheritance & Tool Eligibility

- **Resolution Precedence**:
  $$\\text{tasks.\<id>.sccache} \\longrightarrow \\text{stages}[i]\\text{.sccache} \\longrightarrow \\text{workflow.sccache} \\longrightarrow \\text{try}$$
- **Eligible Compiler Tools**: `cargo-build`, `cargo-check`, `cargo-test`, `cargo-clippy`, `cargo-bench`, and `trunk`.
- **Excluded Tools**: `cargo-fmt`, `cargo-audit`, `mdformat`, `cargo-llvm-cov`, and `cargo-miri` automatically bypass `sccache` so Miri's wrapper and LLVM coverage instrumentation are never clobbered. When `sccache: mandatory` is set at the workflow root, pure hygiene stages containing only non-compiler tasks do not force the `"sccache"` worker tag requirement.

### 3. Example `.muci/mu-ci.yml` (`version: "4"`)

```yaml
version: "4"
name: "Distributed Pipeline with Toolchain Gate & Shared sccache"
toolchain:
  min_version: "1.86.0"
  channel: "stable"
sccache: try # Workflow-wide default (try | mandatory | false)

tasks:
  fmt-task:
    tool: "cargo-fmt"
    args: ["--all", "--", "--check"]

  clippy-task:
    tool: "cargo-clippy"
    args: ["--workspace", "--all-targets", "--", "-D", "warnings"]

  release-build-task:
    tool: "cargo-build"
    args: ["--workspace", "--release"]
    sccache: mandatory # Task-level override requiring sccache

  uncached-test-task:
    tool: "cargo-test"
    args: ["--workspace"]
    sccache: false # Task-level override disabling sccache

  kva23-bench-task:
    tool: "cargo-bench"
    args: ["--workspace"]

stages:
  - id: fmt-check
    name: "Verify Formatting"
    tasks: ["fmt-task"]
    tags: ["fmt"]

  - id: clippy-check
    name: "Verify Linter Hygiene"
    tasks: ["clippy-task"]
    depends_on: ["fmt-check"]
    tags: ["clippy"]

  - id: build-release
    name: "Build Release Binaries"
    tasks: ["release-build-task"]
    depends_on: ["clippy-check"]
    tags: ["build"] # Controller automatically appends "sccache" tag due to mandatory task

  - id: test-suite
    name: "Run Uncached Tests"
    tasks: ["uncached-test-task"]
    depends_on: ["build-release"]
    tags: ["test"]
    sccache: false # Stage-level override

  - id: kva23-bench
    name: "Optional KVA23 Benchmark"
    tasks: ["kva23-bench-task"]
    depends_on: ["build-release"]
    tags: ["kva23"]
    if_unavailable:
      policy: skip
      pr_comment: true
      capability_label: "KVA23"

on_action:
  push: ["fmt-check", "clippy-check", "build-release", "test-suite", "kva23-bench"]
  pull_request: ["fmt-check", "clippy-check", "build-release", "test-suite", "kva23-bench"]
```

For worker-side `sccache` binary installation and `/etc/action-runner/sccache.env` S3/Garage configuration, see [`mu-ci-worker/README.md`](https://github.com/LMA1980/mu-ci-worker#operator-guide-shared-sccache-compiler-cache-integration).

## License

Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-only). See [LICENSE](LICENSE) for details.
