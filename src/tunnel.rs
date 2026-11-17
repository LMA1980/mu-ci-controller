use axum::{
    extract::{
        ws::{Message, WebSocket},
        Query, State, WebSocketUpgrade,
    },
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use mu_ci_ipc::{
    create_fory_runtime, decode_log_batch, decode_metric_batch, IpcHeader, StageCompletionReport,
    StageStarted, WorkerHeartbeat, WorkerRegistration, WorkerShutdown, MSG_TYPE_ARROW_LOG,
    MSG_TYPE_ARROW_METRIC, MSG_TYPE_STAGE_CANCEL, MSG_TYPE_STAGE_COMPLETION,
    MSG_TYPE_STAGE_DISPATCH, MSG_TYPE_STAGE_STARTED, MSG_TYPE_WORKER_HEARTBEAT,
    MSG_TYPE_WORKER_REGISTRATION, MSG_TYPE_WORKER_SHUTDOWN,
};

use crate::aggregator::{aggregate_metrics, append_logs, format_log_entries};
use crate::cluster::WorkerCommand;
use crate::job::{JobRecord, JobStatus, StageStatus};
use crate::storage_backend::{
    job_root_trace_context, job_stage_trace_context, match_explicit_ci_failure_kind, CiFailureKind,
};
use crate::webhook::AppState;
use mu_observable_ipc::{encode_hex, OtelSpanEntry};

/// Classified stage completion status and OpenTelemetry span metadata for `ci.stage.dispatch:*`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct StageDispatchClassification {
    pub stage_status: StageStatus,
    pub span_status_code: String,
    pub span_status_message: Option<String>,
    pub outcome: &'static str,
    pub failure_class: &'static str,
    pub superseded: bool,
    pub cancelled: bool,
}

/// Classifies an incoming [`StageCompletionReport`] against existing job/stage state so ordinary
/// user CI outcomes (`101`), timeouts (`124`), cancellations (`130`), and late `SIGTERM` completions
/// on superseded/skipped jobs record `"OK"` span status with structured outcome attributes, while
/// reserving `"ERROR"` strictly for controller/worker infrastructure faults (`#218`, `#222`).
#[must_use]
pub(crate) fn classify_stage_completion(
    report: &StageCompletionReport,
    existing_job: Option<&JobRecord>,
) -> StageDispatchClassification {
    let job_skip_reason = existing_job.and_then(|j| match &j.status {
        JobStatus::Skipped { reason } => Some(reason.as_str()),
        _ => None,
    });
    let stage_skip_reason = existing_job
        .and_then(|j| j.stages.iter().find(|s| s.id == report.stage_id))
        .and_then(|s| match &s.status {
            StageStatus::Skipped { reason } => Some(reason.as_str()),
            _ => None,
        });

    if let Some(reason) = stage_skip_reason.or(job_skip_reason) {
        let is_superseded = reason.to_ascii_lowercase().contains("superseded");
        let label = if is_superseded {
            "superseded"
        } else {
            "cancelled"
        };
        return StageDispatchClassification {
            stage_status: StageStatus::Skipped {
                reason: reason.to_string(),
            },
            span_status_code: "OK".to_string(),
            span_status_message: None,
            outcome: label,
            failure_class: label,
            superseded: is_superseded,
            cancelled: !is_superseded,
        };
    }

    if let Some(ref denied) = report.security_grant_denied {
        let err = report
            .error_message
            .clone()
            .unwrap_or_else(|| format!("Security grant denied: {denied:?}"));
        return StageDispatchClassification {
            stage_status: StageStatus::Failed { error: err.clone() },
            span_status_code: "ERROR".to_string(),
            span_status_message: Some(err),
            outcome: "infra_failure",
            failure_class: "security_grant_denied",
            superseded: false,
            cancelled: false,
        };
    }

    if report.exit_code == 0 {
        return StageDispatchClassification {
            stage_status: StageStatus::Completed {
                duration_secs: report.duration_secs,
                exit_code: 0,
            },
            span_status_code: "OK".to_string(),
            span_status_message: None,
            outcome: "passed",
            failure_class: "none",
            superseded: false,
            cancelled: false,
        };
    }

    let job_already_terminal = existing_job.is_some_and(|j| {
        matches!(
            j.status,
            JobStatus::Completed { .. } | JobStatus::Failed { .. } | JobStatus::Skipped { .. }
        )
    });
    let explicit_kind = report
        .error_message
        .as_deref()
        .and_then(match_explicit_ci_failure_kind);

    let kind = if job_already_terminal
        && (report.exit_code == 130
            || report.exit_code < 0
            || matches!(
                explicit_kind,
                Some(CiFailureKind::Cancelled | CiFailureKind::Superseded)
            )) {
        CiFailureKind::Cancelled
    } else if let Some(explicit) = explicit_kind {
        match explicit {
            CiFailureKind::UserCode => classify_exit_code(report.exit_code),
            other => other,
        }
    } else {
        classify_exit_code(report.exit_code)
    };

    let err_msg = report
        .error_message
        .clone()
        .unwrap_or_else(|| format!("Process exited with code {}", report.exit_code));

    let stage_status = if job_already_terminal
        && matches!(kind, CiFailureKind::Cancelled | CiFailureKind::Superseded)
    {
        StageStatus::Skipped {
            reason: err_msg.clone(),
        }
    } else {
        StageStatus::Failed {
            error: err_msg.clone(),
        }
    };

    let span_status_message = if kind == CiFailureKind::InfraError {
        Some(err_msg)
    } else {
        None
    };

    StageDispatchClassification {
        stage_status,
        span_status_code: kind.span_status_code().to_string(),
        span_status_message,
        outcome: kind.outcome_label(),
        failure_class: kind.failure_class_label(),
        superseded: kind == CiFailureKind::Superseded,
        cancelled: kind == CiFailureKind::Cancelled,
    }
}

const fn classify_exit_code(exit_code: i32) -> CiFailureKind {
    match exit_code {
        130 => CiFailureKind::Cancelled,
        124 => CiFailureKind::UserTimeout,
        126 | 127 => CiFailureKind::InfraError,
        c if c < 0 => CiFailureKind::InfraError,
        _ => CiFailureKind::UserCode,
    }
}

/// Builds the controller `ci.stage.dispatch:*` [`OtelSpanEntry`] from a classified [`StageCompletionReport`].
#[must_use]
pub(crate) fn build_stage_dispatch_span(
    report: &StageCompletionReport,
    existing_job: Option<&JobRecord>,
    node_id: &str,
    now_ns: i64,
) -> (StageDispatchClassification, OtelSpanEntry) {
    let classification = classify_stage_completion(report, existing_job);
    let commit_sha = existing_job
        .map(|j| j.job.commit_sha.as_str())
        .unwrap_or("");
    let root_ctx = job_root_trace_context(&report.job_id, commit_sha);
    let stage_ctx = job_stage_trace_context(&report.job_id, commit_sha, &report.stage_id);
    let duration_ns = report.duration_secs.saturating_mul(1_000_000_000);
    let start_ns = (now_ns - duration_ns as i64).max(0);
    let mut attrs = serde_json::json!({
        "job_id": report.job_id,
        "stage_id": report.stage_id,
        "exit_code": report.exit_code,
        "ci.outcome": classification.outcome,
        "ci.failure_class": classification.failure_class,
    });
    if let Some(obj) = attrs.as_object_mut() {
        if classification.superseded {
            obj.insert("superseded".to_string(), serde_json::Value::Bool(true));
        }
        if classification.cancelled {
            obj.insert("cancelled".to_string(), serde_json::Value::Bool(true));
        }
    }
    let span = OtelSpanEntry {
        trace_id: encode_hex(&stage_ctx.trace_id),
        span_id: encode_hex(&stage_ctx.span_id),
        parent_span_id: Some(encode_hex(&root_ctx.span_id)),
        service_name: "mu-ci-controller".to_string(),
        node_id: node_id.to_string(),
        span_name: format!("ci.stage.dispatch:{}", report.stage_id),
        span_kind: "INTERNAL".to_string(),
        start_time_unix_nano: start_ns,
        end_time_unix_nano: now_ns,
        duration_ns,
        status_code: classification.span_status_code.clone(),
        status_message: classification.span_status_message.clone(),
        attributes_json: attrs.to_string(),
    };
    (classification, span)
}

#[derive(Deserialize)]
pub struct TunnelQuery {
    pub token: Option<String>,
}

pub async fn handle_cluster_tunnel(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<TunnelQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    // Validate cluster authentication token
    let auth_header = headers
        .get("x-cluster-token")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let provided_token = auth_header.or(query.token).unwrap_or_default();
    if provided_token != state.config.cluster_token {
        warn!("Unauthorized worker connection attempt to /api/cluster/tunnel");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Reject connection if this controller is not the active leader (#104).
    if !state.job_store.is_leader() {
        warn!(
            controller_id = %state.config.node_id,
            ha_role = %state.job_store.ha_role().as_str(),
            "Rejecting worker tunnel connection attempt: controller is in Standby"
        );
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    Ok(ws.on_upgrade(move |socket| handle_socket(socket, state)))
}

async fn handle_socket(socket: WebSocket, state: Arc<AppState>) {
    let (mut ws_sender, mut ws_receiver) = socket.split();
    let fory = match create_fory_runtime() {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to create Fory runtime: {}", e);
            return;
        }
    };

    let (cmd_tx, mut cmd_rx) = mpsc::channel::<WorkerCommand>(32);
    let mut registered_node_id: Option<String> = None;
    let mut seq = 0u64;

    // Guard against role changes occurring during WebSocket upgrade handshake (#104)
    if !state.job_store.is_leader() {
        warn!(
            controller_id = %state.config.node_id,
            "Controller transitioned to Standby before worker registration; closing tunnel"
        );
        let close_frame = axum::extract::ws::CloseFrame {
            code: axum::extract::ws::close_code::NORMAL,
            reason: "controller in standby".into(),
        };
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            ws_sender.send(Message::Close(Some(close_frame))),
        )
        .await;
        return;
    }

    // First message must be WorkerRegistration
    if let Some(Ok(Message::Binary(bin))) = ws_receiver.next().await {
        if let Ok((hdr, payload)) = IpcHeader::parse(&bin) {
            if hdr.msg_type == MSG_TYPE_WORKER_REGISTRATION {
                if let Ok(reg) = fory.deserialize::<WorkerRegistration>(payload) {
                    let node_id = reg.node_id.clone();
                    state.cluster.register(reg, cmd_tx).await;
                    registered_node_id = Some(node_id);
                }
            }
        }
    }

    let node_id = match registered_node_id {
        Some(id) => id,
        None => {
            warn!("Worker failed to register within initial frame; terminating tunnel");
            return;
        }
    };

    info!(node = %node_id, "Cluster tunnel session active");

    loop {
        tokio::select! {
            // Outbound commands dispatched to worker
            cmd_opt = cmd_rx.recv() => {
                let Some(cmd) = cmd_opt else {
                    break;
                };
                seq += 1;
                match cmd {
                    WorkerCommand::Dispatch(task) => {
                        match fory.serialize(&task) {
                            Ok(payload) => {
                                let header = IpcHeader::new(MSG_TYPE_STAGE_DISPATCH, payload.len() as u32, 0, seq);
                                let mut frame = Vec::with_capacity(mu_ci_ipc::HEADER_SIZE + payload.len());
                                frame.extend_from_slice(zerocopy::IntoBytes::as_bytes(&header));
                                frame.extend_from_slice(&payload);
                                match tokio::time::timeout(
                                    std::time::Duration::from_secs(10),
                                    ws_sender.send(Message::Binary(frame.into())),
                                )
                                .await
                                {
                                    Ok(Ok(())) => {
                                        info!(stage = %task.stage_id, "Dispatched stage frame successfully sent to ws_sender");
                                    }
                                    Ok(Err(e)) => {
                                        error!("Failed to send dispatch frame over ws: {}", e);
                                        state
                                            .cluster
                                            .release_stage_slot(&node_id, &task.job_id, &task.stage_id)
                                            .await;
                                        let _ = state
                                            .job_store
                                            .recover_stage_if_active(&task.job_id, &task.stage_id)
                                            .await;
                                        break;
                                    }
                                    Err(_) => {
                                        error!(node = %node_id, stage = %task.stage_id, "Timed out (10s) sending dispatch frame over ws");
                                        state
                                            .cluster
                                            .release_stage_slot(&node_id, &task.job_id, &task.stage_id)
                                            .await;
                                        let _ = state
                                            .job_store
                                            .recover_stage_if_active(&task.job_id, &task.stage_id)
                                            .await;
                                        break;
                                    }
                                }
                            }
                            Err(e) => {
                                error!(stage = %task.stage_id, error = %e, "Failed to serialize StageDispatchTask with Fory");
                                state
                                    .cluster
                                    .release_stage_slot(&node_id, &task.job_id, &task.stage_id)
                                    .await;
                                state
                                    .job_store
                                    .update_stage_status(
                                        &task.job_id,
                                        &task.stage_id,
                                        StageStatus::Failed {
                                            error: format!(
                                                "Failed to serialize stage dispatch frame: {}",
                                                e
                                            ),
                                        },
                                    )
                                    .await;
                                state.job_store.notify_event();
                            }
                        }
                    }
                    WorkerCommand::Cancel(cancel) => {
                        if let Ok(payload) = fory.serialize(&cancel) {
                            let header = IpcHeader::new(MSG_TYPE_STAGE_CANCEL, payload.len() as u32, 0, seq);
                            let mut frame = Vec::with_capacity(mu_ci_ipc::HEADER_SIZE + payload.len());
                            frame.extend_from_slice(zerocopy::IntoBytes::as_bytes(&header));
                            frame.extend_from_slice(&payload);
                            if tokio::time::timeout(
                                std::time::Duration::from_secs(10),
                                ws_sender.send(Message::Binary(frame.into())),
                            )
                            .await
                            .is_err()
                            {
                                warn!(node = %node_id, "Timed out (10s) sending cancel frame over ws");
                                break;
                            }
                        }
                    }
                    WorkerCommand::Disconnect => {
                        let close_frame = axum::extract::ws::CloseFrame {
                            code: axum::extract::ws::close_code::NORMAL,
                            reason: "controller demoted to standby".into(),
                        };
                        let _ = tokio::time::timeout(
                            std::time::Duration::from_secs(10),
                            ws_sender.send(Message::Close(Some(close_frame))),
                        )
                        .await;
                        break;
                    }
                }
            }

            // Inbound messages received from worker
            msg_res = ws_receiver.next() => {
                let msg = match msg_res {
                    Some(Ok(m)) => m,
                    _ => break, // Disconnected
                };

                match msg {
                    Message::Ping(payload) => {
                        if !state.job_store.is_leader() {
                            warn!(
                                node = %node_id,
                                controller_id = %state.config.node_id,
                                "Evicting worker tunnel on Ping: controller is not Leader"
                            );
                            let close_frame = axum::extract::ws::CloseFrame {
                                code: axum::extract::ws::close_code::NORMAL,
                                reason: "controller demoted to standby".into(),
                            };
                            let _ = tokio::time::timeout(
                                std::time::Duration::from_secs(10),
                                ws_sender.send(Message::Close(Some(close_frame))),
                            )
                            .await;
                            break;
                        }
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(10),
                            ws_sender.send(Message::Pong(payload)),
                        )
                        .await
                        {
                            Ok(Ok(())) => {}
                            _ => break,
                        }
                    }
                    Message::Close(_) => break,
                    Message::Binary(bin) => {
                        if let Ok((hdr, payload)) = IpcHeader::parse(&bin) {
                            match hdr.msg_type {
                                MSG_TYPE_WORKER_HEARTBEAT => {
                                    if !state.job_store.is_leader() {
                                        warn!(
                                            node = %node_id,
                                            controller_id = %state.config.node_id,
                                            "Evicting worker tunnel on Heartbeat: controller is not Leader"
                                        );
                                        let close_frame = axum::extract::ws::CloseFrame {
                                            code: axum::extract::ws::close_code::NORMAL,
                                            reason: "controller demoted to standby".into(),
                                        };
                                        let _ = tokio::time::timeout(
                                            std::time::Duration::from_secs(10),
                                            ws_sender.send(Message::Close(Some(close_frame))),
                                        )
                                        .await;
                                        break;
                                    }
                                    if let Ok(hb) = fory.deserialize::<WorkerHeartbeat>(payload) {
                                        state.cluster.heartbeat(hb).await;
                                        // Acknowledge heartbeat at application layer so the worker's
                                        // inbound read-liveness deadline is refreshed every 5s (#104, #39).
                                        match tokio::time::timeout(
                                            std::time::Duration::from_secs(10),
                                            ws_sender.send(Message::Pong(Vec::new().into())),
                                        )
                                        .await
                                        {
                                            Ok(Ok(())) => {}
                                            _ => break,
                                        }
                                    }
                                }
                            MSG_TYPE_STAGE_COMPLETION => {
                                if let Ok(report) = fory.deserialize::<StageCompletionReport>(payload) {
                                    info!(
                                        node = %node_id,
                                        job_id = %report.job_id,
                                        stage = %report.stage_id,
                                        exit_code = report.exit_code,
                                        duration = report.duration_secs,
                                        "Stage completed by worker"
                                    );

                                    // Flush any buffered stage logs and inspect existing job/stage status
                                    // before classifying late worker completions and releasing the slot.
                                    state.job_store.flush_job_log(Some(&report.job_id));

                                    let existing_job =
                                        state.job_store.get_job(&report.job_id).await;
                                    let now_ns = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_nanos() as i64;
                                    let (classification, span_entry) = build_stage_dispatch_span(
                                        &report,
                                        existing_job.as_ref(),
                                        &node_id,
                                        now_ns,
                                    );
                                    state.job_store.emit_trace_spans(&[span_entry]);

                                    state
                                        .cluster
                                        .release_stage_slot(
                                            &node_id,
                                            &report.job_id,
                                            &report.stage_id,
                                        )
                                        .await;
                                    state
                                        .job_store
                                        .update_stage_status(
                                            &report.job_id,
                                            &report.stage_id,
                                            classification.stage_status,
                                        )
                                        .await;
                                    state.job_store.notify_event();
                                }
                            }
                            MSG_TYPE_WORKER_SHUTDOWN => {
                                if let Ok(shutdown) = fory.deserialize::<WorkerShutdown>(payload) {
                                    info!(
                                        node = %node_id,
                                        reason = %shutdown.reason,
                                        interrupted = ?shutdown.interrupted_stages,
                                        "Worker signaled shutdown/restart"
                                    );
                                    state.cluster.release_slot(&node_id).await;
                                    let recovered = state
                                        .job_store
                                        .recover_stages_for_node(
                                            &node_id,
                                            Some(&shutdown.interrupted_stages),
                                        )
                                        .await;
                                    for (job_id, stage_id) in &recovered {
                                        if let Some(record) = state.job_store.get_job(job_id).await
                                        {
                                            let note = format!(
                                                "{} [{}] [{}] [stderr] Worker signaled restart; stage execution interrupted and returned to queue for re-dispatch\n",
                                                chrono::Utc::now().to_rfc3339(),
                                                node_id,
                                                stage_id
                                            );
                                            append_note_to_job_log_bounded(
                                                &state,
                                                &record.log_file,
                                                &note,
                                            )
                                            .await;
                                            state.job_store.append_log_lines(job_id, &note);
                                            state.broadcast_log(job_id, &note);
                                        }
                                    }
                                    state.job_store.notify_event();
                                }
                            }
                            MSG_TYPE_STAGE_STARTED => {
                                if let Ok(started) = fory.deserialize::<StageStarted>(payload) {
                                    info!(
                                        job_id = %started.job_id,
                                        stage_id = %started.stage_id,
                                        node_id = %started.node_id,
                                        pid = started.pid,
                                        "Worker reported stage process spawned with PID"
                                    );
                                    state
                                        .job_store
                                        .update_stage_running(
                                            &started.job_id,
                                            &started.stage_id,
                                            &started.node_id,
                                            started.pid,
                                        )
                                        .await;
                                }
                            }
                            MSG_TYPE_ARROW_LOG => {
                                if let Ok(entries) = decode_log_batch(payload) {
                                    if let Some(first) = entries.first() {
                                        let job_id = first.job_id.clone();
                                        if let Some(record) = state.job_store.get_job(&job_id).await {
                                            let ws_dir = state.config.workspace_dir.clone();
                                            let rel_log = record.log_file.clone();
                                            let entries_for_disk = entries.clone();
                                            let disk_res = tokio::time::timeout(
                                                std::time::Duration::from_secs(5),
                                                tokio::task::spawn_blocking(
                                                    move || -> std::io::Result<()> {
                                                        let Some(full_path) =
                                                            resolve_safe_log_path(&ws_dir, &rel_log)
                                                        else {
                                                            return Err(std::io::Error::new(
                                                                std::io::ErrorKind::InvalidInput,
                                                                "invalid log path",
                                                            ));
                                                        };
                                                        append_logs(&full_path, &entries_for_disk)
                                                    },
                                                ),
                                            )
                                            .await;
                                            match disk_res {
                                                Ok(Ok(Ok(()))) => {
                                                    state.job_store.mark_disk_io_healthy();
                                                }
                                                _ => {
                                                    state.job_store.mark_disk_io_unhealthy();
                                                }
                                            }
                                            state
                                                .job_store
                                                .append_structured_log_entries(&job_id, &entries)
                                                .await;
                                            let chunk = format_log_entries(&entries);
                                            let _ = state.log_broadcaster.send(crate::webhook::LogBroadcast {
                                                job_id,
                                                chunk,
                                            });
                                        }
                                    }
                                }
                            }
                            MSG_TYPE_ARROW_METRIC => {
                                if let Ok(metric_entries) = decode_metric_batch(payload) {
                                    if let Some(first) = metric_entries.first() {
                                        let aggregated = aggregate_metrics(&metric_entries, true);
                                        state.job_store.update_metrics(&first.job_id, aggregated).await;
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    }
                    _ => {}
                }
            }
        }
    }

    state.cluster.unregister(&node_id).await;
    // Auto-recover any remaining stages assigned to this worker node
    let recovered = state
        .job_store
        .recover_stages_for_node(&node_id, None)
        .await;
    if !recovered.is_empty() {
        warn!(
            node = %node_id,
            count = recovered.len(),
            "Worker disconnected; recovered orphan stages back to Pending"
        );
        for (job_id, stage_id) in &recovered {
            if let Some(record) = state.job_store.get_job(job_id).await {
                let note = format!(
                    "{} [controller] [{}] [stderr] Worker '{}' disconnected unexpectedly; stage returned to queue for recovery\n",
                    chrono::Utc::now().to_rfc3339(),
                    stage_id,
                    node_id
                );
                append_note_to_job_log_bounded(&state, &record.log_file, &note).await;
                state.job_store.append_log_lines(job_id, &note);
                state.broadcast_log(job_id, &note);
            }
        }
        state.job_store.notify_event();
    }
    info!(node = %node_id, "Cluster tunnel session terminated");
}

pub(crate) fn resolve_safe_log_path(
    workspace_dir: &std::path::Path,
    rel_log_file: &std::path::Path,
) -> Option<std::path::PathBuf> {
    let canonical_ws = std::fs::canonicalize(workspace_dir).ok()?;
    let mut safe_rel = std::path::PathBuf::new();
    for comp in rel_log_file.components() {
        match comp {
            std::path::Component::Normal(seg) => {
                let s = seg.to_str()?;
                if s.is_empty() || s == "." || s == ".." || s.contains('/') || s.contains('\\') {
                    return None;
                }
                safe_rel.push(s);
            }
            _ => return None,
        }
    }
    if safe_rel.as_os_str().is_empty() {
        return None;
    }
    let joined = canonical_ws.join(&safe_rel);
    if !joined.starts_with(&canonical_ws) {
        return None;
    }
    let parent = joined.parent()?;
    if !parent.starts_with(&canonical_ws) {
        return None;
    }
    std::fs::create_dir_all(parent).ok()?;
    let canonical_parent = std::fs::canonicalize(parent).ok()?;
    if !canonical_parent.starts_with(&canonical_ws) {
        return None;
    }
    let file_name = joined.file_name()?.to_str()?;
    if file_name.contains("..") || file_name.contains('/') || file_name.contains('\\') {
        return None;
    }
    let final_path = canonical_parent.join(file_name);
    if !final_path.starts_with(&canonical_ws) {
        return None;
    }
    Some(final_path)
}

pub(crate) async fn append_note_to_job_log_bounded(
    state: &Arc<AppState>,
    rel_log_file: &std::path::Path,
    note: &str,
) {
    let ws_dir = state.config.workspace_dir.clone();
    let rel = rel_log_file.to_path_buf();
    let note_owned = note.to_string();
    let write_res = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let Some(full_path) = resolve_safe_log_path(&ws_dir, &rel) else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "invalid log path",
                ));
            };
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&full_path)?;
            f.write_all(note_owned.as_bytes())
        }),
    )
    .await;
    match write_res {
        Ok(Ok(Ok(()))) => state.job_store.mark_disk_io_healthy(),
        _ => state.job_store.mark_disk_io_unhealthy(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::{Job, JobStore, StageRecord};
    use chrono::Utc;
    use mu_ci_ipc::SecurityGrantDenied;
    use std::path::PathBuf;

    fn sample_report(exit_code: i32, error_message: Option<&str>) -> StageCompletionReport {
        StageCompletionReport {
            job_id: "job-test-1".to_string(),
            stage_id: "clippy-check".to_string(),
            exit_code,
            duration_secs: 12,
            error_message: error_message.map(ToString::to_string),
            security_grant_denied: None,
            traceparent: None,
        }
    }

    #[test]
    fn stage_dispatch_span_classifies_user_ci_outcomes_cancellations_and_infra_faults() {
        // 1. Clean pass (exit 0)
        let (cls_ok, span_ok) =
            build_stage_dispatch_span(&sample_report(0, None), None, "node-a", 20_000_000_000);
        assert_eq!(span_ok.status_code, "OK");
        assert_eq!(span_ok.status_message, None);
        assert_eq!(cls_ok.outcome, "passed");
        assert_eq!(cls_ok.failure_class, "none");
        assert!(matches!(
            cls_ok.stage_status,
            StageStatus::Completed { exit_code: 0, .. }
        ));

        // 2. Ordinary user CI lint/test exit code (101) -> OK span status with user_failure attrs
        let (cls_101, span_101) = build_stage_dispatch_span(
            &sample_report(
                101,
                Some("Tool 'cargo-clippy' exited with status code Some(101)"),
            ),
            None,
            "node-a",
            20_000_000_000,
        );
        assert_eq!(span_101.status_code, "OK");
        assert_eq!(span_101.status_message, None);
        assert_eq!(cls_101.outcome, "user_failure");
        assert_eq!(cls_101.failure_class, "user_code");
        let attrs_101: serde_json::Value = serde_json::from_str(&span_101.attributes_json).unwrap();
        assert_eq!(attrs_101["exit_code"], 101);
        assert_eq!(attrs_101["ci.outcome"], "user_failure");
        assert_eq!(attrs_101["ci.failure_class"], "user_code");

        // 3. Pre-permit cancellation (130) -> OK span status
        let (cls_130, span_130) = build_stage_dispatch_span(
            &sample_report(130, Some("Stage cancelled before permit acquisition")),
            None,
            "node-a",
            20_000_000_000,
        );
        assert_eq!(span_130.status_code, "OK");
        assert_eq!(cls_130.outcome, "cancelled");
        assert!(cls_130.cancelled);

        // 4. User stage timeout (124) -> OK span status
        let (cls_124, span_124) = build_stage_dispatch_span(
            &sample_report(124, Some("Stage execution timed out after 1200s")),
            None,
            "node-a",
            20_000_000_000,
        );
        assert_eq!(span_124.status_code, "OK");
        assert_eq!(cls_124.outcome, "timeout");
        assert_eq!(cls_124.failure_class, "user_timeout");

        // 5. Unrequested crash (-1) on active/unknown job -> ERROR span status
        let (cls_crash, span_crash) = build_stage_dispatch_span(
            &sample_report(-1, Some("Failed to spawn tool process 'cargo-test'")),
            None,
            "node-a",
            20_000_000_000,
        );
        assert_eq!(span_crash.status_code, "ERROR");
        assert!(span_crash.status_message.is_some());
        assert_eq!(cls_crash.outcome, "infra_failure");

        // 6. SecurityGrantDenied -> ERROR span status
        let mut denied_report = sample_report(1, Some("Sandbox policy violation"));
        denied_report.security_grant_denied = Some(SecurityGrantDenied {
            job_id: "job-test-1".to_string(),
            stage_id: "clippy-check".to_string(),
            violated_layer: "cgroupv2".to_string(),
            offending_field: "max_pids".to_string(),
            requested_value: "1024".to_string(),
            ceiling_value: "256".to_string(),
        });
        let (cls_sec, span_sec) =
            build_stage_dispatch_span(&denied_report, None, "node-a", 20_000_000_000);
        assert_eq!(span_sec.status_code, "ERROR");
        assert_eq!(cls_sec.outcome, "infra_failure");
        assert_eq!(cls_sec.failure_class, "security_grant_denied");
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn late_stage_completion_on_superseded_job_emits_ok_span_and_preserves_skipped() {
        let store = JobStore::new(10, None);
        let now = Utc::now();
        let sha = "abcdef0123456789abcdef0123456789abcdef01";

        let push_job = Job {
            id: "job-superseded-tunnel".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/example".to_string(),
            clone_url: "https://github.com/LMA1980/example.git".to_string(),
            commit_sha: sha.to_string(),
            ref_name: "refs/heads/feat/telemetry".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: now,
            pr_number: None,
        };
        store
            .enqueue_job(push_job.clone(), PathBuf::from("logs/push.log"))
            .await;
        store
            .set_stages(
                &push_job.id,
                vec![StageRecord {
                    id: "test-check".to_string(),
                    name: "Test".to_string(),
                    tags: vec!["x86_64".to_string()],
                    threads: 4,
                    toolchain: None,
                    depends_on: vec![],
                    status: StageStatus::Running {
                        node_id: "node-a".to_string(),
                        started_at: now,
                        pid: Some(777),
                    },
                    assigned_node: Some("node-a".to_string()),
                    exclusive: false,
                    skip_if_unavailable: false,
                    skip_reason_code: None,
                    skip_capability: None,
                }],
            )
            .await;
        store
            .update_status(&push_job.id, JobStatus::Running { started_at: now })
            .await;

        let pr_job = Job {
            id: "job-pr-superseder".to_string(),
            event_type: "pull_request".to_string(),
            repo_name: "LMA1980/example".to_string(),
            clone_url: "https://github.com/LMA1980/example.git".to_string(),
            commit_sha: sha.to_string(),
            ref_name: "refs/heads/feat/telemetry".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: now + chrono::Duration::seconds(1),
            pr_number: Some(9),
        };
        store
            .enqueue_job(pr_job, PathBuf::from("logs/pr.log"))
            .await;

        let existing = store.get_job(&push_job.id).await;
        let late_report = StageCompletionReport {
            job_id: push_job.id.clone(),
            stage_id: "test-check".to_string(),
            exit_code: -1,
            duration_secs: 4,
            error_message: Some("Tool 'cargo-test' terminated by SIGTERM".to_string()),
            security_grant_denied: None,
            traceparent: None,
        };
        let (cls, span) =
            build_stage_dispatch_span(&late_report, existing.as_ref(), "node-a", 10_000_000_000);
        assert_eq!(span.status_code, "OK");
        assert_eq!(span.status_message, None);
        assert!(matches!(cls.stage_status, StageStatus::Skipped { .. }));
        let attrs: serde_json::Value = serde_json::from_str(&span.attributes_json).unwrap();
        assert_eq!(attrs["ci.outcome"], "superseded");
        assert_eq!(attrs["superseded"], true);

        store
            .update_stage_status(&push_job.id, "test-check", cls.stage_status)
            .await;
        let after = store.get_job(&push_job.id).await.unwrap();
        assert!(matches!(after.status, JobStatus::Skipped { .. }));
        assert!(matches!(
            after.stages[0].status,
            StageStatus::Skipped { .. }
        ));
    }
}
