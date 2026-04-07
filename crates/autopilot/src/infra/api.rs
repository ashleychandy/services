use {
    crate::{
        infra::persistence::dto,
        solvable_orders::{DeltaAfterError, DeltaEvent, SolvableOrdersCache},
    },
    alloy::primitives::Address,
    axum::{
        Router,
        body::Body,
        extract::{ConnectInfo, Path, Query, State as AxumState},
        http::{HeaderMap, StatusCode},
        response::{IntoResponse, Json, Response, sse},
        routing::get,
    },
    const_hex,
    futures::StreamExt,
    model::quote::NativeTokenPrice,
    observe::tracing::distributed::axum::{make_span, record_trace_id},
    price_estimation::{PriceEstimationError, native::NativePriceEstimating},
    prometheus::{IntCounter, IntGauge},
    serde::{Deserialize, Serialize},
    sha2::{Digest, Sha256},
    std::{
        convert::Infallible,
        net::SocketAddr,
        ops::RangeInclusive,
        sync::{
            Arc,
            OnceLock,
            atomic::{AtomicU64, Ordering},
        },
        time::{Duration, Instant},
    },
    subtle::ConstantTimeEq,
    tokio::sync::{broadcast::error::TryRecvError, oneshot},
    tokio_stream::wrappers::{
        BroadcastStream,
        ReceiverStream,
        UnboundedReceiverStream,
        errors::BroadcastStreamRecvError,
    },
};

/// Minimum allowed timeout for price estimation requests.
/// Values below this are not useful as they don't give estimators enough time.
const MIN_TIMEOUT: Duration = Duration::from_millis(250);
static DELTA_SYNC_API_KEY: OnceLock<Option<String>> = OnceLock::new();

// Cached env-based delta stream configuration values. Parsing the process
// environment can acquire a global lock; cache the computed values on first
// access to avoid repeated env lookups per connection.
static DELTA_STREAM_MAX_LAG: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
static DELTA_STREAM_BUFFER_SIZE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
static DELTA_STREAM_KEEPALIVE_INTERVAL: std::sync::OnceLock<Duration> = std::sync::OnceLock::new();

#[cfg(test)]
#[derive(Clone, Debug)]
enum ApiKeyOverride {
    /// No override: fall through to the environment variable / OnceLock.
    NotSet,
    /// Override active: no key is required (open endpoint).
    NoKeyRequired,
    /// Override active: require exactly this key.
    Key(String),
}

#[cfg(test)]
mod invariant_tests {
    use super::*;

    #[tokio::test]
    async fn drain_never_produces_stale_envelopes() {
        let (sender, mut receiver) = tokio::sync::broadcast::channel(16);
        let checkpoint = 10u64;
        let mut replay_to = checkpoint;

        // Send envelopes spanning both sides of checkpoint
        for seq in 8u64..=14 {
            sender
                .send(crate::solvable_orders::DeltaEnvelope {
                    auction_id: 0,
                    auction_sequence: seq,
                    from_sequence: seq - 1,
                    to_sequence: seq,
                    published_at: chrono::Utc::now(),
                    published_at_instant: std::time::Instant::now(),
                    events: vec![],
                })
                .unwrap();
        }

        let outcome =
            drain_live_envelopes(&mut receiver, checkpoint, checkpoint, &mut replay_to).unwrap();

        // Every payload must have to_sequence > checkpoint
        for payload in &outcome.payloads {
            let wire: serde_json::Value = serde_json::from_str(payload).unwrap();
            let to_seq = wire["toSequence"].as_u64().unwrap();
            assert!(
                to_seq > checkpoint,
                "drain produced stale envelope with to_sequence={to_seq} <= \
                 checkpoint={checkpoint}"
            );
        }

        // replay_to must be monotonically updated
        assert!(replay_to >= checkpoint);
    }

    /// Verifies replay + drain produces a contiguous sequence.
    #[tokio::test]
    async fn replay_and_drain_produce_contiguous_sequence() {
        let (sender, mut receiver) = tokio::sync::broadcast::channel(16);

        // Simulate publish during replay window
        for seq in 5u64..=8 {
            sender
                .send(crate::solvable_orders::DeltaEnvelope {
                    auction_id: 0,
                    auction_sequence: seq,
                    from_sequence: seq - 1,
                    to_sequence: seq,
                    published_at: chrono::Utc::now(),
                    published_at_instant: std::time::Instant::now(),
                    events: vec![],
                })
                .unwrap();
        }

        let mut replay_to = 4u64;
        let outcome = drain_live_envelopes(&mut receiver, 4, 4, &mut replay_to).unwrap();

        // Verify contiguity
        let mut sequences: Vec<u64> = outcome
            .payloads
            .iter()
            .map(|p| {
                let wire: serde_json::Value = serde_json::from_str(p).unwrap();
                wire["toSequence"].as_u64().unwrap()
            })
            .collect();
        sequences.sort_unstable();

        for window in sequences.windows(2) {
            assert_eq!(
                window[1],
                window[0] + 1,
                "sequence gap detected: {} -> {}",
                window[0],
                window[1]
            );
        }
    }
}

#[cfg(test)]
impl Default for ApiKeyOverride {
    fn default() -> Self {
        Self::NotSet
    }
}

#[cfg(test)]
static DELTA_SYNC_API_KEY_OVERRIDE: std::sync::LazyLock<std::sync::Mutex<ApiKeyOverride>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(ApiKeyOverride::NotSet));

#[cfg(any(test, feature = "test-util"))]
static DELTA_SYNC_ENABLED_OVERRIDE: std::sync::LazyLock<std::sync::Mutex<Option<bool>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

#[cfg(any(test, feature = "test-util"))]
pub fn set_delta_sync_enabled_override(value: Option<bool>) {
    *DELTA_SYNC_ENABLED_OVERRIDE
        .lock()
        .expect("delta sync enabled override lock poisoned") = value;
}

#[cfg(any(test, feature = "test-util"))]
pub fn clear_delta_sync_enabled_override() {
    *DELTA_SYNC_ENABLED_OVERRIDE
        .lock()
        .expect("delta sync enabled override lock poisoned") = None;
}

#[cfg(test)]
static DELTA_SYNC_STREAM_BUFFER_OVERRIDE: std::sync::LazyLock<std::sync::Mutex<Option<usize>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

#[derive(Clone)]
struct State {
    estimator: Arc<dyn NativePriceEstimating>,
    allowed_timeout: RangeInclusive<Duration>,
    solvable_orders_cache: Arc<SolvableOrdersCache>,
}

#[derive(Debug, Deserialize)]
struct NativePriceQuery {
    /// Optional timeout in milliseconds for the price estimation request.
    /// If not provided, uses the default timeout configured for autopilot.
    /// Values below 250ms are automatically clamped to the minimum (250ms).
    /// Values exceeding the configured maximum are clamped to the maximum.
    #[serde(default)]
    timeout_ms: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
struct DeltaStreamQuery {
    /// Return events strictly after this sequence.
    #[serde(default)]
    after_sequence: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeltaSnapshotResponse {
    version: u32,
    boot_id: String,
    auction_id: u64,
    auction_sequence: u64,
    sequence: u64,
    oldest_available: u64,
    auction: dto::RawAuctionData,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeltaChecksumResponse {
    version: u32,
    sequence: u64,
    order_uid_hash: String,
    price_hash: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DeltaEventEnvelope {
    version: u32,
    boot_id: String,
    auction_id: u64,
    auction_sequence: u64,
    from_sequence: u64,
    to_sequence: u64,
    // Wire-only field used to validate stream position against the replay snapshot.
    #[serde(skip_serializing_if = "Option::is_none")]
    snapshot_sequence: Option<u64>,
    published_at: String,
    events: Vec<DeltaEventDto>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DeltaStreamGoneResponse {
    message: String,
    latest_sequence: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    oldest_available: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
enum DeltaEventDto {
    AuctionChanged {
        new_auction_id: u64,
    },
    BlockChanged {
        block: u64,
    },
    OrderAdded {
        order: dto::order::Order,
    },
    OrderRemoved {
        uid: String,
    },
    OrderUpdated {
        order: dto::order::Order,
    },
    PriceChanged {
        token: Address,
        price: Option<String>,
    },
    JitOwnersChanged {
        surplus_capturing_jit_order_owners: Vec<Address>,
    },
}

pub async fn serve(
    addr: SocketAddr,
    estimator: Arc<dyn NativePriceEstimating>,
    solvable_orders_cache: Arc<SolvableOrdersCache>,
    max_timeout: Duration,
    shutdown: oneshot::Receiver<()>,
) -> Result<(), std::io::Error> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    serve_with_listener(
        listener,
        estimator,
        solvable_orders_cache,
        max_timeout,
        shutdown,
    )
    .await
}

pub async fn serve_with_listener(
    listener: tokio::net::TcpListener,
    estimator: Arc<dyn NativePriceEstimating>,
    solvable_orders_cache: Arc<SolvableOrdersCache>,
    max_timeout: Duration,
    shutdown: oneshot::Receiver<()>,
) -> Result<(), std::io::Error> {
    let app = build_app(estimator, solvable_orders_cache, max_timeout);

    let addr = listener
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    tracing::info!(?addr, "serving HTTP API");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        shutdown.await.ok();
    })
    .await
}

pub(crate) fn build_app(
    estimator: Arc<dyn NativePriceEstimating>,
    solvable_orders_cache: Arc<SolvableOrdersCache>,
    max_timeout: Duration,
) -> Router {
    let state = State {
        estimator,
        allowed_timeout: MIN_TIMEOUT..=max_timeout,
        solvable_orders_cache,
    };
    build_router(state)
}

fn build_router(state: State) -> Router {
    let mut app = Router::new().route("/native_price/{token}", get(get_native_price));
    if delta_sync_enabled() {
        // Warn at startup if delta sync is enabled but no API key is configured.
        // This makes the operator aware that the endpoint is running unauthenticated.
        if delta_sync_api_key().is_none() {
            tracing::warn!(
                "delta sync API is running without authentication; set \
                 AUTOPILOT_DELTA_SYNC_API_KEY to require a key"
            );
        }
        app = app
            .route("/delta/snapshot", get(get_delta_snapshot))
            .route("/delta/stream", get(stream_delta_events))
            .route("/delta/checksum", get(get_delta_checksum));
    } else {
        tracing::warn!("delta sync API disabled via AUTOPILOT_DELTA_SYNC_ENABLED");
    }

    app.with_state(state).layer(
        tower::ServiceBuilder::new()
            .layer(tower_http::trace::TraceLayer::new_for_http().make_span_with(make_span))
            .map_request(record_trace_id),
    )
}

async fn get_delta_snapshot(headers: HeaderMap, AxumState(state): AxumState<State>) -> Response {
    if let Err(response) = authorize_delta_sync(&headers) {
        return response;
    }
    let metrics = DeltaMetrics::get();
    metrics.snapshot_requests.inc();
    let Some(snapshot) = state.solvable_orders_cache.delta_snapshot().await else {
        metrics.snapshot_empty.inc();
        return empty_delta_snapshot_response();
    };

    tracing::debug!(sequence = snapshot.sequence, "serving delta snapshot");

    let response = DeltaSnapshotResponse {
        version: 1,
        boot_id: crate::solvable_orders::boot_id().to_owned(),
        auction_id: snapshot.auction_id,
        auction_sequence: snapshot.auction_sequence,
        sequence: snapshot.sequence,
        oldest_available: snapshot.oldest_available,
        auction: dto::auction::from_domain(snapshot.auction),
    };

    let snapshot_bytes = match serialize_snapshot_response(response).await {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::error!(?err, "failed to serialize delta snapshot response");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    };

    let snapshot_len = snapshot_bytes.len();
    match Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(Body::from(snapshot_bytes))
    {
        Ok(response) => {
            metrics.snapshot_bytes.set(snapshot_len as i64);
            response
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response(),
    }
}

async fn stream_delta_events(
    Query(query): Query<DeltaStreamQuery>,
    headers: HeaderMap,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    AxumState(state): AxumState<State>,
) -> Response {
    if let Err(response) = authorize_delta_sync(&headers) {
        return response;
    }
    let metrics = DeltaMetrics::get();
    metrics.stream_connections.inc();
    let api_key_hash = api_key_hash(&headers);
    let active_stream = ActiveStreamGuard::new(remote_addr, api_key_hash);
    let baseline_sequence = query.after_sequence.unwrap_or_default();

    // First attempt: subscribe, build replay payloads, and drain live envelopes.
    let result = match subscribe_and_build_replay(
        &state.solvable_orders_cache,
        query.after_sequence,
        baseline_sequence,
    )
    .await
    {
        Ok(r) => r,

        Err(SubscribeReplayError::Subscribe(
            crate::solvable_orders::DeltaSubscribeError::MissingAfterSequence { .. },
        )) => {
            return (
                StatusCode::BAD_REQUEST,
                "after_sequence is required; call /delta/snapshot and use its sequence",
            )
                .into_response();
        }

        Err(SubscribeReplayError::Subscribe(
            crate::solvable_orders::DeltaSubscribeError::DeltaAfter(err),
        )) => {
            if matches!(
                err,
                crate::solvable_orders::DeltaAfterError::ResyncRequired { .. }
            ) {
                metrics.replay_miss.inc();
            }
            return delta_stream_after_error_response(err);
        }

        Err(SubscribeReplayError::Serialize(err)) => {
            tracing::error!(?err, "failed to serialize delta envelope during replay");
            metrics.serialize_errors.inc();
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }

        // Lag on first attempt: retry once before giving up.
        Err(SubscribeReplayError::Drain(DrainError::Lagged(skipped))) => {
            metrics.stream_lagged.inc();
            tracing::warn!(
                after_sequence = baseline_sequence,
                skipped,
                "delta stream lagged during initial drain; retrying subscription once"
            );

            // Single retry
            match subscribe_and_build_replay(
                &state.solvable_orders_cache,
                query.after_sequence,
                baseline_sequence,
            )
            .await
            {
                Ok(r) => r,

                Err(SubscribeReplayError::Drain(DrainError::Lagged(skipped2))) => {
                    tracing::warn!(
                        after_sequence = baseline_sequence,
                        skipped2,
                        "delta stream lagged even after retry"
                    );
                    return delta_stream_gone_response(
                        format!(
                            "resnapshot required because subscription lagged by {skipped2} \
                             messages"
                        ),
                        skipped2,
                        None,
                    );
                }

                Err(SubscribeReplayError::Serialize(err)) => {
                    tracing::error!(?err, "failed to serialize delta envelope during retry");
                    metrics.serialize_errors.inc();
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
                }

                Err(err) => {
                    tracing::warn!(?err, "failed to re-subscribe after lag");
                    return delta_stream_gone_response(
                        format!(
                            "resnapshot required because subscription lagged by {skipped} messages"
                        ),
                        baseline_sequence,
                        None,
                    );
                }
            }
        }

        Err(SubscribeReplayError::Drain(DrainError::Serialize(err))) => {
            tracing::error!(?err, "failed to serialize drained delta envelope");
            metrics.serialize_errors.inc();
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    };

    // Check initial lag guard (unchanged logic, just uses the result struct).
    let initial_lag = result.replay_to_sequence.saturating_sub(baseline_sequence);
    let max_stream_lag = delta_stream_max_lag();
    if initial_lag > max_stream_lag {
        metrics.stream_lagged.inc();
        tracing::warn!(
            after_sequence = baseline_sequence,
            replay_to_sequence = result.replay_to_sequence,
            initial_lag,
            "delta stream requires resnapshot due to lag"
        );
        return delta_stream_gone_response(
            format!("resnapshot required because subscription lagged by {initial_lag} messages"),
            result.replay_to_sequence,
            None,
        );
    }

    tracing::debug!(
        resume_from = baseline_sequence,
        replay_to_sequence = result.replay_to_sequence,
        "delta stream replay served"
    );

    // IMPORTANT: snapshotSequence semantics and transition
    //
    // Phase 1 (Replay + Drain):
    //   All events have snapshotSequence = baseline_sequence
    //   These events are valid relative to the snapshot at baseline_sequence.
    //   Clients validate these events against their cached snapshot from
    // baseline_sequence.
    //
    // Phase 2 (Live):
    //   All events have snapshotSequence = replay_to_sequence
    //   This marks an ANCHOR TRANSITION. The new snapshot anchor is at
    // replay_to_sequence.   After seeing the first live event, clients should
    // treat state at replay_to_sequence   as their new snapshot anchor for
    // validation.
    //
    // This transition is intentional and correct. The live phase anchor changes
    // because:
    // - Replay phase validates against: snapshot(baseline_sequence) + replay deltas
    // - Live phase validates against: state(replay_to_sequence) + live deltas
    // Both are equivalent states, but the reference point shifts.
    let replay_to_sequence = result.replay_to_sequence;
    // Tracks the latest contiguous sequence emitted to the client.
    let last_sequence = Arc::new(AtomicU64::new(replay_to_sequence));

    tracing::debug!(
        baseline_snapshot_sequence = baseline_sequence,
        live_phase_anchor_sequence = replay_to_sequence,
        "delta stream will transition from replay audit baseline to live phase anchor"
    );
    let replay_stream = tokio_stream::iter(result.payloads.into_iter().map(|payload| {
        Ok::<sse::Event, Infallible>(sse::Event::default().event("delta").data(payload))
    }));

    // Move the receiver out of the helper's result for use by the live stream.
    let receiver = result.receiver;
    let cache = Arc::clone(&state.solvable_orders_cache);
    let live_stream = BroadcastStream::new(receiver).filter_map(move |item| {
        let cache = Arc::clone(&cache);
        let last_sequence = Arc::clone(&last_sequence);
        async move {
            match item {
                Ok(envelope) => {
                    // Strict: skip anything at or below replay boundary. This
                    // handles duplicates that may overlap with the drained
                    // replay.
                    if envelope.to_sequence <= replay_to_sequence {
                        tracing::trace!(
                            to_sequence = envelope.to_sequence,
                            replay_to_sequence,
                            "live stream: skipping envelope already covered by replay"
                        );
                        return None;
                    }

                    let expected = last_sequence.load(Ordering::SeqCst);
                    if envelope.from_sequence != expected {
                        tracing::error!(
                            from_sequence = envelope.from_sequence,
                            expected,
                            "live stream: non-contiguous envelope"
                        );
                        let payload = serde_json::json!({
                            "message": "non-contiguous sequence detected",
                            "latestSequence": envelope.to_sequence,
                        })
                        .to_string();
                        return Some(Ok::<sse::Event, Infallible>(
                            sse::Event::default().event("resync_required").data(payload),
                        ));
                    }

                    last_sequence.store(envelope.to_sequence, Ordering::SeqCst);

                    // Live phase: snapshotSequence = replay_to_sequence (ANCHOR TRANSITION)
                    // After replay completes, we transition to a new snapshot anchor.
                    // Live envelopes validate against state(replay_to_sequence), which is
                    // equivalent to snapshot(baseline_sequence) + all replay deltas.
                    match serialize_envelope_to_payload(&envelope, Some(replay_to_sequence)) {
                        Ok(payload) => Some(Ok::<sse::Event, Infallible>(
                            sse::Event::default().event("delta").data(payload),
                        )),
                        Err(err) => {
                            tracing::error!(?err, "failed to serialize live delta envelope");
                            metrics.serialize_errors.inc();
                            Some(Ok::<sse::Event, Infallible>(
                                sse::Event::default()
                                    .event("error")
                                    .data("failed to serialize live delta envelope"),
                            ))
                        }
                    }
                }
                Err(BroadcastStreamRecvError::Lagged(skipped)) => {
                    metrics.stream_lagged.inc();
                    let latest_sequence =
                        cache.delta_sequence().await.unwrap_or(replay_to_sequence);
                    tracing::warn!(
                        after_sequence = baseline_sequence,
                        replay_to_sequence = replay_to_sequence,
                        skipped,
                        "delta stream lagged"
                    );
                    let payload = serde_json::json!({
                        "message": "delta stream lagged",
                        "latestSequence": latest_sequence,
                        "skipped": skipped,
                    })
                    .to_string();
                    Some(Ok::<sse::Event, Infallible>(
                        sse::Event::default().event("resync_required").data(payload),
                    ))
                }
            }
        }
    });
    let stream = replay_stream.chain(live_stream);

    let (stream_sender, stream_receiver) =
        tokio::sync::mpsc::channel::<Result<sse::Event, Infallible>>(delta_stream_buffer_size());
    let forward_sender = stream_sender.clone();
    // Dedicated unbounded control channel for critical events (resync_required)
    // so they are not dropped when the main bounded buffer is full.
    let (control_sender, control_receiver) =
        tokio::sync::mpsc::unbounded_channel::<Result<sse::Event, Infallible>>();
    let control_sender_clone = control_sender.clone();
    let cache = Arc::clone(&state.solvable_orders_cache);
    tokio::spawn(async move {
        let _active_stream = active_stream;
        let mut stream = Box::pin(stream);
        loop {
            tokio::select! {
                            _ = forward_sender.closed() => {
                                break;
                            }
                            item = stream.next() => {
                                let Some(item) = item else {
                                    break;
                                };
                                match forward_sender.try_send(item) {
                                    Ok(()) => {}
                                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                metrics.stream_lagged.inc();
                let latest_sequence =
                    cache.delta_sequence().await.unwrap_or(replay_to_sequence);
                let resync_payload = serde_json::json!({
                    "message": "delta stream dropped slow consumer",
                    "latestSequence": latest_sequence,
                    "skipped": 0
                })
                .to_string();

                // Send critical resync event over the unbounded control channel so
                // it won't be dropped due to the bounded consumer buffer.
                // control_sender_clone is injected into the spawn closure.
                if let Err(_) = control_sender_clone.send(Ok(sse::Event::default()
                    .event("resync_required")
                    .data(resync_payload))) {
                    tracing::debug!("resync control event dropped: channel closed");
                }

                tracing::warn!("delta stream dropped slow consumer");
                break;
            }
                                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                        break;
                                    }
                                }
                            }
                        }
        }
    });

    if result.drained_closed {
        let latest_sequence = state
            .solvable_orders_cache
            .delta_sequence()
            .await
            .unwrap_or(replay_to_sequence);
        let resync_payload = serde_json::json!({
            "message": "delta stream closed during replay drain",
            "latestSequence": latest_sequence,
            "skipped": 0
        })
        .to_string();
        if let Err(_) = control_sender.send(Ok(sse::Event::default()
            .event("resync_required")
            .data(resync_payload)))
        {
            tracing::debug!("resync control event dropped: channel closed");
        }
    }

    let control_stream = UnboundedReceiverStream::new(control_receiver);
    let regular_stream = ReceiverStream::new(stream_receiver);
    let merged = futures::stream::select(control_stream, regular_stream);

    sse::Sse::new(merged)
        .keep_alive(sse::KeepAlive::new().interval(delta_stream_keepalive_interval()))
        .into_response()
}

async fn get_delta_checksum(headers: HeaderMap, AxumState(state): AxumState<State>) -> Response {
    if let Err(response) = authorize_delta_sync(&headers) {
        return response;
    }

    let Some(checksum) = state.solvable_orders_cache.delta_checksum().await else {
        return StatusCode::NO_CONTENT.into_response();
    };

    Json(DeltaChecksumResponse {
        version: 1,
        sequence: checksum.sequence,
        order_uid_hash: checksum.order_uid_hash,
        price_hash: checksum.price_hash,
    })
    .into_response()
}

fn to_api_envelope(
    envelope: crate::solvable_orders::DeltaEnvelope,
    snapshot_sequence: Option<u64>,
) -> DeltaEventEnvelope {
    DeltaEventEnvelope {
        version: 1,
        boot_id: crate::solvable_orders::boot_id().to_owned(),
        auction_id: envelope.auction_id,
        auction_sequence: envelope.auction_sequence,
        from_sequence: envelope.from_sequence,
        to_sequence: envelope.to_sequence,
        snapshot_sequence,
        published_at: envelope.published_at.to_rfc3339(),
        events: envelope
            .events
            .into_iter()
            .map(delta_event_to_dto)
            .collect(),
    }
}

fn serialize_envelope_to_payload(
    envelope: &crate::solvable_orders::DeltaEnvelope,
    snapshot_sequence: Option<u64>,
) -> Result<String, serde_json::Error> {
    let mut buf = Vec::with_capacity(512 + envelope.events.len() * 256);
    let api_envelope = to_api_envelope(envelope.clone(), snapshot_sequence);
    serde_json::to_writer(&mut buf, &api_envelope)?;
    // serde_json writes valid UTF-8, but convert using checked API for safety
    Ok(String::from_utf8(buf).expect("serde_json always writes valid UTF-8"))
}

/// Build replay payloads from a slice of envelopes reusing a single buffer.
fn build_replay_payloads(
    envelopes: &[crate::solvable_orders::DeltaEnvelope],
    baseline_sequence: u64,
) -> Result<Vec<String>, serde_json::Error> {
    let mut payloads = Vec::with_capacity(envelopes.len());
    let mut buf = Vec::with_capacity(1024);

    for envelope in envelopes {
        buf.clear();
        serde_json::to_writer(
            &mut buf,
            &to_api_envelope(envelope.clone(), Some(baseline_sequence)),
        )?;

        let old = std::mem::replace(&mut buf, Vec::with_capacity(1024));
        let s = String::from_utf8(old).expect("serde_json always writes valid UTF-8");
        payloads.push(s);
    }

    Ok(payloads)
}

async fn serialize_snapshot_response(
    response: DeltaSnapshotResponse,
) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&response)
}

#[derive(Debug)]
enum DrainError {
    Serialize(serde_json::Error),
    Lagged(u64),
}

#[derive(Debug)]
struct DrainOutcome {
    payloads: Vec<String>,
    closed: bool,
}

fn drain_live_envelopes(
    receiver: &mut tokio::sync::broadcast::Receiver<crate::solvable_orders::DeltaEnvelope>,
    already_replayed_up_to: u64,
    baseline_sequence: u64,
    highest_sequence_seen: &mut u64,
) -> Result<DrainOutcome, DrainError> {
    let mut payloads: Vec<String> = Vec::new();
    let mut closed = false;

    loop {
        match receiver.try_recv() {
            Ok(envelope) => {
                if envelope.to_sequence <= already_replayed_up_to {
                    // Already covered by replay; skip.
                    continue;
                }
                // Make monotonicity explicit. If the stream ever yields a
                // non-monotonic `to_sequence`, catch it in debug builds but
                // avoid incorrect backward assignment in release builds.
                debug_assert!(
                    envelope.to_sequence >= *highest_sequence_seen,
                    "non-monotonic delta to_sequence observed"
                );
                *highest_sequence_seen = (*highest_sequence_seen).max(envelope.to_sequence);

                // Drain phase: snapshotSequence = baseline_sequence
                // These envelopes are "catch-up" deltas from the snapshot baseline.
                // They validate against snapshot(baseline_sequence).
                let payload = serialize_envelope_to_payload(&envelope, Some(baseline_sequence))
                    .map_err(DrainError::Serialize)?;
                payloads.push(payload);
            }
            Err(TryRecvError::Empty) => break,
            Err(TryRecvError::Closed) => {
                closed = true;
                break;
            }
            Err(TryRecvError::Lagged(skipped)) => return Err(DrainError::Lagged(skipped)),
        }
    }

    Ok(DrainOutcome { payloads, closed })
}

/// Result type returned by `subscribe_and_build_replay`.
struct ReplayResult {
    receiver: tokio::sync::broadcast::Receiver<crate::solvable_orders::DeltaEnvelope>,
    /// Pre-serialised JSON payloads covering the [after_sequence, live] gap.
    payloads: Vec<String>,
    /// Highest sequence covered by payloads; live stream must start after this.
    replay_to_sequence: u64,
    /// True when the broadcast channel closed during the drain; caller should
    /// signal resync to the client.
    drained_closed: bool,
}

#[derive(Debug)]
enum SubscribeReplayError {
    Subscribe(crate::solvable_orders::DeltaSubscribeError),
    Serialize(serde_json::Error),
    Drain(DrainError),
}

async fn subscribe_and_build_replay(
    cache: &crate::solvable_orders::SolvableOrdersCache,
    after_sequence: Option<u64>,
    baseline_sequence: u64,
) -> Result<ReplayResult, SubscribeReplayError> {
    let (mut receiver, replay) = cache
        .subscribe_deltas_with_replay_checked(after_sequence)
        .await
        .map_err(SubscribeReplayError::Subscribe)?;

    let mut replay_to_sequence = replay.checkpoint_sequence;
    let mut payloads = Vec::with_capacity(replay.envelopes.len());

    for envelope in &replay.envelopes {
        replay_to_sequence = replay_to_sequence.max(envelope.to_sequence);
    }

    if !replay.envelopes.is_empty() {
        let mut replay_payloads = build_replay_payloads(&replay.envelopes, baseline_sequence)
            .map_err(SubscribeReplayError::Serialize)?;
        payloads.append(&mut replay_payloads);
    }

    let drain_outcome = drain_live_envelopes(
        &mut receiver,
        replay_to_sequence,
        baseline_sequence,
        &mut replay_to_sequence,
    )
    .map_err(SubscribeReplayError::Drain)?;

    payloads.extend(drain_outcome.payloads);

    Ok(ReplayResult {
        receiver,
        payloads,
        replay_to_sequence,
        drained_closed: drain_outcome.closed,
    })
}

fn empty_delta_snapshot_response() -> Response {
    StatusCode::NO_CONTENT.into_response()
}

fn delta_stream_after_error_response(err: DeltaAfterError) -> Response {
    match err {
        DeltaAfterError::FutureSequence { latest } => (
            StatusCode::BAD_REQUEST,
            format!("afterSequence cannot be greater than latest sequence ({latest})"),
        )
            .into_response(),
        DeltaAfterError::ResyncRequired {
            oldest_available,
            latest,
        } => delta_stream_gone_response(
            "delta history does not include requested sequence; resnapshot required",
            latest,
            Some(oldest_available),
        ),
    }
}

fn delta_stream_gone_response(
    message: impl Into<String>,
    latest_sequence: u64,
    oldest_available: Option<u64>,
) -> Response {
    let payload = DeltaStreamGoneResponse {
        message: message.into(),
        latest_sequence,
        oldest_available,
    };
    (StatusCode::GONE, Json(payload)).into_response()
}

fn delta_sync_enabled() -> bool {
    #[cfg(any(test, feature = "test-util"))]
    {
        if let Some(value) = *DELTA_SYNC_ENABLED_OVERRIDE
            .lock()
            .expect("delta sync enabled override lock poisoned")
        {
            return value;
        }
    }

    shared::env::flag_enabled(
        std::env::var("AUTOPILOT_DELTA_SYNC_ENABLED")
            .ok()
            .as_deref(),
        false,
    )
}

fn delta_stream_max_lag() -> u64 {
    *DELTA_STREAM_MAX_LAG.get_or_init(|| {
        std::env::var("AUTOPILOT_DELTA_SYNC_STREAM_MAX_LAG")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|&v| v > 0)
            .unwrap_or(256)
    })
}

fn delta_stream_buffer_size() -> usize {
    // The test override is checked first so tests can vary buffer sizes
    // without fighting the OnceLock that caches the first production read.
    #[cfg(test)]
    {
        if let Some(value) = *DELTA_SYNC_STREAM_BUFFER_OVERRIDE
            .lock()
            .expect("delta sync stream buffer override lock poisoned")
        {
            return value;
        }
    }

    *DELTA_STREAM_BUFFER_SIZE.get_or_init(|| {
        std::env::var("AUTOPILOT_DELTA_SYNC_STREAM_BUFFER")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|&v| v > 0)
            .unwrap_or(128)
    })
}

fn delta_stream_keepalive_interval() -> Duration {
    *DELTA_STREAM_KEEPALIVE_INTERVAL.get_or_init(|| {
        let seconds = std::env::var("AUTOPILOT_DELTA_SYNC_STREAM_KEEPALIVE_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(10);
        Duration::from_secs(seconds)
    })
}

fn authorize_delta_sync(headers: &HeaderMap) -> Result<(), Response> {
    let Some(expected) = delta_sync_api_key() else {
        return Ok(());
    };

    let provided = headers
        .get("X-Delta-Sync-Api-Key")
        .and_then(|value| value.to_str().ok());
    if provided
        .map(|value| value.as_bytes().ct_eq(expected.as_bytes()))
        .map(bool::from)
        .unwrap_or(false)
    {
        Ok(())
    } else {
        Err((StatusCode::UNAUTHORIZED, "Unauthorized").into_response())
    }
}

fn api_key_hash(headers: &HeaderMap) -> Option<String> {
    headers
        .get("X-Delta-Sync-Api-Key")
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            let mut hasher = Sha256::new();
            hasher.update(value.as_bytes());
            let digest = hasher.finalize();
            // Expose at least 16 bytes (128 bits) to reduce collision probability
            const_hex::encode(&digest[..16])
        })
}

fn delta_sync_api_key() -> Option<String> {
    #[cfg(test)]
    {
        match DELTA_SYNC_API_KEY_OVERRIDE
            .lock()
            .expect("delta sync api key override lock poisoned")
            .clone()
        {
            ApiKeyOverride::NotSet => {}
            ApiKeyOverride::NoKeyRequired => return None,
            ApiKeyOverride::Key(key) => return Some(key),
        }
    }

    DELTA_SYNC_API_KEY
        .get_or_init(|| std::env::var("AUTOPILOT_DELTA_SYNC_API_KEY").ok())
        .clone()
}

#[derive(prometheus_metric_storage::MetricStorage)]
#[metric(subsystem = "delta_sync")]
struct DeltaMetrics {
    /// Total snapshot requests.
    snapshot_requests: IntCounter,
    /// Snapshot requests that found no active auction snapshot.
    snapshot_empty: IntCounter,
    /// Total stream connection attempts.
    stream_connections: IntCounter,
    /// Number of replay misses that require a new snapshot.
    replay_miss: IntCounter,
    /// Number of stream lag events where client fell behind.
    stream_lagged: IntCounter,
    /// Number of delta envelope serialization failures.
    serialize_errors: IntCounter,
    /// Size in bytes of the most recently served snapshot.
    snapshot_bytes: IntGauge,
    /// Currently active stream handlers.
    active_streams: IntGauge,
}

impl DeltaMetrics {
    fn get() -> &'static Self {
        DeltaMetrics::instance(observe::metrics::get_storage_registry()).unwrap()
    }
}

struct ActiveStreamGuard {
    remote_addr: SocketAddr,
    api_key_hash: Option<String>,
}

impl ActiveStreamGuard {
    fn new(remote_addr: SocketAddr, api_key_hash: Option<String>) -> Self {
        DeltaMetrics::get().active_streams.inc();
        tracing::info!(
            remote_addr = %remote_addr,
            api_key_hash = api_key_hash.as_deref().unwrap_or("none"),
            "delta stream connected"
        );
        Self {
            remote_addr,
            api_key_hash,
        }
    }
}

impl Drop for ActiveStreamGuard {
    fn drop(&mut self) {
        DeltaMetrics::get().active_streams.dec();
        tracing::info!(
            remote_addr = %self.remote_addr,
            api_key_hash = self.api_key_hash.as_deref().unwrap_or("none"),
            "delta stream disconnected"
        );
    }
}

fn delta_event_to_dto(event: DeltaEvent) -> DeltaEventDto {
    match event {
        DeltaEvent::AuctionChanged { new_auction_id } => {
            DeltaEventDto::AuctionChanged { new_auction_id }
        }
        DeltaEvent::BlockChanged { block } => DeltaEventDto::BlockChanged { block },
        DeltaEvent::OrderAdded(order) => DeltaEventDto::OrderAdded {
            order: dto::order::from_domain(order),
        },
        DeltaEvent::OrderRemoved(uid) => DeltaEventDto::OrderRemoved {
            uid: uid.to_string(),
        },
        DeltaEvent::OrderUpdated(order) => DeltaEventDto::OrderUpdated {
            order: dto::order::from_domain(order),
        },
        DeltaEvent::PriceChanged { token, price } => DeltaEventDto::PriceChanged {
            token,
            price: price.map(|price| price.get().0.to_string()),
        },
        DeltaEvent::JitOwnersChanged {
            surplus_capturing_jit_order_owners,
        } => DeltaEventDto::JitOwnersChanged {
            // Move the Vec directly; the enum was consumed by value.
            surplus_capturing_jit_order_owners,
        },
    }
}

async fn get_native_price(
    Path(token): Path<Address>,
    Query(query): Query<NativePriceQuery>,
    AxumState(state): AxumState<State>,
) -> Response {
    let timeout = query
        .timeout_ms
        .map(Duration::from_millis)
        .unwrap_or(*state.allowed_timeout.end())
        .clamp(*state.allowed_timeout.start(), *state.allowed_timeout.end());

    let start = Instant::now();
    match state.estimator.estimate_native_price(token, timeout).await {
        Ok(price) => Json(NativeTokenPrice { price }).into_response(),
        Err(err) => {
            let elapsed = start.elapsed();
            tracing::warn!(
                ?err,
                ?token,
                ?timeout,
                ?elapsed,
                "failed to estimate native token price"
            );
            error_to_response(err)
        }
    }
}

fn error_to_response(err: PriceEstimationError) -> Response {
    match err {
        PriceEstimationError::NoLiquidity | PriceEstimationError::EstimatorInternal(_) => {
            (StatusCode::NOT_FOUND, "No liquidity").into_response()
        }
        PriceEstimationError::UnsupportedToken { token: _, reason } => (
            StatusCode::BAD_REQUEST,
            format!("Unsupported token, reason: {reason}"),
        )
            .into_response(),
        PriceEstimationError::RateLimited => {
            (StatusCode::TOO_MANY_REQUESTS, "Rate limited").into_response()
        }
        PriceEstimationError::TradingOutsideAllowedWindow { message }
        | PriceEstimationError::TokenTemporarilySuspended { message }
        | PriceEstimationError::InsufficientLiquidity { message }
        | PriceEstimationError::CustomSolverError { message } => {
            (StatusCode::BAD_REQUEST, message).into_response()
        }
        PriceEstimationError::UnsupportedOrderType(reason) => (
            StatusCode::BAD_REQUEST,
            format!("Unsupported order type, reason: {reason}"),
        )
            .into_response(),
        PriceEstimationError::ProtocolInternal(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            database::{Config as DbConfig, Postgres},
            domain,
            infra::Persistence,
            solvable_orders::DeltaEnvelope,
            test_helpers::test_order,
        },
        account_balances::BalanceFetching,
        axum::{
            body,
            http::{HeaderValue, Request},
        },
        bad_tokens::list_based::DenyListedTokens,
        bigdecimal::BigDecimal,
        chrono::Utc,
        cow_amm::Registry,
        database::byte_array::ByteArray,
        eth_domain_types as eth,
        ethrpc::{
            alloy::unbuffered_provider,
            block_stream::{BlockInfo, mock_single_block},
        },
        event_indexing::block_retriever::BlockRetriever,
        futures::FutureExt,
        price_estimation::{
            HEALTHY_PRICE_ESTIMATION_TIME,
            native::NativePriceEstimating,
            native_price_cache::{Cache, CachingNativePriceEstimator, NativePriceUpdater},
        },
        serde::Deserialize,
        serde_json,
        sqlx::postgres::PgPoolOptions,
        std::{collections::VecDeque, sync::Arc, time::Duration},
        tower::ServiceExt,
    };

    #[derive(Clone, Default)]
    struct StubBalanceFetcher;

    #[async_trait::async_trait]
    impl BalanceFetching for StubBalanceFetcher {
        async fn get_balances(
            &self,
            queries: &[account_balances::Query],
        ) -> Vec<anyhow::Result<alloy::primitives::U256>> {
            queries
                .iter()
                .map(|_| Ok(alloy::primitives::U256::ZERO))
                .collect()
        }

        async fn can_transfer(
            &self,
            _query: &account_balances::Query,
            _amount: alloy::primitives::U256,
        ) -> Result<(), account_balances::TransferSimulationError> {
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct StubNativePriceEstimator;

    impl NativePriceEstimating for StubNativePriceEstimator {
        fn estimate_native_price(
            &self,
            _token: Address,
            _timeout: Duration,
        ) -> futures::future::BoxFuture<'_, price_estimation::native::NativePriceEstimateResult>
        {
            async { Ok(1.0) }.boxed()
        }
    }

    fn test_price(value: u128) -> domain::auction::Price {
        domain::auction::Price::try_new(eth::Ether::from(eth::U256::from(value))).unwrap()
    }

    #[cfg(test)]
    struct DeltaSyncEnabledGuard {
        previous: Option<bool>,
    }

    #[cfg(test)]
    impl DeltaSyncEnabledGuard {
        fn set(value: bool) -> Self {
            let previous = {
                let mut guard = DELTA_SYNC_ENABLED_OVERRIDE
                    .lock()
                    .expect("delta sync enabled override lock poisoned");
                let prev = *guard;
                *guard = Some(value);
                prev
            };
            Self { previous }
        }
    }

    #[cfg(test)]
    impl Drop for DeltaSyncEnabledGuard {
        fn drop(&mut self) {
            let mut guard = DELTA_SYNC_ENABLED_OVERRIDE
                .lock()
                .expect("delta sync enabled override lock poisoned");
            *guard = self.previous;
        }
    }

    #[cfg(test)]
    struct DeltaStreamBufferGuard {
        previous: Option<usize>,
    }

    #[cfg(test)]
    impl DeltaStreamBufferGuard {
        fn set(value: usize) -> Self {
            let mut lock = DELTA_SYNC_STREAM_BUFFER_OVERRIDE
                .lock()
                .expect("delta sync stream buffer override lock poisoned");
            let previous = *lock;
            *lock = Some(value);
            Self { previous }
        }
    }

    #[cfg(test)]
    impl Drop for DeltaStreamBufferGuard {
        fn drop(&mut self) {
            *DELTA_SYNC_STREAM_BUFFER_OVERRIDE
                .lock()
                .expect("delta sync stream buffer override lock poisoned") = self.previous;
        }
    }

    #[cfg(test)]
    struct ApiKeyOverrideGuard {
        previous: ApiKeyOverride,
    }

    #[cfg(test)]
    impl ApiKeyOverrideGuard {
        /// Sets the override to require `key`.  Pass `None` to override with
        /// "no key required" (open endpoint).
        fn set(key: Option<String>) -> Self {
            let new_value = match key {
                Some(k) => ApiKeyOverride::Key(k),
                None => ApiKeyOverride::NoKeyRequired,
            };
            let mut lock = DELTA_SYNC_API_KEY_OVERRIDE
                .lock()
                .expect("delta sync api key override lock poisoned");
            let previous = lock.clone();
            *lock = new_value;
            Self { previous }
        }

        /// Explicitly clear the override (identical to dropping the guard, but
        /// useful when the guard needs to be cleared early in a test).
        fn clear(&self) {
            *DELTA_SYNC_API_KEY_OVERRIDE
                .lock()
                .expect("delta sync api key override lock poisoned") = ApiKeyOverride::NotSet;
        }
    }

    #[cfg(test)]
    impl Drop for ApiKeyOverrideGuard {
        fn drop(&mut self) {
            *DELTA_SYNC_API_KEY_OVERRIDE
                .lock()
                .expect("delta sync api key override lock poisoned") = self.previous.clone();
        }
    }

    async fn test_cache() -> Arc<SolvableOrdersCache> {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://")
            .expect("lazy pg pool");
        let postgres = Postgres {
            pool,
            config: DbConfig::default(),
        };
        let persistence = Persistence::new(None, Arc::new(postgres)).await;

        let balance_fetcher = Arc::new(StubBalanceFetcher::default());
        let deny_listed_tokens = DenyListedTokens::default();

        let native_price_estimator = StubNativePriceEstimator::default();
        let cache = Cache::new(Duration::from_secs(10), Default::default());
        let caching_estimator = CachingNativePriceEstimator::new(
            Box::new(native_price_estimator),
            cache,
            1,
            Default::default(),
            HEALTHY_PRICE_ESTIMATION_TIME,
        );
        let native_price_estimator =
            NativePriceUpdater::new(caching_estimator, Duration::MAX, Default::default());

        let (provider, _wallet) = unbuffered_provider("http://localhost:0", None);
        let block_stream = mock_single_block(BlockInfo::default());
        let block_retriever = Arc::new(BlockRetriever {
            provider,
            block_stream,
        });
        let cow_amm_registry = Registry::new(block_retriever);

        let protocol_fees = domain::ProtocolFees::new(
            &configs::autopilot::fee_policy::FeePoliciesConfig::default(),
            Vec::new(),
            false,
        );

        SolvableOrdersCache::new(
            Duration::from_secs(0),
            persistence,
            order_validation::banned::Users::none(),
            balance_fetcher,
            deny_listed_tokens,
            native_price_estimator,
            Address::repeat_byte(0xEE),
            protocol_fees,
            cow_amm_registry,
            Duration::from_secs(1),
            Address::repeat_byte(0xFF),
            false,
            None,
        )
    }

    async fn db_cache() -> (Arc<SolvableOrdersCache>, Arc<Postgres>) {
        let postgres = Arc::new(Postgres::with_defaults().await.unwrap());
        let mut tx = postgres.pool.begin().await.unwrap();
        database::clear_DANGER_(&mut tx).await.unwrap();
        tx.commit().await.unwrap();

        let persistence = Persistence::new(None, Arc::clone(&postgres)).await;

        let balance_fetcher = Arc::new(StubBalanceFetcher::default());
        let deny_listed_tokens = DenyListedTokens::default();

        let native_price_estimator = StubNativePriceEstimator::default();
        let cache = Cache::new(Duration::from_secs(10), Default::default());
        let caching_estimator = CachingNativePriceEstimator::new(
            Box::new(native_price_estimator),
            cache,
            1,
            Default::default(),
            HEALTHY_PRICE_ESTIMATION_TIME,
        );
        let native_price_estimator =
            NativePriceUpdater::new(caching_estimator, Duration::MAX, Default::default());

        let (provider, _wallet) = unbuffered_provider("http://localhost:0", None);
        let block_stream = mock_single_block(BlockInfo::default());
        let block_retriever = Arc::new(BlockRetriever {
            provider,
            block_stream,
        });
        let cow_amm_registry = Registry::new(block_retriever);

        let protocol_fees = domain::ProtocolFees::new(
            &configs::autopilot::fee_policy::FeePoliciesConfig::default(),
            Vec::new(),
            false,
        );

        let cache = SolvableOrdersCache::new(
            Duration::from_secs(0),
            persistence,
            order_validation::banned::Users::none(),
            balance_fetcher,
            deny_listed_tokens,
            native_price_estimator,
            Address::repeat_byte(0xEE),
            protocol_fees,
            cow_amm_registry,
            Duration::from_secs(1),
            Address::repeat_byte(0xFF),
            true,
            None,
        );

        (cache, postgres)
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct WireEnvelope {
        version: u32,
        auction_id: u64,
        auction_sequence: u64,
        from_sequence: u64,
        to_sequence: u64,
        snapshot_sequence: Option<u64>,
        published_at: String,
        events: Vec<serde_json::Value>,
    }

    #[test]
    fn to_api_envelope_maps_core_fields() {
        let published_at = chrono::Utc::now();
        let envelope = crate::solvable_orders::DeltaEnvelope {
            auction_id: 7,
            auction_sequence: 3,
            from_sequence: 4,
            to_sequence: 5,
            published_at,
            published_at_instant: Instant::now(),
            events: vec![
                DeltaEvent::OrderAdded(test_order(1, 10)),
                DeltaEvent::OrderRemoved(domain::OrderUid([9; 56])),
                DeltaEvent::PriceChanged {
                    token: Address::repeat_byte(0xAB),
                    price: None,
                },
            ],
        };

        let dto = to_api_envelope(envelope, Some(42));
        assert_eq!(dto.version, 1);
        assert_eq!(dto.auction_id, 7);
        assert_eq!(dto.auction_sequence, 3);
        assert_eq!(dto.from_sequence, 4);
        assert_eq!(dto.to_sequence, 5);
        assert_eq!(dto.snapshot_sequence, Some(42));
        assert_eq!(dto.published_at, published_at.to_rfc3339());
        assert_eq!(dto.events.len(), 3);
    }

    #[test]
    fn api_envelope_serializes_with_expected_wire_shape() {
        let envelope = DeltaEventEnvelope {
            version: 1,
            boot_id: crate::solvable_orders::boot_id().to_owned(),
            auction_id: 9,
            auction_sequence: 4,
            from_sequence: 10,
            to_sequence: 11,
            snapshot_sequence: None,
            published_at: "2026-03-20T00:00:00Z".to_string(),
            events: vec![
                DeltaEventDto::OrderRemoved {
                    uid: "0xdeadbeef".to_string(),
                },
                DeltaEventDto::PriceChanged {
                    token: Address::repeat_byte(0xAA),
                    price: Some("123".to_string()),
                },
            ],
        };

        let json = serde_json::to_string(&envelope).unwrap();
        let wire: WireEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(wire.version, 1);
        assert_eq!(wire.auction_id, 9);
        assert_eq!(wire.auction_sequence, 4);
        assert_eq!(wire.from_sequence, 10);
        assert_eq!(wire.to_sequence, 11);
        assert_eq!(wire.snapshot_sequence, None);
        assert_eq!(wire.published_at, "2026-03-20T00:00:00Z");
        assert_eq!(wire.events.len(), 2);
    }

    #[test]
    fn api_envelope_serializes_block_and_jit_owner_events() {
        let envelope = DeltaEventEnvelope {
            version: 1,
            boot_id: crate::solvable_orders::boot_id().to_owned(),
            auction_id: 9,
            auction_sequence: 4,
            from_sequence: 10,
            to_sequence: 11,
            snapshot_sequence: None,
            published_at: "2026-03-20T00:00:00Z".to_string(),
            events: vec![
                DeltaEventDto::BlockChanged { block: 123 },
                DeltaEventDto::JitOwnersChanged {
                    surplus_capturing_jit_order_owners: vec![Address::repeat_byte(0xAB)],
                },
            ],
        };

        let json = serde_json::to_string(&envelope).unwrap();
        let wire: WireEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(wire.events.len(), 2);
        // Ensure the wire representation includes expected fields for each event.
        let first = &wire.events[0];
        assert_eq!(first["type"], "blockChanged");
        assert_eq!(first["block"], serde_json::json!(123));

        let second = &wire.events[1];
        assert_eq!(second["type"], "jitOwnersChanged");
        // Payload must include at least one additional key (the owners payload).
        let obj = second.as_object().expect("expected event to be an object");
        assert!(
            obj.len() >= 2,
            "expected event object to contain payload field"
        );
    }

    #[test]
    fn delta_sync_enabled_parses_expected_values() {
        assert!(!shared::env::flag_enabled(None, false));
        assert!(!shared::env::flag_enabled(Some("false"), false));
        assert!(!shared::env::flag_enabled(Some("0"), false));
        assert!(shared::env::flag_enabled(Some("true"), false));
        assert!(shared::env::flag_enabled(Some("on"), false));
    }

    #[test]
    fn authorize_delta_sync_rejects_wrong_key() {
        let _guard = ApiKeyOverrideGuard::set(Some("expected".to_string()));
        let headers = HeaderMap::new();

        let response = authorize_delta_sync(&headers).unwrap_err();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn authorize_delta_sync_accepts_correct_key() {
        let _guard = ApiKeyOverrideGuard::set(Some("expected".to_string()));
        let mut headers = HeaderMap::new();
        headers.insert("X-Delta-Sync-Api-Key", HeaderValue::from_static("expected"));

        assert!(authorize_delta_sync(&headers).is_ok());
    }

    #[tokio::test]
    async fn delta_sync_disabled_disables_routes() {
        let _guard = DeltaSyncEnabledGuard::set(false);
        let cache = test_cache().await;
        let state = State {
            estimator: Arc::new(StubNativePriceEstimator::default()),
            allowed_timeout: MIN_TIMEOUT..=MIN_TIMEOUT,
            solvable_orders_cache: cache,
        };
        let app = build_router(state);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/delta/snapshot")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn delta_snapshot_http_response_is_consistent_with_history() {
        let _guard = DeltaSyncEnabledGuard::set(true);
        let cache = test_cache().await;

        let token = Address::repeat_byte(0x11);
        let baseline = domain::RawAuctionData {
            block: 1,
            orders: vec![test_order(1, 10)],
            prices: std::collections::HashMap::from([(token.into(), test_price(1000))]),
            surplus_capturing_jit_order_owners: Vec::new(),
        };
        let events = vec![
            DeltaEvent::OrderUpdated(test_order(1, 11)),
            DeltaEvent::PriceChanged {
                token,
                price: Some(test_price(1200)),
            },
        ];
        let current =
            crate::solvable_orders::apply_delta_events_to_auction(baseline.clone(), &events);
        let envelope = DeltaEnvelope {
            auction_id: 1,
            auction_sequence: 2,
            from_sequence: 1,
            to_sequence: 2,
            published_at: chrono::Utc::now(),
            published_at_instant: Instant::now(),
            events,
        };
        cache
            .set_state_for_tests(current.clone(), 1, 2, 2, VecDeque::from([envelope]))
            .await;

        let state = State {
            estimator: Arc::new(StubNativePriceEstimator::default()),
            allowed_timeout: MIN_TIMEOUT..=MIN_TIMEOUT,
            solvable_orders_cache: cache,
        };
        let app = build_router(state);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/delta/snapshot")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let snapshot: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(snapshot["sequence"], 2);
        assert_eq!(snapshot["auctionId"], 1);
        assert_eq!(snapshot["oldestAvailable"], 1);

        let expected = dto::auction::from_domain(current);
        assert_eq!(snapshot["auction"], serde_json::to_value(expected).unwrap());
    }

    #[tokio::test]
    #[ignore = "requires database-backed update pipeline"]
    async fn update_drives_snapshot_and_stream_end_to_end() {
        let _guard = DeltaSyncEnabledGuard::set(true);
        let (cache, postgres) = db_cache().await;

        let uid: database::OrderUid = ByteArray([0x11; 56]);
        let app_data: database::AppId = ByteArray([0x22; 32]);
        let now = Utc::now();

        let mut conn = postgres.pool.acquire().await.unwrap();
        database::app_data::insert(&mut conn, &app_data, b"{}")
            .await
            .unwrap();

        let order = database::orders::Order {
            uid,
            owner: ByteArray([0x33; 20]),
            creation_timestamp: now,
            sell_token: ByteArray([0x44; 20]),
            buy_token: ByteArray([0x55; 20]),
            receiver: None,
            sell_amount: BigDecimal::from(1000u64),
            buy_amount: BigDecimal::from(900u64),
            valid_to: now.timestamp() + 600,
            app_data,
            fee_amount: BigDecimal::from(0u64),
            kind: database::orders::OrderKind::Sell,
            partially_fillable: false,
            signature: vec![0u8; 65],
            signing_scheme: database::orders::SigningScheme::Eip712,
            settlement_contract: ByteArray([0x66; 20]),
            sell_token_balance: database::orders::SellTokenSource::Erc20,
            buy_token_balance: database::orders::BuyTokenDestination::Erc20,
            cancellation_timestamp: None,
            class: database::orders::OrderClass::Limit,
        };
        database::orders::insert_order(&mut conn, &order)
            .await
            .unwrap();
        drop(conn);

        cache.update(1, false).await.unwrap();

        let snapshot = cache
            .delta_snapshot()
            .await
            .expect("delta snapshot missing");
        let model_uid = model::order::OrderUid(order.uid.0);
        let snapshot_orders = dto::auction::from_domain(snapshot.auction).orders;
        let has_order = snapshot_orders.iter().any(|order| order.uid == model_uid);
        assert!(has_order);

        let (_receiver, replay) = cache
            .subscribe_deltas_with_replay_checked(Some(0))
            .await
            .expect("delta replay missing");
        let replay_has_order = replay.envelopes.iter().any(|envelope| {
            envelope.events.iter().any(|event| match event {
                DeltaEvent::OrderAdded(order) | DeltaEvent::OrderUpdated(order) => {
                    order.uid == domain::OrderUid(model_uid.0)
                }
                DeltaEvent::OrderRemoved(_) | DeltaEvent::AuctionChanged { .. } => false,
                DeltaEvent::PriceChanged { .. } => false,
                DeltaEvent::BlockChanged { .. } | DeltaEvent::JitOwnersChanged { .. } => false,
            })
        });
        assert!(replay_has_order);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn slow_consumer_gets_resync_required_event() {
        let _guard_enabled = DeltaSyncEnabledGuard::set(true);
        let _guard_buffer = DeltaStreamBufferGuard::set(1);
        let cache = test_cache().await;
        cache
            .set_state_for_tests(
                domain::RawAuctionData {
                    block: 1,
                    orders: Vec::new(),
                    prices: std::collections::HashMap::new(),
                    surplus_capturing_jit_order_owners: Vec::new(),
                },
                0,
                0,
                0,
                VecDeque::new(),
            )
            .await;

        let state = State {
            estimator: Arc::new(StubNativePriceEstimator::default()),
            allowed_timeout: MIN_TIMEOUT..=MIN_TIMEOUT,
            solvable_orders_cache: Arc::clone(&cache),
        };
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/delta/stream?after_sequence=0")
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 0))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let collected = Arc::new(tokio::sync::Mutex::new(String::new()));
        let collected_writer = Arc::clone(&collected);

        let mut body_stream = response.into_body().into_data_stream();
        let read_task = tokio::spawn(async move {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            loop {
                match tokio::time::timeout_at(deadline, futures::StreamExt::next(&mut body_stream))
                    .await
                {
                    Ok(Some(Ok(chunk))) => {
                        let mut buf = collected_writer.lock().await;
                        buf.push_str(&String::from_utf8_lossy(&chunk));
                        if buf.contains("event: resync_required") {
                            return;
                        }
                    }
                    _ => return,
                }
            }
        });

        // Wait for the server side to register its delta stream subscriber to
        // avoid races where publishes happen before any receiver exists.
        let start = Instant::now();
        let subscribe_timeout = Duration::from_secs(2);
        while cache.delta_receiver_count() == 0 {
            if start.elapsed() > subscribe_timeout {
                panic!("delta stream subscriber never registered");
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        // Publish events rapidly to overwhelm the buffer (size = 1).
        for sequence in 1..=10u64 {
            cache
                .publish_delta_for_tests(DeltaEnvelope {
                    auction_id: 0,
                    auction_sequence: sequence,
                    from_sequence: sequence - 1,
                    to_sequence: sequence,
                    published_at: chrono::Utc::now(),
                    published_at_instant: Instant::now(),
                    events: vec![DeltaEvent::OrderAdded(test_order(sequence as u8, 10))],
                })
                .await;
        }

        read_task.await.unwrap();

        let text = collected.lock().await;
        println!("Response text: {}", *text);
        assert!(text.contains("event: resync_required"));
    }

    #[tokio::test]
    async fn publish_during_replay_is_drained_without_gap() {
        let (sender, mut receiver) = tokio::sync::broadcast::channel(8);
        let checkpoint_sequence = 5;
        let mut replay_to_sequence = checkpoint_sequence;

        // Simulates publication after replay checkpoint is captured but before
        // switching to live stream.
        sender
            .send(crate::solvable_orders::DeltaEnvelope {
                auction_id: 0,
                auction_sequence: 1,
                from_sequence: 5,
                to_sequence: 6,
                published_at: chrono::Utc::now(),
                published_at_instant: Instant::now(),
                events: vec![DeltaEvent::OrderAdded(test_order(1, 10))],
            })
            .unwrap();

        let drained = drain_live_envelopes(
            &mut receiver,
            checkpoint_sequence,
            checkpoint_sequence,
            &mut replay_to_sequence,
        )
        .unwrap();

        assert_eq!(drained.payloads.len(), 1);
        assert!(!drained.closed);
        assert_eq!(replay_to_sequence, 6);

        let wire: WireEnvelope = serde_json::from_str(&drained.payloads[0]).unwrap();
        assert_eq!(wire.from_sequence, 5);
        assert_eq!(wire.to_sequence, 6);
        assert_eq!(wire.events.len(), 1);
    }

    #[tokio::test]
    async fn drain_live_envelopes_ignores_pre_checkpoint_updates() {
        let (sender, mut receiver) = tokio::sync::broadcast::channel(8);
        let mut replay_to_sequence = 5;

        sender
            .send(crate::solvable_orders::DeltaEnvelope {
                auction_id: 0,
                auction_sequence: 1,
                from_sequence: 4,
                to_sequence: 5,
                published_at: chrono::Utc::now(),
                published_at_instant: Instant::now(),
                events: vec![DeltaEvent::OrderAdded(test_order(9, 90))],
            })
            .unwrap();
        sender
            .send(crate::solvable_orders::DeltaEnvelope {
                auction_id: 0,
                auction_sequence: 2,
                from_sequence: 5,
                to_sequence: 6,
                published_at: chrono::Utc::now(),
                published_at_instant: Instant::now(),
                events: vec![DeltaEvent::OrderUpdated(test_order(1, 11))],
            })
            .unwrap();

        let drained = drain_live_envelopes(&mut receiver, 5, 5, &mut replay_to_sequence).unwrap();

        assert_eq!(drained.payloads.len(), 1);
        assert!(!drained.closed);
        assert_eq!(replay_to_sequence, 6);
        let wire: WireEnvelope = serde_json::from_str(&drained.payloads[0]).unwrap();
        assert_eq!(wire.from_sequence, 5);
        assert_eq!(wire.to_sequence, 6);
    }

    #[tokio::test]
    async fn drain_filters_pre_checkpoint_with_mixed_sequences() {
        let (sender, mut receiver) = tokio::sync::broadcast::channel(16);
        let checkpoint = 6u64;
        let mut replay_to = checkpoint;

        for seq in 4u64..=9 {
            sender
                .send(crate::solvable_orders::DeltaEnvelope {
                    auction_id: 0,
                    auction_sequence: seq,
                    from_sequence: seq - 1,
                    to_sequence: seq,
                    published_at: chrono::Utc::now(),
                    published_at_instant: Instant::now(),
                    events: vec![],
                })
                .unwrap();
        }

        let outcome =
            drain_live_envelopes(&mut receiver, checkpoint, checkpoint, &mut replay_to).unwrap();

        assert_eq!(
            outcome.payloads.len(),
            3,
            "expected 3 post-checkpoint envelopes"
        );

        let sequences: Vec<u64> = outcome
            .payloads
            .iter()
            .map(|p| {
                let wire: serde_json::Value = serde_json::from_str(p).unwrap();
                wire["toSequence"].as_u64().unwrap()
            })
            .collect();

        assert_eq!(sequences, vec![7, 8, 9]);
        assert_eq!(replay_to, 9);
    }

    #[tokio::test]
    async fn drain_live_envelopes_returns_lagged_when_receiver_fell_behind() {
        let (sender, mut receiver) = tokio::sync::broadcast::channel(1);
        let mut replay_to_sequence = 0;

        sender
            .send(crate::solvable_orders::DeltaEnvelope {
                auction_id: 0,
                auction_sequence: 1,
                from_sequence: 0,
                to_sequence: 1,
                published_at: chrono::Utc::now(),
                published_at_instant: Instant::now(),
                events: vec![DeltaEvent::OrderAdded(test_order(1, 10))],
            })
            .unwrap();
        sender
            .send(crate::solvable_orders::DeltaEnvelope {
                auction_id: 0,
                auction_sequence: 2,
                from_sequence: 1,
                to_sequence: 2,
                published_at: chrono::Utc::now(),
                published_at_instant: Instant::now(),
                events: vec![DeltaEvent::OrderAdded(test_order(2, 20))],
            })
            .unwrap();

        let err = drain_live_envelopes(&mut receiver, 0, 0, &mut replay_to_sequence).unwrap_err();
        assert!(matches!(err, DrainError::Lagged(_)));
    }

    #[tokio::test]
    async fn empty_delta_snapshot_response_has_expected_status_and_shape() {
        let response = empty_delta_snapshot_response();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let bytes = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(bytes.is_empty());
    }

    #[tokio::test]
    async fn delta_stream_future_sequence_error_maps_to_400_with_message() {
        let response =
            delta_stream_after_error_response(DeltaAfterError::FutureSequence { latest: 9 });
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let bytes = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(text.contains("afterSequence cannot be greater than latest sequence (9)"));
    }

    #[tokio::test]
    async fn delta_stream_replay_miss_error_maps_to_410_with_message() {
        let response = delta_stream_after_error_response(DeltaAfterError::ResyncRequired {
            oldest_available: 5,
            latest: 12,
        });
        assert_eq!(response.status(), StatusCode::GONE);

        let bytes = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            payload["message"]
                .as_str()
                .unwrap()
                .contains("resnapshot required")
        );
        assert_eq!(payload["oldestAvailable"], 5);
        assert_eq!(payload["latestSequence"], 12);
    }

    #[tokio::test]
    async fn get_delta_snapshot_when_cache_has_data() {
        let _guard = DeltaSyncEnabledGuard::set(true);
        let cache = test_cache().await;

        let auction = domain::RawAuctionData {
            block: 42,
            orders: vec![test_order(1, 100)],
            prices: std::collections::HashMap::from([(
                Address::repeat_byte(0xAA).into(),
                test_price(2000),
            )]),
            surplus_capturing_jit_order_owners: Vec::new(),
        };
        cache
            .set_state_for_tests(auction.clone(), 1, 5, 5, VecDeque::new())
            .await;

        let state = State {
            estimator: Arc::new(StubNativePriceEstimator::default()),
            allowed_timeout: MIN_TIMEOUT..=MIN_TIMEOUT,
            solvable_orders_cache: cache,
        };
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/delta/snapshot")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("Content-Type").unwrap(),
            "application/json"
        );

        let bytes = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let snapshot: DeltaSnapshotResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(snapshot.version, 1);
        assert_eq!(snapshot.sequence, 5);
        assert_eq!(snapshot.auction_id, 1);
        assert_eq!(snapshot.auction.orders.len(), 1);
    }

    #[tokio::test]
    async fn get_delta_snapshot_requires_auth_when_api_key_configured() {
        let _guard_enabled = DeltaSyncEnabledGuard::set(true);
        let _guard_key = ApiKeyOverrideGuard::set(Some("secret123".to_string()));
        let cache = test_cache().await;

        let state = State {
            estimator: Arc::new(StubNativePriceEstimator::default()),
            allowed_timeout: MIN_TIMEOUT..=MIN_TIMEOUT,
            solvable_orders_cache: cache,
        };
        let app = build_router(state);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/delta/snapshot")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response_with_key = app
            .oneshot(
                Request::builder()
                    .uri("/delta/snapshot")
                    .header("X-Delta-Sync-Api-Key", "secret123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response_with_key.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn get_delta_checksum_returns_204_when_no_snapshot() {
        let _guard = DeltaSyncEnabledGuard::set(true);
        let cache = test_cache().await;

        let state = State {
            estimator: Arc::new(StubNativePriceEstimator::default()),
            allowed_timeout: MIN_TIMEOUT..=MIN_TIMEOUT,
            solvable_orders_cache: cache,
        };
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/delta/checksum")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn get_delta_checksum_returns_correct_hash_when_snapshot_exists() {
        let _guard = DeltaSyncEnabledGuard::set(true);
        let cache = test_cache().await;

        let auction = domain::RawAuctionData {
            block: 1,
            orders: vec![test_order(1, 100)],
            prices: std::collections::HashMap::from([(
                Address::repeat_byte(0xBB).into(),
                test_price(3000),
            )]),
            surplus_capturing_jit_order_owners: Vec::new(),
        };
        cache
            .set_state_for_tests(auction, 1, 10, 10, VecDeque::new())
            .await;

        let state = State {
            estimator: Arc::new(StubNativePriceEstimator::default()),
            allowed_timeout: MIN_TIMEOUT..=MIN_TIMEOUT,
            solvable_orders_cache: cache,
        };
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/delta/checksum")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let bytes = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let checksum: DeltaChecksumResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(checksum.version, 1);
        assert_eq!(checksum.sequence, 10);
        assert!(!checksum.order_uid_hash.is_empty());
        assert!(!checksum.price_hash.is_empty());
    }

    #[test]
    fn delta_stream_buffer_size_respects_override() {
        let _guard = DeltaStreamBufferGuard::set(256);
        assert_eq!(delta_stream_buffer_size(), 256);
    }

    #[tokio::test]
    async fn drain_live_envelopes_with_closed_true_triggers_resync_control_event() {
        let (sender, mut receiver) = tokio::sync::broadcast::channel(8);
        let mut replay_to_sequence = 0;

        drop(sender);

        let drained = drain_live_envelopes(&mut receiver, 0, 0, &mut replay_to_sequence).unwrap();

        assert!(drained.closed);
        assert_eq!(drained.payloads.len(), 0);
    }

    #[tokio::test]
    async fn replay_envelopes_with_snapshot_sequence_field_populated() {
        let _guard_enabled = DeltaSyncEnabledGuard::set(true);
        let _guard_key = ApiKeyOverrideGuard::set(None);
        let cache = test_cache().await;

        let auction = domain::RawAuctionData {
            block: 1,
            orders: vec![test_order(1, 100)],
            prices: std::collections::HashMap::new(),
            surplus_capturing_jit_order_owners: Vec::new(),
        };
        let envelope = DeltaEnvelope {
            auction_id: 1,
            auction_sequence: 1,
            from_sequence: 0,
            to_sequence: 1,
            published_at: chrono::Utc::now(),
            published_at_instant: Instant::now(),
            events: vec![DeltaEvent::OrderAdded(test_order(1, 100))],
        };
        cache
            .set_state_for_tests(auction, 1, 1, 1, VecDeque::from([envelope]))
            .await;

        let state = State {
            estimator: Arc::new(StubNativePriceEstimator::default()),
            allowed_timeout: MIN_TIMEOUT..=MIN_TIMEOUT,
            solvable_orders_cache: cache,
        };
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/delta/stream?after_sequence=0")
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 0))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let mut body_stream = response.into_body().into_data_stream();
        let chunk = tokio::time::timeout(
            Duration::from_secs(1),
            futures::StreamExt::next(&mut body_stream),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();

        let text = String::from_utf8_lossy(&chunk);
        assert!(text.contains("snapshotSequence"));
    }

    #[test]
    fn api_key_hash_produces_consistent_short_hex_prefix() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Delta-Sync-Api-Key", HeaderValue::from_static("test_key"));

        let hash1 = api_key_hash(&headers).unwrap();
        let hash2 = api_key_hash(&headers).unwrap();

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
        assert!(hash1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn boot_id_field_appears_in_envelope_responses() {
        let envelope = DeltaEventEnvelope {
            version: 1,
            boot_id: crate::solvable_orders::boot_id().to_owned(),
            auction_id: 1,
            auction_sequence: 1,
            from_sequence: 0,
            to_sequence: 1,
            snapshot_sequence: None,
            published_at: "2026-03-20T00:00:00Z".to_string(),
            events: vec![],
        };

        let json = serde_json::to_string(&envelope).unwrap();
        assert!(json.contains("bootId"));
        assert!(json.contains(&crate::solvable_orders::boot_id()));
    }

    #[test]
    fn active_stream_guard_increments_and_decrements_gauge() {
        let initial = DeltaMetrics::get().active_streams.get();

        {
            let _guard = ActiveStreamGuard::new(
                std::net::SocketAddr::from(([127, 0, 0, 1], 8080)),
                Some("test_hash".to_string()),
            );
            assert_eq!(DeltaMetrics::get().active_streams.get(), initial + 1);
        }

        assert_eq!(DeltaMetrics::get().active_streams.get(), initial);
    }
}
