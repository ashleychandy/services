use {
    crate::{
        domain::competition::delta_replica::{
            Envelope,
            Replica,
            ReplicaChecksum,
            ReplicaState,
            Snapshot,
        },
        infra::observe::metrics,
    },
    reqwest::{StatusCode, Url},
    serde::{Deserialize, Serialize},
    std::{
        collections::HashMap,
        sync::{
            Arc,
            LazyLock,
            OnceLock,
            RwLock as StdRwLock,
            atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering},
        },
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    },
    tokio::sync::{Mutex, RwLock},
};

const DEFAULT_RETRY_DELAY: Duration = Duration::from_secs(2);
const STREAM_RETRY_BACKOFF: Duration = Duration::from_millis(500);
const SNAPSHOT_BOOTSTRAP_RETRIES: usize = 3;
const SNAPSHOT_BOOTSTRAP_DELAY: Duration = Duration::from_millis(100);
const DELTA_SYNC_API_KEY_HEADER: &str = "X-Delta-Sync-Api-Key";
static DELTA_REPLICA: LazyLock<StdRwLock<Arc<RwLock<Replica>>>> =
    LazyLock::new(|| StdRwLock::new(Arc::new(RwLock::new(Replica::default()))));
#[cfg(any(test, feature = "test-helpers"))]
static DELTA_REPLICA_TEST_MUTEX: LazyLock<Arc<tokio::sync::Mutex<()>>> =
    LazyLock::new(|| Arc::new(tokio::sync::Mutex::new(())));
static DELTA_CHECKSUM_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("failed to create reqwest client for delta checksum")
});
#[cfg(any(test, feature = "test-helpers"))]
static DRIVER_DELTA_SYNC_ENABLED_OVERRIDE: LazyLock<std::sync::Mutex<Option<bool>>> =
    LazyLock::new(|| std::sync::Mutex::new(None));

#[cfg(any(test, feature = "test-helpers"))]
pub fn set_driver_delta_sync_enabled_override(value: Option<bool>) {
    *DRIVER_DELTA_SYNC_ENABLED_OVERRIDE
        .lock()
        .expect("driver delta sync enabled override lock poisoned") = value;
}

#[cfg(any(test, feature = "test-helpers"))]
static DRIVER_DELTA_SYNC_AUTOPILOT_URL_OVERRIDE: LazyLock<std::sync::Mutex<Option<Url>>> =
    LazyLock::new(|| std::sync::Mutex::new(None));

#[cfg(any(test, feature = "test-helpers"))]
pub fn set_driver_delta_sync_autopilot_url_override(value: Option<Url>) {
    *DRIVER_DELTA_SYNC_AUTOPILOT_URL_OVERRIDE
        .lock()
        .expect("driver delta sync autopilot url override lock poisoned") = value;
}
// 0 = unset, 1 = enabled, 2 = disabled
static REPLICA_PREPROCESSING_STATE: AtomicU8 = AtomicU8::new(0);
// 0 = unset, 1 = enabled, 2 = disabled
static REPLICA_FULL_BODY_BINDING_STATE: AtomicU8 = AtomicU8::new(0);
static DELTA_REPLICA_MAX_STALENESS: OnceLock<Option<Duration>> = OnceLock::new();
static DELTA_REPLICA_RESNAPSHOT_INTERVAL: OnceLock<Option<Duration>> = OnceLock::new();
static BOOTSTRAP_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
#[cfg(any(test, feature = "test-helpers"))]
pub static REPLICA_PREPROCESSING_OVERRIDE: AtomicU8 = AtomicU8::new(0);
// Circuit breaker for consecutive thin-replica binding failures. This prevents
// repeated thin-replica attempts when the replica is persistently diverged
// (e.g. checksum or sequence mismatches).
static CONSECUTIVE_BINDING_FAILURES: AtomicU32 = AtomicU32::new(0);
const BINDING_FAILURE_CIRCUIT_BREAKER: u32 = 3;

// Timestamp (epoch seconds) when the circuit breaker most recently opened.
// 0 means "not set".
static LAST_BINDING_FAILURE_AT: AtomicU64 = AtomicU64::new(0);

// Cooldown period (seconds) after which the circuit will be allowed to
// transition back to closed automatically. Can be configured via
// `DRIVER_DELTA_SYNC_BINDING_FAILURE_COOLDOWN_SECS`.
static BINDING_FAILURE_COOLDOWN_SECS: OnceLock<u64> = OnceLock::new();

fn binding_failure_cooldown_secs() -> u64 {
    *BINDING_FAILURE_COOLDOWN_SECS.get_or_init(|| {
        std::env::var("DRIVER_DELTA_SYNC_BINDING_FAILURE_COOLDOWN_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(60)
    })
}

pub fn record_binding_failure() {
    use std::sync::atomic::Ordering;

    let prev = CONSECUTIVE_BINDING_FAILURES.fetch_add(1, Ordering::Release);
    let new = prev.saturating_add(1);
    if new >= BINDING_FAILURE_CIRCUIT_BREAKER {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        LAST_BINDING_FAILURE_AT.store(now, Ordering::Release);
    }
}

pub fn record_binding_success() {
    use std::sync::atomic::Ordering;

    CONSECUTIVE_BINDING_FAILURES.store(0, Ordering::Release);
    LAST_BINDING_FAILURE_AT.store(0, Ordering::Release);
}

pub fn replica_binding_circuit_open() -> bool {
    use std::sync::atomic::Ordering;

    let count = CONSECUTIVE_BINDING_FAILURES.load(Ordering::Acquire);
    if count < BINDING_FAILURE_CIRCUIT_BREAKER {
        return false;
    }

    let last = LAST_BINDING_FAILURE_AT.load(Ordering::Acquire);
    if last == 0 {
        // No timestamp set; treat as open until we can set a timestamp.
        return true;
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let cooldown = binding_failure_cooldown_secs();

    if now.saturating_sub(last) >= cooldown {
        // Cooldown expired: reset the circuit so we can attempt bootstrap
        // again.
        CONSECUTIVE_BINDING_FAILURES.store(0, Ordering::Release);
        LAST_BINDING_FAILURE_AT.store(0, Ordering::Release);
        return false;
    }

    true
}

#[derive(Debug, Clone)]
pub(crate) struct ReplicaSnapshot {
    pub(crate) auction_id: u64,
    pub(crate) sequence: u64,
    pub(crate) order_uid_hash: String,
    pub(crate) price_hash: String,
    pub(crate) order_content_hash: String,
    pub(crate) orders: Vec<crate::infra::api::routes::solve::dto::solve_request::Order>,
    pub(crate) prices: HashMap<alloy::primitives::Address, String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicaHealth {
    pub state: ReplicaState,
    pub sequence: u64,
    pub order_count: usize,
    pub last_update: Option<chrono::DateTime<chrono::Utc>>,
    pub last_update_age_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeltaStreamGonePayload {
    latest_sequence: u64,
    #[serde(default)]
    oldest_available: Option<u64>,
    #[serde(default)]
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeltaChecksumResponse {
    version: u32,
    sequence: u64,
    order_uid_hash: String,
    price_hash: String,
    order_content_hash: String,
}

/// Starts a background delta-sync task if DRIVER_DELTA_SYNC_AUTOPILOT_URL is
/// set.
///
/// The task keeps a local replica up to date from snapshot + delta SSE stream.
pub fn maybe_spawn_from_env() -> Option<tokio::task::JoinHandle<()>> {
    #[cfg(any(test, feature = "test-helpers"))]
    {
        let override_lock = DRIVER_DELTA_SYNC_ENABLED_OVERRIDE
            .lock()
            .expect("driver delta sync enabled override lock poisoned");
        if let Some(v) = *override_lock {
            if !v {
                tracing::warn!("driver delta sync disabled via test override");
                return None;
            }
            // Some(true): fallthrough, skipping the env check below.
        } else {
            if !shared::env::flag_enabled(
                std::env::var("DRIVER_DELTA_SYNC_ENABLED").ok().as_deref(),
                true,
            ) {
                tracing::warn!("driver delta sync disabled via DRIVER_DELTA_SYNC_ENABLED");
                return None;
            }
        }
    }

    // Non-test builds (or when test-helpers feature is disabled) still consult
    // the environment flag normally.
    #[cfg(not(any(test, feature = "test-helpers")))]
    if !shared::env::flag_enabled(
        std::env::var("DRIVER_DELTA_SYNC_ENABLED").ok().as_deref(),
        true,
    ) {
        tracing::warn!("driver delta sync disabled via DRIVER_DELTA_SYNC_ENABLED");
        return None;
    }

    let base = delta_sync_base_url_from_env()?;

    // Create two separate reqwest clients: one with a short timeout for
    // snapshot/bootstrap HTTP requests, and one without a global timeout for
    // the long-lived SSE stream. Reusing a client with a total timeout for
    // the stream caused healthy SSE connections to be torn down every
    // timeout interval.
    let snapshot_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("failed to create reqwest client for delta sync snapshot");

    let stream_client = reqwest::Client::builder()
        // Intentionally do not set a global timeout for the SSE stream.
        .build()
        .expect("failed to create reqwest client for delta sync stream");

    let replica = delta_replica();

    Some(tokio::spawn(async move {
        match run(snapshot_client, stream_client, base, replica).await {
            Ok(()) => tracing::warn!("delta sync task exited without error"),
            Err(err) => tracing::error!(?err, "delta sync task exited"),
        }
    }))
}

pub(crate) async fn snapshot() -> Option<ReplicaSnapshot> {
    let replica = delta_replica();
    let replica = replica.read().await;
    snapshot_from_replica(&replica)
}

#[cfg(any(test, feature = "test-helpers"))]
pub fn reset_delta_replica_for_tests() {
    let mut guard = match DELTA_REPLICA.write() {
        Ok(g) => g,
        Err(poison) => poison.into_inner(),
    };
    *guard = Arc::new(RwLock::new(Replica::default()));
}

#[cfg(any(test, feature = "test-helpers"))]
pub async fn reset_delta_replica_for_tests_async() {
    if let Ok(guard) = DELTA_REPLICA.read() {
        // Clone the Arc and release the read guard quickly so we don't hold
        // the std::sync::RwLock across await points (which would block
        // writers). The spin loop below will attempt to reset the inner
        // tokio lock in-place; if contended, we fall back to replacing the
        // global Arc.
        let replica_arc = guard.clone();
        drop(guard);

        let start = Instant::now();
        while start.elapsed() < Duration::from_millis(500) {
            if let Ok(mut inner) = replica_arc.try_write() {
                *inner = Replica::default();
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        if let Ok(mut global_guard) = DELTA_REPLICA.try_write() {
            *global_guard = Arc::new(RwLock::new(Replica::default()));
            return;
        }

        let new_arc = Arc::new(RwLock::new(Replica::default()));
        let _ = tokio::task::spawn_blocking(move || {
            let mut guard = match DELTA_REPLICA.write() {
                Ok(g) => g,
                Err(poison) => poison.into_inner(),
            };
            *guard = new_arc;
        })
        .await;
        return;
    }

    let mut guard = match DELTA_REPLICA.write() {
        Ok(g) => g,
        Err(poison) => poison.into_inner(),
    };
    *guard = Arc::new(RwLock::new(Replica::default()));
}

#[cfg(test)]
pub(crate) async fn set_replica_snapshot_for_tests(snapshot: Snapshot) {
    let replica = delta_replica();
    let mut lock = replica.write().await;
    lock.set_state(ReplicaState::Syncing);
    lock.apply_snapshot(snapshot)
        .expect("failed to apply test snapshot to replica");
}

#[cfg(test)]
mod snapshot_tests {
    use {
        super::*,
        crate::domain::competition::delta_replica::{RawAuctionData, Snapshot as DeltaSnapshot},
        serde_json::json,
        std::collections::HashMap,
    };

    #[tokio::test]
    async fn snapshot_orders_are_sorted_by_uid() {
        // Acquire test guard to reset global replica state.
        let _guard = DeltaReplicaTestGuard::acquire().await;

        let uid1 = format!("0x{}", hex::encode([1u8; 56]));
        let uid2 = format!("0x{}", hex::encode([2u8; 56]));

        let order_a = json!({
            "uid": uid2.clone(),
            "sellToken": format!("0x{}", hex::encode([0x01u8; 20])),
            "buyToken": format!("0x{}", hex::encode([0x02u8; 20])),
            "sellAmount": "1",
            "buyAmount": "1",
            "protocolFees": [],
            "created": 1,
            "validTo": 100,
            "kind": "sell",
            "receiver": serde_json::Value::Null,
            "owner": format!("0x{}", hex::encode([0x03u8; 20])),
            "partiallyFillable": false,
            "executed": "0",
            "preInteractions": [],
            "postInteractions": [],
            "class": "market",
            "appData": format!("0x{}", hex::encode([0u8; 32])),
            "signingScheme": "eip712",
            "signature": format!("0x{}", hex::encode([0u8; 1])),
            "quote": serde_json::Value::Null
        });

        let order_b = json!({
            "uid": uid1.clone(),
            "sellToken": format!("0x{}", hex::encode([0x01u8; 20])),
            "buyToken": format!("0x{}", hex::encode([0x02u8; 20])),
            "sellAmount": "1",
            "buyAmount": "1",
            "protocolFees": [],
            "created": 1,
            "validTo": 100,
            "kind": "sell",
            "receiver": serde_json::Value::Null,
            "owner": format!("0x{}", hex::encode([0x03u8; 20])),
            "partiallyFillable": false,
            "executed": "0",
            "preInteractions": [],
            "postInteractions": [],
            "class": "market",
            "appData": format!("0x{}", hex::encode([0u8; 32])),
            "signingScheme": "eip712",
            "signature": format!("0x{}", hex::encode([0u8; 1])),
            "quote": serde_json::Value::Null
        });

        let delta_snapshot = DeltaSnapshot {
            version: 1,
            boot_id: None,
            auction_id: Some(0),
            sequence: 1,
            auction: RawAuctionData {
                // Intentionally provide orders in reverse (uid2 then uid1)
                orders: vec![order_a, order_b],
                prices: HashMap::new(),
            },
        };

        set_replica_snapshot_for_tests(delta_snapshot).await;

        let rep = snapshot().await.expect("replica snapshot");

        let uids: Vec<String> = rep
            .orders
            .iter()
            .map(|order| {
                let v = serde_json::to_value(order).expect("serialize order");
                v.get("uid")
                    .and_then(|s| s.as_str())
                    .expect("uid string")
                    .to_string()
            })
            .collect();

        // Expect ascending order by UID (uid1 < uid2)
        assert_eq!(uids, vec![uid1, uid2]);
    }
}

#[cfg(any(test, feature = "test-helpers"))]
pub(crate) async fn set_replica_state_for_tests(state: ReplicaState) {
    let replica = delta_replica();
    let mut lock = replica.write().await;
    *lock = Replica::default();
    lock.set_state(state);
}

/// Global test guard to serialize replica usage across tests.
///
/// The guard resets the global replica when acquired and again on drop.

#[cfg(any(test, feature = "test-helpers"))]
pub struct DeltaReplicaTestGuard {
    _lock: Option<tokio::sync::OwnedMutexGuard<()>>,
    replica: Arc<RwLock<Replica>>,
}

#[cfg(any(test, feature = "test-helpers"))]
impl DeltaReplicaTestGuard {
    pub async fn acquire() -> Self {
        // Acquire the serialization mutex for test reset coordination.
        let lock = Arc::clone(&DELTA_REPLICA_TEST_MUTEX).lock_owned().await;

        // Perform a synchronous reset on a blocking thread. Prefer an
        // in-place reset of any preexisting `Arc<RwLock<Replica>>` clones by
        // acquiring the inner tokio RwLock in blocking mode. This is safe
        // because we're executing on a dedicated blocking thread.
        let handle = tokio::task::spawn_blocking(|| {
            // Try to obtain a read guard on the global StdRwLock to access
            // the inner Arc without blocking writers.
            let guard = match DELTA_REPLICA.read() {
                Ok(g) => g,
                Err(poison) => poison.into_inner(),
            };
            let replica_arc = guard.clone();

            // Acquire the inner tokio RwLock in blocking mode and reset in-place.
            let mut inner = replica_arc.blocking_write();
            *inner = Replica::default();

            drop(inner);

            replica_arc
        });
        let replica = handle.await.expect("replica reset thread panicked");

        Self {
            _lock: Some(lock),
            replica,
        }
    }
}

#[cfg(any(test, feature = "test-helpers"))]
impl Drop for DeltaReplicaTestGuard {
    fn drop(&mut self) {
        // Try a non-blocking in-place reset first. This avoids calling
        // `tokio::task::block_in_place` (which panics on current-thread
        // runtimes) and avoids spawning threads that could deadlock if the
        // runtime is holding the inner lock. If the immediate attempt
        // fails, spin briefly trying `try_write()` and then fall back to
        // replacing the global Arc or, as a final fallback, spawning a
        // thread to perform the replacement synchronously.
        let replica_arc = Arc::clone(&self.replica);

        let start = std::time::Instant::now();
        let timeout = Duration::from_millis(500);
        let mut did_reset = false;

        // Fast path: try to obtain the inner write lock without blocking.
        if let Ok(mut inner) = replica_arc.try_write() {
            *inner = Replica::default();
            did_reset = true;
        } else {
            // Spin briefly trying to acquire the write lock. This mirrors the
            // async helper's behaviour but uses `std::thread::sleep` so it
            // can run synchronously from `Drop`.
            while start.elapsed() < timeout {
                if let Ok(mut inner) = replica_arc.try_write() {
                    *inner = Replica::default();
                    did_reset = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        if !did_reset {
            // Try to replace the global Arc quickly without blocking on the
            // inner tokio lock. If that fails, synchronously spawn a thread
            // which takes the std::sync write lock and replaces the Arc.
            if let Ok(mut global_guard) = DELTA_REPLICA.try_write() {
                *global_guard = Arc::new(RwLock::new(Replica::default()));
            } else {
                let handle = std::thread::spawn(move || {
                    let mut guard = match DELTA_REPLICA.write() {
                        Ok(g) => g,
                        Err(poison) => poison.into_inner(),
                    };
                    *guard = Arc::new(RwLock::new(Replica::default()));
                });
                if let Err(e) = handle.join() {
                    tracing::error!(?e, "delta replica reset thread panicked in fallback");
                }
            }
        }

        if let Some(lock) = self._lock.take() {
            drop(lock);
        }
    }
}

fn snapshot_from_replica(replica: &Replica) -> Option<ReplicaSnapshot> {
    if !matches!(replica.state(), ReplicaState::Ready) {
        return None;
    }
    let checksum = replica.checksum()?;
    Some(ReplicaSnapshot {
        auction_id: replica.auction_id(),
        sequence: replica.sequence(),
        order_uid_hash: checksum.order_uid_hash,
        price_hash: checksum.price_hash,
        order_content_hash: checksum.order_content_hash,
        // Collect orders deterministically. The replica stores orders in a
        // HashMap, so iterate and sort by UID to match the autopilot full
        // request ordering (which also sorts by UID). This ensures the
        // thin-path reconstructed request preserves the same deterministic
        // order set and grouping behavior used during preprocessing.
        orders: {
            // Sort by the stored UID string keys to avoid accessing private
            // fields on the DTO `Order` type.
            let mut entries = replica
                .orders()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<Vec<(String, _)>>();
            entries.sort_by(|(a, _), (b, _)| a.cmp(b));
            entries.into_iter().map(|(_, v)| v).collect()
        },
        prices: replica.prices().clone(),
    })
}

pub async fn replica_health() -> Option<ReplicaHealth> {
    // If delta sync is not enabled, treat the replica as disabled for

    #[cfg(any(test, feature = "test-helpers"))]
    {
        let override_lock = DRIVER_DELTA_SYNC_ENABLED_OVERRIDE
            .lock()
            .expect("driver delta sync enabled override lock poisoned");
        if let Some(v) = *override_lock {
            if !v {
                return None;
            }
            // Some(true): fallthrough to continue health reporting.
        } else if !shared::env::flag_enabled(
            std::env::var("DRIVER_DELTA_SYNC_ENABLED").ok().as_deref(),
            true,
        ) {
            return None;
        }
    }

    #[cfg(not(any(test, feature = "test-helpers")))]
    if !shared::env::flag_enabled(
        std::env::var("DRIVER_DELTA_SYNC_ENABLED").ok().as_deref(),
        true,
    ) {
        return None;
    }

    let checksum_enabled = delta_sync_checksum_enabled();
    let base_url = if checksum_enabled {
        delta_sync_base_url_from_env()
    } else {
        None
    };

    let replica = delta_replica();
    let replica = replica.read().await;

    // If there's no external delta sync base URL and the local replica hasn't
    // been initialized, treat the replica as disabled for health reporting.
    if base_url.is_none() && matches!(replica.state(), ReplicaState::Uninitialized) {
        return None;
    }
    let now = chrono::Utc::now();
    let last_update_age_seconds = replica
        .last_update()
        .map(|timestamp| now.signed_duration_since(timestamp).num_seconds())
        .and_then(|seconds| u64::try_from(seconds).ok());

    let local_checksum = base_url.as_ref().and_then(|_| replica.checksum());

    if let Some(age) = last_update_age_seconds {
        metrics::get()
            .delta_replica_last_update_age_seconds
            .set(age as i64);
    }

    let health = ReplicaHealth {
        state: replica.state(),
        sequence: replica.sequence(),
        order_count: replica.orders().len(),
        last_update: replica.last_update(),
        last_update_age_seconds,
    };
    drop(replica);

    if let (Some(base_url), Some(local_checksum)) = (base_url, local_checksum) {
        // Clone the checksum so we can pass an owned value into the remote
        // comparison while still retaining the original for logging.
        let local_checksum_clone = local_checksum.clone();
        match compare_replica_checksum(&base_url, local_checksum_clone).await {
            Ok(true) => {
                // Replica checksum matches remote; proceed to report health.
            }
            Ok(false) => {
                // Replica diverged from remote checksum: treat as unhealthy so
                // the health endpoint can report an explicit failure.
                tracing::warn!(
                    local_sequence = local_checksum.sequence,
                    "delta replica checksum mismatch; reporting unhealthy"
                );
                return None;
            }
            Err(err) => {
                // On transient errors, keep reporting the replica as available
                // but surface a warning to logs for investigation.
                tracing::warn!(?err, "delta replica checksum comparison failed");
            }
        }
    }

    Some(health)
}

pub async fn replica_state() -> Option<ReplicaState> {
    Some(delta_replica().read().await.state())
}

pub async fn mark_replica_resyncing() {
    delta_replica()
        .write()
        .await
        .set_state(ReplicaState::Resyncing);
}

pub async fn replica_is_fresh() -> Option<bool> {
    let Some(max_staleness) = delta_replica_max_staleness() else {
        return Some(true);
    };
    let replica = delta_replica();
    let replica = replica.read().await;
    let Some(last_update) = replica.last_update() else {
        return Some(false);
    };
    let now = chrono::Utc::now();
    let age = now.signed_duration_since(last_update).to_std().ok()?;
    Some(age <= max_staleness)
}

pub async fn ensure_replica_snapshot_from_env() -> anyhow::Result<bool> {
    if !shared::env::flag_enabled(
        std::env::var("DRIVER_DELTA_SYNC_ENABLED").ok().as_deref(),
        true,
    ) {
        return Ok(false);
    }

    let Some(base_url) = delta_sync_base_url_from_env() else {
        return Ok(false);
    };

    let replica = delta_replica();

    let _bootstrap_guard = BOOTSTRAP_LOCK.lock().await;

    {
        let current = replica.read().await;
        if matches!(current.state(), ReplicaState::Ready) {
            return Ok(true);
        }
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("failed to create reqwest client for delta sync bootstrap");

    let mut snapshot = None;
    let mut last_err = None;
    for attempt in 0..SNAPSHOT_BOOTSTRAP_RETRIES {
        match fetch_snapshot(&client, &base_url).await {
            Ok(payload) => {
                snapshot = Some(payload);
                break;
            }
            Err(err) => {
                last_err = Some(err);
                if attempt + 1 < SNAPSHOT_BOOTSTRAP_RETRIES {
                    tokio::time::sleep(SNAPSHOT_BOOTSTRAP_DELAY).await;
                }
            }
        }
    }
    let snapshot = snapshot
        .ok_or_else(|| last_err.unwrap_or_else(|| anyhow::anyhow!("snapshot bootstrap failed")))?;
    {
        let mut lock = replica.write().await;
        lock.set_state(ReplicaState::Syncing);
        lock.apply_snapshot(snapshot)?;
    }
    Ok(true)
}

pub fn replica_preprocessing_enabled() -> bool {
    // Test override (highest precedence)
    #[cfg(any(test, feature = "test-helpers"))]
    if let Some(value) = replica_preprocessing_override() {
        return value;
    }

    // Runtime override/state: if set, use it; otherwise read env var and cache
    // the resolved value in the atomic state for subsequent fast reads.
    let state = REPLICA_PREPROCESSING_STATE.load(Ordering::Relaxed);
    if state != 0 {
        return state == 1;
    }

    let enabled = shared::env::flag_enabled(
        std::env::var("DRIVER_DELTA_SYNC_USE_REPLICA")
            .ok()
            .as_deref(),
        false,
    );
    let new_state = if enabled { 1 } else { 2 };
    let _ = REPLICA_PREPROCESSING_STATE.compare_exchange(
        0,
        new_state,
        Ordering::Relaxed,
        Ordering::Relaxed,
    );
    enabled
}

/// Return whether full-body requests should be allowed to bind to the delta
/// replica (opt-in via env or test override). Default: false.
pub fn replica_full_body_binding_enabled() -> bool {
    let state = REPLICA_FULL_BODY_BINDING_STATE.load(Ordering::Relaxed);
    if state != 0 {
        return state == 1;
    }

    // No override: consult env var. Use compare_exchange to avoid a benign
    // race where multiple threads compute and store the same result.
    let enabled = shared::env::flag_enabled(
        std::env::var("DRIVER_DELTA_SYNC_REPLICA_BIND_FULL_BODY")
            .ok()
            .as_deref(),
        false,
    );
    let new_state = if enabled { 1 } else { 2 };
    let _ = REPLICA_FULL_BODY_BINDING_STATE.compare_exchange(
        0,
        new_state,
        Ordering::Relaxed,
        Ordering::Relaxed,
    );
    enabled
}

#[cfg(any(test, feature = "test-helpers"))]
fn replica_preprocessing_override() -> Option<bool> {
    match REPLICA_PREPROCESSING_OVERRIDE.load(Ordering::SeqCst) {
        1 => Some(true),
        2 => Some(false),
        _ => None,
    }
}

#[cfg(any(test, feature = "test-helpers"))]
pub fn set_replica_preprocessing_override(value: Option<bool>) {
    let encoded = match value {
        Some(true) => 1,
        Some(false) => 2,
        None => 0,
    };
    REPLICA_PREPROCESSING_OVERRIDE.store(encoded, Ordering::SeqCst);
}

/// Test override (and runtime state) setter for full-body replica binding.
#[cfg(any(test, feature = "test-helpers"))]
pub fn set_replica_full_body_binding_override(value: Option<bool>) {
    let encoded = match value {
        Some(true) => 1,
        Some(false) => 2,
        None => 0,
    };
    REPLICA_FULL_BODY_BINDING_STATE.store(encoded, Ordering::SeqCst);
}

async fn run(
    snapshot_client: reqwest::Client,
    stream_client: reqwest::Client,
    base_url: Url,
    replica: Arc<RwLock<Replica>>,
) -> anyhow::Result<()> {
    loop {
        {
            let mut lock = replica.write().await;
            lock.set_state(ReplicaState::Syncing);
        }
        // Fetch snapshot and capture session boot_id for validation of live envelopes.
        let session_boot_id = match fetch_snapshot(&snapshot_client, &base_url).await {
            Ok(snapshot) => {
                let boot_id = snapshot.boot_id.clone();
                let applied = {
                    let mut lock = replica.write().await;
                    lock.apply_snapshot(snapshot)
                };
                if let Err(err) = applied {
                    tracing::warn!(?err, "delta sync snapshot apply failed; retrying");
                    tokio::time::sleep(DEFAULT_RETRY_DELAY).await;
                    continue;
                }
                let view = replica.read().await;
                tracing::info!(
                    sequence = view.sequence(),
                    orders = view.orders().len(),
                    prices = view.prices().len(),
                    "delta sync snapshot applied"
                );
                boot_id
            }
            Err(err) => {
                {
                    let mut lock = replica.write().await;
                    lock.set_state(ReplicaState::Resyncing);
                }
                tracing::warn!(?err, "delta sync snapshot fetch failed; retrying");
                tokio::time::sleep(DEFAULT_RETRY_DELAY).await;
                continue;
            }
        };

        let snapshot_started_at = Instant::now();
        loop {
            match follow_stream(
                &stream_client,
                &base_url,
                &replica,
                snapshot_started_at,
                session_boot_id.as_deref(),
            )
            .await
            {
                Ok(StreamControl::Resnapshot) => {
                    {
                        let mut lock = replica.write().await;
                        lock.set_state(ReplicaState::Resyncing);
                    }
                    let view = replica.read().await;
                    tracing::warn!(
                        sequence = view.sequence(),
                        "delta stream requested resnapshot"
                    );
                    break;
                }
                Ok(StreamControl::RetryStream) => {
                    {
                        let mut lock = replica.write().await;
                        lock.set_state(ReplicaState::Resyncing);
                    }
                    tracing::warn!("delta stream requested retry without resnapshot");
                    tokio::time::sleep(STREAM_RETRY_BACKOFF).await;
                }
                Err(err) => {
                    {
                        let mut lock = replica.write().await;
                        lock.set_state(ReplicaState::Resyncing);
                    }
                    let view = replica.read().await;
                    tracing::warn!(
                        ?err,
                        sequence = view.sequence(),
                        "delta stream failed; forcing resnapshot"
                    );
                    break;
                }
            }
        }

        tokio::time::sleep(DEFAULT_RETRY_DELAY).await;
    }
}

async fn fetch_snapshot(client: &reqwest::Client, base_url: &Url) -> anyhow::Result<Snapshot> {
    let url = shared::url::join(base_url, "delta/snapshot");
    let response = apply_delta_sync_auth(client.get(url)).send().await?;
    if response.status() == StatusCode::NO_CONTENT {
        anyhow::bail!("delta snapshot unavailable")
    }
    let response = response.error_for_status()?;
    Ok(response.json::<Snapshot>().await?)
}

#[derive(Clone, Copy, Debug)]
enum StreamControl {
    Resnapshot,
    RetryStream,
}

async fn follow_stream(
    client: &reqwest::Client,
    base_url: &Url,
    replica: &std::sync::Arc<RwLock<Replica>>,
    snapshot_started_at: Instant,
    session_boot_id: Option<&str>,
) -> anyhow::Result<StreamControl> {
    let url = shared::url::join(base_url, "delta/stream");
    let after_sequence = replica.read().await.sequence();
    let response = apply_delta_sync_auth(client.get(url))
        .query(&[("after_sequence", after_sequence)])
        .send()
        .await?;
    if response.status() == StatusCode::GONE {
        // Autopilot uses 410/Gone to indicate the stream cannot be followed
        // without a fresh snapshot (resync). Historically we attempted a
        // short retry for small gaps, but retrying with the same
        // `after_sequence` cannot advance the replica in many server-side
        // scenarios and can trap the client in a reconnect loop. Prefer to
        // request a resnapshot immediately so the replica can make progress.
        let payload = response.json::<DeltaStreamGonePayload>().await.ok();
        if let Some(payload) = payload {
            // Preserve the more specific diagnostic when the server indicates
            // the requested sequence is older than the oldest available.
            if payload
                .oldest_available
                .is_some_and(|oldest| after_sequence < oldest)
            {
                replica.write().await.set_state(ReplicaState::Resyncing);
                tracing::warn!(
                    after_sequence,
                    latest_sequence = payload.latest_sequence,
                    oldest_available = ?payload.oldest_available,
                    message = payload.message.as_deref().unwrap_or(""),
                    "delta stream lagged beyond retention; resnapshot required"
                );
                return Ok(StreamControl::Resnapshot);
            }
            // For all other 410/Gone cases, treat as resnapshot required.
            replica.write().await.set_state(ReplicaState::Resyncing);
            tracing::warn!(
                after_sequence,
                latest_sequence = payload.latest_sequence,
                oldest_available = ?payload.oldest_available,
                message = payload.message.as_deref().unwrap_or(""),
                "delta stream returned 410 Gone; resnapshot required"
            );
            return Ok(StreamControl::Resnapshot);
        }
        replica.write().await.set_state(ReplicaState::Resyncing);
        tracing::warn!("delta stream returned 410 Gone without payload; resnapshot required");
        return Ok(StreamControl::Resnapshot);
    }

    let mut response = response.error_for_status()?;
    let mut buffer = String::new();
    let max_staleness = delta_replica_max_staleness();
    let resnapshot_interval = delta_replica_resnapshot_interval();

    let mut safety_sleep = tokio::time::sleep(Duration::from_secs(5));
    tokio::pin!(safety_sleep);

    loop {
        tokio::select! {
            chunk = response.chunk() => {
                match chunk? {
                    Some(bytes) => {
                        // Append raw chunk text first. We intentionally avoid doing
                        // per-chunk CRLF normalization because a CRLF boundary may
                        // be split across two chunks. Normalize CRLF on the
                        // accumulated `buffer` after appending the chunk so that
                        // cross-chunk "\r\n\r\n" boundaries become "\n\n".
                        let text = String::from_utf8_lossy(&bytes).into_owned();

                        buffer.push_str(&text);

                        // If any CR characters are present in the buffer, normalize
                        // CRLF -> LF across the whole buffer. Also remove any
                        // stray CRs that may remain (handles odd splits).
                        if buffer.contains('\r') {
                            if buffer.contains("\r\n") {
                                buffer = buffer.replace("\r\n", "\n");
                            }
                            if buffer.contains('\r') {
                                buffer = buffer.replace('\r', "");
                            }
                        }

                        while let Some(idx) = buffer.find("\n\n") {
                            let block = buffer[..idx].to_string();
                            buffer.drain(..idx + 2);

                            match handle_sse_block(&block, replica, session_boot_id).await? {
                                BlockControl::Continue => {}
                                BlockControl::Resnapshot => return Ok(StreamControl::Resnapshot),
                            }
                        }
                    }
                    None => break,
                }
            }
            _ = &mut safety_sleep => {

                if delta_sync_checksum_enabled() {
                    let local_checksum = replica.read().await.checksum();
                    if let Some(local_checksum) = local_checksum {
                        match compare_replica_checksum(base_url, local_checksum).await {
                            Ok(true) => {}
                            Ok(false) => {
                                replica.write().await.set_state(ReplicaState::Resyncing);
                                tracing::warn!("delta replica checksum mismatch; resnapshot required");
                                return Ok(StreamControl::Resnapshot);
                            }
                            Err(err) => {
                                tracing::warn!(?err, "delta replica checksum comparison failed");
                            }
                        }
                    }
                }

                if let Some(max_staleness) = max_staleness {
                    let last_update = replica.read().await.last_update();
                    let now = chrono::Utc::now();
                    if let Some(last_update) = last_update {
                        if let Ok(age) = now.signed_duration_since(last_update).to_std() {
                            if age > max_staleness {
                                tracing::warn!(?age, "delta replica update age exceeded max staleness");
                                return Ok(StreamControl::Resnapshot);
                            }
                        }
                    }
                }

                if let Some(interval) = resnapshot_interval {
                    if snapshot_started_at.elapsed() > interval {
                        tracing::warn!("delta replica resnapshot interval elapsed");
                        return Ok(StreamControl::Resnapshot);
                    }
                }


                safety_sleep.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(5));
            }
        }
    }

    anyhow::bail!("delta stream closed")
}

#[derive(Clone, Copy, Debug)]
enum BlockControl {
    Continue,
    Resnapshot,
}

async fn handle_sse_block(
    block: &str,
    replica: &std::sync::Arc<RwLock<Replica>>,
    session_boot_id: Option<&str>,
) -> anyhow::Result<BlockControl> {
    let (event, data) = parse_sse_block(block);
    let Some(data) = data else {
        return Ok(BlockControl::Continue);
    };

    match event {
        "delta" => {
            let envelope: Envelope = serde_json::from_str(&data)?;
            // Detect autopilot restart by comparing the session boot id from the
            // snapshot with the boot id sent in the live envelope. If they
            // differ, the autopilot restarted and we must request a resnapshot
            // to avoid applying deltas across sessions.
            if let (Some(session), Some(received)) = (session_boot_id, envelope.boot_id.as_deref())
            {
                if session != received {
                    replica.write().await.set_state(ReplicaState::Resyncing);
                    tracing::warn!(
                        session_boot_id = %session,
                        received_boot_id = %received,
                        "autopilot boot ID changed; forcing resnapshot"
                    );
                    return Ok(BlockControl::Resnapshot);
                }
            }

            let applied = {
                let mut lock = replica.write().await;
                lock.apply_delta(envelope)
            };
            if let Err(err) = applied {
                replica.write().await.set_state(ReplicaState::Resyncing);
                tracing::warn!(?err, "delta envelope apply failed; resnapshot required");
                return Ok(BlockControl::Resnapshot);
            }
            let view = replica.read().await;
            tracing::debug!(
                sequence = view.sequence(),
                orders = view.orders().len(),
                prices = view.prices().len(),
                "delta envelope applied"
            );
            Ok(BlockControl::Continue)
        }
        "resync_required" => {
            replica.write().await.set_state(ReplicaState::Resyncing);
            Ok(BlockControl::Resnapshot)
        }
        "error" => {
            replica.write().await.set_state(ReplicaState::Resyncing);
            tracing::warn!(payload = %data, "delta stream returned error event");
            Ok(BlockControl::Resnapshot)
        }
        _ => Ok(BlockControl::Continue),
    }
}

fn delta_sync_base_url_from_env() -> Option<Url> {
    #[cfg(any(test, feature = "test-helpers"))]
    {
        if let Some(url) = DRIVER_DELTA_SYNC_AUTOPILOT_URL_OVERRIDE
            .lock()
            .expect("driver delta sync autopilot url override lock poisoned")
            .clone()
        {
            return Some(url);
        }
    }

    let url = std::env::var("DRIVER_DELTA_SYNC_AUTOPILOT_URL").ok()?;

    match Url::parse(&url) {
        Ok(url) => Some(url),
        Err(err) => {
            tracing::error!(
                ?err,
                value = %url,
                "invalid DRIVER_DELTA_SYNC_AUTOPILOT_URL; delta sync task not started"
            );
            None
        }
    }
}

fn delta_sync_checksum_enabled() -> bool {
    shared::env::flag_enabled(
        std::env::var("DRIVER_DELTA_SYNC_CHECKSUM_ENABLED")
            .ok()
            .as_deref(),
        true,
    )
}

async fn compare_replica_checksum(
    base_url: &Url,
    local_checksum: ReplicaChecksum,
) -> anyhow::Result<bool> {
    let url = shared::url::join(base_url, "delta/checksum");
    let response = apply_delta_sync_auth(DELTA_CHECKSUM_CLIENT.get(url))
        .send()
        .await?;
    if response.status() == StatusCode::NO_CONTENT {
        return Ok(true);
    }
    let response = response.error_for_status()?;
    let remote = response.json::<DeltaChecksumResponse>().await?;

    if local_checksum.sequence > remote.sequence {
        metrics::get().delta_replica_diverged_total.inc();
        tracing::warn!(
            local_sequence = local_checksum.sequence,
            remote_sequence = remote.sequence,
            "delta replica sequence mismatch: remote behind local; resnapshot required"
        );
        return Ok(false);
    }

    if local_checksum.sequence == remote.sequence {
        // If sequences match, fall back to the content hashes check.
        if local_checksum.order_uid_hash != remote.order_uid_hash
            || local_checksum.price_hash != remote.price_hash
            || local_checksum.order_content_hash != remote.order_content_hash
        {
            metrics::get().delta_replica_diverged_total.inc();
            tracing::warn!(
                local_sequence = local_checksum.sequence,
                remote_sequence = remote.sequence,
                "delta replica checksum mismatch"
            );
            return Ok(false);
        }
        return Ok(true);
    }

    // remote.sequence > local_checksum.sequence: remote is ahead — allow the
    // stream to catch up rather than forcing a resnapshot.
    tracing::debug!(
        local_sequence = local_checksum.sequence,
        remote_sequence = remote.sequence,
        "remote checksum sequence ahead of local; will catch up via stream"
    );
    Ok(true)
}

fn delta_replica_max_staleness() -> Option<Duration> {
    DELTA_REPLICA_MAX_STALENESS
        .get_or_init(|| {
            std::env::var("DRIVER_DELTA_SYNC_MAX_STALENESS_SECS")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|value| *value > 0)
                .map(Duration::from_secs)
        })
        .as_ref()
        .copied()
}

fn delta_replica_resnapshot_interval() -> Option<Duration> {
    DELTA_REPLICA_RESNAPSHOT_INTERVAL
        .get_or_init(|| {
            std::env::var("DRIVER_DELTA_SYNC_RESNAPSHOT_SECS")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|value| *value > 0)
                .map(Duration::from_secs)
        })
        .as_ref()
        .copied()
}

fn apply_delta_sync_auth(request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    if let Some(api_key) = delta_sync_api_key_from_env() {
        request.header(DELTA_SYNC_API_KEY_HEADER, api_key)
    } else {
        request
    }
}

fn delta_sync_api_key_from_env() -> Option<String> {
    std::env::var("DRIVER_DELTA_SYNC_API_KEY").ok()
}

fn delta_replica() -> Arc<RwLock<Replica>> {
    DELTA_REPLICA
        .read()
        .expect("delta replica lock poisoned")
        .clone()
}

fn parse_sse_block(block: &str) -> (&str, Option<String>) {
    let mut event = "message";
    let mut data_lines = Vec::new();

    for raw_line in block.lines() {
        if raw_line.is_empty() || raw_line.starts_with(':') {
            continue;
        }

        let (field, value) = raw_line
            .split_once(':')
            .map(|(field, value)| (field, value.strip_prefix(' ').unwrap_or(value)))
            .unwrap_or((raw_line, ""));

        match field {
            "event" => event = value,
            "data" => data_lines.push(value),
            _ => {}
        }
    }

    if data_lines.is_empty() {
        (event, None)
    } else {
        (event, Some(data_lines.join("\n")))
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        axum::{
            Json,
            Router,
            extract::Query,
            response::{IntoResponse, Sse, sse},
            routing::get,
        },
        std::sync::Arc,
    };

    #[derive(Clone)]
    struct TestServerState {
        snapshot_json: String,
        observed_after_sequence: Arc<std::sync::Mutex<Option<u64>>>,
    }

    #[derive(serde::Deserialize)]
    struct StreamQuery {
        after_sequence: Option<u64>,
    }

    fn valid_uid(byte: u8) -> String {
        format!("0x{}", format!("{byte:02x}").repeat(56))
    }

    fn valid_order(uid: &str) -> serde_json::Value {
        serde_json::json!({
            "uid": uid,
            "sellToken": "0x0000000000000000000000000000000000000001",
            "buyToken": "0x0000000000000000000000000000000000000002",
            "sellAmount": "1",
            "buyAmount": "1",
            "protocolFees": [],
            "created": 1,
            "validTo": 100,
            "kind": "sell",
            "receiver": null,
            "owner": "0x0000000000000000000000000000000000000003",
            "partiallyFillable": false,
            "executed": "0",
            "preInteractions": [],
            "postInteractions": [],
            "class": "market",
            "appData": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "signingScheme": "eip712",
            "signature": "0x00",
            "quote": null
        })
    }

    async fn spawn_delta_test_server_with_events(
        snapshot_json: String,
        stream_events: Vec<(String, String)>,
    ) -> (
        Url,
        Arc<std::sync::Mutex<Option<u64>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let observed_after_sequence = Arc::new(std::sync::Mutex::new(None));
        let state = Arc::new(TestServerState {
            snapshot_json,
            observed_after_sequence: Arc::clone(&observed_after_sequence),
        });

        let app = Router::new()
            .route(
                "/delta/snapshot",
                get({
                    let state = Arc::clone(&state);
                    move || {
                        let state = Arc::clone(&state);
                        async move {
                            let value: serde_json::Value =
                                serde_json::from_str(&state.snapshot_json).unwrap();
                            Json(value)
                        }
                    }
                }),
            )
            .route(
                "/delta/stream",
                get({
                    let state = Arc::clone(&state);
                    move |Query(query): Query<StreamQuery>| {
                        let state = Arc::clone(&state);
                        let stream_events = stream_events.clone();
                        async move {
                            *state.observed_after_sequence.lock().unwrap() = query.after_sequence;
                            let events = stream_events.into_iter().map(|(event_name, payload)| {
                                Ok::<_, std::convert::Infallible>(
                                    sse::Event::default().event(event_name).data(payload),
                                )
                            });

                            Sse::new(futures::stream::iter(events)).into_response()
                        }
                    }
                }),
            );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (
            Url::parse(&format!("http://{addr}")).unwrap(),
            observed_after_sequence,
            handle,
        )
    }

    async fn spawn_delta_test_server(
        snapshot_json: String,
        stream_payload: String,
    ) -> (
        Url,
        Arc<std::sync::Mutex<Option<u64>>>,
        tokio::task::JoinHandle<()>,
    ) {
        spawn_delta_test_server_with_events(
            snapshot_json,
            vec![("delta".to_string(), stream_payload)],
        )
        .await
    }

    async fn spawn_delta_test_server_gone(
        snapshot_json: String,
        gone_payload: String,
    ) -> (
        Url,
        Arc<std::sync::Mutex<Option<u64>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let observed_after_sequence = Arc::new(std::sync::Mutex::new(None));
        let state = Arc::new(TestServerState {
            snapshot_json,
            observed_after_sequence: Arc::clone(&observed_after_sequence),
        });

        let app = Router::new()
            .route(
                "/delta/snapshot",
                get({
                    let state = Arc::clone(&state);
                    move || {
                        let state = Arc::clone(&state);
                        async move {
                            let value: serde_json::Value =
                                serde_json::from_str(&state.snapshot_json).unwrap();
                            Json(value)
                        }
                    }
                }),
            )
            .route(
                "/delta/stream",
                get({
                    let state = Arc::clone(&state);
                    move |Query(query): Query<StreamQuery>| {
                        let state = Arc::clone(&state);
                        let gone_payload = gone_payload.clone();
                        async move {
                            *state.observed_after_sequence.lock().unwrap() = query.after_sequence;
                            let value: serde_json::Value =
                                serde_json::from_str(&gone_payload).unwrap();
                            (StatusCode::GONE, Json(value)).into_response()
                        }
                    }
                }),
            );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (
            Url::parse(&format!("http://{addr}")).unwrap(),
            observed_after_sequence,
            handle,
        )
    }

    #[tokio::test]
    async fn applies_delta_block_to_replica() {
        let replica = std::sync::Arc::new(RwLock::new(Replica::default()));
        {
            let mut lock = replica.write().await;
            lock.apply_snapshot(Snapshot {
                version: 1,
                boot_id: None,
                auction_id: Some(0),
                sequence: 0,
                auction: crate::domain::competition::delta_replica::RawAuctionData {
                    orders: vec![],
                    prices: HashMap::new(),
                },
            })
            .unwrap();
        }

        let uid = valid_uid(1);

        let block = format!(
            "event: delta\ndata: \
             {{\"version\":1,\"fromSequence\":0,\"toSequence\":1,\"events\":[{{\"type\":\"\
             orderAdded\",\"order\":{}}}]}}\n\n",
            valid_order(&uid)
        );

        let outcome = handle_sse_block(&block, &replica, None).await.unwrap();
        assert!(matches!(outcome, BlockControl::Continue));

        let view = replica.read().await;
        assert_eq!(view.sequence(), 1);
        assert!(view.orders().contains_key(&uid));
    }

    #[tokio::test]
    async fn resync_event_requests_resnapshot() {
        let replica = std::sync::Arc::new(RwLock::new(Replica::default()));
        let block = "event: resync_required\ndata: lagged\n\n";

        let outcome = handle_sse_block(&block, &replica, None).await.unwrap();
        assert!(matches!(outcome, BlockControl::Resnapshot));
    }

    #[tokio::test]
    async fn unknown_event_is_ignored() {
        let replica = std::sync::Arc::new(RwLock::new(Replica::default()));
        let block = "event: keepalive\ndata: ok\n\n";

        let outcome = handle_sse_block(&block, &replica, None).await.unwrap();
        assert!(matches!(outcome, BlockControl::Continue));
    }

    #[tokio::test]
    async fn malformed_delta_payload_returns_error() {
        let replica = std::sync::Arc::new(RwLock::new(Replica::default()));
        let block = "event: delta\ndata: not-json\n\n";

        let err = handle_sse_block(block, &replica, None).await.unwrap_err();
        assert!(
            err.to_string().contains("expected ident")
                || err.to_string().contains("expected value")
        );
    }

    #[tokio::test]
    async fn unsupported_delta_version_requests_resnapshot() {
        let replica = std::sync::Arc::new(RwLock::new(Replica::default()));
        {
            let mut lock = replica.write().await;
            lock.apply_snapshot(Snapshot {
                version: 1,
                boot_id: None,
                auction_id: Some(0),
                sequence: 0,
                auction: crate::domain::competition::delta_replica::RawAuctionData {
                    orders: vec![],
                    prices: HashMap::new(),
                },
            })
            .unwrap();
        }

        let block = "event: delta\ndata: \
                     {\"version\":2,\"fromSequence\":0,\"toSequence\":1,\"events\":[]}\n\n";

        let outcome = handle_sse_block(&block, &replica, None).await.unwrap();
        assert!(matches!(outcome, BlockControl::Resnapshot));
    }

    #[tokio::test]
    async fn stale_delta_block_is_ignored() {
        let replica = std::sync::Arc::new(RwLock::new(Replica::default()));
        {
            let mut lock = replica.write().await;
            lock.apply_snapshot(Snapshot {
                version: 1,
                boot_id: None,
                auction_id: Some(0),
                sequence: 2,
                auction: crate::domain::competition::delta_replica::RawAuctionData {
                    orders: vec![],
                    prices: HashMap::new(),
                },
            })
            .unwrap();
        }

        let uid = valid_uid(1);

        let block = format!(
            "event: delta\ndata: \
             {{\"version\":1,\"fromSequence\":1,\"toSequence\":2,\"events\":[{{\"type\":\"\
             orderRemoved\",\"uid\":\"{uid}\"}}]}}\n\n"
        );

        let outcome = handle_sse_block(&block, &replica, None).await.unwrap();
        assert!(matches!(outcome, BlockControl::Continue));

        let view = replica.read().await;
        assert_eq!(view.sequence(), 2);
    }

    #[tokio::test]
    async fn multiline_delta_data_is_parsed() {
        let replica = std::sync::Arc::new(RwLock::new(Replica::default()));
        {
            let mut lock = replica.write().await;
            lock.apply_snapshot(Snapshot {
                version: 1,
                boot_id: None,
                auction_id: Some(0),
                sequence: 0,
                auction: crate::domain::competition::delta_replica::RawAuctionData {
                    orders: vec![],
                    prices: HashMap::new(),
                },
            })
            .unwrap();
        }

        let uid = valid_uid(2);

        let block = format!(
            "event: delta\ndata: {{\"version\":1,\"fromSequence\":0,\ndata: \
             \"toSequence\":1,\"events\":[{{\"type\":\"orderAdded\",\"order\":{}}}]}}\n\n",
            valid_order(&uid)
        );

        let outcome = handle_sse_block(&block, &replica, None).await.unwrap();
        assert!(matches!(outcome, BlockControl::Continue));

        let view = replica.read().await;
        assert_eq!(view.sequence(), 1);
        assert!(view.orders().contains_key(&uid));
    }

    #[tokio::test]
    async fn comments_and_unknown_fields_are_ignored() {
        let replica = std::sync::Arc::new(RwLock::new(Replica::default()));
        {
            let mut lock = replica.write().await;
            lock.apply_snapshot(Snapshot {
                version: 1,
                boot_id: None,
                auction_id: Some(0),
                sequence: 0,
                auction: crate::domain::competition::delta_replica::RawAuctionData {
                    orders: vec![],
                    prices: HashMap::new(),
                },
            })
            .unwrap();
        }

        let block = r#":keepalive
id: 9
retry: 5000
event: delta
data: {"version":1,"fromSequence":0,"toSequence":1,"events":[]}

"#;

        let outcome = handle_sse_block(block, &replica, None).await.unwrap();
        assert!(matches!(outcome, BlockControl::Continue));

        let view = replica.read().await;
        assert_eq!(view.sequence(), 1);
    }

    #[tokio::test]
    async fn compare_checksum_remote_ahead_allows_stream() {
        use axum::{Json, Router, response::IntoResponse, routing::get};

        // Server returns a checksum with sequence = 2
        let app = Router::new().route(
            "/delta/checksum",
            get(|| async move {
                let payload = serde_json::json!({
                    "version": 1u32,
                    "sequence": 2u64,
                    "orderUidHash": "a",
                    "priceHash": "b",
                    "orderContentHash": "c",
                });
                (axum::http::StatusCode::OK, Json(payload)).into_response()
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let base = Url::parse(&format!("http://{addr}")).unwrap();

        let local = ReplicaChecksum {
            sequence: 1,
            order_uid_hash: "x".to_string(),
            price_hash: "y".to_string(),
            order_content_hash: "z".to_string(),
        };

        let ok = compare_replica_checksum(&base, local).await.unwrap();
        assert!(ok, "remote ahead should not be treated as divergence");
    }

    #[tokio::test]
    async fn compare_checksum_local_ahead_triggers_resnapshot() {
        use axum::{Json, Router, response::IntoResponse, routing::get};

        // Server returns a checksum with sequence = 1
        let app = Router::new().route(
            "/delta/checksum",
            get(|| async move {
                let payload = serde_json::json!({
                    "version": 1u32,
                    "sequence": 1u64,
                    "orderUidHash": "a",
                    "priceHash": "b",
                    "orderContentHash": "c",
                });
                (axum::http::StatusCode::OK, Json(payload)).into_response()
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let base = Url::parse(&format!("http://{addr}")).unwrap();

        let local = ReplicaChecksum {
            sequence: 2,
            order_uid_hash: "x".to_string(),
            price_hash: "y".to_string(),
            order_content_hash: "z".to_string(),
        };

        let ok = compare_replica_checksum(&base, local).await.unwrap();
        assert!(!ok, "local ahead should be treated as divergence");
    }

    #[test]
    fn replica_preprocessing_flag_parsing() {
        assert!(!shared::env::flag_enabled(None, false));
        assert!(!shared::env::flag_enabled(Some("false"), false));
        assert!(!shared::env::flag_enabled(Some("0"), false));
        assert!(shared::env::flag_enabled(Some("true"), false));
        assert!(shared::env::flag_enabled(Some("on"), false));
    }

    // Verify the exported override works when compiled with the
    // `test-helpers` feature. This guards the regression described in the
    // Problem statement where e2e/test-helper callers could set the override
    // without `replica_preprocessing_enabled()` ever consulting it.
    #[cfg(feature = "test-helpers")]
    #[tokio::test]
    async fn replica_preprocessing_override_feature_flag_effective() {
        // Acquire the global replica test guard to avoid concurrent tests
        // mutating shared replica/global state while we run.
        let _guard = DeltaReplicaTestGuard::acquire().await;

        // Ensure we can set the override to true and have the getter reflect it.
        set_replica_preprocessing_override(Some(true));
        assert!(
            replica_preprocessing_enabled(),
            "override true should enable replica preprocessing"
        );

        // And clearing it to false flips the getter.
        set_replica_preprocessing_override(Some(false));
        assert!(
            !replica_preprocessing_enabled(),
            "override false should disable replica preprocessing"
        );

        set_replica_preprocessing_override(None);
        let _ = replica_preprocessing_enabled();
    }

    #[tokio::test]
    async fn fetch_snapshot_reads_bootstrap_state_from_http_endpoint() {
        let uid = valid_uid(1);
        let snapshot = serde_json::json!({
            "version": 1,
            "auctionId": 0,
            "sequence": 7,
            "auction": {
                "orders": [valid_order(&uid)],
                "prices": {"0x0101010101010101010101010101010101010101": "123"}
            }
        });
        let (base_url, _after_sequence, server) =
            spawn_delta_test_server(snapshot.to_string(), "{}".to_string()).await;
        let client = reqwest::Client::new();

        let fetched = fetch_snapshot(&client, &base_url).await.unwrap();

        assert_eq!(fetched.version, 1);
        assert_eq!(fetched.sequence, 7);
        assert_eq!(fetched.auction.orders.len(), 1);
        assert_eq!(fetched.auction.prices.len(), 1);

        server.abort();
    }

    #[tokio::test]
    async fn follow_stream_applies_delta_and_uses_after_sequence_query() {
        let uid = valid_uid(1);
        let snapshot = serde_json::json!({
            "version": 1,
            "auctionId": 0,
            "sequence": 3,
            "auction": {
                "orders": [valid_order(&uid)],
                "prices": {}
            }
        });
        let stream_delta = serde_json::json!({
            "version": 1,
            "fromSequence": 3,
            "toSequence": 4,
            "events": [{"type": "orderUpdated", "order": valid_order(&uid)}]
        });
        let (base_url, observed_after_sequence, server) =
            spawn_delta_test_server(snapshot.to_string(), stream_delta.to_string()).await;

        let replica = std::sync::Arc::new(RwLock::new(Replica::default()));
        {
            let mut lock = replica.write().await;
            lock.apply_snapshot(Snapshot {
                version: 1,
                boot_id: None,
                auction_id: Some(0),
                sequence: 3,
                auction: crate::domain::competition::delta_replica::RawAuctionData {
                    orders: vec![valid_order(&uid)],
                    prices: HashMap::new(),
                },
            })
            .unwrap();
        }

        let client = reqwest::Client::new();
        let err = follow_stream(&client, &base_url, &replica, Instant::now(), None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("delta stream closed"));

        let view = replica.read().await;
        assert_eq!(view.sequence(), 4);
        assert!(view.orders().contains_key(&uid));
        assert_eq!(*observed_after_sequence.lock().unwrap(), Some(3));

        server.abort();
    }

    #[tokio::test]
    async fn follow_stream_treats_410_gone_as_resnapshot() {
        // snapshot sequence is 5, but the stream responds with 410 Gone
        // indicating the server requires a resnapshot. The client must
        // return StreamControl::Resnapshot instead of retrying.
        let snapshot = serde_json::json!({
            "version": 1,
            "auctionId": 0,
            "sequence": 5,
            "auction": { "orders": [], "prices": {} }
        });

        // The stream endpoint will return 410 with a JSON body matching
        // the driver's DeltaStreamGonePayload shape.
        let gone_payload = serde_json::json!({
            "message": "resnapshot required",
            "latestSequence": 7u64,
            "oldestAvailable": serde_json::Value::Null
        })
        .to_string();

        let (base_url, _observed_after_sequence, server) =
            spawn_delta_test_server_gone(snapshot.to_string(), gone_payload).await;

        let replica = std::sync::Arc::new(RwLock::new(Replica::default()));
        {
            let mut lock = replica.write().await;
            lock.apply_snapshot(Snapshot {
                version: 1,
                boot_id: None,
                auction_id: Some(0),
                sequence: 5,
                auction: crate::domain::competition::delta_replica::RawAuctionData {
                    orders: vec![],
                    prices: HashMap::new(),
                },
            })
            .unwrap();
        }

        let client = reqwest::Client::new();
        let control = follow_stream(&client, &base_url, &replica, Instant::now(), None)
            .await
            .unwrap();
        assert!(matches!(control, StreamControl::Resnapshot));

        server.abort();
    }

    #[tokio::test]
    async fn follow_stream_requests_resnapshot_on_out_of_order_delta() {
        let uid = valid_uid(1);
        let snapshot = serde_json::json!({
            "version": 1,
            "auctionId": 0,
            "sequence": 10,
            "auction": {
                "orders": [valid_order(&uid)],
                "prices": {}
            }
        });
        let out_of_order_delta = serde_json::json!({
            "version": 1,
            "fromSequence": 9,
            "toSequence": 11,
            "events": []
        });
        let (base_url, _after_sequence, server) =
            spawn_delta_test_server(snapshot.to_string(), out_of_order_delta.to_string()).await;

        let replica = std::sync::Arc::new(RwLock::new(Replica::default()));
        {
            let mut lock = replica.write().await;
            lock.apply_snapshot(Snapshot {
                version: 1,
                boot_id: None,
                auction_id: Some(0),
                sequence: 10,
                auction: crate::domain::competition::delta_replica::RawAuctionData {
                    orders: vec![valid_order(&uid)],
                    prices: HashMap::new(),
                },
            })
            .unwrap();
        }

        let client = reqwest::Client::new();
        let control = follow_stream(&client, &base_url, &replica, Instant::now(), None)
            .await
            .unwrap();
        assert!(matches!(control, StreamControl::Resnapshot));

        let view = replica.read().await;
        assert_eq!(view.sequence(), 10);
        assert!(view.orders().contains_key(&uid));

        server.abort();
    }

    #[tokio::test]
    async fn bootstrap_then_streamed_deltas_converge_to_expected_state() {
        let token_a = alloy::primitives::Address::repeat_byte(0xAA);
        let token_b = alloy::primitives::Address::repeat_byte(0xBB);
        let token_c = alloy::primitives::Address::repeat_byte(0xCC);
        let uid_one = valid_uid(1);
        let uid_two = valid_uid(2);
        let uid_three = valid_uid(3);

        let snapshot = serde_json::json!({
            "version": 1,
            "auctionId": 0,
            "sequence": 2,
            "auction": {
                "orders": [
                    valid_order(&uid_one),
                    valid_order(&uid_two)
                ],
                "prices": {
                    token_a.to_string(): "100",
                    token_b.to_string(): "200"
                }
            }
        });
        let delta_one = serde_json::json!({
            "version": 1,
            "fromSequence": 2,
            "toSequence": 3,
            "events": [
                {"type": "orderUpdated", "order": valid_order(&uid_one)},
                {"type": "orderRemoved", "uid": uid_two},
                {"type": "orderAdded", "order": valid_order(&uid_three)},
                {"type": "priceChanged", "token": token_b, "price": null},
                {"type": "priceChanged", "token": token_c, "price": "300"}
            ]
        });
        let delta_two = serde_json::json!({
            "version": 1,
            "fromSequence": 3,
            "toSequence": 4,
            "events": [
                {"type": "orderUpdated", "order": valid_order(&uid_three)}
            ]
        });

        let (base_url, observed_after_sequence, server) = spawn_delta_test_server_with_events(
            snapshot.to_string(),
            vec![
                ("delta".to_string(), delta_one.to_string()),
                ("delta".to_string(), delta_two.to_string()),
            ],
        )
        .await;

        let client = reqwest::Client::new();
        let snapshot_payload = fetch_snapshot(&client, &base_url).await.unwrap();
        let replica = std::sync::Arc::new(RwLock::new(Replica::default()));
        {
            let mut lock = replica.write().await;
            lock.apply_snapshot(snapshot_payload).unwrap();
        }

        let err = follow_stream(&client, &base_url, &replica, Instant::now(), None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("delta stream closed"));

        let view = replica.read().await;
        assert_eq!(view.sequence(), 4);
        assert_eq!(*observed_after_sequence.lock().unwrap(), Some(2));

        assert_eq!(view.orders().len(), 2);
        assert!(view.orders().contains_key(&uid_one));
        assert!(view.orders().contains_key(&uid_three));
        assert!(!view.orders().contains_key(&uid_two));

        assert_eq!(view.prices().len(), 2);
        assert_eq!(view.prices().get(&token_a).unwrap(), "100");
        assert_eq!(view.prices().get(&token_c).unwrap(), "300");
        assert!(!view.prices().contains_key(&token_b));

        server.abort();
    }

    #[tokio::test]
    async fn replica_health_reports_state_and_age() {
        reset_delta_replica_for_tests();
        let replica = delta_replica();

        {
            let mut lock = replica.write().await;
            lock.apply_snapshot(Snapshot {
                version: 1,
                boot_id: None,
                auction_id: Some(0),
                sequence: 1,
                auction: crate::domain::competition::delta_replica::RawAuctionData {
                    orders: vec![valid_order(&valid_uid(1))],
                    prices: HashMap::new(),
                },
            })
            .unwrap();
        }

        let health = replica_health()
            .await
            .expect("replica health should be available");
        assert!(matches!(health.state, ReplicaState::Ready));
        assert_eq!(health.sequence, 1);
        assert_eq!(health.order_count, 1);
        assert!(health.last_update.is_some());
        assert!(health.last_update_age_seconds.is_some());
    }

    #[tokio::test]
    async fn replica_health_returns_none_on_checksum_mismatch() {
        // Ensure clean global replica state for the test.
        let _guard = DeltaReplicaTestGuard::acquire().await;

        // Start a small HTTP server that returns a checksum differing from
        // the local replica's checksum.
        use axum::{Json, Router, response::IntoResponse, routing::get};

        let app = Router::new().route(
            "/delta/checksum",
            get(|| async move {
                let payload = serde_json::json!({
                    "version": 1u32,
                    "sequence": 1u64,
                    "orderUidHash": "mismatch",
                    "priceHash": "mismatch",
                    "orderContentHash": "mismatch",
                });
                (axum::http::StatusCode::OK, Json(payload)).into_response()
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        // Point the delta sync base URL override at the test server.
        set_driver_delta_sync_autopilot_url_override(Some(
            Url::parse(&format!("http://{addr}")).unwrap(),
        ));

        // Apply a local snapshot so the replica has a checksum to compare.
        set_replica_snapshot_for_tests(Snapshot {
            version: 1,
            boot_id: None,
            auction_id: Some(0),
            sequence: 1,
            auction: crate::domain::competition::delta_replica::RawAuctionData {
                orders: vec![valid_order(&valid_uid(1))],
                prices: HashMap::new(),
            },
        })
        .await;

        // When the remote checksum differs, replica_health should report None
        // so the HTTP health route can return SERVICE_UNAVAILABLE.
        let health = replica_health().await;
        assert!(
            health.is_none(),
            "expected replica_health() to return None on checksum mismatch"
        );

        // Clean up server
        server.abort();
    }

    #[tokio::test]
    async fn delta_replica_test_guard_resets_preexisting_clone() {
        let replica = delta_replica();

        {
            let mut lock = replica.write().await;
            lock.apply_snapshot(Snapshot {
                version: 1,
                boot_id: None,
                auction_id: Some(7),
                sequence: 9,
                auction: crate::domain::competition::delta_replica::RawAuctionData {
                    orders: vec![valid_order(&valid_uid(1))],
                    prices: HashMap::new(),
                },
            })
            .unwrap();
        }

        let _guard = DeltaReplicaTestGuard::acquire().await;

        let view = replica.read().await;
        assert!(matches!(view.state(), ReplicaState::Uninitialized));
        assert_eq!(view.sequence(), 0);
        assert!(view.orders().is_empty());
        assert!(view.prices().is_empty());
    }

    #[tokio::test]
    async fn boot_id_mismatch_in_delta_requests_resnapshot() {
        let replica = std::sync::Arc::new(RwLock::new(Replica::default()));
        {
            let mut lock = replica.write().await;
            lock.apply_snapshot(Snapshot {
                version: 1,
                boot_id: Some("session-boot-id-A".to_string()),
                auction_id: Some(0),
                sequence: 0,
                auction: crate::domain::competition::delta_replica::RawAuctionData {
                    orders: vec![],
                    prices: HashMap::new(),
                },
            })
            .unwrap();
        }

        let block = r#"event: delta
data: {"version":1,"bootId":"session-boot-id-B","fromSequence":0,"toSequence":1,"events":[]}

"#;

        let outcome = handle_sse_block(block, &replica, Some("session-boot-id-A"))
            .await
            .unwrap();
        assert!(matches!(outcome, BlockControl::Resnapshot));
        assert_eq!(replica.read().await.sequence(), 0);
    }

    #[tokio::test]
    async fn matching_boot_id_allows_delta_application() {
        let replica = std::sync::Arc::new(RwLock::new(Replica::default()));
        {
            let mut lock = replica.write().await;
            lock.apply_snapshot(Snapshot {
                version: 1,
                boot_id: Some("session-boot-id-A".to_string()),
                auction_id: Some(0),
                sequence: 0,
                auction: crate::domain::competition::delta_replica::RawAuctionData {
                    orders: vec![],
                    prices: HashMap::new(),
                },
            })
            .unwrap();
        }

        let block = r#"event: delta
data: {"version":1,"bootId":"session-boot-id-A","fromSequence":0,"toSequence":1,"events":[]}

"#;

        let outcome = handle_sse_block(block, &replica, Some("session-boot-id-A"))
            .await
            .unwrap();
        assert!(matches!(outcome, BlockControl::Continue));
        assert_eq!(replica.read().await.sequence(), 1);
    }

    #[tokio::test]
    async fn missing_boot_id_in_envelope_does_not_block_application() {
        let replica = std::sync::Arc::new(RwLock::new(Replica::default()));
        {
            let mut lock = replica.write().await;
            lock.apply_snapshot(Snapshot {
                version: 1,
                boot_id: None,
                auction_id: Some(0),
                sequence: 0,
                auction: crate::domain::competition::delta_replica::RawAuctionData {
                    orders: vec![],
                    prices: HashMap::new(),
                },
            })
            .unwrap();
        }

        let block = r#"event: delta
data: {"version":1,"fromSequence":0,"toSequence":1,"events":[]}

"#;

        let outcome = handle_sse_block(block, &replica, None).await.unwrap();
        assert!(matches!(outcome, BlockControl::Continue));
        assert_eq!(replica.read().await.sequence(), 1);
    }

    #[tokio::test]
    async fn session_present_envelope_missing_boot_id_allows_application() {
        let replica = std::sync::Arc::new(RwLock::new(Replica::default()));
        {
            let mut lock = replica.write().await;
            lock.apply_snapshot(Snapshot {
                version: 1,
                boot_id: Some("session-boot-id-A".to_string()),
                auction_id: Some(0),
                sequence: 0,
                auction: crate::domain::competition::delta_replica::RawAuctionData {
                    orders: vec![],
                    prices: HashMap::new(),
                },
            })
            .unwrap();
        }

        let block = r#"event: delta
data: {"version":1,"fromSequence":0,"toSequence":1,"events":[]}

"#;

        let outcome = handle_sse_block(block, &replica, Some("session-boot-id-A"))
            .await
            .unwrap();
        assert!(matches!(outcome, BlockControl::Continue));
        assert_eq!(replica.read().await.sequence(), 1);
    }

    #[test]
    fn snapshot_requires_ready_state() {
        reset_delta_replica_for_tests();
        let mut replica = Replica::default();
        replica
            .apply_snapshot(Snapshot {
                version: 1,
                boot_id: None,
                auction_id: Some(0),
                sequence: 1,
                auction: crate::domain::competition::delta_replica::RawAuctionData {
                    orders: vec![valid_order(&valid_uid(1))],
                    prices: HashMap::new(),
                },
            })
            .unwrap();

        replica.set_state(ReplicaState::Syncing);
        assert!(snapshot_from_replica(&replica).is_none());

        replica.set_state(ReplicaState::Ready);
        assert!(snapshot_from_replica(&replica).is_some());
    }
}
