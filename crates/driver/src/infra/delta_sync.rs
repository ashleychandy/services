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
            atomic::{AtomicU8, Ordering},
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
const DEFAULT_REPLICA_KEY: &str = "__DEFAULT__";

// Backoff for resnapshot/retry loops to avoid tight reconnect storms.
struct Backoff {
    current: Duration,
    base: Duration,
    max: Duration,
}

impl Backoff {
    fn new(base: Duration, max: Duration) -> Self {
        Self { current: base, base, max }
    }

    fn next(&mut self) -> Duration {
        let now = self.current;
        // exponential step
        let doubled = if self.current >= self.max { self.max } else { self.current * 2 };
        self.current = std::cmp::min(doubled, self.max);
        // jitter in [0.8, 1.2)
        let factor: f64 = 0.8 + (rand::random::<f64>() * 0.4);
        Duration::from_secs_f64(now.as_secs_f64() * factor)
    }

    fn reset(&mut self) {
        self.current = self.base;
    }
}

/// Map of replica instances keyed by a per-replica identifier. The key is
/// typically the configured autopilot base URL (when present) so that a
/// single process can safely host multiple drivers talking to different
/// autopilots without sharing replica state.
static DELTA_REPLICA: OnceLock<StdRwLock<HashMap<String, Arc<RwLock<Replica>>>>> = OnceLock::new();

fn delta_replica_map() -> &'static StdRwLock<HashMap<String, Arc<RwLock<Replica>>>> {
    DELTA_REPLICA.get_or_init(|| {
        let mut m = HashMap::new();
        m.insert(
            DEFAULT_REPLICA_KEY.to_string(),
            Arc::new(RwLock::new(Replica::default())),
        );
        StdRwLock::new(m)
    })
}
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
#[cfg(not(any(test, feature = "test-helpers")))]
static DELTA_REPLICA_KEY: OnceLock<String> = OnceLock::new();
static BOOTSTRAP_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
#[cfg(any(test, feature = "test-helpers"))]
pub static REPLICA_PREPROCESSING_OVERRIDE: AtomicU8 = AtomicU8::new(0);
// Circuit breaker for consecutive thin-replica binding failures. This prevents
// repeated thin-replica attempts when the replica is persistently diverged
// (e.g. checksum or sequence mismatches).
const BINDING_FAILURE_CIRCUIT_BREAKER: u32 = 3;

// Per-replica circuit-breaker state keyed by replica identifier.
// Stores: (consecutive_failure_count, opened_at_timestamp_secs,
// opened_auction_id)
#[derive(Debug)]
struct BindingFailureState {
    count: u32,
    ts: u64,
    opened_auction: Option<u64>,
}

static BINDING_FAILURES: OnceLock<
    StdRwLock<HashMap<String, std::sync::Mutex<BindingFailureState>>>,
> = OnceLock::new();

fn binding_failures_map()
-> &'static StdRwLock<HashMap<String, std::sync::Mutex<BindingFailureState>>> {
    BINDING_FAILURES.get_or_init(|| {
        let mut m = HashMap::new();
        m.insert(
            DEFAULT_REPLICA_KEY.to_string(),
            std::sync::Mutex::new(BindingFailureState {
                count: 0,
                ts: 0,
                opened_auction: None,
            }),
        );
        StdRwLock::new(m)
    })
}

#[cfg(any(test, feature = "test-helpers"))]
fn reset_binding_failures_for_tests() {
    let mut guard = binding_failures_map()
        .write()
        .expect("binding failures lock poisoned");
    guard.clear();
    guard.insert(
        DEFAULT_REPLICA_KEY.to_string(),
        std::sync::Mutex::new(BindingFailureState {
            count: 0,
            ts: 0,
            opened_auction: None,
        }),
    );
}

#[cfg(any(test, feature = "test-helpers"))]
static BINDING_FAILURES_TEST_LOCK: LazyLock<std::sync::Mutex<()>> =
    LazyLock::new(|| std::sync::Mutex::new(()));

/// Global test guard to serialize binding-failure state across tests.
#[cfg(any(test, feature = "test-helpers"))]
pub struct BindingFailuresTestGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
}

#[cfg(any(test, feature = "test-helpers"))]
impl BindingFailuresTestGuard {
    pub fn acquire() -> Self {
        let lock = BINDING_FAILURES_TEST_LOCK
            .lock()
            .expect("binding failures test lock poisoned");

        reset_binding_failures_for_tests();
        Self { _lock: lock }
    }
}

#[cfg(any(test, feature = "test-helpers"))]
impl Drop for BindingFailuresTestGuard {
    fn drop(&mut self) {
        reset_binding_failures_for_tests();
    }
}

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
    record_binding_failure_for_auction(None);
}

pub fn record_binding_failure_for_auction(auction_id: Option<u64>) {
    let key = delta_replica_key();

    let mut guard = binding_failures_map()
        .write()
        .expect("binding failures lock poisoned");
    let entry = guard.entry(key).or_insert_with(|| {
        std::sync::Mutex::new(BindingFailureState {
            count: 0,
            ts: 0,
            opened_auction: None,
        })
    });
    if let Ok(mut state) = entry.lock() {
        state.count = state.count.saturating_add(1);
        if state.count >= BINDING_FAILURE_CIRCUIT_BREAKER {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            state.ts = now;
            state.opened_auction = auction_id;
        }
    }
}

pub fn record_binding_success() {
    let key = delta_replica_key();
    // Always reset under write guard so callers holding a read guard cannot
    // observe intermediate mutation.
    let mut guard = binding_failures_map()
        .write()
        .expect("binding failures lock poisoned");
    let entry = guard.entry(key).or_insert_with(|| {
        std::sync::Mutex::new(BindingFailureState {
            count: 0,
            ts: 0,
            opened_auction: None,
        })
    });
    if let Ok(mut state) = entry.lock() {
        state.count = 0;
        state.ts = 0;
        state.opened_auction = None;
    }
}

/// Pure query: evaluate whether the binding failure circuit is open for the
/// given optional `current_auction_id` without mutating stored state.
pub fn replica_binding_circuit_is_open_for_auction(current_auction_id: Option<u64>) -> bool {
    let key = delta_replica_key();

    // Pure query: read-only check of the per-replica circuit state. This
    // function does not mutate the stored state; callers that wish to
    // perform reset behaviour on auction mismatch or cooldown should call
    // `replica_binding_circuit_reset_if_mismatch_or_cooldown()` explicitly.
    let guard = binding_failures_map()
        .read()
        .expect("binding failures lock poisoned");
    let Some(mutex) = guard.get(&key) else {
        return false;
    };
    let Ok(state) = mutex.lock() else {
        return false;
    };

    if state.count < BINDING_FAILURE_CIRCUIT_BREAKER {
        return false;
    }

    if let Some(opened) = state.opened_auction {
        if let Some(current) = current_auction_id {
            return opened == current;
        }
    }

    // Timestamp fallback.
    if state.ts == 0 {
        return true;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now.saturating_sub(state.ts) >= binding_failure_cooldown_secs() {
        return false;
    }
    true
}

/// Mutating helper: reset the per-replica circuit when the provided
/// `current_auction_id` does not match the opened auction, or when the
/// cooldown window has expired. This mirrors the previous behaviour but is
/// intentionally separated from the pure-query function above so callers
/// can choose whether a read should also perform state mutation.
pub fn replica_binding_circuit_reset_if_mismatch_or_cooldown(current_auction_id: Option<u64>) {
    let key = delta_replica_key();

    // Keep check/reset in one critical section to avoid losing failures that
    // arrive between a read probe and a subsequent reset.
    let mut guard = binding_failures_map()
        .write()
        .expect("binding failures lock poisoned");
    let Some(mutex) = guard.get(&key) else {
        return;
    };
    if let Ok(mut state) = mutex.lock() {
        if state.count < BINDING_FAILURE_CIRCUIT_BREAKER {
            return;
        }

        if let Some(opened) = state.opened_auction {
            if let Some(current) = current_auction_id {
                if opened != current {
                    // Auction mismatch: reset and indicate not open.
                    state.count = 0;
                    state.ts = 0;
                    state.opened_auction = None;
                    return;
                }
            }
        }

        // Timestamp fallback.
        if state.ts == 0 {
            return;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now.saturating_sub(state.ts) >= binding_failure_cooldown_secs() {
            state.count = 0;
            state.ts = 0;
            state.opened_auction = None;
            return;
        }
    }
}

/// Backwards-compatible wrapper retaining the original function name but
/// implemented as a pure query (no mutation). Callers that relied on the
/// previous implicit-reset behaviour must call
/// `replica_binding_circuit_reset_if_mismatch_or_cooldown()` explicitly.
pub fn replica_binding_circuit_open_for_auction(current_auction_id: Option<u64>) -> bool {
    replica_binding_circuit_is_open_for_auction(current_auction_id)
}

pub fn replica_binding_circuit_open() -> bool {
    replica_binding_circuit_open_for_auction(None)
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
    pub(crate) surplus_capturing_jit_order_owners: Vec<alloy::primitives::Address>,
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
            // Some(true): fallthrough to continue spawning.
        } else if !shared::env::flag_enabled(
            std::env::var("DRIVER_DELTA_SYNC_ENABLED").ok().as_deref(),
            true,
        ) {
            tracing::warn!("driver delta sync disabled via DRIVER_DELTA_SYNC_ENABLED");
            return None;
        }
    }

    #[cfg(not(any(test, feature = "test-helpers")))]
    if !shared::env::flag_enabled(
        std::env::var("DRIVER_DELTA_SYNC_ENABLED").ok().as_deref(),
        true,
    ) {
        tracing::warn!("driver delta sync disabled via DRIVER_DELTA_SYNC_ENABLED");
        return None;
    }

    let Some(base) = delta_sync_base_url_from_env() else {
        return None;
    };

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
    let active_key = delta_replica_key();
    let mut guard = match delta_replica_map().write() {
        Ok(g) => g,
        Err(poison) => poison.into_inner(),
    };
    guard.clear();
    // Always ensure default mapping exists for tests.
    guard.insert(
        DEFAULT_REPLICA_KEY.to_string(),
        Arc::new(RwLock::new(Replica::default())),
    );
    if active_key != DEFAULT_REPLICA_KEY {
        guard.insert(active_key, Arc::new(RwLock::new(Replica::default())));
    }
}

#[cfg(any(test, feature = "test-helpers"))]
pub async fn reset_delta_replica_for_tests_async() {
    if let Ok(guard) = delta_replica_map().read() {
        // Try to reset the default-key replica in-place to avoid replacing
        // the global map. Clone the Arc and release the read guard quickly
        // so we don't hold the std::sync::RwLock across await points.
        let key = delta_replica_key();
        if let Some(replica_arc) = guard.get(&key) {
            let replica_arc = replica_arc.clone();
            drop(guard);

            let start = Instant::now();
            while start.elapsed() < Duration::from_millis(500) {
                if let Ok(mut inner) = replica_arc.try_write() {
                    *inner = Replica::default();
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }

            if let Ok(mut global_guard) = delta_replica_map().try_write() {
                global_guard.insert(key.clone(), Arc::new(RwLock::new(Replica::default())));
                return;
            }

            let new_arc = Arc::new(RwLock::new(Replica::default()));
            let _ = tokio::task::spawn_blocking(move || {
                let mut guard = match delta_replica_map().write() {
                    Ok(g) => g,
                    Err(poison) => poison.into_inner(),
                };
                guard.insert(key, new_arc);
            })
            .await;
            return;
        }
    }

    let active_key = delta_replica_key();
    let mut guard = match delta_replica_map().write() {
        Ok(g) => g,
        Err(poison) => poison.into_inner(),
    };
    guard.clear();
    guard.insert(
        DEFAULT_REPLICA_KEY.to_string(),
        Arc::new(RwLock::new(Replica::default())),
    );
    if active_key != DEFAULT_REPLICA_KEY {
        guard.insert(active_key, Arc::new(RwLock::new(Replica::default())));
    }
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
            chain_id: None,
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
    key: String,
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
        let key = delta_replica_key();
        let key_for_thread = key.clone();
        let handle = tokio::task::spawn_blocking(move || {
            // Try to obtain a read guard on the global StdRwLock to access
            // the inner Arc without blocking writers.
            let guard = match delta_replica_map().read() {
                Ok(g) => g,
                Err(poison) => poison.into_inner(),
            };
            let replica_arc = guard
                .get(&key_for_thread)
                .cloned()
                .unwrap_or_else(|| Arc::new(RwLock::new(Replica::default())));

            // Acquire the inner tokio RwLock in blocking mode and reset in-place.
            let mut inner = replica_arc.blocking_write();
            *inner = Replica::default();

            drop(inner);

            replica_arc
        });
        let replica = handle.await.expect("replica reset thread panicked");
        // Also reset binding-failure state to keep test state isolated.
        reset_binding_failures_for_tests();

        Self {
            _lock: Some(lock),
            replica,
            key,
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
            // Replace the global map entry for the replica key we recorded
            // at acquisition time. This avoids the surprising fallback of
            // inserting under the default key when the map was mutated
            // concurrently.
            if let Ok(mut global_guard) = delta_replica_map().try_write() {
                global_guard.insert(self.key.clone(), Arc::new(RwLock::new(Replica::default())));
            } else {
                let key = self.key.clone();
                let handle = std::thread::spawn(move || {
                    let mut guard = match delta_replica_map().write() {
                        Ok(g) => g,
                        Err(poison) => poison.into_inner(),
                    };
                    guard.insert(key, Arc::new(RwLock::new(Replica::default())));
                });
                if let Err(e) = handle.join() {
                    tracing::error!(?e, "delta replica reset thread panicked in fallback");
                }
            }
        }

        if let Some(lock) = self._lock.take() {
            drop(lock);
        }
        // Also reset binding-failure state to keep test state isolated on
        // teardown. This mirrors the acquire-time reset and ensures tests
        // that only use `DeltaReplicaTestGuard` do not leak a tripped
        // circuit into subsequent tests.
        reset_binding_failures_for_tests();
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
        surplus_capturing_jit_order_owners: replica.surplus_capturing_jit_order_owners().clone(),
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
                // Replica checksum matches remote; ensure the replica is marked
                // Ready so health checks and consumers can begin serving thin
                // requests again, even if it was previously Resyncing.
                let replica_arc = delta_replica();
                let mut lock = replica_arc.write().await;
                lock.set_state(ReplicaState::Ready);
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
                // On errors (for example network partition or request timeout),
                // treat the replica as degraded: stop serving thin requests by
                // marking the replica as `Syncing` and report unhealthy so
                // health endpoints and consumers observe the degraded state.
                tracing::warn!(
                    ?err,
                    "delta replica checksum comparison failed; marking replica degraded"
                );
                let replica_arc = delta_replica();
                let mut lock = replica_arc.write().await;
                lock.set_state(ReplicaState::Syncing);
                return None;
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
    // Backoff controls retry behavior when snapshot/stream fail repeatedly.
    let mut backoff = Backoff::new(Duration::from_millis(200), Duration::from_secs(5));
    loop {
        {
            let mut lock = replica.write().await;
            lock.set_state(ReplicaState::Syncing);
        }
        // Fetch snapshot and capture session boot_id and chain_id for validation of
        // live envelopes.
        let (session_boot_id, session_chain_id) = match fetch_snapshot(&snapshot_client, &base_url).await {
            Ok(snapshot) => {
                let boot_id = snapshot.boot_id.clone();
                let chain_id = snapshot.chain_id;
                let applied = {
                    let mut lock = replica.write().await;
                    lock.apply_snapshot(snapshot)
                };
                if let Err(err) = applied {
                    tracing::warn!(?err, "delta sync snapshot apply failed; retrying");
                    tokio::time::sleep(backoff.next()).await;
                    continue;
                }
                // Snapshot applied successfully; clear backoff so subsequent
                // retries start from base delay.
                backoff.reset();
                let view = replica.read().await;
                tracing::info!(
                    sequence = view.sequence(),
                    orders = view.orders().len(),
                    prices = view.prices().len(),
                    "delta sync snapshot applied"
                );
                (boot_id, chain_id)
            }
            Err(err) => {
                {
                    let mut lock = replica.write().await;
                    lock.set_state(ReplicaState::Resyncing);
                }
                tracing::warn!(?err, "delta sync snapshot fetch failed; retrying");
                tokio::time::sleep(backoff.next()).await;
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
                session_chain_id,
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
    session_chain_id: Option<u64>,
) -> anyhow::Result<StreamControl> {
    let url = shared::url::join(base_url, "delta/stream");
    let after_sequence = replica.read().await.sequence();

    let response = apply_delta_sync_auth(client.get(url))
        .query(&[("after_sequence", after_sequence)])
        .send()
        .await?;

    if response.status() == StatusCode::GONE {
        // Autopilot signals that a resnapshot is required for the requested
        // sequence. Respect the diagnostic payload when present and request
        // a resnapshot so the replica can make forward progress.
        let payload = response.json::<DeltaStreamGonePayload>().await.ok();
        if let Some(ref payload) = payload {
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
        }

        replica.write().await.set_state(ReplicaState::Resyncing);
        tracing::warn!(
            after_sequence,
            message = payload.as_ref().and_then(|p| p.message.as_deref()).unwrap_or("")
        );
        return Ok(StreamControl::Resnapshot);
    }

    let mut response = response.error_for_status()?;

    let mut buffer = String::new();
    let max_staleness = delta_replica_max_staleness();
    let resnapshot_interval = delta_replica_resnapshot_interval();

    let safety_sleep = tokio::time::sleep(Duration::from_secs(5));
    tokio::pin!(safety_sleep);

    loop {
        tokio::select! {
            chunk = response.chunk() => {
                let chunk = chunk?;
                match chunk {
                    Some(bytes) => {
                        let text = String::from_utf8_lossy(&bytes).into_owned();
                        buffer.push_str(&text);

                        // Normalize CRLF boundaries and stray CRs.
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

                            match handle_sse_block(&block, replica, session_boot_id, session_chain_id).await? {
                                BlockControl::Continue => {}
                                BlockControl::Resnapshot => return Ok(StreamControl::Resnapshot),
                            }
                        }
                    }
                    None => break,
                }
            }
            _ = &mut safety_sleep => {
                // Periodic health checks while the stream is idle.
                if delta_sync_checksum_enabled() {
                    if let Some(local_checksum) = replica.read().await.checksum() {
                        match compare_replica_checksum(base_url, local_checksum).await {
                            Ok(true) => {}
                            Ok(false) => {
                                replica.write().await.set_state(ReplicaState::Resyncing);
                                tracing::warn!("delta replica checksum mismatch; resnapshot required");
                                return Ok(StreamControl::Resnapshot);
                            }
                            Err(err) => {
                                tracing::warn!(?err, "delta replica checksum comparison failed; marking replica degraded");
                                replica.write().await.set_state(ReplicaState::Syncing);
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
    session_chain_id: Option<u64>,
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
                    // If both snapshot and envelope include chain identifiers,
                    // only trigger a resnapshot when the chain ids match. This
                    // avoids cross-chain resnapshot when a different chain's
                    // stream restarted but the autopilot's global boot id
                    // changed.
                    match (session_chain_id, envelope.chain_id) {
                        (Some(s_chain), Some(e_chain)) => {
                            if s_chain == e_chain {
                                replica.write().await.set_state(ReplicaState::Resyncing);
                                tracing::warn!(
                                    session_boot_id = %session,
                                    received_boot_id = %received,
                                    session_chain_id = s_chain,
                                    envelope_chain_id = ?e_chain,
                                    "autopilot boot ID changed for this chain; forcing resnapshot"
                                );
                                return Ok(BlockControl::Resnapshot);
                            } else {
                                tracing::warn!(
                                    session_boot_id = %session,
                                    received_boot_id = %received,
                                    session_chain_id = s_chain,
                                    envelope_chain_id = ?e_chain,
                                    "autopilot boot ID changed for a different chain; ignoring"
                                );
                                // Don't apply deltas from a different chain – skip.
                                return Ok(BlockControl::Continue);
                            }
                        }
                        // Missing chain id information: fall back to the
                        // conservative (safe) behaviour of forcing a resnapshot.
                        _ => {
                            replica.write().await.set_state(ReplicaState::Resyncing);
                            tracing::warn!(
                                session_boot_id = %session,
                                received_boot_id = %received,
                                "autopilot boot ID changed; forcing resnapshot"
                            );
                            return Ok(BlockControl::Resnapshot);
                        }
                    }
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeltaChecksumResponse {
    #[serde(default)]
    version: Option<u64>,
    sequence: u64,
    order_uid_hash: String,
    price_hash: String,
    order_content_hash: String,
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
        // Compare core binding checks (uids + prices). The `order_content_hash`
        // is intentionally excluded because its inputs (serialization and any
        // fee-normalization applied by autopilot) may differ from the raw
        // wire JSON the driver stores; comparing it here can create false
        // positives when both sides are otherwise consistent. Re-enable if
        // serialization/fee-normalization rules are guaranteed to match.
        if local_checksum.order_uid_hash != remote.order_uid_hash
            || local_checksum.price_hash != remote.price_hash
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
    // Determine per-replica key (typically autopilot base URL) and return
    // the corresponding replica `Arc<RwLock<Replica>>`, creating a new
    // default-initialized replica for the key if needed.
    let key = delta_replica_key();

    // Fast path: try read lock and return clone if present.
    {
        let guard = delta_replica_map()
            .read()
            .expect("delta replica lock poisoned");
        if let Some(replica) = guard.get(&key) {
            return replica.clone();
        }
    }

    // Missing entry: create under write lock and return.
    let mut guard = delta_replica_map()
        .write()
        .expect("delta replica lock poisoned");
    guard
        .entry(key)
        .or_insert_with(|| Arc::new(RwLock::new(Replica::default())))
        .clone()
}

fn delta_replica_key() -> String {
    // In test and `test-helpers` builds we intentionally avoid caching the
    // replica key so runtime test overrides (env-based or explicit test
    // helpers) are immediately observed. In production builds we cache the
    // computed key in `DELTA_REPLICA_KEY` (a `OnceLock`) to avoid repeated
    // environment lookups on hot paths.
    #[cfg(any(test, feature = "test-helpers"))]
    {
        if let Some(url) = delta_sync_base_url_from_env() {
            return url.as_str().to_string();
        }
        if let Ok(custom) = std::env::var("DRIVER_DELTA_SYNC_REPLICA_KEY") {
            if !custom.is_empty() {
                return custom;
            }
        }
        return DEFAULT_REPLICA_KEY.to_string();
    }

    #[cfg(not(any(test, feature = "test-helpers")))]
    {
        DELTA_REPLICA_KEY
            .get_or_init(|| {
                if let Some(url) = delta_sync_base_url_from_env() {
                    return url.as_str().to_string();
                }
                if let Ok(custom) = std::env::var("DRIVER_DELTA_SYNC_REPLICA_KEY") {
                    if !custom.is_empty() {
                        return custom;
                    }
                }
                DEFAULT_REPLICA_KEY.to_string()
            })
            .clone()
    }
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
            "signature": format!("0x{}", hex::encode([0u8; 65])),
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
                chain_id: None,
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

        let outcome = handle_sse_block(&block, &replica, None, None)
            .await
            .unwrap();
        assert!(matches!(outcome, BlockControl::Continue));

        let view = replica.read().await;
        assert_eq!(view.sequence(), 1);
        assert!(view.orders().contains_key(&uid));
    }

    #[tokio::test]
    async fn resync_event_requests_resnapshot() {
        let replica = std::sync::Arc::new(RwLock::new(Replica::default()));
        let block = "event: resync_required\ndata: lagged\n\n";

        let outcome = handle_sse_block(&block, &replica, None, None)
            .await
            .unwrap();
        assert!(matches!(outcome, BlockControl::Resnapshot));
    }

    #[tokio::test]
    async fn unknown_event_is_ignored() {
        let replica = std::sync::Arc::new(RwLock::new(Replica::default()));
        let block = "event: keepalive\ndata: ok\n\n";

        let outcome = handle_sse_block(&block, &replica, None, None)
            .await
            .unwrap();
        assert!(matches!(outcome, BlockControl::Continue));
    }

    #[tokio::test]
    async fn malformed_delta_payload_returns_error() {
        let replica = std::sync::Arc::new(RwLock::new(Replica::default()));
        let block = "event: delta\ndata: not-json\n\n";

        let err = handle_sse_block(block, &replica, None, None)
            .await
            .unwrap_err();
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
                chain_id: None,
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

        let outcome = handle_sse_block(&block, &replica, None, None)
            .await
            .unwrap();
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
                chain_id: None,
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

        let outcome = handle_sse_block(&block, &replica, None, None)
            .await
            .unwrap();
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
                chain_id: None,
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

        let outcome = handle_sse_block(&block, &replica, None, None)
            .await
            .unwrap();
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
                chain_id: None,
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

        let outcome = handle_sse_block(block, &replica, None, None).await.unwrap();
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
                chain_id: None,
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
        let err = follow_stream(&client, &base_url, &replica, Instant::now(), None, None)
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
                chain_id: None,
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
        let control = follow_stream(&client, &base_url, &replica, Instant::now(), None, None)
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
                chain_id: None,
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
        let control = follow_stream(&client, &base_url, &replica, Instant::now(), None, None)
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

        let err = follow_stream(&client, &base_url, &replica, Instant::now(), None, None)
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
                chain_id: None,
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
            chain_id: None,
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
    async fn replica_health_returns_none_on_checksum_error() {
        // Ensure clean global replica state for the test.
        let _guard = DeltaReplicaTestGuard::acquire().await;

        use axum::{Router, routing::get};

        // Server returns 500 to simulate an error (e.g., network issue or
        // server-side failure) which should be treated as degraded.
        let app = Router::new().route(
            "/delta/checksum",
            get(|| async move { (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "err") }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        // Point the delta sync base URL override at the test server.
        set_driver_delta_sync_autopilot_url_override(Some(
            Url::parse(&format!("http://{addr}")).unwrap(),
        ));
        set_driver_delta_sync_enabled_override(Some(true));

        // Apply a local snapshot so the replica has a checksum to compare.
        set_replica_snapshot_for_tests(Snapshot {
            version: 1,
            boot_id: None,
            chain_id: None,
            auction_id: Some(0),
            sequence: 1,
            auction: crate::domain::competition::delta_replica::RawAuctionData {
                orders: vec![valid_order(&valid_uid(1))],
                prices: HashMap::new(),
            },
        })
        .await;

        // When the remote checksum endpoint errors, replica_health should
        // report None and the replica should be marked degraded (Syncing).
        let health = replica_health().await;
        assert!(
            health.is_none(),
            "expected replica_health() to return None on checksum error"
        );

        let state = replica_state().await;
        assert!(matches!(state, Some(ReplicaState::Syncing)));

        // Clean up server
        server.abort();
    }

    #[test]
    fn binding_circuit_opens_per_auction() {
        let _guard = BindingFailuresTestGuard::acquire();

        // Trip the circuit for auction id 1.
        record_binding_failure_for_auction(Some(1));
        record_binding_failure_for_auction(Some(1));
        record_binding_failure_for_auction(Some(1));

        // Circuit should be open for auction 1 (pure query).
        assert!(replica_binding_circuit_is_open_for_auction(Some(1)));

        // For a different auction id the circuit must be treated as closed
        // for that auction (pure query remains read-only).
        assert!(!replica_binding_circuit_is_open_for_auction(Some(2)));

        // Explicitly reset the circuit due to auction-id mismatch (this
        // mirrors the previous implicit behaviour, but the reset is now
        // explicit to avoid surprising side-effects from a read).
        replica_binding_circuit_reset_if_mismatch_or_cooldown(Some(2));

        // After reset, circuit should not be open for auction 1 either.
        assert!(!replica_binding_circuit_is_open_for_auction(Some(1)));
    }

    #[tokio::test]
    async fn delta_replica_test_guard_resets_preexisting_clone() {
        let replica = delta_replica();

        {
            let mut lock = replica.write().await;
            lock.apply_snapshot(Snapshot {
                version: 1,
                boot_id: None,
                chain_id: None,
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
    async fn delta_replica_test_guard_replaces_map_entry_when_old_arc_locked() {
        // Ensure clean starting state.
        reset_delta_replica_for_tests();

        // Acquire the test guard which records the key and holds the mutex.
        let guard = DeltaReplicaTestGuard::acquire().await;

        // Determine the recorded key and capture the Arc that was active at
        // acquisition time.
        let key = delta_replica_key();
        let old_arc = {
            let map = delta_replica_map()
                .read()
                .expect("delta replica lock poisoned");
            map.get(&key).cloned().expect("replica arc present")
        };

        // Spawn a thread that takes a blocking write lock on the old Arc and
        // holds it until signalled. This ensures `try_write()` in `Drop`
        // cannot succeed, forcing the replacement fallback path.
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let old_arc_clone = old_arc.clone();
        let handle = std::thread::spawn(move || {
            let _write_guard = old_arc_clone.blocking_write();
            // Notify the main thread that the write lock is held.
            let _ = ready_tx.send(());
            // Wait until main test signals to release the write lock.
            let _ = rx.recv();
        });

        // Ensure the spawned thread holds the write lock before proceeding so
        // the `Drop` fast path cannot acquire the lock.
        let _ = ready_rx.recv().expect("thread ready");

        // Concurrently replace the global map entry for the recorded key with
        // a non-default replica so we can detect whether `Drop` overwrote it.
        let mut special = Replica::default();
        special
            .apply_snapshot(Snapshot {
                version: 1,
                boot_id: None,
                chain_id: None,
                auction_id: Some(0),
                sequence: 999,
                auction: crate::domain::competition::delta_replica::RawAuctionData {
                    orders: vec![],
                    prices: HashMap::new(),
                },
            })
            .expect("apply snapshot");
        let special_arc = Arc::new(RwLock::new(special));
        {
            let mut map = delta_replica_map()
                .write()
                .expect("delta replica lock poisoned");
            map.insert(key.clone(), special_arc.clone());
        }

        // Drop the guard to trigger the `Drop` implementation path. Because
        // the old Arc is write-locked in another thread, the in-place reset
        // will fail and the Drop fallback should replace the map entry by
        // the originally recorded key.
        drop(guard);

        // Allow the spawned thread to release its write lock and join.
        tx.send(()).expect("signal thread");
        handle.join().expect("thread join");

        // Verify that the map entry for the recorded key was replaced by
        // `Drop` (i.e., it is the default replica, not the special one we
        // inserted earlier with sequence = 999).
        let map = delta_replica_map()
            .read()
            .expect("delta replica lock poisoned");
        let current_arc = map.get(&key).expect("entry missing").clone();
        let current = current_arc.read().await;
        assert_eq!(
            current.sequence(),
            0,
            "Drop should have replaced the map entry with a default replica"
        );
        // Also ensure the special arc we inserted is not the same instance
        // still present under the recorded key — Drop must have inserted a
        // fresh default replica instead.
        assert!(
            !Arc::ptr_eq(&current_arc, &special_arc),
            "Drop must have inserted a new arc, not left the special one in place"
        );
    }

    #[tokio::test]
    async fn boot_id_mismatch_in_delta_requests_resnapshot() {
        let replica = std::sync::Arc::new(RwLock::new(Replica::default()));
        {
            let mut lock = replica.write().await;
            lock.apply_snapshot(Snapshot {
                version: 1,
                boot_id: Some("session-boot-id-A".to_string()),
                chain_id: None,
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

        let outcome = handle_sse_block(block, &replica, Some("session-boot-id-A"), None)
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
                chain_id: None,
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

        let outcome = handle_sse_block(block, &replica, Some("session-boot-id-A"), None)
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
                chain_id: None,
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

        let outcome = handle_sse_block(block, &replica, None, None).await.unwrap();
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
                chain_id: None,
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

        let outcome = handle_sse_block(block, &replica, Some("session-boot-id-A"), None)
            .await
            .unwrap();
        assert!(matches!(outcome, BlockControl::Continue));
        assert_eq!(replica.read().await.sequence(), 1);
    }

    #[tokio::test]
    async fn boot_id_mismatch_same_chain_requests_resnapshot() {
        let replica = std::sync::Arc::new(RwLock::new(Replica::default()));
        {
            let mut lock = replica.write().await;
            lock.apply_snapshot(Snapshot {
                version: 1,
                boot_id: Some("session-boot-id-A".to_string()),
                chain_id: None,
                auction_id: Some(0),
                sequence: 0,
                auction: crate::domain::competition::delta_replica::RawAuctionData {
                    orders: vec![],
                    prices: HashMap::new(),
                },
            })
            .unwrap();
        }

        // Envelope from a restarted autopilot for the same chain id should
        // trigger a resnapshot when boot ids differ.
        let block = r#"event: delta
data: {"version":1,"bootId":"session-boot-id-B","chainId":100,"fromSequence":0,"toSequence":1,"events":[]}

"#;

        let outcome = handle_sse_block(block, &replica, Some("session-boot-id-A"), Some(100))
            .await
            .unwrap();
        assert!(matches!(outcome, BlockControl::Resnapshot));
        assert_eq!(replica.read().await.sequence(), 0);
    }

    #[tokio::test]
    async fn boot_id_mismatch_different_chain_is_ignored_and_applies_delta() {
        let replica = std::sync::Arc::new(RwLock::new(Replica::default()));
        {
            let mut lock = replica.write().await;
            lock.apply_snapshot(Snapshot {
                version: 1,
                boot_id: Some("session-boot-id-A".to_string()),
                chain_id: None,
                auction_id: Some(0),
                sequence: 0,
                auction: crate::domain::competition::delta_replica::RawAuctionData {
                    orders: vec![],
                    prices: HashMap::new(),
                },
            })
            .unwrap();
        }

        // Envelope boot id differs but for a different chain -> should be
        // ignored. The implementation skips applying deltas from a different
        // chain to avoid cross-chain contamination, so the sequence remains
        // unchanged.
        let block = r#"event: delta
data: {"version":1,"bootId":"session-boot-id-B","chainId":200,"fromSequence":0,"toSequence":1,"events":[]}

"#;

        let outcome = handle_sse_block(block, &replica, Some("session-boot-id-A"), Some(100))
            .await
            .unwrap();
        assert!(matches!(outcome, BlockControl::Continue));
        // We skip applying deltas from a different chain; sequence should
        // remain at 0.
        assert_eq!(replica.read().await.sequence(), 0);
    }

    #[tokio::test]
    async fn boot_id_mismatch_missing_chain_info_falls_back_to_resnapshot() {
        let replica = std::sync::Arc::new(RwLock::new(Replica::default()));
        {
            let mut lock = replica.write().await;
            lock.apply_snapshot(Snapshot {
                version: 1,
                boot_id: Some("session-boot-id-A".to_string()),
                chain_id: None,
                auction_id: Some(0),
                sequence: 0,
                auction: crate::domain::competition::delta_replica::RawAuctionData {
                    orders: vec![],
                    prices: HashMap::new(),
                },
            })
            .unwrap();
        }

        // Envelope missing chainId while session provides one -> conservative
        // fallback should force a resnapshot.
        let block_missing_chain = r#"event: delta
data: {"version":1,"bootId":"session-boot-id-B","fromSequence":0,"toSequence":1,"events":[]}

"#;

        let outcome = handle_sse_block(
            block_missing_chain,
            &replica,
            Some("session-boot-id-A"),
            Some(100),
        )
        .await
        .unwrap();
        assert!(matches!(outcome, BlockControl::Resnapshot));
        assert_eq!(replica.read().await.sequence(), 0);

        // Session missing chain info but envelope includes it -> also fallback
        // to resnapshot.
        let block_with_chain = r#"event: delta
data: {"version":1,"bootId":"session-boot-id-B","chainId":100,"fromSequence":0,"toSequence":1,"events":[]}

"#;
        let outcome2 =
            handle_sse_block(block_with_chain, &replica, Some("session-boot-id-A"), None)
                .await
                .unwrap();
        assert!(matches!(outcome2, BlockControl::Resnapshot));
        assert_eq!(replica.read().await.sequence(), 0);
    }

    #[test]
    fn snapshot_requires_ready_state() {
        reset_delta_replica_for_tests();
        let mut replica = Replica::default();
        replica
            .apply_snapshot(Snapshot {
                version: 1,
                boot_id: None,
                chain_id: None,
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
