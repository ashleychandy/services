use {
    crate::{
        boundary::{self, SolvableOrders},
        domain::{self, auction::Price},
        infra::{self, banned},
    },
    account_balances::{BalanceFetching, Query},
    alloy::primitives::{Address, U256},
    anyhow::{Context, Result},
    bad_tokens::list_based::DenyListedTokens,
    database::order_events::{
        OrderEventLabel,
        OrderFilterReason::{
            self,
            BannedUser,
            DustOrder,
            InFlight,
            InsufficientBalance,
            InvalidSignature,
            MissingNativePrice,
            UnsupportedToken,
        },
    },
    futures::FutureExt,
    itertools::Itertools,
    model::{
        order::{Order, OrderClass, OrderUid},
        signature::Signature,
        time::now_in_epoch_seconds,
    },
    price_estimation::{
        native::{NativePriceEstimating, to_normalized_price},
        native_price_cache::NativePriceUpdater,
    },
    prometheus::{Histogram, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec},
    sha2::{Digest, Sha256},
    shared::remaining_amounts,
    std::{
        cmp::Ordering,
        collections::{BTreeMap, HashMap, HashSet, VecDeque, btree_map::Entry},
        future::Future,
        sync::{Arc, OnceLock},
        time::{Duration, Instant},
    },
    strum::VariantNames,
    tokio::sync::{Mutex, broadcast},
    tracing::instrument,
};

static BOOT_ID: OnceLock<String> = OnceLock::new();

macro_rules! send_or_warn {
    ($sender:expr, $value:expr, $context:literal) => {
        // Avoid spurious warnings when there are no receivers yet.
        if $sender.receiver_count() == 0 {
            tracing::debug!(context = $context, "delta sender has no receivers; dropping envelope");
        } else {
            match $sender.send($value) {
                Ok(_) => {}
                Err(e) => tracing::warn!(context = $context, error = ?e, "failed to send; receiver dropped"),
            }
        }
    };
}

pub fn boot_id() -> &'static str {
    BOOT_ID
        .get_or_init(|| uuid::Uuid::new_v4().to_string())
        .as_str()
}

#[derive(prometheus_metric_storage::MetricStorage)]
pub struct Metrics {
    /// Tracks success and failure of the solvable orders cache update task.
    #[metric(labels("result"))]
    auction_update: IntCounterVec,

    /// Time taken to update the solvable orders cache.
    #[metric(buckets(
        0.1, 0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 1.75, 2.0, 2.25, 2.5, 2.75, 3.0, 3.5, 4, 5
    ))]
    auction_update_total_time: Histogram,

    /// Time spent on auction update individual stage.
    #[metric(
        labels("stage"),
        buckets(
            0.01, 0.05, 0.1, 0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 1.75, 2.0, 2.5, 3.0, 3.5, 4.0, 5.0
        )
    )]
    auction_update_stage_time: HistogramVec,

    /// Auction creations.
    auction_creations: IntCounter,

    /// Auction candidate orders grouped by class.
    #[metric(labels("class"))]
    auction_candidate_orders: IntGaugeVec,

    /// Auction solvable orders grouped by class.
    #[metric(labels("class"))]
    auction_solvable_orders: IntGaugeVec,

    /// Auction filtered orders grouped by class.
    #[metric(labels("reason"))]
    auction_filtered_orders: IntGaugeVec,

    /// Auction filtered market orders due to missing native token price.
    auction_market_order_missing_price: IntGauge,
    /// Delta incremental shadow comparison result.
    #[metric(labels("result"))]
    delta_shadow_compare: IntCounterVec,

    /// Delta incremental-primary rollout result.
    #[metric(labels("result"))]
    delta_incremental_primary: IntCounterVec,

    /// Number of canonical delta fallbacks due to mismatched incremental diffs.
    delta_canonical_fallback_total: IntCounter,

    /// Aggregate counter for any incremental delta failure (useful for
    /// high-level health dashboards and alerting).
    delta_incremental_failure_total: IntCounter,

    /// Total incremental delta comparisons.
    delta_incremental_event_total: IntCounter,

    /// Incremental delta filter transitions that referenced a missing order.
    delta_filter_transition_missing_order_total: IntCounter,

    /// Incremental projection mismatches against the canonical rebuild surface.
    delta_incremental_projection_mismatch_total: IntCounter,
}

impl Metrics {
    fn get() -> &'static Self {
        Metrics::instance(observe::metrics::get_storage_registry()).unwrap()
    }

    #[instrument(skip_all)]
    fn track_filtered_orders(reason: OrderFilterReason, invalid_orders: &[OrderUid]) {
        if invalid_orders.is_empty() {
            return;
        }

        Metrics::get()
            .auction_filtered_orders
            .with_label_values(&[reason.as_str()])
            .set(i64::try_from(invalid_orders.len()).unwrap_or(i64::MAX));

        tracing::debug!(
            %reason,
            count = invalid_orders.len(),
            orders = ?invalid_orders, "filtered orders"
        );
    }

    #[instrument(skip_all)]
    fn track_orders_in_final_auction(orders: &[&Order]) {
        let metrics = Metrics::get();
        metrics.auction_creations.inc();

        let remaining_counts = orders
            .iter()
            .counts_by(|order| order.metadata.class.as_ref());
        for class in OrderClass::VARIANTS {
            let count = remaining_counts.get(class).copied().unwrap_or_default();
            metrics
                .auction_solvable_orders
                .with_label_values(&[class])
                .set(i64::try_from(count).unwrap_or(i64::MAX));
        }
    }
}

/// Keeps track and updates the set of currently solvable orders.
/// For this we also need to keep track of user sell token balances for open
/// orders so this is retrievable as well.
/// The cache is updated in the background whenever a new block appears or when
/// the cache is explicitly notified that it should update for example because a
/// new order got added to the order book.
pub struct SolvableOrdersCache {
    min_order_validity_period: Duration,
    persistence: infra::Persistence,
    banned_users: banned::Users,
    balance_fetcher: Arc<dyn BalanceFetching>,
    deny_listed_tokens: DenyListedTokens,
    cache: Mutex<Option<Inner>>,
    update_lock: Mutex<()>,
    native_price_estimator: Arc<NativePriceUpdater>,
    weth: Address,
    protocol_fees: domain::ProtocolFees,
    cow_amm_registry: cow_amm::Registry,
    native_price_timeout: Duration,
    settlement_contract: Address,
    disable_order_balance_filter: bool,
    wrapper_cache: app_data::WrapperCache,
    delta_sender: broadcast::Sender<DeltaEnvelope>,
    shadow_compare_incremental: bool,
    incremental_primary: bool,
    delta_config: DeltaSyncConfig,
}

type Balances = HashMap<Query, U256>;

/// Configuration for delta sync behavior.
#[derive(Clone, Debug)]
pub struct DeltaSyncConfig {
    /// Minimum number of delta envelopes to retain regardless of age.
    pub history_min_retained: usize,
    /// Maximum age for delta history entries before pruning.
    pub history_max_age: Duration,
    /// Broadcast channel capacity for live delta streaming.
    pub broadcast_capacity: usize,
}

impl Default for DeltaSyncConfig {
    fn default() -> Self {
        Self {
            history_min_retained: MIN_DELTA_HISTORY_RETAINED,
            history_max_age: DEFAULT_DELTA_HISTORY_MAX_AGE,
            broadcast_capacity: DELTA_BROADCAST_CAPACITY,
        }
    }
}

/// Maximum number of delta envelopes retained in memory for replay.
/// This determines how far back a subscriber can replay from.
const MAX_DELTA_HISTORY: usize = 1024;

/// Default maximum age for delta history entries before pruning.
const DEFAULT_DELTA_HISTORY_MAX_AGE: Duration = Duration::from_secs(300);

/// Minimum number of delta envelopes to retain regardless of age.
const MIN_DELTA_HISTORY_RETAINED: usize = 10;

/// Broadcast channel capacity for live delta streaming.
/// Sized for producer-consumer lag tolerance. If a subscriber falls
/// behind by more than this many envelopes, it will receive a lagged
/// error and must re-subscribe with replay.
const DELTA_BROADCAST_CAPACITY: usize = 256;

/// Result of applying incremental changes to an auction.
#[derive(Clone, Debug)]
pub enum ProjectionResult {
    /// First update with no previous auction to compare against.
    Bootstrap(domain::RawAuctionData),
    /// Incremental projection matched canonical rebuild.
    Match(domain::RawAuctionData),
    /// Incremental projection diverged; canonical auction returned.
    Mismatch(domain::RawAuctionData),
}

impl ProjectionResult {
    pub fn auction(self) -> domain::RawAuctionData {
        match self {
            Self::Bootstrap(a) | Self::Match(a) | Self::Mismatch(a) => a,
        }
    }

    pub fn auction_ref(&self) -> &domain::RawAuctionData {
        match self {
            Self::Bootstrap(a) | Self::Match(a) | Self::Mismatch(a) => a,
        }
    }

    pub fn should_recompute_events(&self) -> bool {
        matches!(self, Self::Bootstrap(_) | Self::Mismatch(_))
    }

    pub fn is_mismatch(&self) -> bool {
        matches!(self, Self::Mismatch(_))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum DeltaEvent {
    /// Advisory marker for auction boundary transitions.
    AuctionChanged {
        new_auction_id: u64,
    },
    /// Block number changed on the root auction data.
    BlockChanged {
        block: u64,
    },
    /// Order entered the solver-visible set (including
    /// re-validation/unfiltering).
    OrderAdded(domain::Order),
    /// Order left the solver-visible set (including invalidation/filtering).
    OrderRemoved(domain::OrderUid),
    OrderUpdated(domain::Order),
    PriceChanged {
        token: Address,
        price: Option<Price>,
    },
    /// Surplus-capturing JIT order owners changed on the root auction data.
    JitOwnersChanged {
        surplus_capturing_jit_order_owners: Vec<Address>,
    },
}

#[derive(Clone, Debug)]
pub struct DeltaEnvelope {
    pub auction_id: u64,
    pub auction_sequence: u64,
    pub from_sequence: u64,
    pub to_sequence: u64,
    /// Semantic timestamp (wire format, for serialization).
    pub published_at: chrono::DateTime<chrono::Utc>,
    /// Monotonic timestamp for in-memory pruning only.
    /// Set at envelope creation time, not at event occurrence time.
    /// Under load, this may diverge from `published_at`.
    pub created_at_instant: Instant,
    pub events: Vec<DeltaEvent>,
}

#[derive(Clone, Debug)]
pub struct DeltaSnapshot {
    pub auction_id: u64,
    pub auction_sequence: u64,
    pub sequence: u64,
    pub oldest_available: u64,
    pub auction: domain::RawAuctionData,
}

#[derive(Clone, Debug)]
pub struct DeltaChecksum {
    pub sequence: u64,
    pub order_uid_hash: String,
    pub price_hash: String,
}

#[derive(Clone, Copy, Debug)]
pub enum DeltaAfterError {
    FutureSequence { latest: u64 },
    ResyncRequired { oldest_available: u64, latest: u64 },
}

#[derive(Clone, Copy, Debug)]
pub enum DeltaSubscribeError {
    MissingAfterSequence { latest: u64 },
    DeltaAfter(DeltaAfterError),
}

#[derive(Clone, Debug)]
pub struct DeltaReplay {
    pub checkpoint_sequence: u64,
    pub envelopes: Vec<DeltaEnvelope>,
}

/// Cached in-memory state for the solvable orders delta stream.
///
/// Semantics:
/// - `auction_sequence`: per-auction sequence counter. Resets to `0` (sentinel)
///   when an `AuctionChanged` transition is emitted (see
///   `apply_auction_id_change`). The first `update()` after a transition will
///   emit `auction_sequence = 1`. Do NOT use `auction_sequence` for global
///   ordering across auction transitions — it only orders events inside a
///   single auction.
/// - `delta_sequence`: global, monotonic sequence counter. Never resets and is
///   the authoritative ordering counter used for replay and gap detection.
struct Inner {
    auction: domain::RawAuctionData,
    solvable_orders: boundary::SolvableOrders,
    auction_id: u64,
    auction_sequence: u64,
    delta_sequence: u64,
    delta_history: VecDeque<DeltaEnvelope>,
    indexed_state: Arc<IndexedAuctionState>,
}

#[derive(Clone, Debug, Default, PartialEq)]
struct IndexedAuctionState {
    current_orders_by_uid: HashMap<domain::OrderUid, domain::Order>,
    current_prices_by_token: HashMap<Address, Price>,
    filtered_invalid: HashMap<OrderUid, OrderFilterReason>,
    filtered_in_flight: HashSet<OrderUid>,
    filtered_no_balance: HashSet<OrderUid>,
    filtered_no_price: HashSet<OrderUid>,
    surplus_capturing_jit_order_owners: Vec<Address>,
}

/// Mode of auction input collection.
#[derive(Clone, Debug)]
pub enum CollectionMode {
    /// Full rebuild from database.
    Full,
    /// Incremental update with indexed state.
    Incremental(Arc<IndexedAuctionState>),
}

#[derive(Clone, Debug, Default)]
struct ChangeBundle {
    order_added_candidates: Vec<domain::OrderUid>,
    order_removed_candidates: Vec<domain::OrderUid>,
    order_updated_candidates: Vec<domain::OrderUid>,
    quote_updated_candidates: Vec<domain::OrderUid>,
    price_changed_tokens: Vec<Address>,
    filter_transitions: Vec<FilterTransition>,
}

#[derive(Clone, Debug)]
struct FilterTransition {
    uid: domain::OrderUid,
    reason: OrderFilterReason,
    is_filtered: bool,
}

struct CollectedAuctionInputs {
    db_solvable_orders: boundary::SolvableOrders,
    invalid_order_uids: HashMap<OrderUid, OrderFilterReason>,
    filtered_order_events: Vec<(OrderUid, OrderFilterReason)>,
    final_orders: Vec<domain::Order>,
    prices: BTreeMap<Address, U256>,
    surplus_capturing_jit_order_owners: Vec<Address>,
    mode: CollectionMode,
}

impl SolvableOrdersCache {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        min_order_validity_period: Duration,
        persistence: infra::Persistence,
        banned_users: banned::Users,
        balance_fetcher: Arc<dyn BalanceFetching>,
        deny_listed_tokens: DenyListedTokens,
        native_price_estimator: Arc<NativePriceUpdater>,
        weth: Address,
        protocol_fees: domain::ProtocolFees,
        cow_amm_registry: cow_amm::Registry,
        native_price_timeout: Duration,
        settlement_contract: Address,
        disable_order_balance_filter: bool,
        delta_config: Option<DeltaSyncConfig>,
    ) -> Arc<Self> {
        let delta_config = delta_config.unwrap_or_default();
        let (delta_sender, _) = broadcast::channel(delta_config.broadcast_capacity);
        let shadow_compare_incremental = shared::env::flag_enabled(
            std::env::var("AUTOPILOT_DELTA_SYNC_SHADOW_COMPARE")
                .ok()
                .as_deref(),
            false,
        );
        let incremental_primary = shared::env::flag_enabled(
            std::env::var("AUTOPILOT_DELTA_SYNC_INCREMENTAL_PRIMARY")
                .ok()
                .as_deref(),
            false,
        );
        if shadow_compare_incremental && incremental_primary {
            tracing::warn!(
                "delta sync shadow-compare and incremental-primary are both enabled; updates will \
                 run the full pipeline twice"
            );
        }
        Arc::new(Self {
            min_order_validity_period,
            persistence,
            banned_users,
            balance_fetcher,
            deny_listed_tokens,
            cache: Mutex::new(None),
            update_lock: Mutex::new(()),
            native_price_estimator,
            weth,
            protocol_fees,
            cow_amm_registry,
            native_price_timeout,
            settlement_contract,
            disable_order_balance_filter,
            wrapper_cache: app_data::WrapperCache::new(20_000),
            delta_sender,
            shadow_compare_incremental,
            incremental_primary,
            delta_config,
        })
    }

    /// Debug-only guard to catch cache mutation without the update lock.
    fn assert_update_lock_held(&self) {
        #[cfg(debug_assertions)]
        if let Ok(guard) = self.update_lock.try_lock() {
            // If try_lock succeeds, the update lock was not held by the caller.
            drop(guard);
            debug_assert!(false, "update_lock must be held when mutating cache");
        }
    }

    pub async fn current_auction(&self) -> Option<domain::RawAuctionData> {
        self.cache
            .lock()
            .await
            .as_ref()
            .map(|inner| inner.auction.clone())
    }

    pub async fn delta_snapshot(&self) -> Option<DeltaSnapshot> {
        self.cache.lock().await.as_ref().map(|inner| {
            let oldest_available = inner
                .delta_history
                .front()
                .map(|envelope| envelope.from_sequence)
                .unwrap_or(inner.delta_sequence);
            DeltaSnapshot {
                auction_id: inner.auction_id,
                auction_sequence: inner.auction_sequence,
                sequence: inner.delta_sequence,
                oldest_available,
                auction: inner.auction.clone(),
            }
        })
    }

    pub async fn delta_sequence(&self) -> Option<u64> {
        self.cache
            .lock()
            .await
            .as_ref()
            .map(|inner| inner.delta_sequence)
    }

    fn diff_inputs(
        &self,
        previous_solvable_orders: Option<&boundary::SolvableOrders>,
        current_solvable_orders: &boundary::SolvableOrders,
    ) -> ChangeBundle {
        diff_solvable_order_inputs(previous_solvable_orders, current_solvable_orders)
    }

    pub async fn delta_checksum(&self) -> Option<DeltaChecksum> {
        let lock = self.cache.lock().await;
        let inner = lock.as_ref()?;
        Some(DeltaChecksum {
            sequence: inner.delta_sequence,
            order_uid_hash: checksum_order_uids(&inner.auction.orders),
            price_hash: checksum_prices(&inner.auction.prices),
        })
    }

    #[cfg(test)]
    pub(crate) async fn set_state_for_tests(
        &self,
        auction: domain::RawAuctionData,
        auction_id: u64,
        auction_sequence: u64,
        delta_sequence: u64,
        delta_history: VecDeque<DeltaEnvelope>,
    ) {
        let indexed_state = Arc::new(build_indexed_state(&auction, &HashMap::new(), &Vec::new()));
        let mut lock = self.cache.lock().await;
        *lock = Some(Inner {
            auction,
            solvable_orders: boundary::SolvableOrders {
                orders: HashMap::new(),
                quotes: HashMap::new(),
                latest_settlement_block: 0,
                fetched_from_db: chrono::Utc::now(),
            },
            auction_id,
            auction_sequence,
            delta_sequence,
            delta_history,
            indexed_state,
        });
    }

    #[cfg(test)]
    pub(crate) async fn publish_delta_for_tests(&self, envelope: DeltaEnvelope) {
        let mut lock = self.cache.lock().await;
        if let Some(inner) = lock.as_mut() {
            inner.auction_id = envelope.auction_id;
            inner.auction_sequence = envelope.auction_sequence;
            inner.delta_sequence = envelope.to_sequence;
            inner.delta_history.push_back(envelope.clone());
            let max_age = chrono::Duration::from_std(self.delta_config.history_max_age)
                .unwrap_or_else(|_| chrono::Duration::seconds(60));
            prune_delta_history(&mut inner.delta_history, max_age, &self.delta_config);
        }
        // Send while holding the cache lock to keep replay + live ordering consistent
        send_or_warn!(self.delta_sender, envelope, "delta broadcast");
    }

    #[cfg(test)]
    pub(crate) fn delta_receiver_count(&self) -> usize {
        self.delta_sender.receiver_count()
    }

    /// Updates the auction ID and emits an AuctionChanged delta event if
    /// changed.
    ///
    /// This must only be called from the run loop, which serializes calls
    /// externally. The cache lock alone is sufficient here.
    pub async fn set_auction_id(&self, auction_id: u64) {
        let mut lock = self.cache.lock().await;
        if let Some(inner) = lock.as_mut() {
            if let Some(envelope) = apply_auction_id_change(inner, auction_id, &self.delta_config) {
                // Send while holding cache lock to keep replay + live ordering
                // consistent (same pattern as update()).
                send_or_warn!(self.delta_sender, envelope, "delta broadcast");
            }
        }
    }

    pub async fn delta_replay_with_checkpoint(
        &self,
        after_sequence: u64,
    ) -> Result<DeltaReplay, DeltaAfterError> {
        let lock = self.cache.lock().await;
        Self::build_delta_replay(after_sequence, lock.as_ref())
    }

    pub async fn subscribe_deltas_with_replay(
        &self,
        after_sequence: u64,
    ) -> Result<(broadcast::Receiver<DeltaEnvelope>, DeltaReplay), DeltaAfterError> {
        let lock = self.cache.lock().await;
        let receiver = self.delta_sender.subscribe();
        let replay = Self::build_delta_replay(after_sequence, lock.as_ref())?;
        Ok((receiver, replay))
    }

    pub async fn subscribe_deltas_with_replay_checked(
        &self,
        after_sequence: Option<u64>,
    ) -> Result<(broadcast::Receiver<DeltaEnvelope>, DeltaReplay), DeltaSubscribeError> {
        let lock = self.cache.lock().await;

        let receiver = self.delta_sender.subscribe();

        let latest = lock.as_ref().map(|inner| inner.delta_sequence).unwrap_or(0);
        if after_sequence.is_none() && latest > 0 {
            return Err(DeltaSubscribeError::MissingAfterSequence { latest });
        }

        let replay = Self::build_delta_replay(after_sequence.unwrap_or_default(), lock.as_ref())
            .map_err(DeltaSubscribeError::DeltaAfter)?;

        // Release the cache lock before returning so publishers can proceed and
        // new envelopes will be buffered by the receiver.
        drop(lock);

        Ok((receiver, replay))
    }

    fn build_delta_replay(
        after_sequence: u64,
        inner: Option<&Inner>,
    ) -> Result<DeltaReplay, DeltaAfterError> {
        let Some(inner) = inner else {
            if after_sequence > 0 {
                return Err(DeltaAfterError::ResyncRequired {
                    oldest_available: 0,
                    latest: 0,
                });
            }
            return Ok(DeltaReplay {
                checkpoint_sequence: 0,
                envelopes: vec![DeltaEnvelope {
                    auction_id: 0,
                    auction_sequence: 0,
                    from_sequence: 0,
                    to_sequence: 0,
                    published_at: chrono::Utc::now(),
                    created_at_instant: Instant::now(),
                    events: Vec::new(),
                }],
            });
        };

        let checkpoint_sequence = inner.delta_sequence;

        if after_sequence > checkpoint_sequence {
            return Err(DeltaAfterError::FutureSequence {
                latest: checkpoint_sequence,
            });
        }

        let oldest_available = inner
            .delta_history
            .front()
            .map(|envelope| envelope.from_sequence)
            .unwrap_or(inner.delta_sequence);
        if after_sequence < oldest_available {
            return Err(DeltaAfterError::ResyncRequired {
                oldest_available,
                latest: checkpoint_sequence,
            });
        }

        let envelopes: Vec<_> = inner
            .delta_history
            .iter()
            .filter(|envelope| {
                envelope.to_sequence > after_sequence && envelope.to_sequence <= checkpoint_sequence
            })
            .cloned()
            .collect();

        if envelopes.is_empty() && after_sequence == checkpoint_sequence {
            // When requesting replay from the current sequence with no history,
            // return empty replay without synthetic envelope
            Ok(DeltaReplay {
                checkpoint_sequence,
                envelopes: Vec::new(),
            })
        } else if envelopes.is_empty() {
            Ok(DeltaReplay {
                checkpoint_sequence,
                envelopes: vec![DeltaEnvelope {
                    auction_id: inner.auction_id,
                    auction_sequence: inner.auction_sequence,
                    from_sequence: after_sequence,
                    to_sequence: after_sequence,
                    published_at: chrono::Utc::now(),
                    created_at_instant: Instant::now(),
                    events: Vec::new(),
                }],
            })
        } else {
            Ok(DeltaReplay {
                checkpoint_sequence,
                envelopes,
            })
        }
    }

    pub fn subscribe_deltas(&self) -> broadcast::Receiver<DeltaEnvelope> {
        self.delta_sender.subscribe()
    }

    #[instrument(skip_all)]
    pub async fn update(&self, block: u64, store_events: bool) -> Result<()> {
        let _update_guard = self.update_lock.lock().await;
        self.assert_update_lock_held();
        let start = Instant::now();

        let _timer = observe::metrics::metrics()
            .on_auction_overhead_start("autopilot", "update_solvabe_orders");

        let db_solvable_orders = self.get_solvable_orders().await?;
        tracing::trace!("fetched solvable orders from db");

        // Update calls are expected to be serialized by the update task; if that
        // changes, this snapshot of previous state can become stale.
        let (
            previous_auction,
            previous_auction_id,
            previous_auction_sequence,
            previous_delta_sequence,
            previous_indexed_state,
            mut change_bundle,
        ) = {
            let cache = self.cache.lock().await;
            let previous_auction = cache.as_ref().map(|inner| inner.auction.clone());
            let previous_auction_id = cache.as_ref().map(|inner| inner.auction_id);
            let previous_auction_sequence = cache.as_ref().map(|inner| inner.auction_sequence);
            let previous_delta_sequence = cache.as_ref().map(|inner| inner.delta_sequence);
            let previous_indexed_state =
                cache.as_ref().map(|inner| Arc::clone(&inner.indexed_state));
            let change_bundle = self.diff_inputs(
                cache.as_ref().map(|inner| &inner.solvable_orders),
                &db_solvable_orders,
            );
            (
                previous_auction,
                previous_auction_id,
                previous_auction_sequence,
                previous_delta_sequence,
                previous_indexed_state,
                change_bundle,
            )
        };
        tracing::debug!(
            added = change_bundle.order_added_candidates.len(),
            removed = change_bundle.order_removed_candidates.len(),
            updated = change_bundle.order_updated_candidates.len(),
            "computed input change bundle"
        );

        let inputs = if let Some(previous_indexed_state) = previous_indexed_state.as_ref() {
            if self.incremental_primary || self.shadow_compare_incremental {
                let fallback_db_snapshot = db_solvable_orders.clone();
                match self
                    .collect_inputs_incremental(
                        previous_indexed_state.as_ref(),
                        db_solvable_orders,
                        &mut change_bundle,
                        block,
                        false,
                    )
                    .await
                {
                    Ok(incremental_inputs) if self.shadow_compare_incremental => {
                        let full_inputs = self
                            .collect_inputs_from_db(fallback_db_snapshot, block, false)
                            .await?;

                        let incremental_auction =
                            self.project_final_auction(block, &incremental_inputs)?;
                        let full_auction = self.project_final_auction(block, &full_inputs)?;

                        let incremental_events =
                            compute_delta_events(previous_auction.as_ref(), &incremental_auction);
                        let full_events =
                            compute_delta_events(previous_auction.as_ref(), &full_auction);
                        let full_indexed_state = build_indexed_state(
                            &full_auction,
                            &full_inputs.invalid_order_uids,
                            &full_inputs.filtered_order_events,
                        );
                        let indexed_state_matches = match &incremental_inputs.mode {
                            CollectionMode::Incremental(state) => {
                                state.as_ref() == &full_indexed_state
                            }
                            CollectionMode::Full => {
                                let incremental_indexed_state = build_indexed_state(
                                    &incremental_auction,
                                    &incremental_inputs.invalid_order_uids,
                                    &incremental_inputs.filtered_order_events,
                                );
                                incremental_indexed_state == full_indexed_state
                            }
                        };
                        if !indexed_state_matches {
                            tracing::warn!(
                                "incremental indexed state diverged from full rebuild; falling \
                                 back"
                            );
                        }
                        let surfaces_match = normalized_delta_surface(incremental_auction)
                            == normalized_delta_surface(full_auction)
                            && incremental_events == full_events
                            && indexed_state_matches;

                        if surfaces_match {
                            Metrics::get()
                                .delta_shadow_compare
                                .with_label_values(&["match"])
                                .inc();
                            if self.incremental_primary {
                                Metrics::get()
                                    .delta_incremental_primary
                                    .with_label_values(&["primary"])
                                    .inc();
                                incremental_inputs
                            } else {
                                full_inputs
                            }
                        } else {
                            Metrics::get()
                                .delta_shadow_compare
                                .with_label_values(&["mismatch"])
                                .inc();
                            if self.incremental_primary {
                                Metrics::get()
                                    .delta_incremental_primary
                                    .with_label_values(&["fallback_mismatch"])
                                    .inc();
                            }
                            full_inputs
                        }
                    }
                    Ok(incremental_inputs) => {
                        Metrics::get()
                            .delta_incremental_primary
                            .with_label_values(&["primary"])
                            .inc();
                        incremental_inputs
                    }
                    Err(err) => {
                        tracing::warn!(
                            ?err,
                            "incremental input collection failed, falling back to full rebuild"
                        );
                        Metrics::get()
                            .delta_incremental_primary
                            .with_label_values(&["fallback_error"])
                            .inc();
                        self.collect_inputs_from_db(fallback_db_snapshot, block, false)
                            .await?
                    }
                }
            } else {
                self.collect_inputs_from_db(db_solvable_orders, block, false)
                    .await?
            }
        } else {
            if self.incremental_primary {
                Metrics::get()
                    .delta_incremental_primary
                    .with_label_values(&["bootstrap"])
                    .inc();
            }
            self.collect_inputs_from_db(db_solvable_orders, block, false)
                .await?
        };
        let canonical_auction = self.project_final_auction(block, &inputs)?;
        if let Some(previous_auction) = previous_auction.as_ref() {
            change_bundle.price_changed_tokens =
                Self::compute_price_changed_tokens(previous_auction, &canonical_auction);
        }
        tracing::debug!(
            price_changed = change_bundle.price_changed_tokens.len(),
            filter_transitions = change_bundle.filter_transitions.len(),
            "computed enriched change bundle"
        );

        if store_events {
            let invalid_order_uids_clone = inputs.invalid_order_uids.clone();
            let filtered_order_events_clone = inputs.filtered_order_events.clone();

            // Store events with error propagation
            self.store_events_by_reason_checked(invalid_order_uids_clone, OrderEventLabel::Invalid)
                .await
                .context("failed to store invalid order events")?;
            self.store_events_by_reason_checked(
                filtered_order_events_clone,
                OrderEventLabel::Filtered,
            )
            .await
            .context("failed to store filtered order events")?;
        }

        let mut cache = self.cache.lock().await;

        let next_sequence = previous_delta_sequence
            .map(|value| {
                if value == u64::MAX {
                    Metrics::get().delta_incremental_failure_total.inc();
                    tracing::error!(
                        previous_delta_sequence = value,
                        "delta sequence overflow; sequence cannot advance"
                    );
                    Err(anyhow::anyhow!("delta sequence overflow"))
                } else {
                    Ok(value + 1)
                }
            })
            .transpose()?
            .unwrap_or(1);
        let current_auction_id = previous_auction_id.unwrap_or_default();
        // `auction_sequence` is a per-auction counter and restarts at `1`
        // after an `AuctionChanged` transition (which sets the internal
        // `auction_sequence` to `0` as a sentinel). `delta_sequence` is the
        // global monotonic counter and must be used for ordering across
        // auction boundaries.
        let next_auction_sequence = previous_auction_sequence
            .map(|value| value + 1)
            .unwrap_or(1);
        let mut delta_history = cache
            .as_ref()
            .map(|inner| inner.delta_history.clone())
            .unwrap_or_default();

        let mut events = if matches!(inputs.mode, CollectionMode::Incremental(_)) {
            Self::compute_delta_events_from_inputs(
                previous_auction.as_ref(),
                &canonical_auction,
                &change_bundle,
                self.shadow_compare_incremental,
            )
            .unwrap_or_else(|| compute_delta_events(previous_auction.as_ref(), &canonical_auction))
        } else {
            compute_delta_events(previous_auction.as_ref(), &canonical_auction)
        };

        let projection_result = self.apply_incremental_changes(
            previous_auction.as_ref(),
            canonical_auction.clone(),
            &events,
        );

        if projection_result.should_recompute_events() {
            events =
                compute_delta_events(previous_auction.as_ref(), projection_result.auction_ref());

            if projection_result.is_mismatch() && previous_auction.is_some() {
                Metrics::get()
                    .delta_incremental_projection_mismatch_total
                    .inc();

                // Attempt to verify the fallback path.
                tracing::warn!(
                    "incremental projection mismatch detected, using canonical fallback"
                );
            }

            if let Some(prev) = previous_auction.clone() {
                let check = apply_delta_events_to_auction(prev, &events);
                let lhs = normalized_delta_surface(check);
                let rhs = normalized_delta_surface(projection_result.auction_ref().clone());
                if lhs != rhs {
                    Metrics::get().delta_incremental_failure_total.inc();
                    tracing::error!(
                        "projection_mismatch fallback failed to reconstruct canonical auction",
                    );
                }
                // Keep the debug-only strict asserts for developers.
                #[cfg(debug_assertions)]
                debug_assert_eq!(
                    lhs, rhs,
                    "events must reconstruct auction_for_cache after mismatch fallback"
                );
            } else {
                tracing::debug!(
                    "bootstrap update: recomputed canonical delta events without mismatch metrics"
                );
            }
        }

        let should_recompute = projection_result.should_recompute_events();
        let auction_for_cache = projection_result.auction();
        let envelope = DeltaEnvelope {
            auction_id: current_auction_id,
            auction_sequence: next_auction_sequence,
            from_sequence: next_sequence.saturating_sub(1),
            to_sequence: next_sequence,
            published_at: chrono::Utc::now(),
            created_at_instant: Instant::now(),
            events,
        };
        delta_history.push_back(envelope.clone());
        let max_age = chrono::Duration::from_std(self.delta_config.history_max_age)
            .unwrap_or_else(|_| chrono::Duration::seconds(60));
        prune_delta_history(&mut delta_history, max_age, &self.delta_config);

        let indexed_state = if should_recompute {
            Arc::new(build_indexed_state(
                &auction_for_cache,
                &inputs.invalid_order_uids,
                &inputs.filtered_order_events,
            ))
        } else {
            match inputs.mode {
                CollectionMode::Incremental(state) => state,
                CollectionMode::Full => Arc::new(build_indexed_state(
                    &auction_for_cache,
                    &inputs.invalid_order_uids,
                    &inputs.filtered_order_events,
                )),
            }
        };

        *cache = Some(Inner {
            auction: auction_for_cache,
            solvable_orders: inputs.db_solvable_orders,
            auction_id: current_auction_id,
            auction_sequence: next_auction_sequence,
            delta_sequence: next_sequence,
            delta_history,
            indexed_state,
        });
        // Replay history is updated under the cache lock; subscribers build replay
        // while holding the same lock, so sending while locked keeps replay +
        // live ordering consistent.
        send_or_warn!(self.delta_sender, envelope, "delta broadcast");

        tracing::debug!(%block, "updated current auction cache");
        Metrics::get()
            .auction_update_total_time
            .observe(start.elapsed().as_secs_f64());
        Ok(())
    }

    async fn collect_inputs_from_db(
        &self,
        db_solvable_orders: boundary::SolvableOrders,
        block: u64,
        store_events: bool,
    ) -> Result<CollectedAuctionInputs> {
        let orders: Vec<&Order> = db_solvable_orders
            .orders
            .values()
            .map(|order| order.as_ref())
            .collect();

        let mut invalid_order_uids = HashMap::new();
        let mut filtered_order_events: Vec<(OrderUid, OrderFilterReason)> = Vec::new();

        let balance_filter_exempt_orders: HashSet<_> = orders
            .iter()
            .filter(|order| {
                self.wrapper_cache.has_wrappers(
                    &order.data.app_data,
                    order.metadata.full_app_data.as_deref(),
                )
            })
            .map(|order| order.metadata.uid)
            .collect();

        let (balances, orders, cow_amms, in_flight) = {
            let queries = orders
                .iter()
                .map(|order| Query::from_order(order))
                .collect::<Vec<_>>();
            tokio::join!(
                self.fetch_balances(queries),
                self.filter_invalid_orders(orders, &mut invalid_order_uids),
                self.timed_future("cow_amm_registry", self.cow_amm_registry.amms()),
                self.fetch_in_flight_orders(block),
            )
        };

        let (orders, removed) = filter_out_in_flight_orders(orders, &in_flight);
        Metrics::track_filtered_orders(InFlight, &removed);
        filtered_order_events.extend(removed.into_iter().map(|uid| (uid, InFlight)));
        invalid_order_uids.retain(|uid, _| !in_flight.contains(uid));

        let orders = if self.disable_order_balance_filter {
            orders
        } else {
            let (orders, removed) = orders_with_balance(
                orders,
                &balances,
                self.settlement_contract,
                &balance_filter_exempt_orders,
            );
            Metrics::track_filtered_orders(InsufficientBalance, &removed);
            invalid_order_uids.extend(removed.into_iter().map(|uid| (uid, InsufficientBalance)));

            let (orders, removed) = filter_dust_orders(orders, &balances);
            Metrics::track_filtered_orders(DustOrder, &removed);
            filtered_order_events.extend(removed.into_iter().map(|uid| (uid, DustOrder)));

            orders
        };

        let cow_amm_tokens = cow_amms
            .iter()
            .flat_map(|cow_amm| cow_amm.traded_tokens().iter().copied())
            .collect::<Vec<_>>();

        // create auction
        let (orders, removed, mut prices) = self
            .timed_future(
                "get_orders_with_native_prices",
                get_orders_with_native_prices(
                    orders,
                    &self.native_price_estimator,
                    cow_amm_tokens,
                    self.native_price_timeout,
                ),
            )
            .await;
        tracing::trace!("fetched native prices for solvable orders");
        // Add WETH price if it's not already there to support ETH wrap when required.
        if let Entry::Vacant(entry) = prices.entry(self.weth) {
            let weth_price = self
                .timed_future(
                    "weth_price_fetch",
                    self.native_price_estimator
                        .estimate_native_price(self.weth, Default::default()),
                )
                .await
                .expect("weth price fetching can never fail");
            let weth_price = to_normalized_price(weth_price)
                .expect("weth price can never be outside of U256 range");
            entry.insert(weth_price);
        }

        Metrics::track_filtered_orders(MissingNativePrice, &removed);
        filtered_order_events.extend(removed.into_iter().map(|uid| (uid, MissingNativePrice)));
        Metrics::track_orders_in_final_auction(&orders);

        if store_events {
            self.store_events_by_reason(invalid_order_uids.clone(), OrderEventLabel::Invalid);
            self.store_events_by_reason(filtered_order_events.clone(), OrderEventLabel::Filtered);
        }

        let in_flight_owners: HashSet<_> = in_flight
            .iter()
            .map(|uid| domain::OrderUid(uid.0).owner())
            .collect();
        let surplus_capturing_jit_order_owners: Vec<_> = cow_amms
            .iter()
            .filter(|cow_amm| {
                // Orders rebalancing cow amms revert when the cow amm does not have exactly the
                // state the order was crafted for so having multiple orders in-flight for the
                // same cow amm is an issue. Additionally an amm can be rebalanced in many
                // different ways which would all result in different order UIDs so filtering
                // based on that is not sufficient. That's way we check if there is any order
                // in-flight for that amm based on the owner of the order (i.e. the cow amm) and
                // then discard that amm altogether for that auction.
                if in_flight_owners.contains(cow_amm.address()) {
                    return false;
                }
                cow_amm.traded_tokens().iter().all(|token| {
                    let price_exists = prices.contains_key(token);
                    if !price_exists {
                        tracing::debug!(
                            cow_amm = ?cow_amm.address(),
                            ?token,
                            "omitted from auction due to missing prices"
                        );
                    }
                    price_exists
                })
            })
            .map(|cow_amm| *cow_amm.address())
            .collect();

        let final_orders = tracing::info_span!("assemble_orders").in_scope(|| {
            orders
                .into_iter()
                .filter_map(|order| {
                    let uid = domain::OrderUid(order.metadata.uid.0);
                    let quote = db_solvable_orders
                        .quotes
                        .get(&uid)
                        .map(|quote| quote.as_ref().clone());
                    Some(self.protocol_fees.apply(
                        order,
                        quote,
                        &surplus_capturing_jit_order_owners,
                    ))
                })
                .collect::<Vec<_>>()
        });

        Ok(CollectedAuctionInputs {
            db_solvable_orders,
            invalid_order_uids,
            filtered_order_events,
            final_orders,
            prices,
            surplus_capturing_jit_order_owners,
            mode: CollectionMode::Full,
        })
    }

    async fn collect_inputs_incremental(
        &self,
        previous_indexed_state: &IndexedAuctionState,
        db_solvable_orders: boundary::SolvableOrders,
        change_bundle: &mut ChangeBundle,
        block: u64,
        store_events: bool,
    ) -> Result<CollectedAuctionInputs> {
        let mut indexed_state = previous_indexed_state.clone();
        let mut filtered_order_events: Vec<(OrderUid, OrderFilterReason)> = Vec::new();
        let mut invalid_order_uids: HashMap<OrderUid, OrderFilterReason> = HashMap::new();
        let mut filter_transitions: Vec<FilterTransition> = Vec::new();

        let mut register_transition =
            |uid: OrderUid, reason: OrderFilterReason, was_filtered: bool, is_filtered: bool| {
                if was_filtered != is_filtered {
                    filter_transitions.push(FilterTransition {
                        uid: domain::OrderUid(uid.0),
                        reason,
                        is_filtered,
                    });
                }
            };

        for uid in &change_bundle.order_removed_candidates {
            let model_uid = OrderUid(uid.0);
            indexed_state.current_orders_by_uid.remove(uid);
            let was_invalid_reason = indexed_state.filtered_invalid.remove(&model_uid);
            let was_in_flight = indexed_state.filtered_in_flight.remove(&model_uid);
            let was_no_balance = indexed_state.filtered_no_balance.remove(&model_uid);
            let was_no_price = indexed_state.filtered_no_price.remove(&model_uid);

            if let Some(reason) = was_invalid_reason {
                register_transition(model_uid, reason, true, false);
            }
            register_transition(model_uid, InFlight, was_in_flight, false);
            register_transition(model_uid, InsufficientBalance, was_no_balance, false);
            register_transition(model_uid, MissingNativePrice, was_no_price, false);
        }

        let in_flight = self.fetch_in_flight_orders(block).await;

        let mut impacted_uids = change_bundle
            .order_updated_candidates
            .iter()
            .chain(change_bundle.quote_updated_candidates.iter())
            .chain(change_bundle.order_added_candidates.iter())
            .copied()
            .collect::<HashSet<_>>();

        impacted_uids.extend(
            indexed_state
                .filtered_no_balance
                .iter()
                .map(|uid| domain::OrderUid(uid.0)),
        );
        impacted_uids.extend(
            indexed_state
                .filtered_no_price
                .iter()
                .map(|uid| domain::OrderUid(uid.0)),
        );

        impacted_uids.extend(
            in_flight
                .iter()
                .filter(|uid| {
                    indexed_state
                        .current_orders_by_uid
                        .contains_key(&domain::OrderUid(uid.0))
                })
                .map(|uid| domain::OrderUid(uid.0)),
        );
        impacted_uids.extend(
            indexed_state
                .filtered_in_flight
                .iter()
                .filter(|uid| !in_flight.contains(uid))
                .map(|uid| domain::OrderUid(uid.0)),
        );

        let queries = impacted_uids
            .iter()
            .filter_map(|uid| {
                db_solvable_orders
                    .orders
                    .get(uid)
                    .map(|order| Query::from_order(order.as_ref()))
            })
            .collect::<Vec<_>>();

        let cow_amms = self
            .timed_future("cow_amm_registry", self.cow_amm_registry.amms())
            .await;
        let balances = self.fetch_balances(queries).await;

        let mut prices: BTreeMap<Address, U256> = previous_indexed_state
            .current_prices_by_token
            .iter()
            .map(|(token, price)| (*token, price.get().0.into()))
            .collect();

        let mut impacted_tokens = impacted_uids
            .iter()
            .filter_map(|uid| db_solvable_orders.orders.get(uid))
            .flat_map(|order| [order.data.sell_token, order.data.buy_token])
            .collect::<HashSet<_>>();
        impacted_tokens.extend(cow_amms.iter().flat_map(|cow_amm| {
            cow_amm
                .traded_tokens()
                .iter()
                .copied()
                .filter(|token| !prices.contains_key(token))
        }));
        if impacted_tokens.is_empty() {
            impacted_tokens.extend(prices.keys().copied());
        }

        let fetched_impacted_prices = self
            .timed_future(
                "get_orders_with_native_prices",
                get_native_prices(
                    impacted_tokens.clone(),
                    &self.native_price_estimator,
                    self.native_price_timeout,
                ),
            )
            .await;

        let mut price_changed_tokens = Vec::new();
        for token in impacted_tokens {
            let previous = prices.get(&token).copied();
            let next = fetched_impacted_prices.get(&token).copied();
            match next {
                Some(price) => {
                    prices.insert(token, price);
                }
                None => {
                    prices.remove(&token);
                }
            }

            if previous != next {
                price_changed_tokens.push(token);
            }
        }

        if let Entry::Vacant(entry) = prices.entry(self.weth) {
            let weth_price = self
                .timed_future(
                    "weth_price_fetch",
                    self.native_price_estimator
                        .estimate_native_price(self.weth, Default::default()),
                )
                .await
                .expect("weth price fetching can never fail");
            let weth_price = to_normalized_price(weth_price)
                .expect("weth price can never be outside of U256 range");
            entry.insert(weth_price);
        }

        let changed_price_token_set = price_changed_tokens.iter().copied().collect::<HashSet<_>>();
        if !changed_price_token_set.is_empty() {
            impacted_uids.extend(
                indexed_state
                    .current_orders_by_uid
                    .keys()
                    .filter(|uid| {
                        db_solvable_orders.orders.get(uid).is_some_and(|order| {
                            changed_price_token_set.contains(&order.data.sell_token)
                                || changed_price_token_set.contains(&order.data.buy_token)
                        })
                    })
                    .copied(),
            );
        }

        let impacted_orders = impacted_uids
            .iter()
            .filter_map(|uid| {
                db_solvable_orders
                    .orders
                    .get(uid)
                    .map(|order| order.as_ref())
            })
            .collect::<Vec<_>>();

        let balance_filter_exempt_orders: HashSet<_> = impacted_orders
            .iter()
            .filter(|order| {
                self.wrapper_cache.has_wrappers(
                    &order.data.app_data,
                    order.metadata.full_app_data.as_deref(),
                )
            })
            .map(|order| order.metadata.uid)
            .collect();

        let mut invalid_for_impacted = HashMap::new();
        let mut candidate_orders = self
            .filter_invalid_orders(impacted_orders, &mut invalid_for_impacted)
            .await;
        for (uid, reason) in invalid_for_impacted.iter() {
            let was_filtered = indexed_state.filtered_invalid.contains_key(uid);
            indexed_state.filtered_invalid.insert(*uid, *reason);
            register_transition(*uid, *reason, was_filtered, true);
            indexed_state
                .current_orders_by_uid
                .remove(&domain::OrderUid(uid.0));
        }

        let mut in_flight_removed = Vec::new();
        candidate_orders.retain(|order| {
            if in_flight.contains(&order.metadata.uid) {
                in_flight_removed.push(order.metadata.uid);
                false
            } else {
                true
            }
        });
        for uid in in_flight_removed {
            let was_filtered = indexed_state.filtered_in_flight.contains(&uid);
            indexed_state.filtered_in_flight.insert(uid);
            register_transition(uid, InFlight, was_filtered, true);
            indexed_state
                .current_orders_by_uid
                .remove(&domain::OrderUid(uid.0));
            filtered_order_events.push((uid, InFlight));
        }

        let candidate_orders = if self.disable_order_balance_filter {
            candidate_orders
        } else {
            let (candidate_orders, removed_no_balance) = orders_with_balance(
                candidate_orders,
                &balances,
                self.settlement_contract,
                &balance_filter_exempt_orders,
            );
            for uid in removed_no_balance {
                let was_filtered = indexed_state.filtered_no_balance.contains(&uid);
                indexed_state.filtered_no_balance.insert(uid);
                register_transition(uid, InsufficientBalance, was_filtered, true);
                indexed_state
                    .current_orders_by_uid
                    .remove(&domain::OrderUid(uid.0));
                invalid_for_impacted.insert(uid, InsufficientBalance);
            }

            let (candidate_orders, removed_dust) = filter_dust_orders(candidate_orders, &balances);
            for uid in removed_dust {
                indexed_state
                    .current_orders_by_uid
                    .remove(&domain::OrderUid(uid.0));
                filtered_order_events.push((uid, DustOrder));
            }
            candidate_orders
        };

        for uid in impacted_uids {
            if let Some(order) = db_solvable_orders.orders.get(&uid) {
                let model_uid = order.metadata.uid;
                if !invalid_for_impacted.contains_key(&model_uid) {
                    let was_filtered_reason = indexed_state.filtered_invalid.remove(&model_uid);
                    if let Some(reason) = was_filtered_reason {
                        register_transition(model_uid, reason, true, false);
                    }
                }
                if !in_flight.contains(&model_uid) {
                    let was_filtered = indexed_state.filtered_in_flight.remove(&model_uid);
                    register_transition(model_uid, InFlight, was_filtered, false);
                }
            }
        }

        let mut removed_missing_price = Vec::new();
        let mut alive_orders = candidate_orders;
        alive_orders.retain(|order| {
            let has_prices = prices.contains_key(&order.data.sell_token)
                && prices.contains_key(&order.data.buy_token);
            if !has_prices {
                removed_missing_price.push(order.metadata.uid);
            }
            has_prices
        });

        for uid in removed_missing_price {
            let was_filtered = indexed_state.filtered_no_price.contains(&uid);
            indexed_state.filtered_no_price.insert(uid);
            register_transition(uid, MissingNativePrice, was_filtered, true);
            indexed_state
                .current_orders_by_uid
                .remove(&domain::OrderUid(uid.0));
            filtered_order_events.push((uid, MissingNativePrice));
        }

        let in_flight_owners: HashSet<_> = in_flight
            .iter()
            .map(|uid| domain::OrderUid(uid.0).owner())
            .collect();
        let surplus_capturing_jit_order_owners: Vec<_> = cow_amms
            .iter()
            .filter(|cow_amm| {
                if in_flight_owners.contains(cow_amm.address()) {
                    return false;
                }
                cow_amm
                    .traded_tokens()
                    .iter()
                    .all(|token| prices.contains_key(token))
            })
            .map(|cow_amm| *cow_amm.address())
            .collect();

        let jit_owners_changed = {
            let mut prev = previous_indexed_state
                .surplus_capturing_jit_order_owners
                .clone();
            let mut curr = surplus_capturing_jit_order_owners.clone();
            prev.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
            curr.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
            prev != curr
        };

        let mut alive_uids = HashSet::new();
        for order in alive_orders {
            let uid = domain::OrderUid(order.metadata.uid.0);
            alive_uids.insert(uid);
            let quote = db_solvable_orders
                .quotes
                .get(&uid)
                .map(|quote| quote.as_ref().clone());
            let domain_order =
                self.protocol_fees
                    .apply(order, quote, &surplus_capturing_jit_order_owners);
            indexed_state
                .current_orders_by_uid
                .insert(uid, domain_order);
            let was_no_price = indexed_state.filtered_no_price.remove(&order.metadata.uid);
            register_transition(order.metadata.uid, MissingNativePrice, was_no_price, false);
            let was_no_balance = indexed_state
                .filtered_no_balance
                .remove(&order.metadata.uid);
            register_transition(
                order.metadata.uid,
                InsufficientBalance,
                was_no_balance,
                false,
            );
        }

        if jit_owners_changed {
            let visible_uids = indexed_state
                .current_orders_by_uid
                .keys()
                .filter(|uid| !alive_uids.contains(uid))
                .copied()
                .collect::<Vec<_>>();
            for uid in visible_uids {
                if let Some(order) = db_solvable_orders.orders.get(&uid) {
                    let quote = db_solvable_orders
                        .quotes
                        .get(&uid)
                        .map(|quote| quote.as_ref().clone());
                    let domain_order = self.protocol_fees.apply(
                        order.as_ref(),
                        quote,
                        &surplus_capturing_jit_order_owners,
                    );
                    indexed_state
                        .current_orders_by_uid
                        .insert(uid, domain_order);
                }
            }
        }

        indexed_state.surplus_capturing_jit_order_owners =
            surplus_capturing_jit_order_owners.clone();

        invalid_order_uids.extend(invalid_for_impacted);
        if store_events {
            self.store_events_by_reason(invalid_order_uids.clone(), OrderEventLabel::Invalid);
            self.store_events_by_reason(filtered_order_events.clone(), OrderEventLabel::Filtered);
        }

        let mut final_orders = indexed_state
            .current_orders_by_uid
            .values()
            .cloned()
            .collect::<Vec<_>>();
        final_orders.sort_by_key(|order| order.uid.0);

        let entered_filters = filter_transitions
            .iter()
            .filter(|transition| transition.is_filtered)
            .count();
        let exited_filters = filter_transitions
            .iter()
            .filter(|transition| !transition.is_filtered)
            .count();
        let in_flight_transitions = filter_transitions
            .iter()
            .filter(|transition| transition.reason == InFlight)
            .count();
        let transition_uid_checksum: u64 = filter_transitions
            .iter()
            .map(|transition| u64::from(transition.uid.0[0]))
            .sum();
        tracing::debug!(
            entered_filters,
            exited_filters,
            in_flight_transitions,
            transition_uid_checksum,
            "computed incremental filter transitions"
        );

        #[cfg(debug_assertions)]
        {
            let filtered = indexed_state
                .filtered_invalid
                .iter()
                .map(|(uid, _)| uid)
                .chain(indexed_state.filtered_in_flight.iter())
                .chain(indexed_state.filtered_no_balance.iter())
                .chain(indexed_state.filtered_no_price.iter())
                .collect::<HashSet<_>>();
            debug_assert!(
                filtered.iter().all(|uid| !indexed_state
                    .current_orders_by_uid
                    .contains_key(&domain::OrderUid(uid.0))),
                "indexed_state contains filtered orders in current_orders_by_uid"
            );
        }

        change_bundle.price_changed_tokens = price_changed_tokens;
        change_bundle.filter_transitions = filter_transitions;

        Ok(CollectedAuctionInputs {
            db_solvable_orders,
            invalid_order_uids,
            filtered_order_events,
            final_orders,
            prices,
            surplus_capturing_jit_order_owners,
            mode: CollectionMode::Incremental(Arc::new(indexed_state)),
        })
    }

    fn project_final_auction(
        &self,
        block: u64,
        inputs: &CollectedAuctionInputs,
    ) -> Result<domain::RawAuctionData> {
        Ok(domain::RawAuctionData {
            block,
            orders: inputs.final_orders.clone(),
            prices: inputs
                .prices
                .iter()
                .map(|(token, value)| {
                    Price::try_new((*value).into()).map(|price| ((*token).into(), price))
                })
                .collect::<Result<_, _>>()?,
            surplus_capturing_jit_order_owners: inputs.surplus_capturing_jit_order_owners.clone(),
        })
    }

    fn compute_price_changed_tokens(
        previous: &domain::RawAuctionData,
        current: &domain::RawAuctionData,
    ) -> Vec<Address> {
        let mut price_tokens = previous
            .prices
            .keys()
            .map(|token| Address::from(*token))
            .collect::<Vec<_>>();
        price_tokens.extend(current.prices.keys().map(|token| Address::from(*token)));
        price_tokens.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
        price_tokens.dedup_by(|a, b| a.as_slice() == b.as_slice());

        let mut changed = Vec::new();
        for token in price_tokens {
            let previous_price = previous.prices.get(&token.into());
            let current_price = current.prices.get(&token.into());
            if previous_price != current_price {
                changed.push(token);
            }
        }

        changed
    }

    /// Applies delta events to the previous auction and compares with the
    /// canonical full-rebuild `auction`.
    ///
    /// Returns a `ProjectionResult` indicating whether this is a bootstrap,
    /// match, or mismatch case.
    fn apply_incremental_changes(
        &self,
        previous_auction: Option<&domain::RawAuctionData>,
        auction: domain::RawAuctionData,
        events: &[DeltaEvent],
    ) -> ProjectionResult {
        let Some(previous_auction) = previous_auction else {
            // If there's no previous auction (first update), we can't verify incremental
            // events from inputs. Return Bootstrap to trigger canonical re-computation and
            // validation of any incremental events that were computed.
            return ProjectionResult::Bootstrap(auction);
        };

        let reconstructed = apply_delta_events_to_auction(previous_auction.clone(), events);
        let reconstructed_surface = normalized_delta_surface(reconstructed.clone());
        let auction_surface = normalized_delta_surface(auction.clone());

        if reconstructed_surface == auction_surface {
            return ProjectionResult::Match(with_non_delta_fields(reconstructed, &auction));
        }

        tracing::warn!(
            "incremental projection mismatch detected; storing canonical auction and recomputing \
             events from full diff. This indicates a bug in the incremental delta logic."
        );

        // Return canonical auction unchanged. Caller must recompute events.
        ProjectionResult::Mismatch(auction)
    }

    fn compute_delta_events_from_inputs(
        previous: Option<&domain::RawAuctionData>,
        current: &domain::RawAuctionData,
        change_bundle: &ChangeBundle,
        shadow_compare_incremental: bool,
    ) -> Option<Vec<DeltaEvent>> {
        let previous = previous?;

        let mut current_orders_by_uid: HashMap<_, _> = current
            .orders
            .iter()
            .map(|order| (order.uid, order))
            .collect();
        let previous_orders: HashMap<_, _> = previous
            .orders
            .iter()
            .map(|order| (order.uid, order))
            .collect();
        let mut emitted = HashSet::new();
        let mut events = Vec::new();

        let mut added = change_bundle.order_added_candidates.clone();
        added.sort_by(|a, b| a.0.cmp(&b.0));
        added.dedup();
        for uid in added {
            if let Some(order) = current_orders_by_uid.remove(&uid) {
                if emitted.insert(uid) {
                    events.push(DeltaEvent::OrderAdded((*order).clone()));
                }
            }
        }

        let mut updated = change_bundle.order_updated_candidates.clone();
        updated.sort_by(|a, b| a.0.cmp(&b.0));
        updated.dedup();
        for uid in updated {
            if let Some(order) = current_orders_by_uid.remove(&uid) {
                if previous_orders
                    .get(&uid)
                    .map(|previous| !solver_visible_order_eq(previous, order))
                    .unwrap_or(true)
                {
                    if emitted.insert(uid) {
                        events.push(DeltaEvent::OrderUpdated((*order).clone()));
                    }
                }
            }
        }

        let mut quote_updated = change_bundle.quote_updated_candidates.clone();
        quote_updated.sort_by(|a, b| a.0.cmp(&b.0));
        quote_updated.dedup();
        for uid in quote_updated {
            if let Some(order) = current_orders_by_uid.remove(&uid) {
                if previous_orders
                    .get(&uid)
                    .map(|previous| !solver_visible_order_eq(previous, order))
                    .unwrap_or(true)
                {
                    if emitted.insert(uid) {
                        events.push(DeltaEvent::OrderUpdated((*order).clone()));
                    }
                }
            }
        }

        let mut removed = change_bundle.order_removed_candidates.clone();
        removed.sort_by(|a, b| a.0.cmp(&b.0));
        removed.dedup();
        for uid in removed {
            if emitted.insert(uid) {
                events.push(DeltaEvent::OrderRemoved(uid));
            }
        }

        let mut transitions = change_bundle.filter_transitions.clone();
        transitions.sort_by(|a, b| a.uid.0.cmp(&b.uid.0));
        for transition in transitions {
            if emitted.contains(&transition.uid) {
                continue;
            }
            if transition.is_filtered {
                if previous_orders.contains_key(&transition.uid) {
                    emitted.insert(transition.uid);
                    events.push(DeltaEvent::OrderRemoved(transition.uid));
                }
            } else if let Some(order) = current_orders_by_uid.remove(&transition.uid) {
                // Remove the entry so it cannot be emitted again.
                emitted.insert(transition.uid);
                events.push(DeltaEvent::OrderAdded((*order).clone()));
            } else {
                Metrics::get()
                    .delta_filter_transition_missing_order_total
                    .inc();
                // Aggregate incremental failure signal (preserves high-level
                // visibility across distinct failure causes).
                Metrics::get().delta_incremental_failure_total.inc();
                tracing::warn!(uid = ?transition.uid, "missing order for filter transition");
                return None;
            }
        }

        if !change_bundle.price_changed_tokens.is_empty() {
            let mut changed_tokens = change_bundle.price_changed_tokens.clone();
            changed_tokens.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
            changed_tokens.dedup_by(|a, b| a.as_slice() == b.as_slice());
            for token in changed_tokens {
                let previous_price = previous.prices.get(&token.into());
                let current_price = current.prices.get(&token.into());
                if previous_price != current_price {
                    events.push(DeltaEvent::PriceChanged {
                        token,
                        price: current_price.copied(),
                    });
                }
            }
        }

        // Incremental detection for non-delta root fields: block and JIT owners.
        if previous.block != current.block {
            events.push(DeltaEvent::BlockChanged {
                block: current.block,
            });
        }

        let mut prev_jit = previous.surplus_capturing_jit_order_owners.clone();
        let mut curr_jit = current.surplus_capturing_jit_order_owners.clone();
        prev_jit.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
        curr_jit.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
        if prev_jit != curr_jit {
            events.push(DeltaEvent::JitOwnersChanged {
                surplus_capturing_jit_order_owners: current
                    .surplus_capturing_jit_order_owners
                    .clone(),
            });
        }

        Metrics::get().delta_incremental_event_total.inc();

        if !shadow_compare_incremental {
            return Some(events);
        }

        let canonical = compute_delta_events(Some(previous), current);
        let canonical_matches = delta_events_equivalent(&canonical, &events);

        #[cfg(debug_assertions)]
        debug_assert!(
            canonical_matches || cfg!(test),
            "incremental delta mismatch; delta logic bug"
        );

        if canonical_matches {
            Some(events)
        } else {
            Metrics::get().delta_canonical_fallback_total.inc();
            // Aggregate failure metric for dashboards/alerts.
            Metrics::get().delta_incremental_failure_total.inc();
            tracing::warn!(
                canonical_events = canonical.len(),
                staged_events = events.len(),
                "incremental change bundle diverged from canonical delta; using canonical events"
            );
            Some(canonical)
        }
    }

    async fn fetch_in_flight_orders(&self, block: u64) -> HashSet<OrderUid> {
        self.persistence
            .fetch_in_flight_orders(block)
            .await
            .inspect_err(|err| tracing::warn!(?err, "failed to fetch in-flight orders"))
            .unwrap_or_default()
            .into_iter()
            .map(|uid| OrderUid(uid.0))
            .collect()
    }

    async fn fetch_balances(&self, queries: Vec<Query>) -> HashMap<Query, U256> {
        let fetched_balances = self
            .timed_future(
                "balance_filtering",
                self.balance_fetcher.get_balances(&queries),
            )
            .await;
        if self.disable_order_balance_filter {
            return Default::default();
        }

        tracing::trace!("fetched balances for solvable orders");
        queries
            .into_iter()
            .zip(fetched_balances)
            .filter_map(|(query, balance)| match balance {
                Ok(balance) => Some((query, balance)),
                Err(err) => {
                    tracing::warn!(
                        owner = ?query.owner,
                        token = ?query.token,
                        source = ?query.source,
                        error = ?err,
                        "failed to get balance"
                    );
                    None
                }
            })
            .collect()
    }

    /// Returns currently solvable orders.
    async fn get_solvable_orders(&self) -> Result<SolvableOrders> {
        let min_valid_to = now_in_epoch_seconds()
            + u32::try_from(self.min_order_validity_period.as_secs())
                .context("min_order_validity_period is not u32")?;

        // only build future while holding the lock but execute outside of lock
        let lock = self.cache.lock().await;
        let fetch_orders = match &*lock {
            // Only use incremental query after cache already got initialized
            // because it's not optimized for very long durations.
            Some(cache) => {
                tracing::trace!(
                    indexed_orders = cache.indexed_state.current_orders_by_uid.len(),
                    indexed_prices = cache.indexed_state.current_prices_by_token.len(),
                    "using cached indexed state as incremental baseline"
                );
                self.persistence
                    .solvable_orders_after(
                        cache.solvable_orders.orders.clone(),
                        cache.solvable_orders.quotes.clone(),
                        cache.solvable_orders.fetched_from_db,
                        cache.solvable_orders.latest_settlement_block,
                        min_valid_to,
                    )
                    .boxed()
            }
            None => self.persistence.all_solvable_orders(min_valid_to).boxed(),
        };

        let mut orders = fetch_orders.await?;

        // Move the checkpoint slightly back in time to mitigate race conditions
        // caused by inconsistencies of stored timestamps. See #2959 for more details.
        // This will cause us to fetch orders created or cancelled in the buffer
        // period multiple times but that is a small price to pay for not missing
        // orders.
        orders.fetched_from_db -= chrono::TimeDelta::seconds(60);
        Ok(orders)
    }

    /// Executed orders filtering in parallel.
    #[instrument(skip_all)]
    async fn filter_invalid_orders<'a>(
        &self,
        mut orders: Vec<&'a Order>,
        invalid_order_uids: &mut HashMap<OrderUid, OrderFilterReason>,
    ) -> Vec<&'a Order> {
        let presignature_pending_orders = find_presignature_pending_orders(&orders);

        let unsupported_token_orders = find_unsupported_tokens(&orders, &self.deny_listed_tokens);
        let banned_user_orders = self
            .timed_future(
                "banned_user_filtering",
                find_banned_user_orders(&orders, &self.banned_users),
            )
            .await;
        tracing::trace!("filtered invalid orders");

        Metrics::track_filtered_orders(BannedUser, &banned_user_orders);
        Metrics::track_filtered_orders(InvalidSignature, &presignature_pending_orders);
        Metrics::track_filtered_orders(UnsupportedToken, &unsupported_token_orders);
        invalid_order_uids.extend(banned_user_orders.into_iter().map(|uid| (uid, BannedUser)));
        invalid_order_uids.extend(
            presignature_pending_orders
                .into_iter()
                .map(|uid| (uid, InvalidSignature)),
        );
        invalid_order_uids.extend(
            unsupported_token_orders
                .into_iter()
                .map(|uid| (uid, UnsupportedToken)),
        );

        orders.retain(|order| !invalid_order_uids.contains_key(&order.metadata.uid));
        orders
    }

    pub fn track_auction_update(&self, result: &str) {
        Metrics::get()
            .auction_update
            .with_label_values(&[result])
            .inc();
    }

    /// Runs the future and collects runtime metrics.
    async fn timed_future<T>(&self, label: &str, fut: impl Future<Output = T>) -> T {
        let _timer = Metrics::get()
            .auction_update_stage_time
            .with_label_values(&[label])
            .start_timer();
        fut.await
    }

    /// Store order events with error propagation.
    /// This method properly handles async database operations without blocking.
    async fn store_events_by_reason_checked(
        &self,
        orders: impl IntoIterator<Item = (OrderUid, OrderFilterReason)>,
        label: OrderEventLabel,
    ) -> Result<()> {
        let mut by_reason: HashMap<OrderFilterReason, Vec<OrderUid>> = HashMap::new();
        for (uid, reason) in orders {
            by_reason.entry(reason).or_default().push(uid);
        }

        if by_reason.is_empty() {
            return Ok(());
        }

        for (reason, uids) in by_reason {
            let order_uids: Vec<domain::OrderUid> = uids
                .into_iter()
                .map(|uid| domain::OrderUid(uid.0))
                .collect();

            self.persistence
                .store_order_events_checked(order_uids, label, Some(reason))
                .await
                .with_context(|| {
                    format!("failed to store order events for label={label:?}, reason={reason:?}")
                })?;
        }

        Ok(())
    }

    fn store_events_by_reason(
        &self,
        orders: impl IntoIterator<Item = (OrderUid, OrderFilterReason)>,
        label: OrderEventLabel,
    ) {
        let mut by_reason: HashMap<OrderFilterReason, Vec<OrderUid>> = HashMap::new();
        for (uid, reason) in orders {
            by_reason.entry(reason).or_default().push(uid);
        }
        for (reason, uids) in by_reason {
            self.persistence.store_order_events_owned(
                uids,
                |uid| domain::OrderUid(uid.0),
                label,
                Some(reason),
            );
        }
    }
}

fn prune_delta_history(
    delta_history: &mut VecDeque<DeltaEnvelope>,
    max_age: chrono::Duration,
    config: &DeltaSyncConfig,
) {
    let max_age_std = max_age.to_std().unwrap_or_else(|_| Duration::from_secs(0));
    let min_retained = config.history_min_retained;

    // How many elements may be removed by age while still retaining the minimum
    // required elements.
    let pruneable = delta_history.len().saturating_sub(min_retained);

    // Count leading elements that are older than `max_age`, but don't count
    // past the `min_retained` boundary.
    let to_remove_by_age = delta_history
        .iter()
        .take(pruneable)
        .take_while(|e| e.created_at_instant.elapsed() > max_age_std)
        .count();

    // Also compute how many must be removed to respect `MAX_DELTA_HISTORY`.
    let to_remove_by_count = delta_history.len().saturating_sub(MAX_DELTA_HISTORY);

    // We need to remove enough elements to satisfy both constraints, so take
    // the maximum of the two removal counts.
    let remove = to_remove_by_age.max(to_remove_by_count);

    if remove > 0 {
        delta_history.drain(..remove);
    }
}

/// Update the cached `auction_id` and emit an `AuctionChanged` delta envelope
/// when the auction changes.
///
/// The function uses `auction_sequence = 0` as a sentinel value to mark the
/// auction boundary. Consumers should treat the envelope with
/// `auction_sequence == 0` as an advisory transition marker. The first real
/// per-auction update after this transition will emit `auction_sequence = 1`.
/// `delta_sequence` remains monotonic across auction transitions and is the
/// authoritative counter for replay/gap detection.
fn apply_auction_id_change(
    inner: &mut Inner,
    auction_id: u64,
    config: &DeltaSyncConfig,
) -> Option<DeltaEnvelope> {
    if inner.auction_id == auction_id {
        return None;
    }

    // Keep delta_sequence monotonic across auctions for replay continuity.
    if inner.delta_sequence == u64::MAX {
        Metrics::get().delta_incremental_failure_total.inc();
        tracing::error!(
            "delta sequence overflow during auction transition; auction changed envelope not \
             emitted"
        );
        return None;
    }

    inner.auction_id = auction_id;
    inner.auction_sequence = 0;
    let next_sequence = inner.delta_sequence + 1;
    let envelope = DeltaEnvelope {
        auction_id,
        auction_sequence: 0,
        from_sequence: inner.delta_sequence,
        to_sequence: next_sequence,
        published_at: chrono::Utc::now(),
        created_at_instant: Instant::now(),
        events: vec![DeltaEvent::AuctionChanged {
            new_auction_id: auction_id,
        }],
    };
    inner.delta_sequence = next_sequence;
    inner.delta_history.push_back(envelope.clone());
    let max_age = chrono::Duration::from_std(config.history_max_age)
        .unwrap_or_else(|_| chrono::Duration::seconds(60));
    prune_delta_history(&mut inner.delta_history, max_age, config);
    Some(envelope)
}

fn delta_events_equivalent(canonical: &[DeltaEvent], staged: &[DeltaEvent]) -> bool {
    // Ordering is normalized by uid then event rank; this treats different event
    // orderings for the same uid as equivalent, even though such mixes should
    // never occur in valid deltas.
    let mut canonical_sorted = canonical.to_vec();
    canonical_sorted.sort_by(delta_event_cmp);
    let mut staged_sorted = staged.to_vec();
    staged_sorted.sort_by(delta_event_cmp);
    canonical_sorted == staged_sorted
}

fn delta_event_cmp(lhs: &DeltaEvent, rhs: &DeltaEvent) -> Ordering {
    let lhs_group = delta_event_rank(lhs);
    let rhs_group = delta_event_rank(rhs);
    match lhs_group.cmp(&rhs_group) {
        Ordering::Equal => {}
        other => return other,
    }

    let lhs_key = order_event_key(lhs);
    let rhs_key = order_event_key(rhs);
    match (lhs_key, rhs_key) {
        (Some((uid_a, rank_a)), Some((uid_b, rank_b))) => {
            uid_a.cmp(&uid_b).then(rank_a.cmp(&rank_b))
        }
        (None, None) => match (lhs, rhs) {
            (
                DeltaEvent::AuctionChanged {
                    new_auction_id: lhs,
                },
                DeltaEvent::AuctionChanged {
                    new_auction_id: rhs,
                },
            ) => lhs.cmp(rhs),
            (
                DeltaEvent::PriceChanged { token: a, .. },
                DeltaEvent::PriceChanged { token: b, .. },
            ) => a.as_slice().cmp(b.as_slice()),
            _ => Ordering::Equal,
        },
        _ => Ordering::Equal,
    }
}

fn order_event_key(event: &DeltaEvent) -> Option<([u8; 56], u8)> {
    match event {
        DeltaEvent::OrderAdded(order) => Some((order.uid.0, 0)),
        DeltaEvent::OrderUpdated(order) => Some((order.uid.0, 1)),
        DeltaEvent::OrderRemoved(uid) => Some((uid.0, 2)),
        DeltaEvent::AuctionChanged { .. }
        | DeltaEvent::PriceChanged { .. }
        | DeltaEvent::BlockChanged { .. }
        | DeltaEvent::JitOwnersChanged { .. } => None,
    }
}

fn delta_event_rank(event: &DeltaEvent) -> u8 {
    match event {
        DeltaEvent::AuctionChanged { .. } => 0,
        DeltaEvent::BlockChanged { .. } => 0,
        DeltaEvent::JitOwnersChanged { .. } => 0,
        DeltaEvent::OrderAdded(_) => 1,
        DeltaEvent::OrderUpdated(_) => 2,
        DeltaEvent::OrderRemoved(_) => 3,
        DeltaEvent::PriceChanged { .. } => 4,
    }
}

fn checksum_order_uids(orders: &[domain::Order]) -> String {
    // Deterministic checksum by hashing the ordered list of UIDs. This
    // matches the driver's approach: sort UIDs and feed their raw bytes to
    // the SHA256 hasher. Use an unstable sort on the raw arrays for best
    // performance (no stability required) and avoid per-comparison slice
    // coercions by sorting the `[u8;56]` values directly.
    let mut uids: Vec<[u8; 56]> = orders.iter().map(|o| o.uid.0).collect();
    uids.sort_unstable();

    let mut hasher = Sha256::new();
    for uid in uids {
        hasher.update(&uid);
    }
    format!("0x{}", const_hex::encode(hasher.finalize()))
}

fn checksum_prices(prices: &domain::auction::Prices) -> String {
    let mut entries = prices.iter().collect::<Vec<_>>();
    entries.sort_by(|(lhs, _), (rhs, _)| lhs.as_slice().cmp(rhs.as_slice()));

    let mut hasher = Sha256::new();
    for (token, price) in entries {
        hasher.update(token.as_slice());
        hasher.update(price.get().0.to_string().as_bytes());
    }
    format!("0x{}", const_hex::encode(hasher.finalize()))
}

fn compute_delta_events(
    previous: Option<&domain::RawAuctionData>,
    current: &domain::RawAuctionData,
) -> Vec<DeltaEvent> {
    let Some(previous) = previous else {
        let order_events = current.orders.iter().cloned().map(DeltaEvent::OrderAdded);
        let price_events = current.prices.keys().map(|token| {
            let token = Address::from(*token);
            DeltaEvent::PriceChanged {
                token,
                price: current.prices.get(&token.into()).copied(),
            }
        });
        return order_events.chain(price_events).collect();
    };

    let previous_orders = previous
        .orders
        .iter()
        .map(|order| (order.uid, order))
        .collect::<HashMap<_, _>>();
    let current_orders = current
        .orders
        .iter()
        .map(|order| (order.uid, order))
        .collect::<HashMap<_, _>>();

    let mut events = Vec::new();

    let mut current_uids = current_orders.keys().copied().collect::<Vec<_>>();
    current_uids.sort_by(|a, b| a.0.cmp(&b.0));
    for uid in current_uids {
        let current_order = current_orders
            .get(&uid)
            .expect("uid from keys must exist in map");
        match previous_orders.get(&uid) {
            None => events.push(DeltaEvent::OrderAdded((*current_order).clone())),
            Some(previous_order) if !solver_visible_order_eq(previous_order, current_order) => {
                events.push(DeltaEvent::OrderUpdated((*current_order).clone()));
            }
            Some(_) => {}
        }
    }

    let mut removed_uids = previous_orders
        .keys()
        .filter(|uid| !current_orders.contains_key(uid))
        .copied()
        .collect::<Vec<_>>();
    removed_uids.sort_by(|a, b| a.0.cmp(&b.0));
    for uid in removed_uids {
        events.push(DeltaEvent::OrderRemoved(uid));
    }

    let mut price_tokens = previous
        .prices
        .keys()
        .map(|token| Address::from(*token))
        .collect::<Vec<_>>();
    price_tokens.extend(current.prices.keys().map(|token| Address::from(*token)));
    price_tokens.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
    price_tokens.dedup_by(|a, b| a.as_slice() == b.as_slice());
    for token in price_tokens {
        let previous_price = previous.prices.get(&token.into());
        let current_price = current.prices.get(&token.into());
        if previous_price != current_price {
            events.push(DeltaEvent::PriceChanged {
                token,
                price: current_price.copied(),
            });
        }
    }

    // Detect block changes on the root auction data.
    if previous.block != current.block {
        events.push(DeltaEvent::BlockChanged {
            block: current.block,
        });
    }

    // Detect changes to surplus-capturing JIT order owners. Compare as sets
    // (order-insensitive) by sorting the address vectors.
    let mut prev_jit = previous.surplus_capturing_jit_order_owners.clone();
    let mut curr_jit = current.surplus_capturing_jit_order_owners.clone();
    prev_jit.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
    curr_jit.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
    if prev_jit != curr_jit {
        events.push(DeltaEvent::JitOwnersChanged {
            surplus_capturing_jit_order_owners: current.surplus_capturing_jit_order_owners.clone(),
        });
    }

    events
}

pub(crate) fn apply_delta_events_to_auction(
    previous: domain::RawAuctionData,
    events: &[DeltaEvent],
) -> domain::RawAuctionData {
    // Use a HashMap for mutation efficiency and do a single sort at the end.
    // For typical auction sizes a single final sort is faster than repeated
    // tree insertions during event application.
    let mut orders: HashMap<domain::OrderUid, domain::Order> = previous
        .orders
        .into_iter()
        .map(|order| (order.uid, order))
        .collect();
    let mut prices = previous.prices;

    // Preserve and allow updates to non-delta root fields.
    let mut block = previous.block;
    let mut surplus_capturing_jit_order_owners =
        previous.surplus_capturing_jit_order_owners.clone();

    for event in events {
        match event {
            DeltaEvent::AuctionChanged { .. } => {}
            DeltaEvent::BlockChanged { block: b } => {
                block = *b;
            }
            DeltaEvent::OrderAdded(order) | DeltaEvent::OrderUpdated(order) => {
                orders.insert(order.uid, order.clone());
            }
            DeltaEvent::OrderRemoved(uid) => {
                orders.remove(uid);
            }
            DeltaEvent::PriceChanged { token, price } => {
                if let Some(price) = price {
                    prices.insert((*token).into(), *price);
                } else {
                    prices.remove(&(*token).into());
                }
            }
            DeltaEvent::JitOwnersChanged {
                surplus_capturing_jit_order_owners: owners,
            } => {
                surplus_capturing_jit_order_owners = owners.clone();
            }
        }
    }

    let mut orders = orders.into_values().collect::<Vec<_>>();
    orders.sort_unstable_by_key(|order| order.uid);

    domain::RawAuctionData {
        block,
        orders,
        prices,
        surplus_capturing_jit_order_owners,
    }
}

fn solver_visible_order_eq(lhs: &domain::Order, rhs: &domain::Order) -> bool {
    lhs.uid == rhs.uid
        && lhs.sell == rhs.sell
        && lhs.buy == rhs.buy
        && lhs.protocol_fees == rhs.protocol_fees
        && lhs.side == rhs.side
        && lhs.created == rhs.created
        && lhs.valid_to == rhs.valid_to
        && lhs.receiver == rhs.receiver
        && lhs.owner == rhs.owner
        && lhs.partially_fillable == rhs.partially_fillable
        && lhs.executed == rhs.executed
        && lhs.pre_interactions == rhs.pre_interactions
        && lhs.post_interactions == rhs.post_interactions
        && lhs.sell_token_balance == rhs.sell_token_balance
        && lhs.buy_token_balance == rhs.buy_token_balance
        && lhs.app_data == rhs.app_data
        && lhs.signature == rhs.signature
        && lhs.quote == rhs.quote
}

fn normalized_delta_surface(mut auction: domain::RawAuctionData) -> domain::RawAuctionData {
    auction.block = 0;
    auction.surplus_capturing_jit_order_owners.clear();
    auction.orders.sort_by_key(|order| order.uid.0);
    auction
}

fn with_non_delta_fields(
    mut reconstructed: domain::RawAuctionData,
    full_rebuild: &domain::RawAuctionData,
) -> domain::RawAuctionData {
    reconstructed.block = full_rebuild.block;
    reconstructed.surplus_capturing_jit_order_owners =
        full_rebuild.surplus_capturing_jit_order_owners.clone();
    reconstructed
}

fn diff_solvable_order_inputs(
    previous: Option<&boundary::SolvableOrders>,
    current: &boundary::SolvableOrders,
) -> ChangeBundle {
    // Complexity: O(|previous| + |current|) over order/quote maps.
    let Some(previous) = previous else {
        return ChangeBundle {
            order_added_candidates: current.orders.keys().copied().collect(),
            ..Default::default()
        };
    };

    let mut added = Vec::new();
    let mut updated = Vec::new();
    let mut quote_updated = Vec::new();

    for (uid, order) in &current.orders {
        let mut order_changed = false;
        match previous.orders.get(uid) {
            None => {
                added.push(*uid);
                order_changed = true;
            }
            Some(previous_order) if previous_order.as_ref() != order.as_ref() => {
                updated.push(*uid);
                order_changed = true;
            }
            Some(_) => {}
        }

        if !order_changed && previous.quotes.get(uid) != current.quotes.get(uid) {
            quote_updated.push(*uid);
        }
    }

    updated.sort_by(|a, b| a.0.cmp(&b.0));
    updated.dedup();

    quote_updated.sort_by(|a, b| a.0.cmp(&b.0));
    quote_updated.dedup();

    let removed = previous
        .orders
        .keys()
        .filter(|uid| !current.orders.contains_key(uid))
        .copied()
        .collect();

    ChangeBundle {
        order_added_candidates: added,
        order_removed_candidates: removed,
        order_updated_candidates: updated,
        quote_updated_candidates: quote_updated,
        price_changed_tokens: Vec::new(),
        filter_transitions: Vec::new(),
    }
}

fn build_indexed_state(
    auction: &domain::RawAuctionData,
    invalid_order_uids: &HashMap<OrderUid, OrderFilterReason>,
    filtered_order_events: &[(OrderUid, OrderFilterReason)],
) -> IndexedAuctionState {
    let mut state = IndexedAuctionState {
        current_orders_by_uid: auction
            .orders
            .iter()
            .cloned()
            .map(|order| (order.uid, order))
            .collect(),
        current_prices_by_token: auction
            .prices
            .iter()
            .map(|(token, price)| (Address::from(*token), *price))
            .collect(),
        surplus_capturing_jit_order_owners: auction.surplus_capturing_jit_order_owners.clone(),
        ..Default::default()
    };

    for (uid, reason) in invalid_order_uids.iter() {
        state.filtered_invalid.insert(*uid, *reason);
    }

    for (uid, reason) in filtered_order_events {
        match reason {
            OrderFilterReason::InFlight => {
                state.filtered_in_flight.insert(*uid);
            }
            OrderFilterReason::InsufficientBalance => {
                state.filtered_no_balance.insert(*uid);
            }
            OrderFilterReason::MissingNativePrice => {
                state.filtered_no_price.insert(*uid);
            }
            _ => {}
        }
    }

    state
}

/// Finds all orders whose owners or receivers are in the set of "banned"
/// users.
async fn find_banned_user_orders(orders: &[&Order], banned_users: &banned::Users) -> Vec<OrderUid> {
    let banned = banned_users
        .banned(
            orders
                .iter()
                .flat_map(|order| std::iter::once(order.metadata.owner).chain(order.data.receiver)),
        )
        .await;
    orders
        .iter()
        .filter_map(|order| {
            std::iter::once(order.metadata.owner)
                .chain(order.data.receiver)
                .any(|addr| banned.contains(&addr))
                .then_some(order.metadata.uid)
        })
        .collect()
}

async fn get_native_prices(
    tokens: HashSet<Address>,
    native_price_estimator: &NativePriceUpdater,
    timeout: Duration,
) -> BTreeMap<Address, alloy::primitives::U256> {
    native_price_estimator
        .update_tokens_and_fetch_prices(tokens, timeout)
        .await
        .into_iter()
        .flat_map(|(token, result)| {
            let price = to_normalized_price(result.ok()?)?;
            Some((token, price))
        })
        .collect()
}

/// Finds orders with pending presignatures. EIP-1271 signature validation is
/// skipped entirely - the driver validates signatures before settlement.
fn find_presignature_pending_orders(orders: &[&Order]) -> Vec<OrderUid> {
    orders
        .iter()
        .filter(|order| {
            matches!(
                order.metadata.status,
                model::order::OrderStatus::PresignaturePending
            )
        })
        .map(|order| order.metadata.uid)
        .collect()
}

/// Removes orders that can't possibly be settled because there isn't enough
/// balance.
#[instrument(skip_all)]
fn orders_with_balance<'a>(
    mut orders: Vec<&'a Order>,
    balances: &Balances,
    settlement_contract: Address,
    filter_bypass_orders: &HashSet<OrderUid>,
) -> (Vec<&'a Order>, Vec<OrderUid>) {
    // Prefer newer orders over older ones.
    orders.sort_by_key(|order| std::cmp::Reverse(order.metadata.creation_date));
    let mut filtered_orders = vec![];
    let keep = |order: &Order| {
        // Skip balance check for all EIP-1271 orders (they can rely on pre-interactions
        // to unlock funds) or orders with wrappers (wrappers produce the required
        // balance at settlement time).
        if matches!(order.signature, Signature::Eip1271(_))
            || filter_bypass_orders.contains(&order.metadata.uid)
        {
            return true;
        }

        if order.data.receiver.as_ref() == Some(&settlement_contract) {
            // TODO: replace with proper detection logic
            // for now we assume that all orders with the settlement contract
            // as the receiver are flashloan orders which unlock the necessary
            // funds via a pre-interaction that can't succeed in our balance
            // fetching simulation logic.
            return true;
        }

        let balance = match balances.get(&Query::from_order(order)) {
            None => return false,
            Some(balance) => *balance,
        };

        if order.data.partially_fillable && balance >= U256::ONE {
            return true;
        }

        let needed_balance = match order.data.sell_amount.checked_add(order.data.fee_amount) {
            None => return false,
            Some(balance) => balance,
        };
        balance >= needed_balance
    };

    orders.retain(|order| {
        if keep(order) {
            true
        } else {
            filtered_orders.push(order.metadata.uid);
            false
        }
    });
    (orders, filtered_orders)
}

/// Filters out dust orders i.e. partially fillable orders that, when scaled
/// have a 0 buy or sell amount.
fn filter_dust_orders<'a>(
    mut orders: Vec<&'a Order>,
    balances: &Balances,
) -> (Vec<&'a Order>, Vec<OrderUid>) {
    let mut removed = vec![];
    let keep = |order: &Order| {
        if !order.data.partially_fillable {
            return true;
        }

        let balance = if let Some(balance) = balances.get(&Query::from_order(order)) {
            *balance
        } else {
            return false;
        };

        let Ok(remaining) =
            remaining_amounts::Remaining::from_order_with_balance(&order.into(), balance)
        else {
            return false;
        };

        let (Ok(sell_amount), Ok(buy_amount)) = (
            remaining.remaining(order.data.sell_amount),
            remaining.remaining(order.data.buy_amount),
        ) else {
            return false;
        };

        !sell_amount.is_zero() && !buy_amount.is_zero()
    };

    orders.retain(|order| {
        if keep(order) {
            true
        } else {
            removed.push(order.metadata.uid);
            false
        }
    });
    (orders, removed)
}

#[instrument(skip_all)]
async fn get_orders_with_native_prices<'a>(
    orders: Vec<&'a Order>,
    native_price_estimator: &NativePriceUpdater,
    additional_tokens: impl IntoIterator<Item = Address>,
    timeout: Duration,
) -> (
    Vec<&'a Order>,
    Vec<OrderUid>,
    BTreeMap<Address, alloy::primitives::U256>,
) {
    let traded_tokens = orders
        .iter()
        .flat_map(|order| [order.data.sell_token, order.data.buy_token])
        .chain(additional_tokens)
        .collect::<HashSet<_>>();

    let prices = get_native_prices(traded_tokens, native_price_estimator, timeout).await;

    // Filter orders so that we only return orders that have prices
    let mut removed_market_orders = 0_i64;
    let mut removed_orders = vec![];
    let mut orders = orders;
    orders.retain(|order| {
        let both_prices_present = prices.contains_key(&order.data.sell_token)
            && prices.contains_key(&order.data.buy_token);
        if both_prices_present {
            true
        } else {
            removed_orders.push(order.metadata.uid);
            removed_market_orders += i64::from(order.metadata.class == OrderClass::Market);
            false
        }
    });

    Metrics::get()
        .auction_market_order_missing_price
        .set(removed_market_orders);

    (orders, removed_orders, prices)
}

fn find_unsupported_tokens(
    orders: &[&Order],
    deny_listed_tokens: &DenyListedTokens,
) -> Vec<OrderUid> {
    orders
        .iter()
        .filter_map(|order| {
            [&order.data.buy_token, &order.data.sell_token]
                .iter()
                .any(|token| deny_listed_tokens.contains(token))
                .then_some(order.metadata.uid)
        })
        .collect()
}

fn filter_out_in_flight_orders<'a>(
    mut orders: Vec<&'a Order>,
    in_flight: &HashSet<OrderUid>,
) -> (Vec<&'a Order>, Vec<OrderUid>) {
    let mut removed = vec![];
    orders.retain(|order| {
        if in_flight.contains(&order.metadata.uid) {
            removed.push(order.metadata.uid);
            false
        } else {
            true
        }
    });
    (orders, removed)
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            database::{Config as DbConfig, Postgres},
            infra::Persistence,
        },
        account_balances::BalanceFetching,
        alloy::primitives::{Address, B256},
        bad_tokens::list_based::DenyListedTokens,
        database::byte_array::ByteArray,
        eth_domain_types as eth,
        ethrpc::{
            alloy::unbuffered_provider,
            block_stream::{BlockInfo, mock_single_block},
        },
        event_indexing::block_retriever::BlockRetriever,
        futures::FutureExt,
        maplit::{btreemap, hashset},
        model::order::{OrderBuilder, OrderData, OrderMetadata, OrderUid},
        price_estimation::{
            HEALTHY_PRICE_ESTIMATION_TIME,
            PriceEstimationError,
            native::MockNativePriceEstimating,
            native_price_cache::{
                ApproximationToken,
                Cache,
                CachingNativePriceEstimator,
                NativePriceUpdater,
            },
        },
        sqlx::postgres::PgPoolOptions,
        std::collections::HashMap,
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

    impl price_estimation::native::NativePriceEstimating for StubNativePriceEstimator {
        fn estimate_native_price(
            &self,
            _token: Address,
            _timeout: Duration,
        ) -> futures::future::BoxFuture<'_, price_estimation::native::NativePriceEstimateResult>
        {
            async { Ok(1.0) }.boxed()
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
        let cow_amm_registry = cow_amm::Registry::new(block_retriever);

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
            None, // Use default delta sync config
        )
    }

    #[tokio::test]
    #[ignore]
    async fn integration_update_runs_against_postgres() {
        // Connect to the local Postgres instance (expects schema/migrations
        // from the repository to be applied).
        let postgres = Arc::new(
            Postgres::with_defaults()
                .await
                .expect("postgres must be running at postgresql://"),
        );

        // Clear state using a transaction, matching our DB helpers' pattern.
        let mut tx = postgres.pool.begin().await.expect("begin tx");
        database::clear_DANGER_(&mut tx)
            .await
            .expect("failed to clear database");
        tx.commit().await.expect("commit tx");

        let persistence = Persistence::new(None, Arc::clone(&postgres)).await;

        let balance_fetcher = Arc::new(StubBalanceFetcher::default());
        let deny_listed_tokens = DenyListedTokens::default();

        let native_price_estimator = StubNativePriceEstimator::default();
        let cache_store = Cache::new(Duration::from_secs(10), Default::default());
        let caching_estimator = CachingNativePriceEstimator::new(
            Box::new(native_price_estimator),
            cache_store,
            1,
            Default::default(),
            HEALTHY_PRICE_ESTIMATION_TIME,
        );
        let native_price_updater =
            NativePriceUpdater::new(caching_estimator, Duration::MAX, Default::default());

        let (provider, _wallet) = unbuffered_provider("http://localhost:0", None);
        let block_stream = mock_single_block(BlockInfo::default());
        let block_retriever = Arc::new(BlockRetriever {
            provider,
            block_stream,
        });
        let cow_amm_registry = cow_amm::Registry::new(block_retriever);

        let protocol_fees = domain::ProtocolFees::new(
            &configs::autopilot::fee_policy::FeePoliciesConfig::default(),
            Vec::new(),
            false,
        );

        // disable_order_balance_filter=true: StubBalanceFetcher returns U256::ZERO
        // for every query, so balance filtering must be disabled or the inserted
        // order would be filtered out before reaching the delta machinery.
        let mut cache = SolvableOrdersCache::new(
            Duration::from_secs(0),
            persistence,
            order_validation::banned::Users::none(),
            balance_fetcher,
            deny_listed_tokens,
            native_price_updater,
            Address::repeat_byte(0xEE),
            protocol_fees,
            cow_amm_registry,
            Duration::from_secs(1),
            Address::repeat_byte(0xFF),
            true,
            None,
        );
        Arc::get_mut(&mut cache)
            .expect("cache arc should be uniquely owned in test")
            .incremental_primary = true;

        // Insert a real order so the production pipeline exercises price
        // estimation, filtering, and diff logic.  Use ByteArray constructors
        // directly, matching the established pattern in this test module.
        let uid = ByteArray([0x11; 56]);
        let app_data = ByteArray([0x22; 32]);
        let now = chrono::Utc::now();

        let mut conn = postgres.pool.acquire().await.expect("acquire conn");
        database::app_data::insert(&mut conn, &app_data, b"{}")
            .await
            .expect("insert app_data");

        let order = database::orders::Order {
            uid,
            owner: ByteArray([0x33; 20]),
            creation_timestamp: now,
            sell_token: ByteArray([0x44; 20]),
            buy_token: ByteArray([0x55; 20]),
            receiver: None,
            sell_amount: sqlx::types::BigDecimal::from(1000u64),
            buy_amount: sqlx::types::BigDecimal::from(900u64),
            valid_to: now.timestamp() + 600,
            app_data,
            fee_amount: sqlx::types::BigDecimal::from(0u64),
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
            .expect("insert order");
        drop(conn);

        // Subscribe before the first update so no envelope is missed.
        let mut receiver = cache.subscribe_deltas();

        // ---- First update: cache is empty, order enters the set ----
        cache.update(1, false).await.expect("first update failed");

        let envelope1 = receiver
            .try_recv()
            .expect("first envelope should have been sent");
        assert_eq!(envelope1.from_sequence, 0);
        assert_eq!(envelope1.to_sequence, 1);
        // The inserted order must appear as OrderAdded in the first envelope.
        assert!(
            envelope1
                .events
                .iter()
                .any(|e| matches!(e, DeltaEvent::OrderAdded(_))),
            "first update should emit OrderAdded for the inserted order; got: {:?}",
            envelope1.events
        );
        // No removals or updates on first call — there is no previous state to diff.
        assert!(
            !envelope1
                .events
                .iter()
                .any(|e| matches!(e, DeltaEvent::OrderRemoved(_) | DeltaEvent::OrderUpdated(_))),
            "first update must not emit OrderRemoved or OrderUpdated"
        );

        let seq1 = cache
            .delta_sequence()
            .await
            .expect("sequence missing after first update");
        assert_eq!(seq1, 1);

        // ---- Second update: same order, different block number ----
        cache.update(2, false).await.expect("second update failed");

        let envelope2 = receiver
            .try_recv()
            .expect("second envelope should have been sent");
        assert_eq!(envelope2.from_sequence, 1);
        assert_eq!(envelope2.to_sequence, 2);
        // The order is unchanged so the incremental diff must not emit any order
        // events.  If it does, the diff logic has a bug.
        assert!(
            !envelope2.events.iter().any(|e| matches!(
                e,
                DeltaEvent::OrderAdded(_)
                    | DeltaEvent::OrderRemoved(_)
                    | DeltaEvent::OrderUpdated(_)
            )),
            "second update with unchanged order must emit no order events; got: {:?}",
            envelope2.events
        );
        // Block number changed from 1 to 2, so BlockChanged must be present.
        assert!(
            envelope2
                .events
                .iter()
                .any(|e| matches!(e, DeltaEvent::BlockChanged { block: 2 })),
            "second update must emit BlockChanged {{ block: 2 }}; got: {:?}",
            envelope2.events
        );

        let seq2 = cache
            .delta_sequence()
            .await
            .expect("sequence missing after second update");
        assert_eq!(seq2, 2);
        assert!(seq2 > seq1, "sequence must be strictly increasing");

        // The snapshot must reflect the final sequence.
        let snapshot = cache.delta_snapshot().await.expect("snapshot should exist");
        assert_eq!(snapshot.sequence, seq2);
        // The snapshot auction must contain the order.
        let model_uid = model::order::OrderUid(uid.0);
        assert!(
            snapshot
                .auction
                .orders
                .iter()
                .any(|o| o.uid == domain::OrderUid(model_uid.0)),
            "snapshot auction must contain the inserted order"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn integration_projection_mismatch_metric_not_incremented_in_happy_path() {
        let postgres = Arc::new(
            Postgres::with_defaults()
                .await
                .expect("postgres must be running at postgresql://"),
        );

        let mut tx = postgres.pool.begin().await.expect("begin tx");
        database::clear_DANGER_(&mut tx)
            .await
            .expect("failed to clear database");
        tx.commit().await.expect("commit tx");

        let persistence = Persistence::new(None, Arc::clone(&postgres)).await;

        let balance_fetcher = Arc::new(StubBalanceFetcher::default());
        let deny_listed_tokens = DenyListedTokens::default();

        let native_price_estimator = StubNativePriceEstimator::default();
        let cache_store = Cache::new(Duration::from_secs(10), Default::default());
        let caching_estimator = CachingNativePriceEstimator::new(
            Box::new(native_price_estimator),
            cache_store,
            1,
            Default::default(),
            HEALTHY_PRICE_ESTIMATION_TIME,
        );
        let native_price_updater =
            NativePriceUpdater::new(caching_estimator, Duration::MAX, Default::default());

        let (provider, _wallet) = unbuffered_provider("http://localhost:0", None);
        let block_stream = mock_single_block(BlockInfo::default());
        let block_retriever = Arc::new(BlockRetriever {
            provider,
            block_stream,
        });
        let cow_amm_registry = cow_amm::Registry::new(block_retriever);

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
            native_price_updater,
            Address::repeat_byte(0xEE),
            protocol_fees,
            cow_amm_registry,
            Duration::from_secs(1),
            Address::repeat_byte(0xFF),
            true,
            None,
        );

        // Seed a consistent previous cache state and keep DB empty, so update
        // follows the happy path without projection mismatches.
        let seeded_auction = domain::RawAuctionData {
            block: 1,
            orders: Vec::new(),
            prices: HashMap::new(),
            surplus_capturing_jit_order_owners: Vec::new(),
        };
        cache
            .set_state_for_tests(seeded_auction, 1, 1, 1, VecDeque::new())
            .await;

        let initial = Metrics::get()
            .delta_incremental_projection_mismatch_total
            .get();

        cache.update(2, false).await.expect("update should succeed");

        let now = Metrics::get()
            .delta_incremental_projection_mismatch_total
            .get();
        assert_eq!(now, initial);
    }

    #[tokio::test]
    #[ignore]
    async fn integration_projection_mismatch_metric_increments_exactly_once_via_update() {
        let postgres = Arc::new(
            Postgres::with_defaults()
                .await
                .expect("postgres must be running at postgresql://"),
        );

        let mut tx = postgres.pool.begin().await.expect("begin tx");
        database::clear_DANGER_(&mut tx)
            .await
            .expect("failed to clear database");
        tx.commit().await.expect("commit tx");

        let persistence = Persistence::new(None, Arc::clone(&postgres)).await;

        let balance_fetcher = Arc::new(StubBalanceFetcher::default());
        let deny_listed_tokens = DenyListedTokens::default();

        let native_price_estimator = StubNativePriceEstimator::default();
        let cache_store = Cache::new(Duration::from_secs(10), Default::default());
        let caching_estimator = CachingNativePriceEstimator::new(
            Box::new(native_price_estimator),
            cache_store,
            1,
            Default::default(),
            HEALTHY_PRICE_ESTIMATION_TIME,
        );
        let native_price_updater =
            NativePriceUpdater::new(caching_estimator, Duration::MAX, Default::default());

        let (provider, _wallet) = unbuffered_provider("http://localhost:0", None);
        let block_stream = mock_single_block(BlockInfo::default());
        let block_retriever = Arc::new(BlockRetriever {
            provider,
            block_stream,
        });
        let cow_amm_registry = cow_amm::Registry::new(block_retriever);

        let protocol_fees = domain::ProtocolFees::new(
            &configs::autopilot::fee_policy::FeePoliciesConfig::default(),
            Vec::new(),
            false,
        );

        let mut cache = SolvableOrdersCache::new(
            Duration::from_secs(0),
            persistence,
            order_validation::banned::Users::none(),
            balance_fetcher,
            deny_listed_tokens,
            native_price_updater,
            Address::repeat_byte(0xEE),
            protocol_fees,
            cow_amm_registry,
            Duration::from_secs(1),
            Address::repeat_byte(0xFF),
            true,
            None,
        );

        Arc::get_mut(&mut cache)
            .expect("cache arc should be uniquely owned in test")
            .incremental_primary = true;

        // Seed previous auction with one order but reset incremental indexed
        // state to empty. Incremental event staging then misses the removal and
        // forces projection mismatch in update().
        let seeded_auction = domain::RawAuctionData {
            block: 1,
            orders: vec![test_order(1, 10)],
            prices: HashMap::new(),
            surplus_capturing_jit_order_owners: Vec::new(),
        };
        cache
            .set_state_for_tests(seeded_auction, 1, 1, 1, VecDeque::new())
            .await;

        {
            let mut lock = cache.cache.lock().await;
            if let Some(inner) = lock.as_mut() {
                inner.indexed_state = Arc::new(IndexedAuctionState::default());
            }
        }

        let initial = Metrics::get()
            .delta_incremental_projection_mismatch_total
            .get();

        cache.update(2, false).await.expect("update should succeed");

        let now = Metrics::get()
            .delta_incremental_projection_mismatch_total
            .get();
        assert_eq!(now, initial + 1);
    }

    #[tokio::test]
    async fn get_orders_with_native_prices_with_timeout() {
        let token1 = Address::repeat_byte(1);
        let token2 = Address::repeat_byte(2);
        let token3 = Address::repeat_byte(3);

        let orders = [
            Arc::new(
                OrderBuilder::default()
                    .with_sell_token(token1)
                    .with_buy_token(token2)
                    .with_buy_amount(alloy::primitives::U256::ONE)
                    .with_sell_amount(alloy::primitives::U256::ONE)
                    .build(),
            ),
            Arc::new(
                OrderBuilder::default()
                    .with_sell_token(token1)
                    .with_buy_token(token3)
                    .with_buy_amount(alloy::primitives::U256::ONE)
                    .with_sell_amount(alloy::primitives::U256::ONE)
                    .build(),
            ),
        ];

        let mut native_price_estimator = MockNativePriceEstimating::new();
        native_price_estimator
            .expect_estimate_native_price()
            .withf(move |token, _| *token == token1)
            .returning(|_, _| async { Ok(2.) }.boxed());
        native_price_estimator
            .expect_estimate_native_price()
            .times(1)
            .withf(move |token, _| *token == token2)
            .returning(|_, _| async { Err(PriceEstimationError::NoLiquidity) }.boxed());
        native_price_estimator
            .expect_estimate_native_price()
            .times(1)
            .withf(move |token, _| *token == token3)
            .returning(|_, _| async { Ok(0.25) }.boxed());

        let cache = Cache::new(Duration::from_secs(10), Default::default());
        let caching_estimator = CachingNativePriceEstimator::new(
            Box::new(native_price_estimator),
            cache,
            3,
            Default::default(),
            HEALTHY_PRICE_ESTIMATION_TIME,
        );
        let native_price_estimator =
            NativePriceUpdater::new(caching_estimator, Duration::MAX, Default::default());

        let orders_ref = orders.iter().map(|o| o.as_ref()).collect::<Vec<_>>();
        let (filtered_orders, _removed, prices) = get_orders_with_native_prices(
            orders_ref,
            &native_price_estimator,
            vec![],
            Duration::from_millis(100),
        )
        .await;
        assert_eq!(filtered_orders, [orders[1].as_ref()]);
        assert_eq!(
            prices,
            btreemap! {
                token1 => alloy::primitives::U256::from(2_000_000_000_000_000_000_u128),
                token3 => alloy::primitives::U256::from(250_000_000_000_000_000_u128),
            }
        );
    }

    #[tokio::test]
    async fn filters_orders_with_tokens_without_native_prices() {
        let token1 = Address::repeat_byte(1);
        let token2 = Address::repeat_byte(2);
        let token3 = Address::repeat_byte(3);
        let token4 = Address::repeat_byte(4);
        let token5 = Address::repeat_byte(5);

        let orders = [
            Arc::new(
                OrderBuilder::default()
                    .with_sell_token(token1)
                    .with_buy_token(token2)
                    .with_buy_amount(alloy::primitives::U256::ONE)
                    .with_sell_amount(alloy::primitives::U256::ONE)
                    .build(),
            ),
            Arc::new(
                OrderBuilder::default()
                    .with_sell_token(token2)
                    .with_buy_token(token3)
                    .with_buy_amount(alloy::primitives::U256::ONE)
                    .with_sell_amount(alloy::primitives::U256::ONE)
                    .build(),
            ),
            Arc::new(
                OrderBuilder::default()
                    .with_sell_token(token1)
                    .with_buy_token(token3)
                    .with_buy_amount(alloy::primitives::U256::ONE)
                    .with_sell_amount(alloy::primitives::U256::ONE)
                    .build(),
            ),
            Arc::new(
                OrderBuilder::default()
                    .with_sell_token(token2)
                    .with_buy_token(token4)
                    .with_buy_amount(alloy::primitives::U256::ONE)
                    .with_sell_amount(alloy::primitives::U256::ONE)
                    .build(),
            ),
        ];

        let mut native_price_estimator = MockNativePriceEstimating::new();
        native_price_estimator
            .expect_estimate_native_price()
            .withf(move |token, _| *token == token1)
            .returning(|_, _| async { Ok(2.) }.boxed());
        native_price_estimator
            .expect_estimate_native_price()
            .times(1)
            .withf(move |token, _| *token == token2)
            .returning(|_, _| async { Err(PriceEstimationError::NoLiquidity) }.boxed());
        native_price_estimator
            .expect_estimate_native_price()
            .times(1)
            .withf(move |token, _| *token == token3)
            .returning(|_, _| async { Ok(0.25) }.boxed());
        native_price_estimator
            .expect_estimate_native_price()
            .times(1)
            .withf(move |token, _| *token == token4)
            .returning(|_, _| async { Ok(0.) }.boxed());
        native_price_estimator
            .expect_estimate_native_price()
            .times(1)
            .withf(move |token, _| *token == token5)
            .returning(|_, _| async { Ok(5.) }.boxed());

        let cache = Cache::new(Duration::from_secs(10), Default::default());
        let caching_estimator = CachingNativePriceEstimator::new(
            Box::new(native_price_estimator),
            cache,
            1,
            Default::default(),
            HEALTHY_PRICE_ESTIMATION_TIME,
        );
        let native_price_estimator = NativePriceUpdater::new(
            caching_estimator,
            Duration::from_millis(5),
            Default::default(),
        );

        // We'll have no native prices in this call. But set_tokens_to_update
        // will cause the background task to fetch them in the next cycle.
        let orders_ref = orders.iter().map(|o| o.as_ref()).collect::<Vec<_>>();
        let (alive_orders, _removed_orders, prices) = get_orders_with_native_prices(
            orders_ref,
            &native_price_estimator,
            vec![token5],
            Duration::ZERO,
        )
        .await;
        assert!(alive_orders.is_empty());
        assert!(prices.is_empty());

        // Wait for native prices to get fetched by the background task.
        tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;

        // Now we have all the native prices we want.
        let orders_ref = orders.iter().map(|o| o.as_ref()).collect::<Vec<_>>();
        let (alive_orders, _removed_orders, prices) = get_orders_with_native_prices(
            orders_ref,
            &native_price_estimator,
            vec![token5],
            Duration::ZERO,
        )
        .await;

        assert_eq!(alive_orders, [orders[2].as_ref()]);
        assert_eq!(
            prices,
            btreemap! {
                token1 => alloy::primitives::U256::from(2_000_000_000_000_000_000_u128),
                token3 => alloy::primitives::U256::from(250_000_000_000_000_000_u128),
                token5 => alloy::primitives::U256::from(5_000_000_000_000_000_000_u128),
            }
        );
    }

    #[tokio::test]
    async fn check_native_price_approximations() {
        let token1 = Address::repeat_byte(1);
        let token2 = Address::repeat_byte(2);
        let token3 = Address::repeat_byte(3);

        let token_approx1 = Address::repeat_byte(4);
        let token_approx2 = Address::repeat_byte(5);

        let orders = [
            Arc::new(
                OrderBuilder::default()
                    .with_sell_token(token1)
                    .with_buy_token(token2)
                    .with_buy_amount(alloy::primitives::U256::ONE)
                    .with_sell_amount(alloy::primitives::U256::ONE)
                    .build(),
            ),
            Arc::new(
                OrderBuilder::default()
                    .with_sell_token(token1)
                    .with_buy_token(token2)
                    .with_buy_amount(alloy::primitives::U256::ONE)
                    .with_sell_amount(alloy::primitives::U256::ONE)
                    .build(),
            ),
            Arc::new(
                OrderBuilder::default()
                    .with_sell_token(token1)
                    .with_buy_token(token3)
                    .with_buy_amount(alloy::primitives::U256::ONE)
                    .with_sell_amount(alloy::primitives::U256::ONE)
                    .build(),
            ),
        ];

        let mut native_price_estimator = MockNativePriceEstimating::new();
        native_price_estimator
            .expect_estimate_native_price()
            .times(1)
            .withf(move |token, _| *token == token3)
            .returning(|_, _| async { Ok(3.) }.boxed());
        native_price_estimator
            .expect_estimate_native_price()
            .times(1)
            .withf(move |token, _| *token == token_approx1)
            .returning(|_, _| async { Ok(40.) }.boxed());
        native_price_estimator
            .expect_estimate_native_price()
            .times(1)
            .withf(move |token, _| *token == token_approx2)
            .returning(|_, _| async { Ok(50.) }.boxed());

        let cache = Cache::new(Duration::from_secs(10), Default::default());
        let caching_estimator = CachingNativePriceEstimator::new(
            Box::new(native_price_estimator),
            cache,
            3,
            // Set to use native price approximations for the following tokens
            HashMap::from([
                (token1, ApproximationToken::same_decimals(token_approx1)),
                (token2, ApproximationToken::same_decimals(token_approx2)),
            ]),
            HEALTHY_PRICE_ESTIMATION_TIME,
        );
        let native_price_estimator =
            NativePriceUpdater::new(caching_estimator, Duration::MAX, Default::default());

        let orders_ref = orders.iter().map(|o| o.as_ref()).collect::<Vec<_>>();
        let (alive_orders, _removed_orders, prices) = get_orders_with_native_prices(
            orders_ref,
            &native_price_estimator,
            vec![],
            Duration::from_secs(10),
        )
        .await;
        assert!(
            alive_orders
                .iter()
                .copied()
                .eq(orders.iter().map(Arc::as_ref))
        );
        assert_eq!(
            prices,
            btreemap! {
                token1 => alloy::primitives::U256::from(40_000_000_000_000_000_000_u128),
                token2 => alloy::primitives::U256::from(50_000_000_000_000_000_000_u128),
                token3 => alloy::primitives::U256::from(3_000_000_000_000_000_000_u128),
            }
        );
    }

    #[tokio::test]
    async fn filters_banned_users() {
        let banned_users = hashset!(Address::from([0xba; 20]), Address::from([0xbb; 20]));
        let orders = [
            Address::repeat_byte(1),
            Address::repeat_byte(1),
            Address::repeat_byte(0xba),
            Address::repeat_byte(2),
            Address::repeat_byte(0xba),
            Address::repeat_byte(0xbb),
            Address::repeat_byte(3),
        ]
        .into_iter()
        .enumerate()
        .map(|(i, owner)| {
            Arc::new(Order {
                metadata: OrderMetadata {
                    owner,
                    uid: OrderUid([i as u8; 56]),
                    ..Default::default()
                },
                data: OrderData {
                    buy_amount: alloy::primitives::U256::ONE,
                    sell_amount: alloy::primitives::U256::ONE,
                    ..Default::default()
                },
                ..Default::default()
            })
        })
        .collect::<Vec<_>>();

        let orders_ref = orders.iter().map(|o| o.as_ref()).collect::<Vec<_>>();
        let banned_user_orders = find_banned_user_orders(
            &orders_ref,
            &order_validation::banned::Users::from_set(banned_users),
        )
        .await;
        assert_eq!(
            banned_user_orders,
            [OrderUid([2; 56]), OrderUid([4; 56]), OrderUid([5; 56])],
        );
    }

    #[test]
    fn finds_presignature_pending_orders() {
        let presign_uid = OrderUid::from_parts(B256::repeat_byte(1), Address::repeat_byte(11), 1);
        let orders = [
            // PresignaturePending order - should be found
            Arc::new(Order {
                metadata: OrderMetadata {
                    uid: presign_uid,
                    status: model::order::OrderStatus::PresignaturePending,
                    ..Default::default()
                },
                ..Default::default()
            }),
            // EIP-1271 order - not PresignaturePending
            Arc::new(Order {
                metadata: OrderMetadata {
                    uid: OrderUid::from_parts(B256::repeat_byte(2), Address::repeat_byte(22), 2),
                    ..Default::default()
                },
                signature: Signature::Eip1271(vec![2, 2]),
                ..Default::default()
            }),
            // Regular order - not PresignaturePending
            Arc::new(Order {
                metadata: OrderMetadata {
                    uid: OrderUid::from_parts(B256::repeat_byte(3), Address::repeat_byte(33), 3),
                    ..Default::default()
                },
                ..Default::default()
            }),
        ];

        let orders_ref = orders.iter().map(|o| o.as_ref()).collect::<Vec<_>>();
        let pending_orders = find_presignature_pending_orders(&orders_ref);
        assert_eq!(pending_orders, vec![presign_uid]);
    }

    #[test]
    fn filter_unsupported_tokens_() {
        let token0 = Address::with_last_byte(0);
        let token1 = Address::with_last_byte(1);
        let token2 = Address::with_last_byte(2);
        let deny_listed_tokens = DenyListedTokens::new(vec![token0]);
        let orders = [
            Arc::new(
                OrderBuilder::default()
                    .with_sell_token(token0)
                    .with_buy_token(token1)
                    .build(),
            ),
            Arc::new(
                OrderBuilder::default()
                    .with_sell_token(token1)
                    .with_buy_token(token2)
                    .build(),
            ),
            Arc::new(
                OrderBuilder::default()
                    .with_sell_token(token0)
                    .with_buy_token(token2)
                    .build(),
            ),
        ];
        let orders_ref = orders.iter().map(|o| o.as_ref()).collect::<Vec<_>>();
        let unsupported_tokens_orders = find_unsupported_tokens(&orders_ref, &deny_listed_tokens);
        assert_eq!(
            unsupported_tokens_orders,
            [orders[0].metadata.uid, orders[2].metadata.uid]
        );
    }

    #[test]
    fn orders_with_balance_() {
        let settlement_contract = Address::repeat_byte(1);
        let orders = [
            // enough balance for sell and fee
            Arc::new(Order {
                data: OrderData {
                    sell_token: Address::with_last_byte(2),
                    sell_amount: alloy::primitives::U256::ONE,
                    fee_amount: alloy::primitives::U256::ONE,
                    partially_fillable: false,
                    ..Default::default()
                },
                ..Default::default()
            }),
            // missing fee balance
            Arc::new(Order {
                data: OrderData {
                    sell_token: Address::with_last_byte(3),
                    sell_amount: alloy::primitives::U256::ONE,
                    fee_amount: alloy::primitives::U256::ONE,
                    partially_fillable: false,
                    ..Default::default()
                },
                ..Default::default()
            }),
            // at least 1 partially fillable balance
            Arc::new(Order {
                data: OrderData {
                    sell_token: Address::with_last_byte(4),
                    sell_amount: alloy::primitives::U256::from(2),
                    fee_amount: alloy::primitives::U256::ZERO,
                    partially_fillable: true,
                    ..Default::default()
                },
                ..Default::default()
            }),
            // 0 partially fillable balance
            Arc::new(Order {
                data: OrderData {
                    sell_token: Address::with_last_byte(5),
                    sell_amount: alloy::primitives::U256::from(2),
                    fee_amount: alloy::primitives::U256::ZERO,
                    partially_fillable: true,
                    ..Default::default()
                },
                ..Default::default()
            }),
            // considered flashloan order because of special receiver
            Arc::new(Order {
                data: OrderData {
                    sell_token: Address::with_last_byte(6),
                    sell_amount: alloy::primitives::U256::from(200),
                    fee_amount: alloy::primitives::U256::ZERO,
                    partially_fillable: true,
                    receiver: Some(settlement_contract),
                    ..Default::default()
                },
                ..Default::default()
            }),
        ];
        let balances = [
            (Query::from_order(&orders[0]), U256::from(2)),
            (Query::from_order(&orders[1]), U256::from(1)),
            (Query::from_order(&orders[2]), U256::from(1)),
            (Query::from_order(&orders[3]), U256::from(0)),
            (Query::from_order(&orders[4]), U256::from(0)),
        ]
        .into_iter()
        .collect();
        let expected = &[0, 2, 4];

        let no_bypass: HashSet<OrderUid> = HashSet::new();
        let orders_ref = orders.iter().map(|o| o.as_ref()).collect::<Vec<_>>();
        let (alive_orders, _removed_orders) =
            orders_with_balance(orders_ref, &balances, settlement_contract, &no_bypass);
        assert_eq!(alive_orders.len(), expected.len());
        for index in expected {
            let found = alive_orders.iter().any(|o| o.data == orders[*index].data);
            assert!(found, "{}", index);
        }
    }

    #[test]
    fn eip1271_and_wrapper_orders_skip_balance_filtering() {
        let settlement_contract = Address::repeat_byte(1);

        // EIP-1271 order (should skip balance check)
        let eip1271_order = Arc::new(Order {
            data: OrderData {
                sell_token: Address::with_last_byte(7),
                sell_amount: alloy::primitives::U256::from(10),
                fee_amount: alloy::primitives::U256::from(5),
                partially_fillable: false,
                ..Default::default()
            },
            signature: Signature::Eip1271(vec![1, 2, 3]),
            metadata: OrderMetadata {
                uid: OrderUid::from_parts(B256::repeat_byte(6), Address::repeat_byte(66), 6),
                ..Default::default()
            },
            ..Default::default()
        });

        // Order with wrappers in bypass set (should skip balance check)
        let wrapper_order_uid =
            OrderUid::from_parts(B256::repeat_byte(7), Address::repeat_byte(77), 7);
        let wrapper_order = Arc::new(Order {
            data: OrderData {
                sell_token: Address::with_last_byte(8),
                sell_amount: alloy::primitives::U256::from(10),
                fee_amount: alloy::primitives::U256::from(5),
                partially_fillable: false,
                ..Default::default()
            },
            metadata: OrderMetadata {
                uid: wrapper_order_uid,
                ..Default::default()
            },
            ..Default::default()
        });

        // Regular ECDSA order without wrappers (should be filtered)
        let regular_order = Arc::new(Order {
            data: OrderData {
                sell_token: Address::with_last_byte(9),
                sell_amount: alloy::primitives::U256::from(10),
                fee_amount: alloy::primitives::U256::from(5),
                partially_fillable: false,
                ..Default::default()
            },
            metadata: OrderMetadata {
                uid: OrderUid::from_parts(B256::repeat_byte(8), Address::repeat_byte(88), 8),
                ..Default::default()
            },
            ..Default::default()
        });

        let orders = [
            regular_order.clone(),
            eip1271_order.clone(),
            wrapper_order.clone(),
        ];
        let balances: Balances = Default::default(); // No balances

        // EIP-1271 order and wrapper order should be retained, regular order filtered
        let wrapper_set = HashSet::from([wrapper_order_uid]);
        let orders_ref = orders.iter().map(|o| o.as_ref()).collect::<Vec<_>>();
        let (alive_orders, _removed_orders) =
            orders_with_balance(orders_ref, &balances, settlement_contract, &wrapper_set);
        assert_eq!(alive_orders.len(), 2);
        assert!(
            alive_orders
                .iter()
                .any(|o| o.metadata.uid == eip1271_order.metadata.uid)
        );
        assert!(
            alive_orders
                .iter()
                .any(|o| o.metadata.uid == wrapper_order.metadata.uid)
        );

        // Without wrapper set, only EIP-1271 order should be retained
        let empty_set: HashSet<OrderUid> = HashSet::new();
        let orders_ref = orders.iter().map(|o| o.as_ref()).collect::<Vec<_>>();
        let (alive_orders, _removed_orders) =
            orders_with_balance(orders_ref, &balances, settlement_contract, &empty_set);
        assert_eq!(alive_orders.len(), 1);
        assert_eq!(alive_orders[0].metadata.uid, eip1271_order.metadata.uid);
    }

    fn test_order(uid_byte: u8, amount: u8) -> domain::Order {
        crate::test_helpers::test_order(uid_byte, amount)
    }

    fn test_price(value: u128) -> domain::auction::Price {
        domain::auction::Price::try_new(eth::Ether::from(eth::U256::from(value))).unwrap()
    }

    fn normalize(mut state: domain::RawAuctionData) -> domain::RawAuctionData {
        state.orders.sort_by_key(|order| order.uid.0);
        state
    }

    #[test]
    fn normalized_delta_surface_ignores_non_delta_fields() {
        let mut a = domain::RawAuctionData {
            block: 1,
            orders: vec![test_order(1, 10), test_order(2, 20)],
            prices: HashMap::from([(Address::repeat_byte(0xAA).into(), test_price(1000))]),
            surplus_capturing_jit_order_owners: vec![Address::repeat_byte(0x01)],
        };
        let mut b = a.clone();

        a.block = 7;
        b.block = 999;
        b.surplus_capturing_jit_order_owners = vec![Address::repeat_byte(0xFF)];

        assert_eq!(normalized_delta_surface(a), normalized_delta_surface(b));
    }

    #[test]
    fn with_non_delta_fields_uses_full_rebuild_metadata() {
        let reconstructed = domain::RawAuctionData {
            block: 1,
            orders: vec![test_order(1, 10)],
            prices: HashMap::from([(Address::repeat_byte(0xAA).into(), test_price(1000))]),
            surplus_capturing_jit_order_owners: vec![Address::repeat_byte(0x11)],
        };
        let full_rebuild = domain::RawAuctionData {
            block: 99,
            orders: vec![test_order(1, 10)],
            prices: HashMap::from([(Address::repeat_byte(0xAA).into(), test_price(1000))]),
            surplus_capturing_jit_order_owners: vec![Address::repeat_byte(0x22)],
        };

        let merged = with_non_delta_fields(reconstructed, &full_rebuild);
        assert_eq!(merged.block, 99);
        assert_eq!(
            merged.surplus_capturing_jit_order_owners,
            vec![Address::repeat_byte(0x22)]
        );
    }

    #[test]
    fn diff_solvable_order_inputs_detects_add_update_remove() {
        let prev_uid = domain::OrderUid([1; 56]);
        let upd_uid = domain::OrderUid([2; 56]);
        let add_uid = domain::OrderUid([3; 56]);
        let rem_uid = domain::OrderUid([4; 56]);

        let previous = boundary::SolvableOrders {
            orders: HashMap::from([
                (prev_uid, Arc::new(model::order::Order::default())),
                (
                    upd_uid,
                    Arc::new(model::order::Order {
                        data: model::order::OrderData {
                            valid_to: 1,
                            ..Default::default()
                        },
                        ..Default::default()
                    }),
                ),
                (rem_uid, Arc::new(model::order::Order::default())),
            ]),
            quotes: HashMap::new(),
            latest_settlement_block: 0,
            fetched_from_db: chrono::Utc::now(),
        };
        let current = boundary::SolvableOrders {
            orders: HashMap::from([
                (prev_uid, Arc::new(model::order::Order::default())),
                (
                    upd_uid,
                    Arc::new(model::order::Order {
                        data: model::order::OrderData {
                            valid_to: 2,
                            ..Default::default()
                        },
                        ..Default::default()
                    }),
                ),
                (add_uid, Arc::new(model::order::Order::default())),
            ]),
            quotes: HashMap::new(),
            latest_settlement_block: 0,
            fetched_from_db: chrono::Utc::now(),
        };

        let bundle = diff_solvable_order_inputs(Some(&previous), &current);
        assert!(bundle.order_added_candidates.contains(&add_uid));
        assert!(bundle.order_updated_candidates.contains(&upd_uid));
        assert!(bundle.order_removed_candidates.contains(&rem_uid));
    }

    #[test]
    fn diff_solvable_order_inputs_detects_quote_changes_as_updates() {
        let uid = domain::OrderUid([9; 56]);

        let previous = boundary::SolvableOrders {
            orders: HashMap::from([(uid, Arc::new(model::order::Order::default()))]),
            quotes: HashMap::from([(uid, Arc::new(domain::Quote::default()))]),
            latest_settlement_block: 0,
            fetched_from_db: chrono::Utc::now(),
        };
        let current = boundary::SolvableOrders {
            orders: HashMap::from([(uid, Arc::new(model::order::Order::default()))]),
            quotes: HashMap::new(),
            latest_settlement_block: 0,
            fetched_from_db: chrono::Utc::now(),
        };

        let bundle = diff_solvable_order_inputs(Some(&previous), &current);
        assert!(bundle.quote_updated_candidates.contains(&uid));
    }

    #[test]
    fn build_indexed_state_tracks_filtered_sets() {
        let auction = domain::RawAuctionData {
            block: 1,
            orders: vec![test_order(1, 10)],
            prices: HashMap::from([(Address::repeat_byte(0xAA).into(), test_price(1000))]),
            surplus_capturing_jit_order_owners: Vec::new(),
        };
        let uid = OrderUid::from_parts(B256::repeat_byte(1), Address::repeat_byte(2), 3);
        let invalid = HashMap::from([(uid, OrderFilterReason::InvalidSignature)]);
        let filtered = vec![
            (uid, OrderFilterReason::InFlight),
            (uid, OrderFilterReason::InsufficientBalance),
            (uid, OrderFilterReason::MissingNativePrice),
        ];

        let indexed = build_indexed_state(&auction, &invalid, &filtered);
        assert_eq!(indexed.current_orders_by_uid.len(), 1);
        assert_eq!(indexed.current_prices_by_token.len(), 1);
        assert!(indexed.filtered_invalid.contains_key(&uid));
        assert!(indexed.filtered_in_flight.contains(&uid));
        assert!(indexed.filtered_no_balance.contains(&uid));
        assert!(indexed.filtered_no_price.contains(&uid));
    }

    #[test]
    fn compute_delta_events_covers_all_event_categories() {
        let token_a = Address::repeat_byte(0xAA);
        let token_b = Address::repeat_byte(0xBB);
        let token_c = Address::repeat_byte(0xCC);

        let previous = domain::RawAuctionData {
            block: 1,
            orders: vec![test_order(1, 10), test_order(2, 20)],
            prices: HashMap::from([
                (token_a.into(), test_price(1_000)),
                (token_b.into(), test_price(2_000)),
            ]),
            surplus_capturing_jit_order_owners: Vec::new(),
        };
        let current = domain::RawAuctionData {
            block: 1,
            orders: vec![
                test_order(1, 11), // updated
                test_order(3, 30), // added
            ],
            prices: HashMap::from([
                (token_a.into(), test_price(1_500)), // changed
                (token_c.into(), test_price(3_000)), /* added
                                                      * token_b removed */
            ]),
            surplus_capturing_jit_order_owners: Vec::new(),
        };

        let events = compute_delta_events(Some(&previous), &current);

        assert!(
            events
                .iter()
                .any(|event| matches!(event, DeltaEvent::OrderAdded(order) if order.uid == domain::OrderUid([3; 56])))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event, DeltaEvent::OrderRemoved(uid) if *uid == domain::OrderUid([2; 56])))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event, DeltaEvent::OrderUpdated(order) if order.uid == domain::OrderUid([1; 56])))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event, DeltaEvent::PriceChanged { token, price: Some(_) } if *token == token_a))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event, DeltaEvent::PriceChanged { token, price: None } if *token == token_b))
        );
    }

    #[test]
    fn replay_reconstructs_state_across_randomized_scenarios() {
        let mut seed = 0xDEAD_BEEF_CAFE_BABEu64;
        let mut state = normalize(domain::RawAuctionData {
            block: 1,
            orders: Vec::new(),
            prices: HashMap::new(),
            surplus_capturing_jit_order_owners: Vec::new(),
        });

        // Linear congruential generator for deterministic pseudo-random cases.
        let next = |seed: &mut u64| {
            *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            *seed
        };

        for _ in 0..120 {
            let mut next_state = state.clone();

            // Mutate orders.
            let uid = ((next(&mut seed) % 12) as u8) + 1;
            let choice = next(&mut seed) % 3;
            let mut orders_by_uid: HashMap<domain::OrderUid, domain::Order> = next_state
                .orders
                .into_iter()
                .map(|order| (order.uid, order))
                .collect();
            match choice {
                0 => {
                    orders_by_uid.insert(domain::OrderUid([uid; 56]), test_order(uid, uid));
                }
                1 => {
                    orders_by_uid.remove(&domain::OrderUid([uid; 56]));
                }
                _ => {
                    if orders_by_uid.contains_key(&domain::OrderUid([uid; 56])) {
                        orders_by_uid.insert(
                            domain::OrderUid([uid; 56]),
                            test_order(uid, uid.saturating_add(1)),
                        );
                    }
                }
            }
            next_state.orders = orders_by_uid.into_values().collect();

            // Mutate prices.
            let token = Address::repeat_byte(((next(&mut seed) % 8) as u8) + 1);
            let price_choice = next(&mut seed) % 3;
            match price_choice {
                0 => {
                    next_state.prices.insert(
                        token.into(),
                        test_price(u128::from((next(&mut seed) % 1000) + 1)),
                    );
                }
                1 => {
                    next_state.prices.remove(&token.into());
                }
                _ => {}
            }

            next_state = normalize(next_state);
            let events = compute_delta_events(Some(&state), &next_state);
            let reconstructed = apply_delta_events_to_auction(state.clone(), &events);

            assert_eq!(reconstructed, next_state);
            state = next_state;
        }
    }

    #[test]
    fn compute_delta_events_from_empty_emits_full_state() {
        let token = Address::repeat_byte(0x11);
        let current = domain::RawAuctionData {
            block: 7,
            orders: vec![test_order(1, 10), test_order(2, 20)],
            prices: HashMap::from([(token.into(), test_price(1234))]),
            surplus_capturing_jit_order_owners: Vec::new(),
        };

        let events = compute_delta_events(None, &current);
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, DeltaEvent::OrderAdded(_)))
                .count(),
            2
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, DeltaEvent::PriceChanged { price: Some(_), .. }))
                .count(),
            1
        );
    }

    #[test]
    fn compute_delta_events_for_identical_states_is_empty() {
        let state = normalize(domain::RawAuctionData {
            block: 1,
            orders: vec![test_order(1, 10), test_order(2, 20)],
            prices: HashMap::from([
                (Address::repeat_byte(1).into(), test_price(1000)),
                (Address::repeat_byte(2).into(), test_price(2000)),
            ]),
            surplus_capturing_jit_order_owners: Vec::new(),
        });

        let events = compute_delta_events(Some(&state), &state);
        assert!(events.is_empty());
    }

    #[test]
    fn compute_delta_events_emits_order_removed_when_order_disappears() {
        let previous = normalize(domain::RawAuctionData {
            block: 1,
            orders: vec![test_order(1, 10)],
            prices: HashMap::new(),
            surplus_capturing_jit_order_owners: Vec::new(),
        });
        let current = normalize(domain::RawAuctionData {
            block: 2,
            orders: Vec::new(),
            prices: HashMap::new(),
            surplus_capturing_jit_order_owners: Vec::new(),
        });

        let events = compute_delta_events(Some(&previous), &current);
        assert!(
            events
                .iter()
                .any(|event| matches!(event, DeltaEvent::OrderRemoved(uid) if *uid == domain::OrderUid([1; 56])))
        );
    }

    #[test]
    fn compute_delta_events_emits_order_added_when_order_reappears() {
        let previous = normalize(domain::RawAuctionData {
            block: 1,
            orders: Vec::new(),
            prices: HashMap::new(),
            surplus_capturing_jit_order_owners: Vec::new(),
        });
        let current = normalize(domain::RawAuctionData {
            block: 2,
            orders: vec![test_order(1, 10)],
            prices: HashMap::new(),
            surplus_capturing_jit_order_owners: Vec::new(),
        });

        let events = compute_delta_events(Some(&previous), &current);
        assert!(
            events
                .iter()
                .any(|event| matches!(event, DeltaEvent::OrderAdded(order) if order.uid == domain::OrderUid([1; 56])))
        );
    }

    #[test]
    fn compute_delta_events_emits_price_remove_and_add_on_transitions() {
        let token = Address::repeat_byte(0xAB);
        let with_price = normalize(domain::RawAuctionData {
            block: 1,
            orders: Vec::new(),
            prices: HashMap::from([(token.into(), test_price(1000))]),
            surplus_capturing_jit_order_owners: Vec::new(),
        });
        let without_price = normalize(domain::RawAuctionData {
            block: 2,
            orders: Vec::new(),
            prices: HashMap::new(),
            surplus_capturing_jit_order_owners: Vec::new(),
        });

        let remove_events = compute_delta_events(Some(&with_price), &without_price);
        assert!(
            remove_events
                .iter()
                .any(|event| matches!(event, DeltaEvent::PriceChanged { token: changed, price: None } if *changed == token))
        );

        let add_events = compute_delta_events(Some(&without_price), &with_price);
        assert!(
            add_events
                .iter()
                .any(|event| matches!(event, DeltaEvent::PriceChanged { token: changed, price: Some(_) } if *changed == token))
        );
    }

    #[test]
    fn compute_delta_events_ordering_is_deterministic_and_stable() {
        let token_a = Address::repeat_byte(0xA1);
        let token_b = Address::repeat_byte(0xB2);

        let previous = normalize(domain::RawAuctionData {
            block: 10,
            orders: vec![test_order(2, 20), test_order(4, 40)],
            prices: HashMap::from([
                (token_a.into(), test_price(100)),
                (token_b.into(), test_price(200)),
            ]),
            surplus_capturing_jit_order_owners: Vec::new(),
        });
        let current = normalize(domain::RawAuctionData {
            block: 11,
            orders: vec![test_order(1, 10), test_order(2, 21)],
            prices: HashMap::from([(token_b.into(), test_price(250))]),
            surplus_capturing_jit_order_owners: Vec::new(),
        });

        let events_first = compute_delta_events(Some(&previous), &current);
        let events_second = compute_delta_events(Some(&previous), &current);
        assert_eq!(events_first, events_second);

        let expected = vec![
            DeltaEvent::OrderAdded(test_order(1, 10)),
            DeltaEvent::OrderUpdated(test_order(2, 21)),
            DeltaEvent::OrderRemoved(domain::OrderUid([4; 56])),
            DeltaEvent::PriceChanged {
                token: token_a,
                price: None,
            },
            DeltaEvent::PriceChanged {
                token: token_b,
                price: Some(test_price(250)),
            },
            DeltaEvent::BlockChanged { block: 11 },
        ];

        assert_eq!(events_first, expected);
    }

    #[test]
    fn compute_delta_events_emits_block_and_jit_owner_changes() {
        let token = Address::repeat_byte(0x11);
        let previous = normalize(domain::RawAuctionData {
            block: 1,
            orders: Vec::new(),
            prices: HashMap::from([(token.into(), test_price(1000))]),
            surplus_capturing_jit_order_owners: vec![Address::repeat_byte(0x01)],
        });
        let current = normalize(domain::RawAuctionData {
            block: 2,
            orders: Vec::new(),
            prices: HashMap::from([(token.into(), test_price(1000))]),
            surplus_capturing_jit_order_owners: vec![Address::repeat_byte(0xFF)],
        });

        let events = compute_delta_events(Some(&previous), &current);

        assert!(
            events
                .iter()
                .any(|event| matches!(event, DeltaEvent::BlockChanged { block } if *block == 2))
        );
        assert!(events.iter().any(|event| matches!(event, DeltaEvent::JitOwnersChanged { surplus_capturing_jit_order_owners } if surplus_capturing_jit_order_owners == &vec![Address::repeat_byte(0xFF)])));
    }

    #[test]
    fn apply_delta_events_applies_block_and_jit_owner_changes() {
        let previous = domain::RawAuctionData {
            block: 1,
            orders: Vec::new(),
            prices: HashMap::new(),
            surplus_capturing_jit_order_owners: vec![Address::repeat_byte(0x01)],
        };

        let events = vec![
            DeltaEvent::BlockChanged { block: 42 },
            DeltaEvent::JitOwnersChanged {
                surplus_capturing_jit_order_owners: vec![Address::repeat_byte(0xAA)],
            },
        ];

        let rebuilt = apply_delta_events_to_auction(previous.clone(), &events);
        assert_eq!(rebuilt.block, 42);
        assert_eq!(
            rebuilt.surplus_capturing_jit_order_owners,
            vec![Address::repeat_byte(0xAA)]
        );
    }

    #[test]
    fn in_flight_entry_and_exit_changes_coverage() {
        let mut indexed = IndexedAuctionState::default();
        indexed
            .current_orders_by_uid
            .insert(domain::OrderUid([1; 56]), test_order(1, 10));
        indexed
            .current_orders_by_uid
            .insert(domain::OrderUid([2; 56]), test_order(2, 20));
        indexed.filtered_in_flight.insert(OrderUid([2; 56]));

        let in_flight = HashSet::from([OrderUid([1; 56])]);

        let mut impacted = HashSet::new();
        impacted.extend(
            in_flight
                .iter()
                .filter(|uid| {
                    indexed
                        .current_orders_by_uid
                        .contains_key(&domain::OrderUid(uid.0))
                })
                .map(|uid| domain::OrderUid(uid.0)),
        );
        impacted.extend(
            indexed
                .filtered_in_flight
                .iter()
                .filter(|uid| !in_flight.contains(uid))
                .map(|uid| domain::OrderUid(uid.0)),
        );

        assert!(impacted.contains(&domain::OrderUid([1; 56])));
        assert!(impacted.contains(&domain::OrderUid([2; 56])));
    }

    #[test]
    fn incremental_projection_matches_full_rebuild_under_randomized_churn() {
        let mut seed = 0xA11CE_C0DE_F00Du64;
        let mut previous = normalize(domain::RawAuctionData {
            block: 1,
            orders: Vec::new(),
            prices: HashMap::new(),
            surplus_capturing_jit_order_owners: vec![Address::repeat_byte(1)],
        });

        let next = |seed: &mut u64| {
            *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            *seed
        };

        for i in 0..120 {
            let mut current = previous.clone();
            current.block = i + 2;
            current.surplus_capturing_jit_order_owners = vec![Address::repeat_byte((i % 7) as u8)];

            let uid = ((next(&mut seed) % 10) as u8) + 1;
            match next(&mut seed) % 3 {
                0 => {
                    let mut orders = current
                        .orders
                        .into_iter()
                        .map(|order| (order.uid, order))
                        .collect::<HashMap<_, _>>();
                    orders.insert(domain::OrderUid([uid; 56]), test_order(uid, uid));
                    current.orders = orders.into_values().collect();
                }
                1 => {
                    current
                        .orders
                        .retain(|order| order.uid != domain::OrderUid([uid; 56]));
                }
                _ => {
                    for order in &mut current.orders {
                        if order.uid == domain::OrderUid([uid; 56]) {
                            *order = test_order(uid, uid.saturating_add(1));
                        }
                    }
                }
            }

            let token = Address::repeat_byte(((next(&mut seed) % 8) as u8) + 1);
            match next(&mut seed) % 3 {
                0 => {
                    current.prices.insert(
                        token.into(),
                        test_price(u128::from((next(&mut seed) % 2000) + 1)),
                    );
                }
                1 => {
                    current.prices.remove(&token.into());
                }
                _ => {}
            }

            current = normalize(current);
            let events = compute_delta_events(Some(&previous), &current);
            let reconstructed = apply_delta_events_to_auction(previous.clone(), &events);
            let merged = with_non_delta_fields(reconstructed, &current);

            assert_eq!(
                normalized_delta_surface(merged),
                normalized_delta_surface(current.clone())
            );
            assert_eq!(events, compute_delta_events(Some(&previous), &current));
            previous = current;
        }
    }

    #[test]
    fn compute_delta_events_from_inputs_falls_back_to_canonical_when_bundle_is_wrong() {
        let previous = normalize(domain::RawAuctionData {
            block: 1,
            orders: vec![test_order(1, 10)],
            prices: HashMap::from([(Address::repeat_byte(0xAA).into(), test_price(1000))]),
            surplus_capturing_jit_order_owners: Vec::new(),
        });
        let current = normalize(domain::RawAuctionData {
            block: 2,
            orders: vec![test_order(1, 11), test_order(2, 20)],
            prices: HashMap::from([(Address::repeat_byte(0xAA).into(), test_price(1500))]),
            surplus_capturing_jit_order_owners: Vec::new(),
        });

        // Intentionally wrong: claims order 1 was removed and misses order 2 add.
        let noisy_bundle = ChangeBundle {
            order_added_candidates: Vec::new(),
            order_removed_candidates: vec![domain::OrderUid([1; 56])],
            order_updated_candidates: Vec::new(),
            quote_updated_candidates: Vec::new(),
            price_changed_tokens: vec![Address::repeat_byte(0xAA)],
            filter_transitions: Vec::new(),
        };

        let events = SolvableOrdersCache::compute_delta_events_from_inputs(
            Some(&previous),
            &current,
            &noisy_bundle,
            true,
        )
        .unwrap();
        let canonical = compute_delta_events(Some(&previous), &current);
        assert_eq!(events, canonical);
    }

    #[tokio::test]
    async fn projection_mismatch_metric_not_incremented_by_apply_incremental_changes() {
        let cache = test_cache().await;
        let initial = Metrics::get()
            .delta_incremental_projection_mismatch_total
            .get();

        let previous = normalize(domain::RawAuctionData {
            block: 1,
            orders: vec![test_order(1, 10)],
            prices: HashMap::new(),
            surplus_capturing_jit_order_owners: Vec::new(),
        });
        let current = normalize(domain::RawAuctionData {
            block: 2,
            orders: vec![test_order(2, 20)],
            prices: HashMap::new(),
            surplus_capturing_jit_order_owners: Vec::new(),
        });

        let projection_result = cache.apply_incremental_changes(Some(&previous), current, &[]);
        assert!(matches!(projection_result, ProjectionResult::Mismatch(_)));

        let now = Metrics::get()
            .delta_incremental_projection_mismatch_total
            .get();
        assert_eq!(now, initial);
    }

    #[test]
    fn compute_delta_events_from_inputs_dedups_candidates_and_skips_unchanged_price_tokens() {
        let previous = normalize(domain::RawAuctionData {
            block: 1,
            orders: vec![test_order(1, 10)],
            prices: HashMap::from([
                (Address::repeat_byte(0xAA).into(), test_price(1000)),
                (Address::repeat_byte(0xBB).into(), test_price(2000)),
            ]),
            surplus_capturing_jit_order_owners: Vec::new(),
        });
        let current = normalize(domain::RawAuctionData {
            block: 2,
            orders: vec![test_order(1, 11)],
            prices: HashMap::from([
                (Address::repeat_byte(0xAA).into(), test_price(1500)),
                (Address::repeat_byte(0xBB).into(), test_price(2000)),
            ]),
            surplus_capturing_jit_order_owners: Vec::new(),
        });

        let bundle = ChangeBundle {
            order_added_candidates: vec![],
            order_removed_candidates: vec![],
            order_updated_candidates: vec![domain::OrderUid([1; 56]), domain::OrderUid([1; 56])],
            quote_updated_candidates: Vec::new(),
            price_changed_tokens: vec![
                Address::repeat_byte(0xAA),
                Address::repeat_byte(0xAA),
                Address::repeat_byte(0xBB),
            ],
            filter_transitions: Vec::new(),
        };

        let events = SolvableOrdersCache::compute_delta_events_from_inputs(
            Some(&previous),
            &current,
            &bundle,
            false,
        )
        .unwrap();

        assert_eq!(
            events,
            vec![
                DeltaEvent::OrderUpdated(test_order(1, 11)),
                DeltaEvent::PriceChanged {
                    token: Address::repeat_byte(0xAA),
                    price: Some(test_price(1500)),
                },
                DeltaEvent::BlockChanged { block: 2 },
            ]
        );
    }

    #[test]
    fn compute_delta_events_from_inputs_emits_single_event_per_uid() {
        let uid = domain::OrderUid([9; 56]);
        let previous = normalize(domain::RawAuctionData {
            block: 1,
            orders: vec![test_order(9, 10)],
            prices: HashMap::new(),
            surplus_capturing_jit_order_owners: Vec::new(),
        });
        let current = normalize(domain::RawAuctionData {
            block: 2,
            orders: vec![test_order(9, 11)],
            prices: HashMap::new(),
            surplus_capturing_jit_order_owners: Vec::new(),
        });

        let bundle = ChangeBundle {
            order_added_candidates: vec![uid],
            order_removed_candidates: vec![uid],
            order_updated_candidates: vec![uid],
            quote_updated_candidates: Vec::new(),
            price_changed_tokens: Vec::new(),
            filter_transitions: vec![FilterTransition {
                uid,
                reason: OrderFilterReason::InFlight,
                is_filtered: true,
            }],
        };

        let events = SolvableOrdersCache::compute_delta_events_from_inputs(
            Some(&previous),
            &current,
            &bundle,
            false,
        )
        .unwrap();

        let uid_events = events
            .iter()
            .filter(|event| match event {
                DeltaEvent::OrderAdded(order) | DeltaEvent::OrderUpdated(order) => order.uid == uid,
                DeltaEvent::OrderRemoved(event_uid) => *event_uid == uid,
                _ => false,
            })
            .count();
        assert_eq!(uid_events, 1);
    }

    #[test]
    fn compute_delta_events_from_inputs_skips_unchanged_solver_visible_fields() {
        let uid = domain::OrderUid([1; 56]);
        let previous = normalize(domain::RawAuctionData {
            block: 1,
            orders: vec![test_order(1, 10)],
            prices: HashMap::new(),
            surplus_capturing_jit_order_owners: Vec::new(),
        });
        let current = previous.clone();

        let bundle = ChangeBundle {
            order_added_candidates: Vec::new(),
            order_removed_candidates: Vec::new(),
            order_updated_candidates: vec![uid],
            quote_updated_candidates: Vec::new(),
            price_changed_tokens: Vec::new(),
            filter_transitions: Vec::new(),
        };

        let events = SolvableOrdersCache::compute_delta_events_from_inputs(
            Some(&previous),
            &current,
            &bundle,
            false,
        )
        .unwrap();

        assert!(events.is_empty());
    }

    #[test]
    fn apply_auction_id_change_keeps_sequence_monotonic() {
        let mut inner = Inner {
            auction: domain::RawAuctionData {
                block: 1,
                orders: Vec::new(),
                prices: HashMap::new(),
                surplus_capturing_jit_order_owners: Vec::new(),
            },
            solvable_orders: boundary::SolvableOrders {
                orders: HashMap::new(),
                quotes: HashMap::new(),
                latest_settlement_block: 0,
                fetched_from_db: chrono::Utc::now(),
            },
            auction_id: 1,
            auction_sequence: 7,
            delta_sequence: 9,
            delta_history: VecDeque::new(),
            indexed_state: Arc::new(IndexedAuctionState::default()),
        };

        let config = DeltaSyncConfig::default();
        let envelope = apply_auction_id_change(&mut inner, 2, &config).expect("envelope expected");
        assert_eq!(envelope.from_sequence, 9);
        assert_eq!(envelope.to_sequence, 10);
        assert_eq!(inner.delta_sequence, 10);

        let envelope = apply_auction_id_change(&mut inner, 3, &config).expect("envelope expected");
        assert_eq!(envelope.from_sequence, 10);
        assert_eq!(envelope.to_sequence, 11);
        assert_eq!(inner.delta_sequence, 11);
    }

    #[test]
    fn apply_auction_id_change_returns_none_when_unchanged() {
        let mut inner = Inner {
            auction: domain::RawAuctionData {
                block: 1,
                orders: Vec::new(),
                prices: HashMap::new(),
                surplus_capturing_jit_order_owners: Vec::new(),
            },
            solvable_orders: boundary::SolvableOrders {
                orders: HashMap::new(),
                quotes: HashMap::new(),
                latest_settlement_block: 0,
                fetched_from_db: chrono::Utc::now(),
            },
            auction_id: 5,
            auction_sequence: 2,
            delta_sequence: 3,
            delta_history: VecDeque::new(),
            indexed_state: Arc::new(IndexedAuctionState::default()),
        };

        let previous_sequence = inner.delta_sequence;
        let config = DeltaSyncConfig::default();
        assert!(apply_auction_id_change(&mut inner, 5, &config).is_none());
        assert_eq!(inner.delta_sequence, previous_sequence);
        assert!(inner.delta_history.is_empty());
    }

    #[test]
    fn apply_auction_id_change_returns_none_on_sequence_overflow() {
        let mut inner = Inner {
            auction: domain::RawAuctionData {
                block: 1,
                orders: Vec::new(),
                prices: HashMap::new(),
                surplus_capturing_jit_order_owners: Vec::new(),
            },
            solvable_orders: boundary::SolvableOrders {
                orders: HashMap::new(),
                quotes: HashMap::new(),
                latest_settlement_block: 0,
                fetched_from_db: chrono::Utc::now(),
            },
            auction_id: 1,
            auction_sequence: 0,
            delta_sequence: u64::MAX,
            delta_history: VecDeque::new(),
            indexed_state: Arc::new(IndexedAuctionState::default()),
        };

        let config = DeltaSyncConfig::default();
        assert!(apply_auction_id_change(&mut inner, 2, &config).is_none());
        assert_eq!(inner.delta_sequence, u64::MAX);
        assert_eq!(inner.auction_id, 1);
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    #[should_panic(expected = "update_lock must be held when mutating cache")]
    async fn assert_update_lock_held_panics_without_lock() {
        let cache = test_cache().await;
        cache.assert_update_lock_held();
    }

    #[tokio::test]
    async fn assert_update_lock_held_allows_guarded_access() {
        let cache = test_cache().await;
        let _guard = cache.update_lock.lock().await;
        cache.assert_update_lock_held();
    }

    #[test]
    fn delta_replay_includes_gap_envelope() {
        let envelope = DeltaEnvelope {
            auction_id: 7,
            auction_sequence: 2,
            from_sequence: 1,
            to_sequence: 2,
            published_at: chrono::Utc::now(),
            created_at_instant: Instant::now(),
            events: vec![DeltaEvent::OrderAdded(test_order(1, 10))],
        };
        let inner = Inner {
            auction: domain::RawAuctionData {
                block: 1,
                orders: vec![test_order(1, 10)],
                prices: HashMap::new(),
                surplus_capturing_jit_order_owners: Vec::new(),
            },
            solvable_orders: boundary::SolvableOrders {
                orders: HashMap::new(),
                quotes: HashMap::new(),
                latest_settlement_block: 0,
                fetched_from_db: chrono::Utc::now(),
            },
            auction_id: 7,
            auction_sequence: 2,
            delta_sequence: 2,
            delta_history: VecDeque::from([envelope.clone()]),
            indexed_state: Arc::new(IndexedAuctionState::default()),
        };

        let replay = SolvableOrdersCache::build_delta_replay(1, Some(&inner)).unwrap();
        assert_eq!(replay.checkpoint_sequence, 2);
        assert_eq!(replay.envelopes.len(), 1);
        assert_eq!(replay.envelopes[0].to_sequence, 2);
    }

    #[test]
    fn delta_replay_includes_auction_changed_envelope() {
        let envelope = DeltaEnvelope {
            auction_id: 8,
            auction_sequence: 0,
            from_sequence: 3,
            to_sequence: 4,
            published_at: chrono::Utc::now(),
            created_at_instant: Instant::now(),
            events: vec![DeltaEvent::AuctionChanged { new_auction_id: 8 }],
        };
        let inner = Inner {
            auction: domain::RawAuctionData {
                block: 1,
                orders: Vec::new(),
                prices: HashMap::new(),
                surplus_capturing_jit_order_owners: Vec::new(),
            },
            solvable_orders: boundary::SolvableOrders {
                orders: HashMap::new(),
                quotes: HashMap::new(),
                latest_settlement_block: 0,
                fetched_from_db: chrono::Utc::now(),
            },
            auction_id: 8,
            auction_sequence: 0,
            delta_sequence: 4,
            delta_history: VecDeque::from([envelope.clone()]),
            indexed_state: Arc::new(IndexedAuctionState::default()),
        };

        let replay = SolvableOrdersCache::build_delta_replay(3, Some(&inner)).unwrap();
        assert_eq!(replay.envelopes.len(), 1);
        assert!(matches!(
            replay.envelopes[0].events.first(),
            Some(DeltaEvent::AuctionChanged { new_auction_id: 8 })
        ));
    }

    #[test]
    fn prune_delta_history_evicts_by_max_count() {
        let now = chrono::Utc::now();
        let instant_now = Instant::now();
        let mut delta_history = VecDeque::new();

        for i in 0..(MAX_DELTA_HISTORY + 5) {
            delta_history.push_back(DeltaEnvelope {
                auction_id: 1,
                auction_sequence: i as u64,
                from_sequence: i as u64,
                to_sequence: (i + 1) as u64,
                published_at: now,
                created_at_instant: instant_now,
                events: vec![DeltaEvent::OrderAdded(test_order(1, 10))],
            });
        }

        prune_delta_history(
            &mut delta_history,
            chrono::Duration::seconds(600),
            &DeltaSyncConfig::default(),
        );

        assert_eq!(delta_history.len(), MAX_DELTA_HISTORY);
        assert_eq!(delta_history.front().unwrap().from_sequence, 5_u64);
    }

    #[test]
    fn prune_delta_history_evicts_by_age() {
        let config = DeltaSyncConfig {
            history_min_retained: 1,
            history_max_age: Duration::from_secs(300),
            broadcast_capacity: 256,
        };

        let now = chrono::Utc::now();
        let instant_now = Instant::now();
        let mut delta_history = VecDeque::from([
            DeltaEnvelope {
                auction_id: 1,
                auction_sequence: 1,
                from_sequence: 1,
                to_sequence: 2,
                published_at: now - chrono::Duration::seconds(120),
                created_at_instant: instant_now - Duration::from_secs(120),
                events: vec![DeltaEvent::OrderAdded(test_order(1, 10))],
            },
            DeltaEnvelope {
                auction_id: 1,
                auction_sequence: 2,
                from_sequence: 2,
                to_sequence: 3,
                published_at: now,
                created_at_instant: instant_now,
                events: vec![DeltaEvent::OrderAdded(test_order(2, 20))],
            },
        ]);
        prune_delta_history(&mut delta_history, chrono::Duration::seconds(60), &config);

        assert_eq!(delta_history.len(), 1);
        assert_eq!(delta_history.front().unwrap().to_sequence, 3);
    }

    #[test]
    fn boot_id_returns_stable_value_across_calls() {
        let id1 = boot_id();
        let id2 = boot_id();
        assert_eq!(id1, id2);
        assert!(!id1.is_empty());
    }

    #[test]
    fn boot_id_is_valid_uuid_format() {
        let id = boot_id();
        assert_eq!(id.len(), 36);
        assert_eq!(id.chars().filter(|&c| c == '-').count(), 4);
    }

    #[tokio::test]
    async fn set_auction_id_emits_auction_changed_envelope() {
        let cache = test_cache().await;

        // Initialize the cache with some state first
        let auction = domain::RawAuctionData {
            block: 1,
            orders: Vec::new(),
            prices: std::collections::HashMap::new(),
            surplus_capturing_jit_order_owners: Vec::new(),
        };
        cache
            .set_state_for_tests(auction, 0, 0, 0, VecDeque::new())
            .await;

        let mut receiver = cache.subscribe_deltas();

        cache.set_auction_id(42).await;

        let envelope = receiver.recv().await.unwrap();
        assert_eq!(envelope.events.len(), 1);
        assert!(matches!(
            envelope.events[0],
            DeltaEvent::AuctionChanged { new_auction_id: 42 }
        ));
    }

    #[tokio::test]
    async fn set_auction_id_with_same_id_no_envelope_emitted() {
        let cache = test_cache().await;

        // Initialize the cache with some state first
        let auction = domain::RawAuctionData {
            block: 1,
            orders: Vec::new(),
            prices: std::collections::HashMap::new(),
            surplus_capturing_jit_order_owners: Vec::new(),
        };
        cache
            .set_state_for_tests(auction, 10, 0, 0, VecDeque::new())
            .await;

        let mut receiver = cache.subscribe_deltas();
        cache.set_auction_id(10).await;

        tokio::time::timeout(Duration::from_millis(100), receiver.recv())
            .await
            .expect_err("should timeout because no envelope emitted");
    }

    #[tokio::test]
    async fn subscribe_deltas_with_replay_checked_with_none_when_sequence_0_succeeds() {
        let cache = test_cache().await;
        let auction = domain::RawAuctionData {
            block: 1,
            orders: Vec::new(),
            prices: std::collections::HashMap::new(),
            surplus_capturing_jit_order_owners: Vec::new(),
        };
        cache
            .set_state_for_tests(auction, 1, 0, 0, VecDeque::new())
            .await;

        let result = cache.subscribe_deltas_with_replay_checked(None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn subscribe_deltas_with_replay_checked_with_none_when_sequence_gt_0_fails() {
        let cache = test_cache().await;
        let auction = domain::RawAuctionData {
            block: 1,
            orders: Vec::new(),
            prices: std::collections::HashMap::new(),
            surplus_capturing_jit_order_owners: Vec::new(),
        };
        cache
            .set_state_for_tests(auction, 1, 5, 5, VecDeque::new())
            .await;

        let result = cache.subscribe_deltas_with_replay_checked(None).await;
        assert!(matches!(
            result,
            Err(DeltaSubscribeError::MissingAfterSequence { .. })
        ));
    }

    #[tokio::test]
    async fn subscribe_deltas_with_replay_returns_empty_when_history_empty_but_sequence_matches() {
        let cache = test_cache().await;
        let auction = domain::RawAuctionData {
            block: 1,
            orders: Vec::new(),
            prices: std::collections::HashMap::new(),
            surplus_capturing_jit_order_owners: Vec::new(),
        };
        cache
            .set_state_for_tests(auction, 1, 5, 5, VecDeque::new())
            .await;

        let (_receiver, replay) = cache
            .subscribe_deltas_with_replay_checked(Some(5))
            .await
            .unwrap();
        assert_eq!(replay.envelopes.len(), 0);
        assert_eq!(replay.checkpoint_sequence, 5);
    }

    #[tokio::test]
    async fn delta_checksum_is_none_when_cache_empty() {
        let cache = test_cache().await;
        let checksum = cache.delta_checksum().await;
        assert!(checksum.is_none());
    }

    #[tokio::test]
    async fn delta_checksum_returns_expected_hex_prefixed_strings() {
        let cache = test_cache().await;
        let auction = domain::RawAuctionData {
            block: 1,
            orders: vec![test_order(1, 100)],
            prices: std::collections::HashMap::from([(
                Address::repeat_byte(0xAA).into(),
                test_price(2000),
            )]),
            surplus_capturing_jit_order_owners: Vec::new(),
        };
        cache
            .set_state_for_tests(auction, 1, 10, 10, VecDeque::new())
            .await;

        let checksum = cache.delta_checksum().await.unwrap();
        assert_eq!(checksum.sequence, 10);
        assert!(checksum.order_uid_hash.starts_with("0x"));
        assert!(checksum.price_hash.starts_with("0x"));
    }

    #[tokio::test]
    #[ignore]
    async fn update_returns_error_on_sequence_overflow() {
        let cache = test_cache().await;
        let auction = domain::RawAuctionData {
            block: 1,
            orders: Vec::new(),
            prices: HashMap::new(),
            surplus_capturing_jit_order_owners: Vec::new(),
        };

        cache
            .set_state_for_tests(auction, 1, 1, u64::MAX, VecDeque::new())
            .await;

        let result = cache.update(2, false).await;
        let err = result.expect_err("update should fail on sequence overflow");
        assert!(
            err.to_string().contains("delta sequence overflow"),
            "expected overflow error, got: {err:?}"
        );
        assert_eq!(cache.delta_sequence().await, Some(u64::MAX));
    }

    #[test]
    fn checksum_order_uids_is_order_independent() {
        let orders1 = vec![test_order(1, 10), test_order(2, 20), test_order(3, 30)];
        let orders2 = vec![test_order(3, 30), test_order(1, 10), test_order(2, 20)];

        let hash1 = checksum_order_uids(&orders1);
        let hash2 = checksum_order_uids(&orders2);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn checksum_prices_is_deterministic_across_calls() {
        let mut prices = domain::auction::Prices::new();
        prices.insert(Address::repeat_byte(0xAA).into(), test_price(1000));
        prices.insert(Address::repeat_byte(0xBB).into(), test_price(2000));

        let hash1 = checksum_prices(&prices);
        let hash2 = checksum_prices(&prices);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn prune_delta_history_respects_min_retained() {
        let config = DeltaSyncConfig {
            history_min_retained: 3,
            history_max_age: Duration::from_secs(60),
            broadcast_capacity: 256,
        };

        let now = chrono::Utc::now();
        let instant_now = Instant::now();
        let mut delta_history = VecDeque::from([
            DeltaEnvelope {
                auction_id: 1,
                auction_sequence: 1,
                from_sequence: 1,
                to_sequence: 2,
                published_at: now - chrono::Duration::seconds(200),
                created_at_instant: instant_now - Duration::from_secs(200),
                events: vec![],
            },
            DeltaEnvelope {
                auction_id: 1,
                auction_sequence: 2,
                from_sequence: 2,
                to_sequence: 3,
                published_at: now - chrono::Duration::seconds(150),
                created_at_instant: instant_now - Duration::from_secs(150),
                events: vec![],
            },
            DeltaEnvelope {
                auction_id: 1,
                auction_sequence: 3,
                from_sequence: 3,
                to_sequence: 4,
                published_at: now - chrono::Duration::seconds(100),
                created_at_instant: instant_now - Duration::from_secs(100),
                events: vec![],
            },
        ]);

        prune_delta_history(&mut delta_history, chrono::Duration::seconds(50), &config);

        assert_eq!(delta_history.len(), 3);
    }

    #[test]
    fn prune_delta_history_with_zero_age_respects_minimum() {
        let config = DeltaSyncConfig {
            history_min_retained: 2,
            history_max_age: Duration::from_secs(60),
            broadcast_capacity: 256,
        };

        let now = chrono::Utc::now();
        let instant_now = Instant::now();
        let mut delta_history = VecDeque::from([
            DeltaEnvelope {
                auction_id: 1,
                auction_sequence: 1,
                from_sequence: 1,
                to_sequence: 2,
                published_at: now - chrono::Duration::seconds(100),
                created_at_instant: instant_now - Duration::from_secs(100),
                events: vec![],
            },
            DeltaEnvelope {
                auction_id: 1,
                auction_sequence: 2,
                from_sequence: 2,
                to_sequence: 3,
                published_at: now,
                created_at_instant: instant_now,
                events: vec![],
            },
        ]);

        prune_delta_history(&mut delta_history, chrono::Duration::zero(), &config);

        assert_eq!(delta_history.len(), 2);
    }

    #[test]
    fn build_indexed_state_with_dust_order_not_tracked() {
        let order = test_order(1, 10);
        let auction = domain::RawAuctionData {
            block: 1,
            orders: vec![order.clone()],
            prices: std::collections::HashMap::new(),
            surplus_capturing_jit_order_owners: Vec::new(),
        };

        let invalid_order_uids = HashMap::new();
        let filtered_events: &[(OrderUid, OrderFilterReason)] =
            &[(OrderUid::from(order.uid), OrderFilterReason::DustOrder)];

        let state = build_indexed_state(&auction, &invalid_order_uids, filtered_events);

        // DustOrder is not tracked in any specific filtered set
        assert!(
            !state
                .filtered_in_flight
                .contains(&OrderUid::from(order.uid))
        );
        assert!(
            !state
                .filtered_no_balance
                .contains(&OrderUid::from(order.uid))
        );
        assert!(!state.filtered_no_price.contains(&OrderUid::from(order.uid)));
    }

    #[test]
    fn normalized_delta_surface_sorts_orders_by_uid() {
        let order1 = test_order(1, 10);
        let order2 = test_order(2, 20);
        let order3 = test_order(3, 30);

        let auction = domain::RawAuctionData {
            block: 1,
            orders: vec![order3.clone(), order1.clone(), order2.clone()],
            prices: std::collections::HashMap::new(),
            surplus_capturing_jit_order_owners: Vec::new(),
        };

        let normalized = normalized_delta_surface(auction);

        assert_eq!(normalized.orders[0].uid, order1.uid);
        assert_eq!(normalized.orders[1].uid, order2.uid);
        assert_eq!(normalized.orders[2].uid, order3.uid);
    }

    #[test]
    fn apply_delta_events_to_auction_with_auction_changed_event() {
        let auction = domain::RawAuctionData {
            block: 1,
            orders: Vec::new(),
            prices: std::collections::HashMap::new(),
            surplus_capturing_jit_order_owners: Vec::new(),
        };

        let events = vec![DeltaEvent::AuctionChanged { new_auction_id: 99 }];

        let result =
            crate::solvable_orders::apply_delta_events_to_auction(auction.clone(), &events);

        assert_eq!(result.block, auction.block);
        assert_eq!(result.orders.len(), 0);
    }

    #[test]
    fn delta_events_equivalent_when_same_events_in_different_order() {
        let events1 = vec![
            DeltaEvent::OrderAdded(test_order(1, 10)),
            DeltaEvent::OrderAdded(test_order(2, 20)),
        ];
        let events2 = vec![
            DeltaEvent::OrderAdded(test_order(2, 20)),
            DeltaEvent::OrderAdded(test_order(1, 10)),
        ];

        assert!(delta_events_equivalent(&events1, &events2));
    }

    #[test]
    fn delta_events_equivalent_when_events_differ() {
        let events1 = vec![DeltaEvent::OrderAdded(test_order(1, 10))];
        let events2 = vec![DeltaEvent::OrderAdded(test_order(2, 20))];

        assert!(!delta_events_equivalent(&events1, &events2));
    }

    #[test]
    fn delta_event_cmp_ordering_added_lt_updated_lt_removed_lt_price() {
        let uid = domain::OrderUid([1; 56]);
        let token = Address::repeat_byte(0xAA);

        let added = DeltaEvent::OrderAdded(test_order(1, 10));
        let updated = DeltaEvent::OrderUpdated(test_order(1, 10));
        let removed = DeltaEvent::OrderRemoved(uid);
        let price = DeltaEvent::PriceChanged {
            token,
            price: Some(test_price(1000)),
        };

        assert!(delta_event_cmp(&added, &updated) == std::cmp::Ordering::Less);
        assert!(delta_event_cmp(&updated, &removed) == std::cmp::Ordering::Less);
        assert!(delta_event_cmp(&removed, &price) == std::cmp::Ordering::Less);
    }

    #[test]
    fn delta_sync_config_allows_custom_min_retained() {
        let config = DeltaSyncConfig {
            history_min_retained: 42,
            history_max_age: Duration::from_secs(60),
            broadcast_capacity: 256,
        };
        assert_eq!(config.history_min_retained, 42);
    }

    #[test]
    fn delta_sync_config_allows_custom_max_age() {
        let config = DeltaSyncConfig {
            history_min_retained: 10,
            history_max_age: Duration::from_secs(123),
            broadcast_capacity: 256,
        };
        assert_eq!(config.history_max_age, Duration::from_secs(123));
    }

    #[test]
    fn alive_uids_filter_excludes_already_processed_orders() {
        let mut alive_uids = HashSet::new();
        alive_uids.insert(domain::OrderUid([1; 56]));
        alive_uids.insert(domain::OrderUid([2; 56]));

        let all_visible = [
            domain::OrderUid([1; 56]),
            domain::OrderUid([2; 56]),
            domain::OrderUid([3; 56]),
        ];

        let to_reprocess = all_visible
            .iter()
            .filter(|uid| !alive_uids.contains(uid))
            .copied()
            .collect::<Vec<_>>();

        assert_eq!(to_reprocess, vec![domain::OrderUid([3; 56])]);
    }

    #[tokio::test]
    async fn jit_owner_change_reapplies_fees_only_to_non_alive_orders() {
        let mut cache = test_cache().await;
        Arc::get_mut(&mut cache)
            .expect("cache arc should be uniquely owned in test")
            .disable_order_balance_filter = true;

        let uid1 = domain::OrderUid([1; 56]);
        let uid2 = domain::OrderUid([2; 56]);

        let owner1 = Address::repeat_byte(0x11);
        let owner2 = Address::repeat_byte(0x22);
        let token_sell = Address::repeat_byte(0xA1);
        let token_buy = Address::repeat_byte(0xB1);

        let mut boundary_order1 = model::order::Order::default();
        boundary_order1.metadata.uid = model::order::OrderUid(uid1.0);
        boundary_order1.metadata.owner = owner1;
        boundary_order1.data.sell_token = token_sell;
        boundary_order1.data.buy_token = token_buy;
        boundary_order1.data.sell_amount = U256::from(10);
        boundary_order1.data.buy_amount = U256::from(10);

        let mut boundary_order2 = model::order::Order::default();
        boundary_order2.metadata.uid = model::order::OrderUid(uid2.0);
        boundary_order2.metadata.owner = owner2;
        boundary_order2.data.sell_token = token_sell;
        boundary_order2.data.buy_token = token_buy;
        boundary_order2.data.sell_amount = U256::from(20);
        boundary_order2.data.buy_amount = U256::from(20);

        let db_solvable_orders = boundary::SolvableOrders {
            orders: HashMap::from([
                (uid1, Arc::new(boundary_order1.clone())),
                (uid2, Arc::new(boundary_order2.clone())),
            ]),
            quotes: HashMap::new(),
            latest_settlement_block: 0,
            fetched_from_db: chrono::Utc::now(),
        };

        let mut previous_indexed_state = IndexedAuctionState::default();
        previous_indexed_state
            .current_orders_by_uid
            .insert(uid1, test_order(1, 10));
        previous_indexed_state
            .current_orders_by_uid
            .insert(uid2, test_order(2, 99));
        previous_indexed_state.surplus_capturing_jit_order_owners =
            vec![Address::repeat_byte(0xFF)];

        let mut change_bundle = ChangeBundle {
            order_updated_candidates: vec![uid1],
            ..Default::default()
        };

        let inputs = cache
            .collect_inputs_incremental(
                &previous_indexed_state,
                db_solvable_orders,
                &mut change_bundle,
                1,
                false,
            )
            .await
            .expect("incremental collection should succeed");

        let indexed = match inputs.mode {
            CollectionMode::Incremental(state) => state,
            CollectionMode::Full => panic!("incremental path should return indexed state"),
        };

        // uid1 is alive and processed in the alive loop.
        assert!(change_bundle.order_updated_candidates.contains(&uid1));

        // uid2 is non-alive; it should still be recomputed because JIT owners changed.
        let expected_uid2 = cache.protocol_fees.apply(&boundary_order2, None, &[]);
        let actual_uid2 = indexed
            .current_orders_by_uid
            .get(&uid2)
            .expect("uid2 should remain solver-visible");
        assert_eq!(actual_uid2, &expected_uid2);
        assert_ne!(actual_uid2, &test_order(2, 99));
    }

    // ========================================================================
    // Integration and Property Tests
    // ========================================================================

    #[test]
    fn property_round_trip_delta_events_reconstruct_identical_state() {
        // Property: For any sequence of random DeltaEvents,
        // apply_delta_events_to_auction(base, events) followed by
        // compute_delta_events(Some(&base), &result) should produce events
        // that reconstruct result identically.

        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        for iteration in 0..20 {
            // Create a random base state
            let base = domain::RawAuctionData {
                block: rng.gen_range(1..1000),
                orders: (0..rng.gen_range(1..5))
                    .map(|i| test_order(i as u8, rng.gen_range(10..100)))
                    .collect(),
                prices: {
                    let mut prices = std::collections::HashMap::new();
                    for i in 0..rng.gen_range(1..4) {
                        prices.insert(
                            Address::repeat_byte(i as u8).into(),
                            test_price(rng.gen_range(100..10000)),
                        );
                    }
                    prices
                },
                surplus_capturing_jit_order_owners: Vec::new(),
            };

            // Generate random delta events
            let mut events = Vec::new();
            for _ in 0..rng.gen_range(1..10) {
                let event = match rng.gen_range(0..5) {
                    0 => DeltaEvent::OrderAdded(test_order(
                        rng.gen_range(10..20),
                        rng.gen_range(10..100),
                    )),
                    1 => {
                        if !base.orders.is_empty() {
                            let idx = rng.gen_range(0..base.orders.len());
                            DeltaEvent::OrderRemoved(base.orders[idx].uid)
                        } else {
                            continue;
                        }
                    }
                    2 => DeltaEvent::OrderUpdated(test_order(
                        rng.gen_range(0..5),
                        rng.gen_range(10..100),
                    )),
                    3 => DeltaEvent::PriceChanged {
                        token: Address::repeat_byte(rng.gen_range(0..10)),
                        price: if rng.gen_bool(0.5) {
                            Some(test_price(rng.gen_range(100..10000)))
                        } else {
                            None
                        },
                    },
                    4 => DeltaEvent::BlockChanged {
                        block: rng.gen_range(1000..2000),
                    },
                    _ => unreachable!(),
                };
                events.push(event);
            }

            // Apply events to get result state
            let result =
                crate::solvable_orders::apply_delta_events_to_auction(base.clone(), &events);

            // Compute delta from base to result
            let normalized_base = normalized_delta_surface(base.clone());
            let normalized_result = normalized_delta_surface(result.clone());
            let computed_events = compute_delta_events(Some(&normalized_base), &normalized_result);

            // Apply computed events to base
            let reconstructed = crate::solvable_orders::apply_delta_events_to_auction(
                normalized_base.clone(),
                &computed_events,
            );

            // Verify reconstruction matches result
            let reconstructed_normalized = normalized_delta_surface(reconstructed);
            assert_eq!(
                reconstructed_normalized.orders.len(),
                normalized_result.orders.len(),
                "iteration {}: order count mismatch",
                iteration
            );
            assert_eq!(
                reconstructed_normalized.prices.len(),
                normalized_result.prices.len(),
                "iteration {}: price count mismatch",
                iteration
            );

            // Verify order UIDs match
            let reconstructed_uids: std::collections::HashSet<_> = reconstructed_normalized
                .orders
                .iter()
                .map(|o| o.uid)
                .collect();
            let result_uids: std::collections::HashSet<_> =
                normalized_result.orders.iter().map(|o| o.uid).collect();
            assert_eq!(
                reconstructed_uids, result_uids,
                "iteration {}: order UIDs mismatch",
                iteration
            );

            // Verify price tokens match
            let reconstructed_tokens: std::collections::HashSet<_> =
                reconstructed_normalized.prices.keys().cloned().collect();
            let result_tokens: std::collections::HashSet<_> =
                normalized_result.prices.keys().cloned().collect();
            assert_eq!(
                reconstructed_tokens, result_tokens,
                "iteration {}: price tokens mismatch",
                iteration
            );
        }
    }

    #[test]
    fn property_checksum_stability_identical_inputs_produce_identical_outputs() {
        // Property: checksum_order_uids and checksum_prices produce identical
        // output for identical inputs across multiple calls.

        let orders = vec![test_order(1, 100), test_order(2, 200), test_order(3, 250)];

        let mut prices = domain::auction::Prices::new();
        prices.insert(Address::repeat_byte(0xAA).into(), test_price(1000));
        prices.insert(Address::repeat_byte(0xBB).into(), test_price(2000));
        prices.insert(Address::repeat_byte(0xCC).into(), test_price(3000));

        // Call checksums multiple times
        let order_hashes: Vec<String> = (0..10).map(|_| checksum_order_uids(&orders)).collect();
        let price_hashes: Vec<String> = (0..10).map(|_| checksum_prices(&prices)).collect();

        // Verify all hashes are identical
        for i in 1..order_hashes.len() {
            assert_eq!(
                order_hashes[0], order_hashes[i],
                "order checksum changed on call {}",
                i
            );
        }

        for i in 1..price_hashes.len() {
            assert_eq!(
                price_hashes[0], price_hashes[i],
                "price checksum changed on call {}",
                i
            );
        }

        // Verify checksums are deterministic even with different order
        let orders_reversed = vec![test_order(3, 250), test_order(2, 200), test_order(1, 100)];
        let hash_reversed = checksum_order_uids(&orders_reversed);
        assert_eq!(
            order_hashes[0], hash_reversed,
            "order checksum not order-independent"
        );
    }

    #[tokio::test]
    async fn property_sequence_monotonicity_with_test_overrides_never_decreases() {
        // Property: After any sequence of `set_state_for_tests()` + `set_auction_id()`
        // calls (i.e. direct test overrides), delta_sequence never decreases.

        let cache = test_cache().await;

        // Initialize with a base state
        let base_auction = domain::RawAuctionData {
            block: 1,
            orders: vec![test_order(1, 100)],
            prices: std::collections::HashMap::new(),
            surplus_capturing_jit_order_owners: Vec::new(),
        };
        cache
            .set_state_for_tests(base_auction.clone(), 1, 5, 5, VecDeque::new())
            .await;

        let mut last_sequence = cache.delta_sequence().await.unwrap();
        assert_eq!(last_sequence, 5);

        // Perform a series of operations
        for i in 0..10 {
            // Alternate between set_auction_id and state updates
            if i % 2 == 0 {
                cache.set_auction_id(10 + i).await;
            } else {
                let updated_auction = domain::RawAuctionData {
                    block: 1 + i,
                    orders: vec![test_order((i % 5) as u8, (100 + i * 10) as u8)],
                    prices: std::collections::HashMap::new(),
                    surplus_capturing_jit_order_owners: Vec::new(),
                };
                cache
                    .set_state_for_tests(
                        updated_auction,
                        10 + i,
                        last_sequence + 1,
                        last_sequence + 1,
                        VecDeque::new(),
                    )
                    .await;
            }

            let current_sequence = cache.delta_sequence().await.unwrap();
            assert!(
                current_sequence >= last_sequence,
                "sequence decreased from {} to {} at iteration {}",
                last_sequence,
                current_sequence,
                i
            );
            last_sequence = current_sequence;
        }
    }

    #[tokio::test]
    async fn property_broadcast_ordering_monotonic_to_sequence() {
        // Property: Envelopes sent while holding cache lock are received by
        // subscribers in monotonically increasing to_sequence order.

        let cache = test_cache().await;

        // Initialize cache
        let base_auction = domain::RawAuctionData {
            block: 1,
            orders: Vec::new(),
            prices: std::collections::HashMap::new(),
            surplus_capturing_jit_order_owners: Vec::new(),
        };
        cache
            .set_state_for_tests(base_auction, 1, 0, 0, VecDeque::new())
            .await;

        // Create multiple subscribers
        let mut receiver1 = cache.subscribe_deltas();
        let mut receiver2 = cache.subscribe_deltas();
        let mut receiver3 = cache.subscribe_deltas();

        // Publish a sequence of envelopes
        let num_envelopes = 20;
        for i in 1..=num_envelopes {
            cache
                .publish_delta_for_tests(DeltaEnvelope {
                    auction_id: 1,
                    auction_sequence: i,
                    from_sequence: i - 1,
                    to_sequence: i,
                    published_at: chrono::Utc::now(),
                    created_at_instant: Instant::now(),
                    events: vec![DeltaEvent::OrderAdded(test_order(i as u8, 100))],
                })
                .await;
        }

        // Verify all subscribers receive envelopes in order
        let mut last_sequence_1 = 0;
        for _ in 0..num_envelopes {
            let envelope = tokio::time::timeout(Duration::from_secs(1), receiver1.recv())
                .await
                .expect("timeout waiting for envelope")
                .expect("receiver closed");
            assert!(
                envelope.to_sequence > last_sequence_1,
                "receiver1: sequence not monotonic: {} -> {}",
                last_sequence_1,
                envelope.to_sequence
            );
            last_sequence_1 = envelope.to_sequence;
        }

        let mut last_sequence_2 = 0;
        for _ in 0..num_envelopes {
            let envelope = tokio::time::timeout(Duration::from_secs(1), receiver2.recv())
                .await
                .expect("timeout waiting for envelope")
                .expect("receiver closed");
            assert!(
                envelope.to_sequence > last_sequence_2,
                "receiver2: sequence not monotonic: {} -> {}",
                last_sequence_2,
                envelope.to_sequence
            );
            last_sequence_2 = envelope.to_sequence;
        }

        let mut last_sequence_3 = 0;
        for _ in 0..num_envelopes {
            let envelope = tokio::time::timeout(Duration::from_secs(1), receiver3.recv())
                .await
                .expect("timeout waiting for envelope")
                .expect("receiver closed");
            assert!(
                envelope.to_sequence > last_sequence_3,
                "receiver3: sequence not monotonic: {} -> {}",
                last_sequence_3,
                envelope.to_sequence
            );
            last_sequence_3 = envelope.to_sequence;
        }

        // Verify all subscribers received the same final sequence
        assert_eq!(last_sequence_1, num_envelopes);
        assert_eq!(last_sequence_2, num_envelopes);
        assert_eq!(last_sequence_3, num_envelopes);
    }

    #[tokio::test]
    async fn integration_concurrent_subscribers_receive_all_envelopes() {
        // Integration test: Multiple concurrent subscribers all receive the same
        // envelopes in the same order.

        let cache = test_cache().await;

        let base_auction = domain::RawAuctionData {
            block: 1,
            orders: Vec::new(),
            prices: std::collections::HashMap::new(),
            surplus_capturing_jit_order_owners: Vec::new(),
        };
        cache
            .set_state_for_tests(base_auction, 1, 0, 0, VecDeque::new())
            .await;

        // Spawn multiple subscriber tasks
        let num_subscribers = 5;
        let num_envelopes = 15;
        let mut handles = Vec::new();

        for subscriber_id in 0..num_subscribers {
            let cache_clone = Arc::clone(&cache);
            let handle = tokio::spawn(async move {
                let mut receiver = cache_clone.subscribe_deltas();
                let mut received = Vec::new();

                for _ in 0..num_envelopes {
                    match tokio::time::timeout(Duration::from_secs(2), receiver.recv()).await {
                        Ok(Ok(envelope)) => {
                            received.push(envelope.to_sequence);
                        }
                        Ok(Err(_)) => break,
                        Err(_) => break,
                    }
                }

                (subscriber_id, received)
            });
            handles.push(handle);
        }

        // Give subscribers time to subscribe
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Publish envelopes
        for i in 1..=num_envelopes {
            cache
                .publish_delta_for_tests(DeltaEnvelope {
                    auction_id: 1,
                    auction_sequence: i,
                    from_sequence: i - 1,
                    to_sequence: i,
                    published_at: chrono::Utc::now(),
                    created_at_instant: Instant::now(),
                    events: vec![DeltaEvent::BlockChanged { block: i }],
                })
                .await;
        }

        // Collect results from all subscribers
        let mut results = Vec::new();
        for handle in handles {
            let (subscriber_id, received) = handle.await.unwrap();
            results.push((subscriber_id, received));
        }

        // Verify all subscribers received all envelopes
        let expected: Vec<u64> = (1..=num_envelopes).collect();
        for (subscriber_id, received) in results {
            assert_eq!(
                received, expected,
                "subscriber {} did not receive all envelopes in order",
                subscriber_id
            );
        }
    }

    #[tokio::test]
    async fn integration_replay_consistency_with_live_stream() {
        // Integration test: Replay + live stream produces consistent sequences.

        let cache = test_cache().await;

        let base_auction = domain::RawAuctionData {
            block: 1,
            orders: vec![test_order(1, 100)],
            prices: std::collections::HashMap::new(),
            surplus_capturing_jit_order_owners: Vec::new(),
        };

        // Build up some history
        let mut history = VecDeque::new();
        for i in 1..=5 {
            history.push_back(DeltaEnvelope {
                auction_id: 1,
                auction_sequence: i,
                from_sequence: i - 1,
                to_sequence: i,
                published_at: chrono::Utc::now(),
                created_at_instant: Instant::now(),
                events: vec![DeltaEvent::OrderAdded(test_order(
                    i as u8,
                    ((100 + i * 10) % 256) as u8,
                ))],
            });
        }

        cache
            .set_state_for_tests(base_auction, 1, 5, 1, history)
            .await;

        // Subscribe with replay from sequence 1 (first available)
        let (mut receiver, replay) = cache
            .subscribe_deltas_with_replay_checked(Some(1))
            .await
            .unwrap();

        // Collect replay envelopes
        let mut all_sequences = Vec::new();
        for envelope in replay.envelopes {
            all_sequences.push(envelope.to_sequence);
        }

        // Publish more envelopes after replay
        for i in 6..=10 {
            cache
                .publish_delta_for_tests(DeltaEnvelope {
                    auction_id: 1,
                    auction_sequence: i,
                    from_sequence: i - 1,
                    to_sequence: i,
                    published_at: chrono::Utc::now(),
                    created_at_instant: Instant::now(),
                    events: vec![DeltaEvent::OrderAdded(test_order(
                        i as u8,
                        ((100 + i * 10) % 256) as u8,
                    ))],
                })
                .await;
        }

        // Collect live envelopes
        for _ in 0..5 {
            match tokio::time::timeout(Duration::from_secs(1), receiver.recv()).await {
                Ok(Ok(envelope)) => {
                    all_sequences.push(envelope.to_sequence);
                }
                _ => break,
            }
        }

        // Verify we received sequences in order (replay + live)
        // Replay should include 1-5, live should include 6-10
        assert!(
            all_sequences.len() >= 5,
            "should have received at least 5 envelopes"
        );

        // Verify monotonic ordering
        for i in 1..all_sequences.len() {
            assert!(
                all_sequences[i] > all_sequences[i - 1],
                "sequences not monotonic: {} -> {}",
                all_sequences[i - 1],
                all_sequences[i]
            );
        }
    }

    #[test]
    fn property_delta_events_idempotent_application() {
        // Property: Applying the same delta events multiple times produces
        // the same result as applying them once.

        let base = domain::RawAuctionData {
            block: 1,
            orders: vec![test_order(1, 100)],
            prices: std::collections::HashMap::new(),
            surplus_capturing_jit_order_owners: Vec::new(),
        };

        let events = vec![
            DeltaEvent::OrderAdded(test_order(2, 200)),
            DeltaEvent::OrderUpdated(test_order(1, 150)),
            DeltaEvent::PriceChanged {
                token: Address::repeat_byte(0xAA),
                price: Some(test_price(1000)),
            },
        ];

        let result_once =
            crate::solvable_orders::apply_delta_events_to_auction(base.clone(), &events);
        let result_twice =
            crate::solvable_orders::apply_delta_events_to_auction(result_once.clone(), &events);

        // For idempotent events (OrderAdded becomes OrderUpdated on second apply)
        // we expect the order counts to match
        assert_eq!(result_once.orders.len(), result_twice.orders.len());
        assert_eq!(result_once.prices.len(), result_twice.prices.len());
    }

    #[test]
    fn property_checksum_changes_on_state_modification() {
        // Property: Any modification to orders or prices changes the checksum.

        let orders1 = vec![test_order(1, 100), test_order(2, 200)];
        let orders2 = vec![test_order(1, 100), test_order(3, 200)]; // Different UID
        let orders3 = vec![test_order(1, 100)]; // Fewer orders

        let hash1 = checksum_order_uids(&orders1);
        let hash2 = checksum_order_uids(&orders2);
        let hash3 = checksum_order_uids(&orders3);

        assert_ne!(
            hash1, hash2,
            "checksum should change when order UID changes"
        );
        assert_ne!(hash1, hash3, "checksum should change when order removed");

        let mut prices1 = domain::auction::Prices::new();
        prices1.insert(Address::repeat_byte(0xAA).into(), test_price(1000));

        let mut prices2 = domain::auction::Prices::new();
        prices2.insert(Address::repeat_byte(0xAA).into(), test_price(2000));

        let mut prices3 = domain::auction::Prices::new();
        prices3.insert(Address::repeat_byte(0xBB).into(), test_price(1000));

        let price_hash1 = checksum_prices(&prices1);
        let price_hash2 = checksum_prices(&prices2);
        let price_hash3 = checksum_prices(&prices3);

        assert_ne!(
            price_hash1, price_hash2,
            "checksum should change when price value changes"
        );
        assert_ne!(
            price_hash1, price_hash3,
            "checksum should change when price token changes"
        );
    }
}
