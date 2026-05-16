use prometheus::{HistogramVec, IntCounterVec, IntGaugeVec};

#[derive(prometheus_metric_storage::MetricStorage)]
pub struct Metrics {
    /// Counter of cache hits grouped by detector (approval/balance).
    #[metric(labels("detector"))]
    pub cache_hits: IntCounterVec,

    /// Counter of cache misses grouped by detector (approval/balance).
    #[metric(labels("detector"))]
    pub cache_misses: IntCounterVec,

    /// Detection duration for *cache hit* paths (microsecond-scale).
    /// Labels: `detector`, `type` (cache_hit|cache_hit_specific).
    #[metric(
        labels("detector", "hit_type"),
        buckets(
            0.000001, 0.0000025, 0.000005, 0.00001, 0.000025, 0.00005, 0.0001, 0.00025, 0.0005,
            0.001
        )
    )]
    pub detection_duration_cache_hit_seconds: HistogramVec,

    /// Detection duration for *uncached* (RPC) paths (millisecond+ scale).
    /// Labels: `detector`, `result`
    /// (uncached_found|uncached_not_found|uncached_error).
    #[metric(
        labels("detector", "result"),
        buckets(
            0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0
        )
    )]
    pub detection_duration_uncached_seconds: HistogramVec,

    /// Current number of entries in the cache, labeled by detector.
    #[metric(labels("detector"))]
    pub cache_entries: IntGaugeVec,

    /// Total number of cache evictions observed, labeled by detector.
    #[metric(labels("detector"))]
    pub cache_evictions_total: IntCounterVec,
}

impl Metrics {
    pub fn get() -> &'static Self {
        Metrics::instance(observe::metrics::get_storage_registry())
            .expect("unexpected error getting metrics instance")
    }
}
