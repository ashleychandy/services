/// Note: cloning shares the underlying cache instance.
#[derive(Clone)]
pub(crate) struct Cache<K, V> {
    data: moka::sync::Cache<K, V>,
    detector: &'static str,
}

impl<K, V> Cache<K, V>
where
    K: std::hash::Hash + Eq + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    pub(crate) fn new(max_capacity: u64, detector: &'static str) -> Self {
        let detector_copy = detector;

        let data = moka::sync::Cache::builder()
            .max_capacity(max_capacity)
            .eviction_listener(move |_k, _v, _cause| {
                crate::metrics::Metrics::get()
                    .cache_evictions_total
                    .with_label_values(&[detector_copy])
                    .inc();
                crate::metrics::Metrics::get()
                    .cache_entries
                    .with_label_values(&[detector_copy])
                    .dec();
            })
            .build();

        let cache = Self { data, detector };

        crate::metrics::Metrics::get()
            .cache_entries
            .with_label_values(&[cache.detector])
            .set(i64::try_from(cache.data.entry_count()).unwrap_or(i64::MAX));

        cache
    }

    pub(crate) fn get(&self, key: &K) -> Option<V> {
        self.data.get(key)
    }

    pub(crate) fn insert(&self, key: K, value: V) {
        self.data.insert(key, value);
        crate::metrics::Metrics::get()
            .cache_entries
            .with_label_values(&[self.detector])
            .inc();
    }
}
