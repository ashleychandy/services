/// Note: cloning shares the underlying cache instance.
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

#[derive(Clone)]
pub(crate) struct Cache<K, V> {
    data: moka::sync::Cache<K, V>,
    detector: &'static str,
    entry_count: Arc<AtomicU64>,
}

impl<K, V> Cache<K, V>
where
    K: std::hash::Hash + Eq + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    pub(crate) fn new(max_capacity: u64, detector: &'static str) -> Self {
        let detector_copy = detector;

        let entry_count = Arc::new(AtomicU64::new(0));
        let entry_count_listener = entry_count.clone();

        let data = moka::sync::Cache::builder()
            .max_capacity(max_capacity)
            .eviction_listener(move |_k, _v, _cause| {
                crate::metrics::Metrics::get()
                    .cache_evictions_total
                    .with_label_values(&[detector_copy])
                    .inc();

                loop {
                    let current = entry_count_listener.load(Ordering::Acquire);
                    if current == 0 {
                        break;
                    }
                    let new = current - 1;
                    if entry_count_listener
                        .compare_exchange(current, new, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        break;
                    }
                }

                crate::metrics::Metrics::get()
                    .cache_entries
                    .with_label_values(&[detector_copy])
                    .set(
                        i64::try_from(entry_count_listener.load(Ordering::Relaxed))
                            .unwrap_or(i64::MAX),
                    );
            })
            .build();

        let cache = Self {
            data,
            detector,
            entry_count,
        };

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
        let is_new = self.data.get(&key).is_none();
        self.data.insert(key, value);
        if is_new {
            let new = self.entry_count.fetch_add(1, Ordering::AcqRel) + 1;
            crate::metrics::Metrics::get()
                .cache_entries
                .with_label_values(&[self.detector])
                .set(i64::try_from(new).unwrap_or(i64::MAX));
        }
    }
}
