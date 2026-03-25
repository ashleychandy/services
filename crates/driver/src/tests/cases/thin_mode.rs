use crate::{
    infra::delta_sync::{DeltaReplicaTestGuard, REPLICA_PREPROCESSING_OVERRIDE},
    tests::{
        self,
        setup::{ab_order, ab_pool, ab_solution},
    },
};

struct ReplicaOverrideGuard {
    previous: u8,
}

impl ReplicaOverrideGuard {
    fn enable() -> Self {
        let previous = REPLICA_PREPROCESSING_OVERRIDE.swap(1, std::sync::atomic::Ordering::SeqCst);
        Self { previous }
    }
}

impl Drop for ReplicaOverrideGuard {
    fn drop(&mut self) {
        REPLICA_PREPROCESSING_OVERRIDE.store(self.previous, std::sync::atomic::Ordering::SeqCst);
    }
}

#[tokio::test]
async fn thin_mode_falls_back_to_full_body_when_replica_unavailable() {
    let _replica_guard = DeltaReplicaTestGuard::acquire();
    let _env = ReplicaOverrideGuard::enable();

    let test = tests::setup()
        .name("thin body fallback")
        .pool(ab_pool())
        .order(ab_order())
        .solution(ab_solution())
        .done()
        .await;

    let solve = test.solve_with_body_mode("thin").await;
    solve.ok();
}
