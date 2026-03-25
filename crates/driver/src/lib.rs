//! This is a library so that it can be used from e2e tests without having to
//! spawn a process.

#![forbid(unsafe_code)]

pub mod boundary;
pub mod domain;
pub mod infra;
mod run;
pub mod util;

#[cfg(test)]
mod tests;

#[cfg(feature = "test-helpers")]
pub mod test_helpers {
    pub use crate::infra::delta_sync::{
        DeltaReplicaTestGuard,
        reset_delta_replica_for_tests as reset_delta_replica,
        set_driver_delta_sync_autopilot_url_override,
        set_driver_delta_sync_enabled_override,
        set_replica_preprocessing_override,
    };
}

pub use self::run::{run, start};
