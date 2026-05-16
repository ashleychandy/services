pub mod approval;
pub mod balance;
mod cache;
pub mod detector;
mod metrics;

use {alloy_primitives::Address, alloy_rpc_types::state::AccountOverride};
pub use {
    approval::{ApprovalOverrideRequest, ApprovalStrategy},
    balance::BalanceOverrideRequest,
};

/// A component that can provide ERC-20 balance and allowance state overrides.
///
/// This allows a wider range of verified quotes to work, even when balances or
/// approvals are not available for the quoter.
#[async_trait::async_trait]
pub trait StateOverriding: Send + Sync + 'static {
    async fn balance_override(
        &self,
        request: BalanceOverrideRequest,
    ) -> Option<(Address, AccountOverride)>;

    async fn approval_override(
        &self,
        request: ApprovalOverrideRequest,
    ) -> Option<(Address, AccountOverride)>;
}

/// The default state override provider, handling both ERC-20 balance and
/// allowance overrides.
#[derive(Debug)]
pub struct StateOverrides {
    pub(crate) balance_detector: balance::Detector,
    pub(crate) approval_detector: approval::Detector,
}

impl StateOverrides {
    /// Creates a new instance with default detection parameters.
    pub fn new(web3: ethrpc::Web3) -> Self {
        Self::with_config(web3, 60, detector::DEFAULT_VERIFICATION_TIMEOUT, 1000)
    }

    /// Creates a new instance with custom detection parameters.
    pub fn with_config(
        web3: ethrpc::Web3,
        probing_depth: u8,
        verification_timeout: std::time::Duration,
        cache_size: usize,
    ) -> Self {
        Self {
            balance_detector: balance::Detector::new(
                web3.clone(),
                probing_depth,
                verification_timeout,
                cache_size,
            ),
            approval_detector: approval::Detector::new(
                web3,
                probing_depth,
                verification_timeout,
                cache_size,
            ),
        }
    }
}

#[async_trait::async_trait]
impl StateOverriding for StateOverrides {
    async fn balance_override(
        &self,
        request: BalanceOverrideRequest,
    ) -> Option<(Address, AccountOverride)> {
        let strategy = self
            .balance_detector
            .detect(request.token, request.holder)
            .await?;

        strategy
            .state_override(&request.holder, &request.amount)
            .await
            .into_iter()
            .last()
    }

    async fn approval_override(
        &self,
        request: ApprovalOverrideRequest,
    ) -> Option<(Address, AccountOverride)> {
        let strategy = self
            .approval_detector
            .detect(request.token, request.owner, request.spender)
            .await?;
        strategy
            .state_override(request.owner, request.spender, request.amount)
            .into_iter()
            .last()
    }
}

/// State overrider that always returns `None`. Useful for testing.
pub struct DummyStateOverrider;

#[async_trait::async_trait]
impl StateOverriding for DummyStateOverrider {
    async fn balance_override(
        &self,
        _request: BalanceOverrideRequest,
    ) -> Option<(Address, AccountOverride)> {
        None
    }

    async fn approval_override(
        &self,
        _request: ApprovalOverrideRequest,
    ) -> Option<(Address, AccountOverride)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::balance::Strategy,
        alloy_primitives::{B256, U256, address, b256},
        ethrpc::mock,
    };

    #[tokio::test]
    async fn balance_override_computation() {
        let cow = address!("DEf1CA1fb7FBcDC777520aa7f396b4E015F497aB");
        let holder = address!("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
        let amount = U256::from(0x42);
        let strategy = Strategy::SolidityMapping {
            target_contract: cow,
            map_slot: U256::from(0),
        };

        let result = strategy
            .state_override(&holder, &amount)
            .await
            .into_iter()
            .last();
        assert_eq!(
            result,
            Some((
                cow,
                AccountOverride {
                    state_diff: Some(
                        std::iter::once((
                            b256!(
                                "fca351f4d96129454cfc8ef7930b638ac71fea35eb69ee3b8d959496beb04a33"
                            ),
                            b256!(
                                "0000000000000000000000000000000000000000000000000000000000000042"
                            )
                        ))
                        .collect()
                    ),
                    ..Default::default()
                }
            )),
        );
    }

    #[tokio::test]
    async fn balance_overrides_none_for_unknown_tokens() {
        let state_overrides = DummyStateOverrider;
        assert_eq!(
            state_overrides
                .balance_override(BalanceOverrideRequest {
                    token: address!("0000000000000000000000000000000000000000"),
                    holder: address!("0000000000000000000000000000000000000001"),
                    amount: U256::ZERO,
                })
                .await,
            None,
        );
    }

    #[tokio::test]
    async fn balance_override_computation_solady() {
        let token = address!("0000000000c5dc95539589fbd24be07c6c14eca4");
        let holder = address!("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
        let amount = U256::from(0x42);
        let strategy = Strategy::SoladyMapping {
            target_contract: address!("0000000000c5dc95539589fbd24be07c6c14eca4"),
        };

        let result = strategy
            .state_override(&holder, &amount)
            .await
            .into_iter()
            .last();
        assert_eq!(
            result,
            Some((
                token,
                AccountOverride {
                    state_diff: Some({
                        std::iter::once((
                            b256!(
                                "f6a6656ed2d14bad3cdd3e8871db3f535a136a1b6cd5ae2dced8eb813f3d4e4f"
                            ),
                            b256!(
                                "0000000000000000000000000000000000000000000000000000000000000042"
                            ),
                        ))
                        .collect()
                    }),
                    ..Default::default()
                }
            )),
        );
    }

    #[tokio::test]
    async fn cached_detection_caches_holder_agnostic_strategies_without_holder() {
        let token = address!("DEf1CA1fb7FBcDC777520aa7f396b4E015F497aB");
        let holder1 = address!("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
        let holder2 = address!("0000000000000000000000000000000000000001");
        let target_contract = address!("0000000000000000000000000000000000000002");

        let strategy = Strategy::SolidityMapping {
            target_contract,
            map_slot: U256::from(3),
        };

        let mock_web3 = mock::web3();
        let state_overrides = StateOverrides::new(mock_web3);

        state_overrides
            .balance_detector
            .cache
            .insert((token, None), Some(strategy.clone()));

        assert_eq!(
            state_overrides
                .balance_detector
                .detect(token, holder1)
                .await,
            Some(strategy.clone())
        );
        assert_eq!(
            state_overrides
                .balance_detector
                .detect(token, holder2)
                .await,
            Some(strategy)
        );
    }

    #[tokio::test]
    async fn cached_detection_caches_holder_specific_strategies_with_holder() {
        let token = address!("DEf1CA1fb7FBcDC777520aa7f396b4E015F497aB");
        let holder1 = address!("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
        let holder2 = address!("0000000000000000000000000000000000000001");
        let target_contract = address!("0000000000000000000000000000000000000002");

        let strategy_h1 = Strategy::DirectSlot {
            target_contract,
            slot: B256::repeat_byte(1),
        };
        let strategy_h2 = Strategy::DirectSlot {
            target_contract,
            slot: B256::repeat_byte(2),
        };

        let mock_web3 = mock::web3();
        let state_overrides = StateOverrides::new(mock_web3);

        state_overrides
            .balance_detector
            .cache
            .insert((token, Some(holder1)), Some(strategy_h1.clone()));
        state_overrides
            .balance_detector
            .cache
            .insert((token, Some(holder2)), Some(strategy_h2.clone()));

        assert_eq!(
            state_overrides
                .balance_detector
                .detect(token, holder1)
                .await,
            Some(strategy_h1)
        );
        assert_eq!(
            state_overrides
                .balance_detector
                .detect(token, holder2)
                .await,
            Some(strategy_h2)
        );
    }

    /// Universal strategies can be used to compute the state override for
    /// any spender or owner inputs. This test asserts that we cache those
    /// with the key (token, None).
    #[tokio::test]
    async fn caches_universal_approval_strategy_without_inputs() {
        let token = address!("DEf1CA1fb7FBcDC777520aa7f396b4E015F497aB");
        let owner1 = address!("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
        let spender1 = Address::with_last_byte(1);
        let owner2 = Address::with_last_byte(2);
        let spender2 = Address::with_last_byte(3);
        let target_contract = Address::with_last_byte(4);

        let strategy = ApprovalStrategy::SolidityMappingOwnerToSpender {
            target_contract,
            map_slot: U256::from(1),
        };

        let mock_web3 = mock::web3();
        let state_overrides = StateOverrides::new(mock_web3);

        state_overrides
            .approval_detector
            .cache
            .insert((token, None), Some(strategy.clone()));

        assert_eq!(
            state_overrides
                .approval_detector
                .detect(token, owner1, spender1)
                .await,
            Some(strategy.clone())
        );
        assert_eq!(
            state_overrides
                .approval_detector
                .detect(token, owner2, spender2)
                .await,
            Some(strategy)
        );
    }

    /// Some strategies can not be used to compute the state override for
    /// any spender or owner inputs. This test asserts that we cache those
    /// with the key (token, (owner, spender)) as they only work for those
    /// specific inputs.
    #[tokio::test]
    async fn caches_input_specific_approval_strategy_with_inputs() {
        let token = address!("DEf1CA1fb7FBcDC777520aa7f396b4E015F497aB");
        let owner1 = address!("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
        let spender1 = Address::with_last_byte(1);
        let owner2 = Address::with_last_byte(2);
        let spender2 = Address::with_last_byte(3);
        let target_contract = Address::with_last_byte(4);

        let strategy_p1 = ApprovalStrategy::DirectSlot {
            target_contract,
            slot: alloy_primitives::B256::repeat_byte(1),
        };
        let strategy_p2 = ApprovalStrategy::DirectSlot {
            target_contract,
            slot: alloy_primitives::B256::repeat_byte(2),
        };

        let mock_web3 = mock::web3();
        let state_overrides = StateOverrides::new(mock_web3);

        state_overrides
            .approval_detector
            .cache
            .insert((token, Some((owner1, spender1))), Some(strategy_p1.clone()));
        state_overrides
            .approval_detector
            .cache
            .insert((token, Some((owner2, spender2))), Some(strategy_p2.clone()));

        assert_eq!(
            state_overrides
                .approval_detector
                .detect(token, owner1, spender1)
                .await,
            Some(strategy_p1)
        );
        assert_eq!(
            state_overrides
                .approval_detector
                .detect(token, owner2, spender2)
                .await,
            Some(strategy_p2)
        );
    }

    #[ignore]
    #[tokio::test]
    async fn stress_cache_moka() {
        use std::{sync::Arc, time::Instant};

        let mock_web3 = mock::web3();
        let state_overrides = StateOverrides::new(mock_web3);
        let state_overrides = Arc::new(state_overrides);

        let token_count = 200usize;
        let mut tokens = Vec::with_capacity(token_count);
        for i in 0..token_count {
            tokens.push(Address::with_last_byte((i % 255) as u8));
        }

        for i in 0..(token_count / 2) {
            let token = tokens[i];
            let strategy = Strategy::SolidityMapping {
                target_contract: token,
                map_slot: U256::ONE,
            };
            state_overrides
                .balance_detector
                .cache
                .insert((token, None), Some(strategy));
        }

        let concurrency = 64usize;
        let iterations_per_worker = 2000usize;
        let start = Instant::now();

        let mut handles = Vec::with_capacity(concurrency);
        for worker in 0..concurrency {
            let so = Arc::clone(&state_overrides);
            let toks = tokens.clone();
            let handle = tokio::spawn(async move {
                for j in 0..iterations_per_worker {
                    let idx = (worker + j) % toks.len();
                    let token = toks[idx];
                    let holder = Address::with_last_byte(((idx + 7) % 255) as u8);
                    let _ = so.balance_detector.detect(token, holder).await;
                }
            });
            handles.push(handle);
        }

        for h in handles {
            let _ = h.await;
        }

        let elapsed = start.elapsed();
        println!("stress run completed: {:?}", elapsed);

        // Print the collected metrics to help local inspection.
        println!(
            "METRICS:\n{}",
            observe::metrics::encode(observe::metrics::get_registry())
        );
    }

    #[ignore]
    #[test]
    fn compare_moka_vs_mutex_cache() {
        use {
            cached::Cached,
            std::{
                sync::{Arc, Mutex},
                thread,
                time::Instant,
            },
        };

        let key_count = 1000usize;
        let workers = 64usize;
        let iters = 2000usize;

        // Moka cache benchmark
        let moka_cache = Arc::new(moka::sync::Cache::builder().max_capacity(10_000).build());
        for i in 0..(key_count / 2) {
            moka_cache.insert(i as u64, i as u64);
        }

        let start = Instant::now();
        let mut handles = Vec::new();
        for worker in 0..workers {
            let cache = Arc::clone(&moka_cache);
            let handle = thread::spawn(move || {
                for j in 0..iters {
                    let idx = ((worker + j) % key_count) as u64;
                    let _ = cache.get(&idx);
                }
            });
            handles.push(handle);
        }
        for h in handles {
            let _ = h.join();
        }
        let duration_moka = start.elapsed();

        // cached::SizedCache behind a Mutex benchmark (closer to the previous
        // implementation)
        let cached_map = Arc::new(Mutex::new(cached::SizedCache::<u64, u64>::with_size(
            10_000,
        )));
        {
            let mut guard = cached_map.lock().unwrap();
            for i in 0..(key_count / 2) {
                guard.cache_set(i as u64, i as u64);
            }
        }

        let start = Instant::now();
        let mut handles = Vec::new();
        for worker in 0..workers {
            let map = Arc::clone(&cached_map);
            let handle = thread::spawn(move || {
                for j in 0..iters {
                    let idx = ((worker + j) % key_count) as u64;
                    let mut guard = map.lock().unwrap();
                    let _ = guard.cache_get(&idx).cloned();
                    drop(guard);
                }
            });
            handles.push(handle);
        }
        for h in handles {
            let _ = h.join();
        }
        let duration_cached = start.elapsed();

        println!("Moka duration: {:?}", duration_moka);
        println!("cached::SizedCache (Mutex) duration: {:?}", duration_cached);
    }
}
