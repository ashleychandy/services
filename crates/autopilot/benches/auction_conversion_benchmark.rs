use {
    autopilot::{
        domain::{self, auction::order::*, auction::Price},
        infra::persistence::dto,
    },
    criterion::{black_box, criterion_group, criterion_main, BenchmarkId, BatchSize, Criterion},
    eth_domain_types as eth,
    std::{collections::HashMap, sync::Arc, time::Duration},
};

/// Helper to create a test order with realistic data
fn make_uid_from_index(i: usize) -> OrderUid {
    let le = (i as u64).to_le_bytes();
    let mut uid = [0u8; 56];
    for j in 0..56 {
        uid[j] = le[j % 8];
    }
    OrderUid(uid)
}

fn make_address_from_index(i: usize, extra: u64) -> eth::Address {
    let v = (i as u64).wrapping_add(extra).to_le_bytes();
    let mut addr = [0u8; 20];
    for j in 0..20 {
        addr[j] = v[j % 8];
    }
    eth::Address::from(addr)
}

fn create_test_order(index: usize) -> domain::Order {
    let uid = make_uid_from_index(index);
    domain::Order {
        uid,
        sell: eth::Asset {
            token: eth::TokenAddress::from(make_address_from_index(index, 0)),
            amount: eth::TokenAmount(eth::U256::from(1_000_000_000_000_000_000_u128)), // 1 token
        },
        buy: eth::Asset {
            token: eth::TokenAddress::from(make_address_from_index(index, 1)),
            amount: eth::TokenAmount(eth::U256::from(2_000_000_000_000_000_000_u128)), // 2 tokens
        },
        protocol_fees: vec![
            domain::fee::Policy::Surplus {
                factor: configs::fee_factor::FeeFactor::try_from(0.5).unwrap(),
                max_volume_factor: configs::fee_factor::FeeFactor::try_from(0.1).unwrap(),
            },
            domain::fee::Policy::Volume {
                factor: configs::fee_factor::FeeFactor::try_from(0.01).unwrap(),
            },
        ],
        side: Side::Sell,
        created: 1234567890,
        valid_to: 1234567890 + 3600,
        receiver: Some(make_address_from_index(index, 2)),
        owner: make_address_from_index(index, 3),
        partially_fillable: false,
        executed: TargetAmount(eth::U256::ZERO),
        pre_interactions: vec![
            Interaction {
                target: alloy::primitives::Address::from(make_address_from_index(index, 4).0),
                value: alloy::primitives::U256::from(100),
                call_data: vec![0x12, 0x34, 0x56, 0x78],
            },
            Interaction {
                target: alloy::primitives::Address::from(make_address_from_index(index, 5).0),
                value: alloy::primitives::U256::from(200),
                call_data: vec![0xab, 0xcd, 0xef],
            },
        ],
        post_interactions: vec![Interaction {
            target: alloy::primitives::Address::from(make_address_from_index(index, 6).0),
            value: alloy::primitives::U256::from(300),
            call_data: vec![0x11, 0x22, 0x33, 0x44, 0x55],
        }],
        sell_token_balance: SellTokenSource::Erc20,
        buy_token_balance: BuyTokenDestination::Erc20,
        app_data: AppDataHash([(index as u8); 32]),
        signature: Signature::Eip712(EcdsaSignature {
            r: alloy::primitives::B256::from([index as u8; 32]),
            s: alloy::primitives::B256::from([(index as u8).wrapping_add(1); 32]),
            v: 27,
        }),
        quote: Some(domain::Quote {
            order_uid: make_uid_from_index(index),
            sell_amount: eth::SellTokenAmount(eth::U256::from(1_000_000_000_000_000_000_u128)),
            buy_amount: eth::TokenAmount(eth::U256::from(2_000_000_000_000_000_000_u128)),
            fee: eth::SellTokenAmount(eth::U256::from(10_000_000_000_000_000_u128)),
            solver: alloy::primitives::Address::from(make_address_from_index(index, 7).0),
        }),
    }
}

/// Create a test auction with the specified number of orders
fn create_test_auction(num_orders: usize) -> domain::RawAuctionData {
    let orders: Vec<domain::Order> = (0..num_orders).map(|i| create_test_order(i)).collect();

    let mut prices = HashMap::new();
    for i in 0..num_orders.min(100) {
        // Add up to 100 unique token prices (cap at 100 tokens)
        let token = eth::TokenAddress::from(make_address_from_index(i, 10));
        prices.insert(
            token,
            Price::try_new(eth::Ether(eth::U256::from(1_000_000_000_000_000_000_u128))).unwrap(),
        );
    }

    let surplus_capturing_jit_order_owners: Vec<eth::Address> = (0..10)
        .map(|i| make_address_from_index(i, 20))
        .collect();

    domain::RawAuctionData {
        block: 12345678,
        orders,
        prices,
        surplus_capturing_jit_order_owners,
    }
}

/// Old implementation: takes ownership and clones everything
fn from_domain_old(auction: domain::RawAuctionData) -> dto::auction::RawAuctionData {
    dto::auction::RawAuctionData {
        block: auction.block,
        orders: auction
            .orders
            .into_iter()
            .map(dto::order::from_domain_old)
            .collect(),
        prices: auction
            .prices
            .into_iter()
            .map(|(key, value)| (*key, value.get().0))
            .collect(),
        surplus_capturing_jit_order_owners: auction
            .surplus_capturing_jit_order_owners
            .into_iter()
            .collect(),
    }
}

/// New implementation: takes reference and minimizes cloning
fn from_domain_new(auction: &domain::RawAuctionData) -> dto::auction::RawAuctionData {
    dto::auction::from_domain(auction)
}

fn benchmark_small_auction(c: &mut Criterion) {
    let auction = create_test_auction(10);
    let mut group = c.benchmark_group("auction_conversion/10_orders");

    group.bench_function("old", |b| {
        b.iter_batched(
            || auction.clone(),
            |a| black_box(from_domain_old(black_box(a))),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("new", |b| {
        b.iter(|| black_box(from_domain_new(black_box(&auction))))
    });

    group.finish();
}

fn benchmark_medium_auction(c: &mut Criterion) {
    let auction = create_test_auction(100);
    let mut group = c.benchmark_group("auction_conversion/100_orders");

    group.bench_function("old", |b| {
        b.iter_batched(
            || auction.clone(),
            |a| black_box(from_domain_old(black_box(a))),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("new", |b| {
        b.iter(|| black_box(from_domain_new(black_box(&auction))))
    });

    group.finish();
}

fn benchmark_large_auction(c: &mut Criterion) {
    let auction = create_test_auction(500);
    let mut group = c.benchmark_group("auction_conversion/500_orders");

    group.bench_function("old", |b| {
        b.iter_batched(
            || auction.clone(),
            |a| black_box(from_domain_old(black_box(a))),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("new", |b| {
        b.iter(|| black_box(from_domain_new(black_box(&auction))))
    });

    group.finish();
}

fn benchmark_arc_cloning(c: &mut Criterion) {
    // Compare deep-cloning the DTO vs Arc::clone of the DTO (what the PR proposes)
    let auction = create_test_auction(100);
    let dto_auction = dto::auction::from_domain(&auction);
    let arc_dto = Arc::new(dto_auction.clone());

    let mut group = c.benchmark_group("dto_arc_cloning/100_orders");

    group.bench_function("dto_clone_100_orders", |b| {
        b.iter(|| black_box(dto_auction.clone()))
    });

    group.bench_function("arc_clone_100_orders", |b| {
        b.iter(|| black_box(Arc::clone(&arc_dto)))
    });

    group.finish();
}

fn benchmark_order_conversion(c: &mut Criterion) {
    let order = create_test_order(42);
    let mut group = c.benchmark_group("order_conversion/1_order");

    group.bench_function("old_order_conversion", |b| {
        b.iter_batched(
            || order.clone(),
            |o| black_box(dto::order::from_domain_old(black_box(o))),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("new_order_conversion", |b| {
        b.iter(|| black_box(dto::order::from_domain(black_box(&order))))
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(10))
        .sample_size(200);
    targets = 
        benchmark_small_auction,
        benchmark_medium_auction,
        benchmark_large_auction,
        benchmark_arc_cloning,
        benchmark_order_conversion,
    
}
criterion_main!(benches);
