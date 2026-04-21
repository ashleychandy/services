use {
    crate::infra::observe::metrics,
    alloy::primitives::Address,
    eth_domain_types as eth,
    serde::Deserialize,
    serde_json::Value,
    sha2::{Digest, Sha256},
    std::{collections::HashMap, str::FromStr},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unsupported delta protocol version {0}")]
    UnsupportedVersion(u32),
    #[error("invalid sequence range: from={from}, to={to}")]
    InvalidSequenceRange { from: u64, to: u64 },
    #[error("delta sequence mismatch: expected from={expected}, got from={got}")]
    SequenceMismatch { expected: u64, got: u64 },
    #[error("unknown event type received in envelope")]
    UnknownEventType,
    #[error("snapshot missing auction_id")]
    MissingSnapshotAuctionId,
    #[error("delta snapshot sequence mismatch: current={current}, snapshot={snapshot}")]
    SnapshotSequenceMismatch { current: u64, snapshot: u64 },
    #[error("order payload is missing uid")]
    MissingOrderUid,
    #[error("order uid has invalid format: {0}")]
    InvalidOrderUidFormat(String),
    #[error("order payload failed schema validation: {0}")]
    InvalidOrderSchema(String),
    #[error("price payload has invalid format: {0}")]
    InvalidPriceFormat(String),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub version: u32,
    #[serde(default)]
    pub boot_id: Option<String>,
    #[serde(default)]
    pub chain_id: Option<u64>,
    pub auction_id: Option<u64>,
    pub sequence: u64,
    pub auction: RawAuctionData,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawAuctionData {
    pub orders: Vec<Value>,
    pub prices: HashMap<Address, String>,
    #[serde(default)]
    pub block: Option<u64>,
    #[serde(default)]
    pub surplus_capturing_jit_order_owners: Vec<Address>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Envelope {
    pub version: u32,
    #[serde(default)]
    pub boot_id: Option<String>,
    #[serde(default)]
    pub chain_id: Option<u64>,
    #[serde(default)]
    pub auction_id: u64,
    #[serde(default)]
    pub auction_sequence: u64,
    pub from_sequence: u64,
    pub to_sequence: u64,
    #[serde(default)]
    pub snapshot_sequence: Option<u64>,
    pub events: Vec<Event>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Event {
    AuctionChanged {
        new_auction_id: u64,
    },
    OrderAdded {
        order: Value,
    },
    OrderRemoved {
        uid: String,
    },
    OrderUpdated {
        order: Value,
    },
    PriceChanged {
        token: Address,
        price: Option<String>,
    },

    BlockChanged {
        block: u64,
    },

    JitOwnersChanged {
        surplus_capturing_jit_order_owners: Vec<Address>,
    },
    /// Unknown events are ignored for forward compatibility; breaking changes
    /// must bump the protocol version.
    #[serde(other)]
    Unknown,
}

/// Driver-side local replica of the order and price subset needed for delta
/// sync.
#[derive(Debug, Clone)]
pub struct Replica {
    sequence: u64,
    auction_id: u64,
    orders: HashMap<String, ReplicaOrder>,
    orders_raw: HashMap<String, Value>,
    order_uid_bytes: HashMap<String, [u8; 56]>,
    prices: HashMap<Address, String>,
    block: u64,
    surplus_capturing_jit_order_owners: Vec<Address>,
    state: ReplicaState,
    last_update: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone)]
pub struct ReplicaChecksum {
    pub sequence: u64,
    pub order_uid_hash: String,
    pub price_hash: String,
    pub order_content_hash: String,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplicaState {
    Uninitialized,
    Syncing,
    Ready,
    Resyncing,
}

impl Default for Replica {
    fn default() -> Self {
        Self {
            sequence: 0,
            auction_id: 0,
            orders: HashMap::new(),
            orders_raw: HashMap::new(),
            order_uid_bytes: HashMap::new(),
            prices: HashMap::new(),
            block: 0,
            surplus_capturing_jit_order_owners: Vec::new(),
            state: ReplicaState::Uninitialized,
            last_update: None,
        }
    }
}

impl Replica {
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn auction_id(&self) -> u64 {
        self.auction_id
    }

    pub(crate) fn orders(&self) -> &HashMap<String, ReplicaOrder> {
        &self.orders
    }

    pub fn prices(&self) -> &HashMap<Address, String> {
        &self.prices
    }

    pub fn block(&self) -> u64 {
        self.block
    }

    pub fn surplus_capturing_jit_order_owners(&self) -> &Vec<Address> {
        &self.surplus_capturing_jit_order_owners
    }

    pub fn state(&self) -> ReplicaState {
        self.state
    }

    pub fn last_update(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.last_update
    }

    pub fn checksum(&self) -> Option<ReplicaChecksum> {
        let order_uid_hash = Self::checksum_order_uids(&self.order_uid_bytes);
        let price_hash = Self::checksum_prices(&self.prices).ok()?;
        let order_content_hash = Self::checksum_order_contents_raw(&self.orders_raw);
        Some(ReplicaChecksum {
            sequence: self.sequence,
            order_uid_hash,
            price_hash,
            order_content_hash,
        })
    }

    pub fn set_state(&mut self, state: ReplicaState) {
        self.state = state;
    }

    pub fn apply_snapshot(&mut self, snapshot: Snapshot) -> Result<(), Error> {
        Self::ensure_version(snapshot.version)?;

        for (token, price) in &snapshot.auction.prices {
            validate_price_string(*token, price)?;
        }
        let mut new_orders = HashMap::with_capacity(snapshot.auction.orders.len());
        let mut new_orders_raw = HashMap::with_capacity(snapshot.auction.orders.len());
        let mut new_order_uid_bytes = HashMap::with_capacity(snapshot.auction.orders.len());
        for order in snapshot.auction.orders {
            let uid = order_uid(&order)?;
            let uid_bytes = decode_order_uid_bytes(&uid)?;
            let parsed = Self::parse_order(&order)?;
            new_order_uid_bytes.insert(uid.clone(), uid_bytes);
            new_orders.insert(uid.clone(), parsed);
            new_orders_raw.insert(uid, order);
        }
        let new_prices = snapshot.auction.prices;
        let new_sequence = snapshot.sequence;

        let auction_id = snapshot.auction_id.ok_or(Error::MissingSnapshotAuctionId)?;

        self.sequence = new_sequence;
        self.auction_id = auction_id;
        self.orders = new_orders;
        self.orders_raw = new_orders_raw;
        self.order_uid_bytes = new_order_uid_bytes;
        self.prices = new_prices;
        // Capture non-order fields from the snapshot when available.
        self.block = snapshot.auction.block.unwrap_or(0);
        self.surplus_capturing_jit_order_owners =
            snapshot.auction.surplus_capturing_jit_order_owners.clone();
        self.state = ReplicaState::Ready;
        self.last_update = Some(chrono::Utc::now());
        metrics::get()
            .delta_replica_order_count
            .set(self.orders.len() as i64);

        Ok(())
    }

    pub fn apply_delta(&mut self, envelope: Envelope) -> Result<(), Error> {
        Self::ensure_version(envelope.version)?;
        // Capture sequence bounds before moving `envelope.events` below.
        let from_sequence = envelope.from_sequence;
        let to_sequence = envelope.to_sequence;

        if let Some(snapshot_sequence) = envelope.snapshot_sequence {
            if self.sequence < snapshot_sequence {
                return Err(Error::SnapshotSequenceMismatch {
                    current: self.sequence,
                    snapshot: snapshot_sequence,
                });
            }
        }

        if from_sequence > to_sequence {
            return Err(Error::InvalidSequenceRange {
                from: from_sequence,
                to: to_sequence,
            });
        }

        // At-least-once delivery can replay already-applied envelopes.
        if to_sequence <= self.sequence {
            return Ok(());
        }

        if from_sequence != self.sequence {
            return Err(Error::SequenceMismatch {
                expected: self.sequence,
                got: from_sequence,
            });
        }

        enum Mutation {
            UpsertOrder {
                uid: String,
                uid_bytes: [u8; 56],
                order: ReplicaOrder,
                raw: Option<Value>,
            },
            RemoveOrder {
                uid: String,
            },
            PriceChanged {
                token: Address,
                price: Option<String>,
            },
        }

        let mut mutations = Vec::with_capacity(envelope.events.len());
        for event in envelope.events {
            match event {
                Event::AuctionChanged { .. } => {
                    // Treat AuctionChanged as an explicit auction boundary.
                    // Clear per-auction projection state so that the replica's
                    // view matches the autopilot projection after a transition.
                    // This avoids semantic divergence when the same event
                    // stream is consumed by both autopilot and driver paths.
                    self.orders.clear();
                    self.orders_raw.clear();
                    self.order_uid_bytes.clear();
                    self.prices.clear();
                    self.block = 0;
                    self.surplus_capturing_jit_order_owners.clear();
                    metrics::get().delta_replica_order_count.set(self.orders.len() as i64);
                }
                Event::BlockChanged { block } => {
                    // Track block changes so consumers can detect missing
                    // BlockChanged events even though orders/prices are the
                    // primary projection surface.
                    self.block = block;
                }
                Event::JitOwnersChanged { surplus_capturing_jit_order_owners } => {
                    // Track surplus-capturing JIT owners so replica-based
                    // solve requests can use the same owner set as the
                    // autopilot that applied protocol fees.
                    self.surplus_capturing_jit_order_owners = surplus_capturing_jit_order_owners;
                }
                Event::OrderAdded { order } | Event::OrderUpdated { order } => {
                    let uid = order_uid(&order)?;
                    let uid_bytes = decode_order_uid_bytes(&uid)?;
                    let parsed = Self::parse_order(&order)?;
                    mutations.push(Mutation::UpsertOrder {
                        uid,
                        uid_bytes,
                        order: parsed,
                        raw: Some(order),
                    });
                }
                Event::OrderRemoved { uid } => {
                    if !is_valid_order_uid(&uid) {
                        return Err(Error::InvalidOrderUidFormat(uid));
                    }
                    mutations.push(Mutation::RemoveOrder { uid });
                }
                Event::PriceChanged { token, price } => {
                    if let Some(ref value) = price {
                        validate_price_string(token, value)?;
                    }
                    mutations.push(Mutation::PriceChanged { token, price });
                }
                Event::Unknown => {
                    metrics::get().delta_replica_unknown_event_types_total.inc();
                    tracing::debug!(
                        from_sequence = from_sequence,
                        to_sequence = to_sequence,
                        "delta replica received unknown event type; ignoring for forward \
                         compatibility"
                    );
                }
            }
        }

        for mutation in mutations {
            match mutation {
                Mutation::UpsertOrder {
                    uid,
                    uid_bytes,
                    order,
                    raw,
                } => {
                    self.order_uid_bytes.insert(uid.clone(), uid_bytes);
                    self.orders.insert(uid.clone(), order);
                    if let Some(value) = raw {
                        self.orders_raw.insert(uid, value);
                    }
                }
                Mutation::RemoveOrder { uid } => {
                    self.order_uid_bytes.remove(&uid);
                    self.orders_raw.remove(&uid);
                    if self.orders.remove(&uid).is_none() {
                        metrics::get()
                            .delta_replica_unknown_order_removals_total
                            .inc();
                        tracing::warn!(order_uid = %uid, "delta replica removed unknown order");
                    }
                }
                Mutation::PriceChanged { token, price } => {
                    if let Some(price) = price {
                        self.prices.insert(token, price);
                    } else {
                        self.prices.remove(&token);
                    }
                }
            }
        }

        self.sequence = to_sequence;
        self.auction_id = envelope.auction_id;
        self.state = ReplicaState::Ready;
        self.last_update = Some(chrono::Utc::now());
        metrics::get()
            .delta_replica_order_count
            .set(self.orders.len() as i64);
        Ok(())
    }

    fn ensure_version(version: u32) -> Result<(), Error> {
        if version == 1 {
            Ok(())
        } else {
            Err(Error::UnsupportedVersion(version))
        }
    }

    fn checksum_order_uids(order_uid_bytes: &HashMap<String, [u8; 56]>) -> String {
        let mut uids: Vec<[u8; 56]> = order_uid_bytes.values().cloned().collect();
        uids.sort_unstable();

        let mut hasher = Sha256::new();
        for uid_bytes in uids {
            hasher.update(&uid_bytes);
        }
        format!("0x{}", const_hex::encode(hasher.finalize()))
    }

    fn checksum_prices(prices: &HashMap<Address, String>) -> Result<String, String> {
        let mut entries = prices.iter().collect::<Vec<_>>();
        entries.sort_by(|(lhs, _), (rhs, _)| lhs.as_slice().cmp(rhs.as_slice()));

        let mut hasher = Sha256::new();
        for (token, price) in entries {
            hasher.update(token.as_slice());
            // Parse and canonicalize price string. Avoid panicking in production
            // if the stored price is malformed — emit a metric and return an
            // error marker instead so health-check code can continue running.
            let canonical = eth::U256::from_str(price)
                .map(|value| value.to_string())
                .map_err(|err| {
                    metrics::get()
                        .delta_replica_checksum_decode_errors_total
                        .inc();
                    tracing::warn!(%price, ?token, ?err, "checksum: invalid price string");
                    format!("invalid price for token {token:?}")
                })?;
            hasher.update(canonical.as_bytes());
        }
        Ok(format!("0x{}", const_hex::encode(hasher.finalize())))
    }

    fn checksum_order_contents_raw(orders_raw: &HashMap<String, Value>) -> String {
        let mut entries = orders_raw.iter().collect::<Vec<_>>();
        entries.sort_by(|(lhs, _), (rhs, _)| lhs.cmp(rhs));

        let mut hasher = Sha256::new();
        for (_, order_val) in entries {
            // Prefer serializing the order as the DTO used for solve requests
            // to ensure a stable deterministic shape. Canonicalize the JSON
            // representation (sorted object keys) before hashing so different
            // serde insertion orders do not affect the checksum.
            let value_to_hash = match serde_json::from_value::<ReplicaOrder>(order_val.clone()) {
                Ok(order_dto) => serde_json::to_value(&order_dto).expect("order DTO -> value"),
                Err(_) => order_val.clone(),
            };
            let bytes = Self::canonical_json_bytes(&value_to_hash);
            hasher.update(&bytes);
        }
        format!("0x{}", const_hex::encode(hasher.finalize()))
    }

    fn canonical_json_bytes(value: &serde_json::Value) -> Vec<u8> {
        match value {
            serde_json::Value::Object(map) => {
                let mut entries: Vec<_> = map.iter().collect();
                entries.sort_by(|(a, _), (b, _)| a.as_str().cmp(b.as_str()));
                let mut out = Vec::new();
                out.push(b'{');
                let mut first = true;
                for (k, v) in entries {
                    if !first {
                        out.push(b',');
                    }
                    first = false;
                    out.extend_from_slice(serde_json::to_string(k).unwrap().as_bytes());
                    out.push(b':');
                    out.extend_from_slice(&Self::canonical_json_bytes(v));
                }
                out.push(b'}');
                out
            }
            serde_json::Value::Array(arr) => {
                let mut out = Vec::new();
                out.push(b'[');
                let mut first = true;
                for v in arr {
                    if !first {
                        out.push(b',');
                    }
                    first = false;
                    out.extend_from_slice(&Self::canonical_json_bytes(v));
                }
                out.push(b']');
                out
            }
            _ => serde_json::to_vec(value).expect("value serializable"),
        }
    }

    fn parse_order(order: &Value) -> Result<ReplicaOrder, Error> {
        validate_order_minimal(order)?;
        log_unknown_order_fields(order);
        serde_json::from_value::<ReplicaOrder>(order.clone())
            .map_err(|err| Error::InvalidOrderSchema(err.to_string()))
    }
}

type ReplicaOrder = crate::infra::api::routes::solve::dto::solve_request::Order;

const ORDER_REQUIRED_FIELDS: [&str; 5] =
    ["uid", "sellToken", "buyToken", "sellAmount", "buyAmount"];

const ORDER_KNOWN_FIELDS: [&str; 22] = [
    "uid",
    "sellToken",
    "buyToken",
    "sellAmount",
    "buyAmount",
    "protocolFees",
    "created",
    "validTo",
    "kind",
    "receiver",
    "owner",
    "partiallyFillable",
    "executed",
    "preInteractions",
    "postInteractions",
    "sellTokenBalance",
    "buyTokenBalance",
    "class",
    "appData",
    "signingScheme",
    "signature",
    "quote",
];

fn validate_order_minimal(order: &Value) -> Result<(), Error> {
    let obj = order
        .as_object()
        .ok_or_else(|| Error::InvalidOrderSchema("order payload is not an object".to_string()))?;

    for field in ORDER_REQUIRED_FIELDS {
        if obj.get(field).is_none() {
            metrics::get()
                .delta_replica_missing_required_fields_total
                .inc();
            return Err(Error::InvalidOrderSchema(format!(
                "order payload missing required field {field}"
            )));
        }
    }

    Ok(())
}

fn log_unknown_order_fields(order: &Value) {
    let Some(obj) = order.as_object() else {
        return;
    };

    let mut unknown = Vec::new();
    for key in obj.keys() {
        if !ORDER_KNOWN_FIELDS.contains(&key.as_str()) {
            unknown.push(key.clone());
        }
    }

    if !unknown.is_empty() {
        metrics::get()
            .delta_replica_unknown_fields_total
            .inc_by(unknown.len() as u64);
        tracing::warn!(unknown_fields = ?unknown, "delta replica order contains unknown fields");
    }
}

fn order_uid(order: &Value) -> Result<String, Error> {
    let uid = order
        .get("uid")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or(Error::MissingOrderUid)?;
    if !is_valid_order_uid(&uid) {
        return Err(Error::InvalidOrderSchema(format!(
            "order uid has invalid format: {uid}"
        )));
    }
    Ok(uid)
}

fn is_valid_order_uid(uid: &str) -> bool {
    uid.starts_with("0x")
        && uid.len() == 114
        && uid
            .as_bytes()
            .iter()
            .skip(2)
            .all(|byte| byte.is_ascii_hexdigit())
}

fn decode_order_uid_bytes(uid: &str) -> Result<[u8; 56], Error> {
    let mut bytes = [0u8; 56];
    let uid_without_prefix = uid.strip_prefix("0x").unwrap_or(uid);
    const_hex::decode_to_slice(uid_without_prefix, &mut bytes)
        .map_err(|_| Error::InvalidOrderUidFormat(uid.to_string()))?;
    Ok(bytes)
}

fn validate_price_string(token: Address, value: &str) -> Result<(), Error> {
    if value.is_empty() {
        return Err(Error::InvalidPriceFormat(format!("{token:?}:{value}")));
    }
    eth::U256::from_str(value)
        .map_err(|_| Error::InvalidPriceFormat(format!("{token:?}:{value}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_order(uid: &str) -> Value {
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
            "sellTokenBalance": "erc20",
            "buyTokenBalance": "erc20",
            "appData": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "signingScheme": "eip712",
            "signature": format!("0x{}", hex::encode([0u8; 65])),
            "quote": null
        })
    }

    fn snapshot(sequence: u64, orders: Vec<Value>) -> Snapshot {
        Snapshot {
            version: 1,
            boot_id: None,
            chain_id: None,
            auction_id: Some(0),
            sequence,
            auction: RawAuctionData {
                orders,
                prices: HashMap::new(),
            },
        }
    }

    #[test]
    fn checksum_prices_canonicalizes_decimal_strings() {
        let token = Address::repeat_byte(0xAA);
        let mut prices = HashMap::new();
        prices.insert(token, "0010".to_string());

        let hash_with_padding = Replica::checksum_prices(&prices).unwrap();
        prices.insert(token, "10".to_string());
        let hash_without_padding = Replica::checksum_prices(&prices).unwrap();

        assert_eq!(hash_with_padding, hash_without_padding);
    }

    #[test]
    fn checksum_prices_returns_err_for_malformed_price() {
        let token = Address::repeat_byte(0xAA);
        let mut prices = HashMap::new();
        prices.insert(token, "not-a-number".to_string());

        let result = Replica::checksum_prices(&prices);
        assert!(result.is_err());
    }

    #[test]
    fn checksum_prices_leading_zero_variants() {
        let token = Address::repeat_byte(0xBB);
        let mut prices = HashMap::new();
        prices.insert(token, "0".to_string());

        let hash_zero = Replica::checksum_prices(&prices).unwrap();
        prices.insert(token, "000".to_string());
        let hash_zero_padded = Replica::checksum_prices(&prices).unwrap();

        assert_eq!(hash_zero, hash_zero_padded);
    }

    #[test]
    fn checksum_prices_large_number_and_padded() {
        let token = Address::repeat_byte(0xCC);
        let mut prices = HashMap::new();
        let max_str = eth::U256::MAX.to_string();
        prices.insert(token, max_str.clone());

        let hash_max = Replica::checksum_prices(&prices).unwrap();
        prices.insert(token, format!("000{}", max_str));
        let hash_max_padded = Replica::checksum_prices(&prices).unwrap();

        assert_eq!(hash_max, hash_max_padded);
    }

    #[test]
    fn checksum_prices_rejects_space_and_plus_variants() {
        let token = Address::repeat_byte(0xDD);
        let mut prices = HashMap::new();
        prices.insert(token, " 10".to_string());
        assert!(Replica::checksum_prices(&prices).is_err());

        prices.insert(token, "+10".to_string());
        assert!(Replica::checksum_prices(&prices).is_err());
    }

    fn envelope(from_sequence: u64, to_sequence: u64, events: Vec<Event>) -> Envelope {
        Envelope {
            version: 1,
            boot_id: None,
            chain_id: None,
            auction_id: 0,
            auction_sequence: 0,
            from_sequence,
            to_sequence,
            snapshot_sequence: None,
            events,
        }
    }

    #[test]
    fn snapshot_then_delta_updates_replica() {
        let mut replica = Replica::default();
        let uid_1 = valid_uid(1);
        let uid_2 = valid_uid(2);

        replica
            .apply_snapshot(Snapshot {
                version: 1,
                boot_id: None,
                chain_id: None,
                auction_id: Some(0),
                sequence: 7,
                auction: RawAuctionData {
                    orders: vec![valid_order(&uid_1)],
                    prices: HashMap::from([(Address::repeat_byte(1), "100".to_string())]),
                },
            })
            .unwrap();

        replica
            .apply_delta(envelope(
                7,
                8,
                vec![
                    Event::OrderUpdated {
                        order: valid_order(&uid_1),
                    },
                    Event::OrderAdded {
                        order: valid_order(&uid_2),
                    },
                    Event::PriceChanged {
                        token: Address::repeat_byte(1),
                        price: Some("120".to_string()),
                    },
                ],
            ))
            .unwrap();

        assert_eq!(replica.sequence(), 8);
        assert_eq!(replica.orders().len(), 2);
        assert!(replica.orders().contains_key(&uid_1));
        assert_eq!(
            replica.prices().get(&Address::repeat_byte(1)).unwrap(),
            "120"
        );
    }

    fn valid_uid(byte: u8) -> String {
        format!("0x{}", hex::encode([byte; 56]))
    }

    fn uid_from_u16(value: u16) -> String {
        format!("0x{:0>112x}", value)
    }

    #[test]
    fn rejects_sequence_mismatch() {
        let mut replica = Replica::default();
        replica.apply_snapshot(snapshot(3, vec![])).unwrap();

        let err = replica.apply_delta(envelope(2, 4, vec![])).unwrap_err();

        assert!(matches!(
            err,
            Error::SequenceMismatch {
                expected: 3,
                got: 2
            }
        ));
    }

    #[test]
    fn multi_envelope_replay_matches_expected_state() {
        let mut replica = Replica::default();
        let token_a = Address::repeat_byte(0xAA);
        let token_b = Address::repeat_byte(0xBB);

        replica
            .apply_snapshot(Snapshot {
                version: 1,
                boot_id: None,
                chain_id: None,
                auction_id: Some(0),
                sequence: 10,
                auction: RawAuctionData {
                    orders: vec![valid_order(&uid_from_u16(1)), valid_order(&uid_from_u16(2))],
                    prices: HashMap::from([
                        (token_a, "100".to_string()),
                        (token_b, "200".to_string()),
                    ]),
                },
            })
            .unwrap();

        replica
            .apply_delta(envelope(
                10,
                11,
                vec![
                    Event::OrderUpdated {
                        order: valid_order(&uid_from_u16(1)),
                    },
                    Event::PriceChanged {
                        token: token_a,
                        price: Some("150".to_string()),
                    },
                ],
            ))
            .unwrap();

        replica
            .apply_delta(envelope(
                11,
                12,
                vec![
                    Event::OrderRemoved {
                        uid: uid_from_u16(2),
                    },
                    Event::PriceChanged {
                        token: token_b,
                        price: None,
                    },
                ],
            ))
            .unwrap();

        assert_eq!(replica.sequence(), 12);
        assert_eq!(replica.orders().len(), 1);
        assert!(replica.orders().contains_key(&uid_from_u16(1)));
        assert_eq!(replica.prices().len(), 1);
        assert_eq!(replica.prices().get(&token_a).unwrap(), "150");
        assert!(!replica.prices().contains_key(&token_b));
    }

    #[test]
    fn duplicate_envelope_is_ignored() {
        let mut replica = Replica::default();
        replica
            .apply_snapshot(snapshot(5, vec![valid_order(&uid_from_u16(1))]))
            .unwrap();

        let envelope = envelope(
            5,
            6,
            vec![Event::OrderUpdated {
                order: valid_order(&uid_from_u16(1)),
            }],
        );

        replica.apply_delta(envelope.clone()).unwrap();
        replica.apply_delta(envelope).unwrap();

        assert_eq!(replica.sequence(), 6);
        assert!(replica.orders().contains_key(&uid_from_u16(1)));
    }

    #[test]
    fn stale_envelope_is_ignored() {
        let mut replica = Replica::default();
        replica
            .apply_snapshot(snapshot(8, vec![valid_order(&uid_from_u16(1))]))
            .unwrap();

        replica
            .apply_delta(envelope(
                6,
                7,
                vec![Event::OrderRemoved {
                    uid: uid_from_u16(1),
                }],
            ))
            .unwrap();

        assert_eq!(replica.sequence(), 8);
        assert!(replica.orders().contains_key(&uid_from_u16(1)));
    }

    #[test]
    fn removing_unknown_order_is_idempotent() {
        let mut replica = Replica::default();
        let uid_known = uid_from_u16(1);
        let uid_unknown = uid_from_u16(2);

        replica
            .apply_snapshot(Snapshot {
                version: 1,
                boot_id: None,
                chain_id: None,
                auction_id: Some(0),
                sequence: 5,
                auction: RawAuctionData {
                    orders: vec![valid_order(&uid_known)],
                    prices: HashMap::new(),
                },
            })
            .unwrap();

        // Remove an order that doesn't exist in the replica; this should
        // not error and should advance the sequence while keeping existing
        // known orders intact.
        replica
            .apply_delta(envelope(
                5,
                6,
                vec![Event::OrderRemoved {
                    uid: uid_unknown.clone(),
                }],
            ))
            .unwrap();

        assert_eq!(replica.sequence(), 6);
        assert_eq!(replica.orders().len(), 1);
        assert!(replica.orders().contains_key(&uid_known));
        assert!(!replica.orders().contains_key(&uid_unknown));
    }

    #[test]
    fn updating_unknown_order_inserts() {
        let mut replica = Replica::default();
        let uid_unknown = uid_from_u16(2);

        // Start from an empty snapshot
        replica.apply_snapshot(snapshot(5, vec![])).unwrap();

        // An OrderUpdated for an unknown UID should upsert the order into the replica
        replica
            .apply_delta(envelope(
                5,
                6,
                vec![Event::OrderUpdated {
                    order: valid_order(&uid_unknown),
                }],
            ))
            .unwrap();

        assert_eq!(replica.sequence(), 6);
        assert!(replica.orders().contains_key(&uid_unknown));
        assert_eq!(replica.orders().len(), 1);
    }

    #[test]
    fn overlapping_envelope_is_rejected() {
        let mut replica = Replica::default();
        replica.apply_snapshot(snapshot(8, vec![])).unwrap();

        let err = replica.apply_delta(envelope(7, 9, vec![])).unwrap_err();

        assert!(matches!(
            err,
            Error::SequenceMismatch {
                expected: 8,
                got: 7,
            }
        ));
    }

    #[test]
    fn snapshot_sequence_mismatch_is_rejected() {
        let mut replica = Replica::default();
        replica.apply_snapshot(snapshot(5, vec![])).unwrap();

        let err = replica
            .apply_delta(Envelope {
                version: 1,
                boot_id: None,
                chain_id: None,
                auction_id: 0,
                auction_sequence: 0,
                from_sequence: 5,
                to_sequence: 6,
                snapshot_sequence: Some(6),
                events: vec![],
            })
            .unwrap_err();

        assert!(matches!(
            err,
            Error::SnapshotSequenceMismatch {
                current: 5,
                snapshot: 6
            }
        ));
    }

    #[test]
    fn invalid_uid_payload_is_rejected() {
        let mut replica = Replica::default();
        let err = replica
            .apply_snapshot(snapshot(1, vec![serde_json::json!({"uid": "bad"})]))
            .unwrap_err();

        assert!(matches!(err, Error::InvalidOrderSchema(_)));
    }

    #[test]
    fn invalid_price_payload_is_rejected() {
        let mut replica = Replica::default();
        let err = replica
            .apply_snapshot(Snapshot {
                version: 1,
                boot_id: None,
                chain_id: None,
                auction_id: Some(0),
                sequence: 1,
                auction: RawAuctionData {
                    orders: vec![],
                    prices: HashMap::from([(Address::repeat_byte(1), "not-a-number".to_string())]),
                },
            })
            .unwrap_err();

        assert!(matches!(err, Error::InvalidPriceFormat(_)));
    }

    #[test]
    fn large_batch_delta_application_converges_to_expected_state() {
        let mut replica = Replica::default();
        replica.apply_snapshot(snapshot(0, vec![])).unwrap();

        let mut events = Vec::new();
        for i in 0..600u16 {
            events.push(Event::OrderAdded {
                order: valid_order(&uid_from_u16(i)),
            });
        }
        for i in 0..300u16 {
            events.push(Event::OrderUpdated {
                order: valid_order(&uid_from_u16(i)),
            });
        }
        for i in 300..450u16 {
            events.push(Event::OrderRemoved {
                uid: uid_from_u16(i),
            });
        }
        for i in 1..=20u8 {
            events.push(Event::PriceChanged {
                token: Address::repeat_byte(i),
                price: Some((u128::from(i) * 100).to_string()),
            });
        }
        for i in 11..=20u8 {
            events.push(Event::PriceChanged {
                token: Address::repeat_byte(i),
                price: None,
            });
        }

        replica.apply_delta(envelope(0, 1, events)).unwrap();

        assert_eq!(replica.sequence(), 1);
        assert_eq!(replica.orders().len(), 450);
        assert!(replica.orders().contains_key(&uid_from_u16(0)));
        assert!(replica.orders().contains_key(&uid_from_u16(0x012b)));
        assert!(!replica.orders().contains_key(&uid_from_u16(0x012c)));
        assert_eq!(replica.prices().len(), 10);
        assert_eq!(
            replica.prices().get(&Address::repeat_byte(1)).unwrap(),
            "100"
        );
        assert!(!replica.prices().contains_key(&Address::repeat_byte(20)));
    }

    #[test]
    // Verifies autopilot <-> driver checksum equivalence for a single order.
    fn checksum_equivalence_autopilot_driver_single_order() {
        use {
            alloy::primitives::{Address, B256},
            autopilot::{domain as ap_domain, infra::persistence::dto::order as ap_order},
            eth_domain_types as eth,
            sha2::{Digest, Sha256},
            std::collections::HashMap,
        };

        // Build a canonical domain order (similar to
        // autopilot::test_helpers::test_order)
        let uid_byte: u8 = 1;
        let amount: u8 = 1;
        let domain_order = ap_domain::Order {
            uid: ap_domain::OrderUid([uid_byte; 56]),
            sell: eth::Asset {
                token: Address::repeat_byte(uid_byte).into(),
                amount: eth::TokenAmount::from(eth::U256::from(u128::from(amount))),
            },
            buy: eth::Asset {
                token: Address::repeat_byte(uid_byte.saturating_add(1)).into(),
                amount: eth::TokenAmount::from(eth::U256::from(u128::from(
                    amount.saturating_add(1),
                ))),
            },
            protocol_fees: Vec::new(),
            side: ap_domain::auction::order::Side::Sell,
            created: u32::from(uid_byte),
            valid_to: u32::from(uid_byte) + 100,
            receiver: None,
            owner: Address::repeat_byte(uid_byte.saturating_add(2)).into(),
            partially_fillable: false,
            executed: ap_domain::auction::order::TargetAmount(eth::U256::ZERO),
            pre_interactions: Vec::new(),
            post_interactions: Vec::new(),
            sell_token_balance: ap_domain::auction::order::SellTokenSource::Erc20,
            buy_token_balance: ap_domain::auction::order::BuyTokenDestination::Erc20,
            app_data: ap_domain::auction::order::AppDataHash([uid_byte; 32]),
            signature: ap_domain::auction::order::Signature::Eip712(
                ap_domain::auction::order::EcdsaSignature {
                    r: B256::ZERO,
                    s: B256::ZERO,
                    v: 27,
                },
            ),
            quote: None,
        };

        // Compute autopilot-style checksum by serializing the persistence DTO.
        let ap_dto = ap_order::from_domain(domain_order.clone());
        let ap_bytes = serde_json::to_vec(&ap_dto).expect("serialize ap dto");
        let mut ap_serialized = vec![ap_bytes.clone()];
        ap_serialized.sort();
        let mut hasher = Sha256::new();
        for b in ap_serialized {
            hasher.update(&b);
        }
        let ap_hash = format!("0x{}", const_hex::encode(hasher.finalize()));

        // Compute driver-style checksum from a raw JSON `Value` that is
        // constructed independently from the autopilot DTO. This ensures the
        // test would fail if autopilot and driver produce different canonical
        // serializations rather than simply matching the same preprocessed
        // input.
        fn manual_value_from_domain(domain_order: &ap_domain::Order) -> serde_json::Value {
            use serde_json::json;
            let uid = domain_order.uid.to_string();
            let sell = domain_order.sell.token;
            let buy = domain_order.buy.token;
            // signature: scheme + bytes
            let scheme = match domain_order.signature.scheme() {
                ap_domain::auction::order::SigningScheme::Eip712 => "eip712",
                ap_domain::auction::order::SigningScheme::EthSign => "ethsign",
                ap_domain::auction::order::SigningScheme::Eip1271 => "eip1271",
                ap_domain::auction::order::SigningScheme::PreSign => "presign",
            };
            let sig_bytes = domain_order.signature.to_bytes();
            let sig_hex = format!("0x{}", hex::encode(sig_bytes));

            json!({
                "uid": uid,
                "sellToken": sell.to_string(),
                "buyToken": buy.to_string(),
                "sellAmount": domain_order.sell.amount.0.to_string(),
                "buyAmount": domain_order.buy.amount.0.to_string(),
                "protocolFees": serde_json::Value::Array(vec![]),
                "created": domain_order.created,
                "validTo": domain_order.valid_to,
                "kind": match domain_order.side {
                    ap_domain::auction::order::Side::Sell => "sell",
                    ap_domain::auction::order::Side::Buy => "buy",
                },
                "receiver": serde_json::Value::Null,
                "owner": domain_order.owner.to_string(),
                "partiallyFillable": domain_order.partially_fillable,
                "executed": "0",
                "preInteractions": serde_json::Value::Array(vec![]),
                "postInteractions": serde_json::Value::Array(vec![]),
                "sellTokenBalance": "erc20",
                "buyTokenBalance": "erc20",
                "class": "limit",
                "appData": format!("0x{}", hex::encode(domain_order.app_data.0)),
                "signingScheme": scheme,
                "signature": sig_hex,
                "quote": serde_json::Value::Null
            })
        }

        let uid = domain_order.uid.to_string();
        let mut orders_map: HashMap<String, serde_json::Value> = HashMap::new();
        orders_map.insert(uid, manual_value_from_domain(&domain_order));
        let driver_hash = Replica::checksum_order_contents_raw(&orders_map);

        // Validate the manually constructed JSON parses into the driver's DTO.
        let _parsed_driver: crate::infra::api::routes::solve::dto::solve_request::Order =
            serde_json::from_value(manual_value_from_domain(&domain_order)).expect("driver parse");
        assert_eq!(ap_hash, driver_hash);
    }

    #[test]
    // Verifies autopilot <-> driver checksum equivalence for a multi-order
    // auction including UID, prices and full snapshot checksum.
    fn checksum_equivalence_autopilot_driver_full_auction() {
        use {
            alloy::primitives::Address,
            autopilot::{domain as ap_domain, infra::persistence::dto::order as ap_order},
            eth_domain_types as eth,
            serde_json::Value,
            sha2::{Digest, Sha256},
            std::collections::HashMap,
        };

        // Build several canonical domain orders.
        let mut domain_orders = Vec::new();
        for (uid_byte, sell_token_byte, buy_token_byte, amount) in vec![
            (1u8, 0x10u8, 0x11u8, 1u8),
            (2u8, 0x20u8, 0x21u8, 10u8),
            (3u8, 0x30u8, 0x31u8, 255u8),
        ] {
            let domain_order = ap_domain::Order {
                uid: ap_domain::OrderUid([uid_byte; 56]),
                sell: eth::Asset {
                    token: Address::repeat_byte(sell_token_byte).into(),
                    amount: eth::TokenAmount::from(eth::U256::from(u128::from(amount))),
                },
                buy: eth::Asset {
                    token: Address::repeat_byte(buy_token_byte).into(),
                    amount: eth::TokenAmount::from(eth::U256::from(u128::from(
                        amount.saturating_add(1),
                    ))),
                },
                protocol_fees: Vec::new(),
                side: ap_domain::auction::order::Side::Sell,
                created: u32::from(uid_byte),
                valid_to: u32::from(uid_byte) + 100,
                receiver: None,
                owner: Address::repeat_byte(uid_byte.saturating_add(2)).into(),
                partially_fillable: false,
                executed: ap_domain::auction::order::TargetAmount(eth::U256::ZERO),
                pre_interactions: Vec::new(),
                post_interactions: Vec::new(),
                sell_token_balance: ap_domain::auction::order::SellTokenSource::Erc20,
                buy_token_balance: ap_domain::auction::order::BuyTokenDestination::Erc20,
                app_data: ap_domain::auction::order::AppDataHash([uid_byte; 32]),
                signature: ap_domain::auction::order::Signature::Eip712(
                    ap_domain::auction::order::EcdsaSignature {
                        r: alloy::primitives::B256::ZERO,
                        s: alloy::primitives::B256::ZERO,
                        v: 27,
                    },
                ),
                quote: None,
            };
            domain_orders.push(domain_order);
        }

        // Autopilot-style order content hash: serialize DTOs, sort and hash.
        let mut serialized: Vec<Vec<u8>> = Vec::new();
        let mut ap_values: Vec<Value> = Vec::new();
        for domain_order in &domain_orders {
            let dto = ap_order::from_domain(domain_order.clone());
            let bytes = serde_json::to_vec(&dto).expect("serialize ap dto");
            serialized.push(bytes.clone());
            ap_values.push(serde_json::to_value(&dto).expect("ap dto -> value"));
        }
        serialized.sort();
        let mut hasher = Sha256::new();
        for b in &serialized {
            hasher.update(b);
        }
        let ap_order_content_hash = format!("0x{}", const_hex::encode(hasher.finalize()));

        // Driver-style hash from a raw orders map constructed independently
        // from the autopilot DTOs. Build JSON values from the domain orders
        // rather than reusing the autopilot DTO `Value` to avoid a false
        // positive where both sides rely on the same conversion.
        fn manual_value_from_domain(domain_order: &ap_domain::Order) -> serde_json::Value {
            use serde_json::json;
            let uid = domain_order.uid.to_string();
            let sell = domain_order.sell.token;
            let buy = domain_order.buy.token;
            let scheme = match domain_order.signature.scheme() {
                ap_domain::auction::order::SigningScheme::Eip712 => "eip712",
                ap_domain::auction::order::SigningScheme::EthSign => "ethsign",
                ap_domain::auction::order::SigningScheme::Eip1271 => "eip1271",
                ap_domain::auction::order::SigningScheme::PreSign => "presign",
            };
            let sig_bytes = domain_order.signature.to_bytes();
            let sig_hex = format!("0x{}", hex::encode(sig_bytes));

            json!({
                "uid": uid,
                "sellToken": sell.to_string(),
                "buyToken": buy.to_string(),
                "sellAmount": domain_order.sell.amount.0.to_string(),
                "buyAmount": domain_order.buy.amount.0.to_string(),
                "protocolFees": serde_json::Value::Array(vec![]),
                "created": domain_order.created,
                "validTo": domain_order.valid_to,
                "kind": match domain_order.side {
                    ap_domain::auction::order::Side::Sell => "sell",
                    ap_domain::auction::order::Side::Buy => "buy",
                },
                "receiver": serde_json::Value::Null,
                "owner": domain_order.owner.to_string(),
                "partiallyFillable": domain_order.partially_fillable,
                "executed": "0",
                "preInteractions": serde_json::Value::Array(vec![]),
                "postInteractions": serde_json::Value::Array(vec![]),
                "sellTokenBalance": "erc20",
                "buyTokenBalance": "erc20",
                "class": "limit",
                "appData": format!("0x{}", hex::encode(domain_order.app_data.0)),
                "signingScheme": scheme,
                "signature": sig_hex,
                "quote": serde_json::Value::Null
            })
        }

        let mut orders_map: HashMap<String, Value> = HashMap::new();
        for domain_order in domain_orders.iter() {
            orders_map.insert(
                domain_order.uid.to_string(),
                manual_value_from_domain(domain_order),
            );
        }
        let driver_order_content_hash = Replica::checksum_order_contents_raw(&orders_map);
        // If checksums differ, print canonical serialized forms for debugging
        if ap_order_content_hash != driver_order_content_hash {
            // ap serialized vector `serialized` contains the autopilot DTO bytes
            // sorted earlier. Build the driver-serialized bytes for comparison.
            let mut driver_serialized_vec: Vec<Vec<u8>> = Vec::new();
            for domain_order in domain_orders.iter() {
                let val = manual_value_from_domain(domain_order);
                let parsed: crate::infra::api::routes::solve::dto::solve_request::Order =
                    serde_json::from_value(val).expect("driver parse");
                driver_serialized_vec.push(serde_json::to_vec(&parsed).expect("driver serialize"));
            }
            driver_serialized_vec.sort();
        }
        assert_eq!(ap_order_content_hash, driver_order_content_hash);

        // UID hash: autopilot sorts raw uid bytes then hashes.
        let mut uids: Vec<[u8; 56]> = domain_orders.iter().map(|o| o.uid.0).collect();
        uids.sort_unstable();
        let mut hasher = Sha256::new();
        for uid in uids {
            hasher.update(&uid);
        }
        let ap_uid_hash = format!("0x{}", const_hex::encode(hasher.finalize()));

        // Driver uid hash should match when computed from the uid bytes map.
        let mut uid_map: HashMap<String, [u8; 56]> = HashMap::new();
        for domain_order in &domain_orders {
            uid_map.insert(domain_order.uid.to_string(), domain_order.uid.0);
        }
        let driver_uid_hash = Replica::checksum_order_uids(&uid_map);
        assert_eq!(ap_uid_hash, driver_uid_hash);

        // Prices: include non-canonical representations to exercise canonicalization.
        let token_a = Address::repeat_byte(0xAA);
        let token_b = Address::repeat_byte(0xBB);
        let mut prices: HashMap<Address, String> = HashMap::new();
        prices.insert(token_a, "0010".to_string());
        prices.insert(token_b, "20".to_string());

        // Autopilot-style price hash: sort tokens and canonicalize decimals.
        let mut entries = prices.iter().collect::<Vec<_>>();
        entries.sort_by(|(l, _), (r, _)| l.as_slice().cmp(r.as_slice()));
        let mut hasher = Sha256::new();
        for (token, price_str) in entries {
            hasher.update(token.as_slice());
            let canonical = eth::U256::from_str(price_str)
                .expect("parse price")
                .to_string();
            hasher.update(canonical.as_bytes());
        }
        let ap_price_hash = format!("0x{}", const_hex::encode(hasher.finalize()));

        // Driver price hash should match.
        let driver_price_hash = Replica::checksum_prices(&prices).unwrap();
        assert_eq!(ap_price_hash, driver_price_hash);

        // Full Replica checksum via apply_snapshot should reflect the same components.
        let snapshot = Snapshot {
            version: 1,
            boot_id: None,
            chain_id: None,
            auction_id: Some(0),
            sequence: 42,
            auction: RawAuctionData {
                orders: ap_values,
                prices: prices.clone(),
            },
        };

        let mut replica = Replica::default();
        replica.apply_snapshot(snapshot).unwrap();
        let checksum = replica.checksum().unwrap();
        assert_eq!(checksum.order_uid_hash, ap_uid_hash);
        assert_eq!(checksum.order_content_hash, ap_order_content_hash);
        assert_eq!(checksum.price_hash, ap_price_hash);
    }
}
