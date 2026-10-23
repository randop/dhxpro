//! Single-writer state coordinator with a durable redo journal.
//!
//! FeOxDB has atomic single-key operations but no multi-key transactions.
//! A logical mutation (for example "record an offer, claim the IP and advance
//! the subnet cursor") is therefore journaled:
//!
//! 1. write the complete intent and `flush()` it durably,
//! 2. apply every put/delete,
//! 3. `flush()` the applied state,
//! 4. only then delete the intent and `flush()` again.
//!
//! Startup replays any intent that survived a crash. Replay is idempotent:
//! puts overwrite with the same value and deletes tolerate missing keys.

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::Config;
use crate::error::{Error, Result};
use crate::keys;
use crate::mac::MacAddr;
use crate::model::{
    encode_record, IpOwner, JournalIntent, JournalOp, LeaseRecord, OwnerRole, ReservationRecord,
    SubnetMeta,
};
use crate::storage::repo::{Repo, StoreOptions};

/// Any wall clock before 2020-01-01 is treated as invalid. Starting with a
/// bogus clock could otherwise expire every lease at once.
pub const MIN_VALID_TIME: u64 = 1_577_836_800;

#[derive(Debug, Clone)]
enum ClockSource {
    System,
    Manual,
}

/// Wall clock used for lease timestamps.
///
/// The clock never moves backwards during one process lifetime. Backward jumps
/// are clamped to the last observed value, which avoids extending or expiring
/// bindings based on a bad clock.
pub struct Clock {
    last: u64,
    source: ClockSource,
}

impl Clock {
    pub fn system() -> Result<Self> {
        let now = system_now()?;
        if now < MIN_VALID_TIME {
            return Err(Error::State(format!(
                "system clock reads {now} (before 2020-01-01); refusing to start because \
                 lease expiry and decline quarantine cannot be evaluated safely"
            )));
        }
        Ok(Self {
            last: now,
            source: ClockSource::System,
        })
    }

    /// Deterministic clock for tests.
    pub fn manual(now: u64) -> Self {
        Self {
            last: now,
            source: ClockSource::Manual,
        }
    }

    pub fn now(&mut self) -> u64 {
        if matches!(self.source, ClockSource::System) {
            if let Ok(now) = system_now() {
                if now >= self.last {
                    self.last = now;
                }
            }
        }
        self.last
    }

    /// Advance a manual clock (tests only).
    pub fn set(&mut self, now: u64) {
        if now > self.last {
            self.last = now;
        }
    }
}

fn system_now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| Error::State("system clock is before the Unix epoch".to_string()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreHealth {
    Healthy,
    Unhealthy(String),
}

impl StoreHealth {
    pub fn is_healthy(&self) -> bool {
        matches!(self, StoreHealth::Healthy)
    }

    pub fn message(&self) -> Option<&str> {
        match self {
            StoreHealth::Healthy => None,
            StoreHealth::Unhealthy(message) => Some(message),
        }
    }
}

/// Fault points used by the crash-boundary tests. The queue is empty in
/// production, making every check a branch over an empty deque.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    BeforeIntentWrite,
    FailIntentFlush,
    AfterIntentFlush,
    AfterApply(usize),
    FailStateFlush,
    AfterStateFlush,
    FailRetireFlush,
    AfterRetire,
}

pub struct StateCoordinator {
    repo: Repo,
    health: StoreHealth,
    next_sequence: u64,
    faults: VecDeque<Fault>,
}

impl StateCoordinator {
    /// Open the store, acquire the exclusive lock and replay pending intents.
    /// Any replay failure aborts startup instead of serving with uncertain
    /// lease ownership.
    pub fn open(options: &StoreOptions) -> Result<Self> {
        let repo = Repo::open(options)?;
        let mut coordinator = Self {
            repo,
            health: StoreHealth::Healthy,
            next_sequence: 1,
            faults: VecDeque::new(),
        };

        let intents = coordinator.repo.intents()?;
        coordinator.next_sequence = intents
            .iter()
            .map(|intent| intent.sequence)
            .max()
            .map(|max| max.saturating_add(1))
            .unwrap_or(1);
        let replayed = coordinator.replay_pending()?;
        if replayed > 0 {
            eprintln!("dhxpro: replayed {replayed} pending storage intent(s) before serving");
        }
        Ok(coordinator)
    }

    pub fn open_memory() -> Result<Self> {
        Self::open(&StoreOptions::memory())
    }

    pub fn store_path(&self) -> Option<&std::path::Path> {
        self.repo.path()
    }

    pub fn health(&self) -> &StoreHealth {
        &self.health
    }

    pub fn is_healthy(&self) -> bool {
        self.health.is_healthy()
    }

    /// Apply one logical mutation through the redo journal.
    pub fn apply(&mut self, ops: Vec<JournalOp>, now: u64) -> Result<()> {
        if let StoreHealth::Unhealthy(message) = &self.health {
            return Err(Error::StorageUnhealthy(message.clone()));
        }
        if ops.is_empty() {
            return Err(Error::state("refusing to journal an empty mutation"));
        }

        let sequence = self.next_sequence;
        let intent = JournalIntent {
            sequence,
            created_at: now,
            ops,
        };
        intent.validate()?;
        if let Err(error) = self.run_journal(&intent) {
            self.health = StoreHealth::Unhealthy(error.to_string());
            return Err(error);
        }

        self.next_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| Error::state("journal sequence exhausted"))?;
        Ok(())
    }

    fn run_journal(&mut self, intent: &JournalIntent) -> Result<()> {
        self.check_fault(Fault::BeforeIntentWrite)?;
        self.repo.put_intent(intent)?;

        if self.fault_matches(Fault::FailIntentFlush) {
            return Err(Error::state("injected failure: intent flush"));
        }
        self.repo.flush()?;
        self.check_fault(Fault::AfterIntentFlush)?;

        for (index, op) in intent.ops.iter().enumerate() {
            self.apply_op(op)?;
            if self.fault_matches(Fault::AfterApply(index + 1)) {
                return Err(Error::state(format!(
                    "injected failure: after applying operation {}",
                    index + 1
                )));
            }
        }

        if self.fault_matches(Fault::FailStateFlush) {
            return Err(Error::state("injected failure: state flush"));
        }
        self.repo.flush()?;
        self.check_fault(Fault::AfterStateFlush)?;

        self.repo.delete_intent(intent.sequence)?;
        if self.fault_matches(Fault::FailRetireFlush) {
            return Err(Error::state("injected failure: retire flush"));
        }
        self.repo.flush()?;
        self.check_fault(Fault::AfterRetire)?;
        Ok(())
    }

    fn apply_op(&self, op: &JournalOp) -> Result<()> {
        match op {
            JournalOp::Put { key, value } => self.repo.put_raw(key, value),
            JournalOp::Delete { key } => self.repo.delete_raw(key),
        }
    }

    /// Replay every pending intent in sequence order. Returns the number of
    /// intents applied. Idempotent and safe to call repeatedly.
    pub fn replay_pending(&mut self) -> Result<usize> {
        let intents = self.repo.intents()?;
        let mut applied = 0;
        for intent in intents {
            for op in &intent.ops {
                self.apply_op(op)?;
            }
            self.repo.flush()?;
            self.repo.delete_intent(intent.sequence)?;
            self.repo.flush()?;
            applied += 1;
            self.next_sequence = self.next_sequence.max(intent.sequence.saturating_add(1));
        }
        // A flush with no pending intents is the health probe.
        self.repo.flush()?;
        Ok(applied)
    }

    /// Attempt to restore storage health after a transient failure.
    pub fn recover_health(&mut self) -> Result<()> {
        if self.is_healthy() {
            return Ok(());
        }
        self.replay_pending()?;
        self.health = StoreHealth::Healthy;
        eprintln!("dhxpro: storage health restored after a successful flush/replay");
        Ok(())
    }

    // ------------------------------------------------------------------
    // Read accessors for allocation and administration
    // ------------------------------------------------------------------

    pub fn reservation(&self, mac: MacAddr) -> Result<Option<ReservationRecord>> {
        self.repo.reservation(mac)
    }

    pub fn reservations(&self) -> Result<Vec<ReservationRecord>> {
        self.repo.reservations()
    }

    pub fn lease(&self, mac: MacAddr) -> Result<Option<LeaseRecord>> {
        self.repo.lease(mac)
    }

    pub fn leases(&self) -> Result<Vec<LeaseRecord>> {
        self.repo.leases()
    }

    pub fn owner(&self, ip: Ipv4Addr) -> Result<Option<IpOwner>> {
        self.repo.owner(ip)
    }

    pub fn owners(&self) -> Result<Vec<IpOwner>> {
        self.repo.owners()
    }

    pub fn subnet_meta(&self, subnet_id: &str) -> Result<Option<SubnetMeta>> {
        self.repo.subnet_meta(subnet_id)
    }

    pub fn flush(&self) -> Result<()> {
        self.repo.flush()
    }

    pub fn verify_capabilities(&self) -> Result<()> {
        self.repo.verify_capabilities()
    }

    /// Validate or initialize the per-subnet allocator metadata. Stale cursors
    /// (for example after a range change) are reset through the journal so the
    /// reset has the same durability guarantees as an allocation.
    pub fn prepare_subnets(&mut self, config: &Config, now: u64) -> Result<()> {
        for subnet in &config.subnets {
            match self.repo.subnet_meta(&subnet.id)? {
                None => {
                    let meta = SubnetMeta {
                        subnet_id: subnet.id.clone(),
                        cursor: subnet.range_start,
                        range_start: subnet.range_start,
                        range_end: subnet.range_end,
                        generation: 1,
                        updated_at: now,
                    };
                    self.apply(
                        vec![JournalOp::put(
                            keys::subnet_key(&subnet.id),
                            encode_record(&meta)?,
                        )],
                        now,
                    )?;
                }
                Some(meta) => {
                    let range_changed = meta.range_start != subnet.range_start
                        || meta.range_end != subnet.range_end;
                    let cursor_outside =
                        meta.cursor < subnet.range_start || meta.cursor > subnet.range_end;
                    if range_changed || cursor_outside {
                        let updated = SubnetMeta {
                            subnet_id: subnet.id.clone(),
                            cursor: subnet.range_start,
                            range_start: subnet.range_start,
                            range_end: subnet.range_end,
                            generation: meta.generation.saturating_add(1),
                            updated_at: now,
                        };
                        self.apply(
                            vec![JournalOp::put(
                                keys::subnet_key(&subnet.id),
                                encode_record(&updated)?,
                            )],
                            now,
                        )?;
                        eprintln!(
                            "dhxpro: reset allocator cursor for subnet {:?} to {}",
                            subnet.id, subnet.range_start
                        );
                    }
                }
            }
        }
        Ok(())
    }

    /// Read-only consistency report used by `preflight` and operators.
    pub fn integrity_report(&self, config: &Config, now: u64) -> Result<Vec<String>> {
        let mut problems = Vec::new();
        let owners = self.repo.owners()?;
        for owner in &owners {
            let Some(subnet) = config.subnet(&owner.subnet_id) else {
                problems.push(format!(
                    "IP owner {} references unknown subnet {:?}",
                    owner.ip, owner.subnet_id
                ));
                continue;
            };
            if !subnet.contains(owner.ip) {
                problems.push(format!(
                    "IP owner {} is outside subnet {:?} ({})",
                    owner.ip, subnet.id, subnet.cidr
                ));
            }
            match owner.role {
                OwnerRole::Reservation => {
                    let record = self.repo.reservation(owner.mac)?;
                    let matches = record
                        .as_ref()
                        .and_then(|record| record.entries_by_subnet.get(&owner.subnet_id))
                        .map(|entry| entry.ip == owner.ip && entry.enabled)
                        .unwrap_or(false);
                    if !matches {
                        problems.push(format!(
                            "reservation owner {} for {} has no matching enabled reservation",
                            owner.ip, owner.mac
                        ));
                    }
                }
                // A quarantine is owned by the IP and may outlast the client's
                // lease record when that client receives a replacement address.
                OwnerRole::Decline => {}
                OwnerRole::Offer | OwnerRole::Lease => {
                    if owner.expires_at != 0 && owner.expires_at <= now {
                        continue; // expired entries are reclaimed by maintenance
                    }
                    let record = self.repo.lease(owner.mac)?;
                    let matches = record
                        .as_ref()
                        .and_then(|record| record.entries_by_subnet.get(&owner.subnet_id))
                        .map(|entry| {
                            entry.ip == owner.ip
                                && entry.generation == owner.generation
                                && entry.blocks_at(now)
                        })
                        .unwrap_or(false);
                    if !matches {
                        problems.push(format!(
                            "owner {} for {} ({:?}, generation {}) has no matching live lease entry",
                            owner.ip, owner.mac, owner.role, owner.generation
                        ));
                    }
                }
            }
        }

        // Reservations are the authority for fixed bindings. Check that each
        // entry is internally consistent, points at a legal reservation
        // address and is mirrored by exactly one enabled IP-owner entry.
        let mut reserved: HashMap<(String, Ipv4Addr), MacAddr> = HashMap::new();
        for record in self.repo.reservations()? {
            for (key, entry) in &record.entries_by_subnet {
                if key != &entry.subnet_id {
                    problems.push(format!(
                        "reservation {} has map key {key:?} but entry subnet {:?}",
                        record.mac, entry.subnet_id
                    ));
                }
                let Some(subnet) = config.subnet(&entry.subnet_id) else {
                    problems.push(format!(
                        "reservation {} references unknown subnet {:?}",
                        record.mac, entry.subnet_id
                    ));
                    continue;
                };
                if !subnet.is_valid_reservation_ip(entry.ip) {
                    problems.push(format!(
                        "reservation {} in subnet {:?} points at {} which is not a valid reservation address in {}",
                        record.mac, entry.subnet_id, entry.ip, subnet.cidr
                    ));
                }
                if entry.enabled {
                    if let Some(previous) =
                        reserved.insert((entry.subnet_id.clone(), entry.ip), record.mac)
                    {
                        if previous != record.mac {
                            problems.push(format!(
                                "reservation address {}/{} is claimed by both {} and {}",
                                entry.subnet_id, entry.ip, previous, record.mac
                            ));
                        }
                    }
                    // While the reserved client holds an offer/lease (or a
                    // decline quarantine), the owner role reflects that live
                    // binding instead of the permanent reservation role. The
                    // MAC and subnet must still match the reservation.
                    let owner_matches = self
                        .repo
                        .owner(entry.ip)?
                        .map(|owner| owner.mac == record.mac && owner.subnet_id == entry.subnet_id)
                        .unwrap_or(false);
                    if !owner_matches {
                        problems.push(format!(
                            "enabled reservation {}/{} for {} has no matching IP-owner entry",
                            entry.subnet_id, entry.ip, record.mac
                        ));
                    }
                } else if let Some(owner) = self.repo.owner(entry.ip)? {
                    if owner.mac == record.mac
                        && owner.subnet_id == entry.subnet_id
                        && owner.role == OwnerRole::Reservation
                    {
                        problems.push(format!(
                            "disabled reservation {}/{} for {} still owns the address",
                            entry.subnet_id, entry.ip, record.mac
                        ));
                    }
                }
            }
        }

        for record in self.repo.leases()? {
            for entry in record.entries_by_subnet.values() {
                if !entry.blocks_at(now) {
                    continue;
                }
                match self.repo.owner(entry.ip)? {
                    Some(owner)
                        if owner.mac == record.mac
                            && owner.subnet_id == entry.subnet_id
                            && owner.generation == entry.generation => {}
                    Some(owner) => problems.push(format!(
                        "lease {}/{} for {} is blocked in the lease record but owned by {} ({:?})",
                        entry.subnet_id, entry.ip, record.mac, owner.mac, owner.role
                    )),
                    None => problems.push(format!(
                        "lease {}/{} for {} has no IP-owner index entry",
                        entry.subnet_id, entry.ip, record.mac
                    )),
                }
            }
        }

        Ok(problems)
    }

    fn check_fault(&mut self, point: Fault) -> Result<()> {
        if self.fault_matches(point) {
            return Err(Error::state(format!("injected failure at {point:?}")));
        }
        Ok(())
    }

    fn fault_matches(&mut self, point: Fault) -> bool {
        if self.faults.front() == Some(&point) {
            self.faults.pop_front();
            true
        } else {
            false
        }
    }

    #[cfg(test)]
    pub fn inject_fault(&mut self, fault: Fault) {
        self.faults.push_back(fault);
    }

    #[cfg(test)]
    fn pending_faults(&self) -> usize {
        self.faults.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{LeaseEntry, LeaseState};

    fn sample_ops(mac: MacAddr, ip: Ipv4Addr, generation: u64) -> (Vec<JournalOp>, IpOwner) {
        let entry = LeaseEntry {
            subnet_id: "lan".to_string(),
            ip,
            client_id: None,
            hostname: None,
            state: LeaseState::Offered,
            lease_started_at: 0,
            lease_expires_at: 0,
            offer_expires_at: 1000,
            declined_until: 0,
            generation,
            updated_at: 100,
        };
        let mut record = LeaseRecord {
            mac,
            ..Default::default()
        };
        record.entries_by_subnet.insert("lan".to_string(), entry);
        let owner = IpOwner {
            ip,
            subnet_id: "lan".to_string(),
            mac,
            role: OwnerRole::Offer,
            generation,
            expires_at: 1000,
            updated_at: 100,
        };
        (
            vec![
                JournalOp::put(keys::lease_key(mac), encode_record(&record).unwrap()),
                JournalOp::put(keys::ip_owner_key(ip), encode_record(&owner).unwrap()),
            ],
            owner,
        )
    }

    #[test]
    fn journaled_mutation_applies_and_retires() {
        let mut coordinator = StateCoordinator::open_memory().unwrap();
        let mac = MacAddr::parse("aabbccddeeff").unwrap();
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let (ops, _) = sample_ops(mac, ip, 1);
        coordinator.apply(ops, 100).unwrap();

        let lease = coordinator.lease(mac).unwrap().unwrap();
        assert_eq!(lease.entries_by_subnet["lan"].ip, ip);
        assert!(coordinator.owner(ip).unwrap().is_some());
        assert!(coordinator.repo.intents().unwrap().is_empty());
        assert_eq!(coordinator.next_sequence, 2);
    }

    #[test]
    fn deleting_a_missing_key_is_idempotent() {
        let mut coordinator = StateCoordinator::open_memory().unwrap();
        let mac = MacAddr::parse("aabbccddeeff").unwrap();
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let (mut ops, _) = sample_ops(mac, ip, 1);
        ops.push(JournalOp::delete(keys::ip_owner_key(Ipv4Addr::new(
            192, 168, 1, 101,
        ))));
        coordinator.apply(ops, 100).unwrap();
        assert!(coordinator.owner(ip).unwrap().is_some());
    }

    #[test]
    fn replay_after_crash_before_any_operation() {
        let mut coordinator = StateCoordinator::open_memory().unwrap();
        let mac = MacAddr::parse("aabbccddeeff").unwrap();
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let (ops, _) = sample_ops(mac, ip, 1);
        coordinator.inject_fault(Fault::AfterIntentFlush);
        assert!(coordinator.apply(ops, 100).is_err());
        assert!(!coordinator.is_healthy());
        // Nothing was applied yet, but the intent is durable.
        assert!(coordinator.lease(mac).unwrap().is_none());
        assert_eq!(coordinator.repo.intents().unwrap().len(), 1);

        coordinator.recover_health().unwrap();
        assert!(coordinator.is_healthy());
        assert_eq!(
            coordinator.lease(mac).unwrap().unwrap().entries_by_subnet["lan"].ip,
            ip
        );
        assert!(coordinator.repo.intents().unwrap().is_empty());
    }

    #[test]
    fn replay_after_crash_between_multi_key_writes() {
        let mut coordinator = StateCoordinator::open_memory().unwrap();
        let mac = MacAddr::parse("aabbccddeeff").unwrap();
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let (ops, _) = sample_ops(mac, ip, 1);
        coordinator.inject_fault(Fault::AfterApply(1));
        assert!(coordinator.apply(ops, 100).is_err());
        // Only the lease record was applied, the owner index was not.
        assert!(coordinator.lease(mac).unwrap().is_some());
        assert!(coordinator.owner(ip).unwrap().is_none());

        coordinator.recover_health().unwrap();
        assert!(coordinator.lease(mac).unwrap().is_some());
        assert!(coordinator.owner(ip).unwrap().is_some());
        assert!(coordinator.repo.intents().unwrap().is_empty());
    }

    #[test]
    fn replay_after_state_flush_but_before_retirement() {
        let mut coordinator = StateCoordinator::open_memory().unwrap();
        let mac = MacAddr::parse("aabbccddeeff").unwrap();
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let (ops, _) = sample_ops(mac, ip, 1);
        coordinator.inject_fault(Fault::AfterStateFlush);
        assert!(coordinator.apply(ops, 100).is_err());
        // State is already applied, the intent is still present.
        assert!(coordinator.lease(mac).unwrap().is_some());
        assert_eq!(coordinator.repo.intents().unwrap().len(), 1);

        coordinator.recover_health().unwrap();
        assert_eq!(coordinator.repo.intents().unwrap().len(), 0);
        assert!(coordinator.lease(mac).unwrap().is_some());
    }

    #[test]
    fn injected_flush_failures_block_new_mutations_until_recovery() {
        for fault in [
            Fault::FailIntentFlush,
            Fault::FailStateFlush,
            Fault::FailRetireFlush,
        ] {
            let mut coordinator = StateCoordinator::open_memory().unwrap();
            let mac = MacAddr::parse("aabbccddeeff").unwrap();
            let ip = Ipv4Addr::new(192, 168, 1, 100);
            let (ops, _) = sample_ops(mac, ip, 1);
            coordinator.inject_fault(fault);
            assert!(coordinator.apply(ops.clone(), 100).is_err(), "{fault:?}");
            assert!(!coordinator.is_healthy(), "{fault:?}");
            let second = coordinator.apply(ops, 100);
            assert!(
                matches!(second, Err(Error::StorageUnhealthy(_))),
                "{fault:?}: {second:?}"
            );
            coordinator.recover_health().unwrap();
            assert!(coordinator.is_healthy(), "{fault:?}");
            coordinator.apply(Vec::new(), 100).unwrap_err();
        }
    }

    #[test]
    fn crash_before_intent_write_applies_nothing() {
        let mut coordinator = StateCoordinator::open_memory().unwrap();
        let mac = MacAddr::parse("aabbccddeeff").unwrap();
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let (ops, _) = sample_ops(mac, ip, 1);
        coordinator.inject_fault(Fault::BeforeIntentWrite);
        assert!(coordinator.apply(ops, 100).is_err());
        assert!(coordinator.repo.intents().unwrap().is_empty());
        assert!(coordinator.lease(mac).unwrap().is_none());
        coordinator.recover_health().unwrap();
        assert!(coordinator.is_healthy());
    }

    #[test]
    fn fully_retired_mutation_reports_success_only_after_retirement() {
        let mut coordinator = StateCoordinator::open_memory().unwrap();
        let mac = MacAddr::parse("aabbccddeeff").unwrap();
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let (ops, _) = sample_ops(mac, ip, 1);
        coordinator.inject_fault(Fault::AfterRetire);
        assert!(coordinator.apply(ops, 100).is_err());
        // Everything is durable and the intent is retired; the caller still
        // must not ACK because the operation reported failure.
        assert!(coordinator.lease(mac).unwrap().is_some());
        assert!(coordinator.repo.intents().unwrap().is_empty());
        coordinator.recover_health().unwrap();
        assert!(coordinator.is_healthy());
    }

    #[test]
    fn sequence_advances_across_crashes() {
        let mut coordinator = StateCoordinator::open_memory().unwrap();
        let mac = MacAddr::parse("aabbccddeeff").unwrap();
        let (ops, _) = sample_ops(mac, Ipv4Addr::new(192, 168, 1, 100), 1);
        coordinator.inject_fault(Fault::AfterIntentFlush);
        assert!(coordinator.apply(ops, 100).is_err());
        coordinator.recover_health().unwrap();

        let (ops, _) = sample_ops(mac, Ipv4Addr::new(192, 168, 1, 101), 2);
        coordinator.apply(ops, 200).unwrap();
        assert!(coordinator.repo.intents().unwrap().is_empty());
    }

    #[test]
    fn prepare_subnets_initializes_and_resets_cursor() {
        let yaml = crate::config::example_config();
        let config = Config::parse_str(yaml).unwrap();
        let mut coordinator = StateCoordinator::open_memory().unwrap();
        coordinator.prepare_subnets(&config, 100).unwrap();
        let meta = coordinator.subnet_meta("lan").unwrap().unwrap();
        assert_eq!(meta.cursor, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(meta.range_start, Ipv4Addr::new(192, 168, 1, 100));

        // Simulate a stale cursor from an older, larger range.
        let stale = SubnetMeta {
            cursor: Ipv4Addr::new(192, 168, 2, 50),
            range_start: Ipv4Addr::new(192, 168, 2, 1),
            range_end: Ipv4Addr::new(192, 168, 2, 100),
            generation: 7,
            ..meta
        };
        coordinator
            .apply(
                vec![JournalOp::put(
                    keys::subnet_key("lan"),
                    encode_record(&stale).unwrap(),
                )],
                200,
            )
            .unwrap();
        coordinator.prepare_subnets(&config, 300).unwrap();
        let meta = coordinator.subnet_meta("lan").unwrap().unwrap();
        assert_eq!(meta.cursor, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(meta.range_start, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(meta.generation, 8);
    }

    #[test]
    fn integrity_report_detects_orphan_owner() {
        let config = Config::parse_str(crate::config::example_config()).unwrap();
        let mut coordinator = StateCoordinator::open_memory().unwrap();
        coordinator.prepare_subnets(&config, 100).unwrap();
        let owner = IpOwner {
            ip: Ipv4Addr::new(192, 168, 1, 100),
            subnet_id: "lan".to_string(),
            mac: MacAddr::parse("aabbccddeeff").unwrap(),
            role: OwnerRole::Lease,
            generation: 1,
            expires_at: 1000,
            updated_at: 100,
        };
        coordinator
            .apply(
                vec![JournalOp::put(
                    keys::ip_owner_key(owner.ip),
                    encode_record(&owner).unwrap(),
                )],
                100,
            )
            .unwrap();
        let problems = coordinator.integrity_report(&config, 200).unwrap();
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems[0].contains("no matching live lease"),
            "{problems:?}"
        );
    }

    #[test]
    fn lock_is_exclusive_and_released_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.feox");
        let options = StoreOptions {
            path: Some(path.clone()),
            file_size_bytes: 8 * 1024 * 1024,
            max_memory_bytes: 8 * 1024 * 1024,
            hash_bits: 12,
        };
        let first = StateCoordinator::open(&options).unwrap();
        let second = StateCoordinator::open(&options);
        assert!(matches!(second, Err(Error::StoreLocked(_))));
        drop(first);
        let third = StateCoordinator::open(&options).unwrap();
        drop(third);
    }

    #[test]
    fn persistent_store_reopens_with_state_and_no_intents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.feox");
        let options = StoreOptions {
            path: Some(path),
            file_size_bytes: 8 * 1024 * 1024,
            max_memory_bytes: 8 * 1024 * 1024,
            hash_bits: 12,
        };
        let mac = MacAddr::parse("aabbccddeeff").unwrap();
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        {
            let mut coordinator = StateCoordinator::open(&options).unwrap();
            let (ops, _) = sample_ops(mac, ip, 1);
            coordinator.apply(ops, 100).unwrap();
        }
        let coordinator = StateCoordinator::open(&options).unwrap();
        let lease = coordinator.lease(mac).unwrap().unwrap();
        assert_eq!(lease.entries_by_subnet["lan"].ip, ip);
        assert!(coordinator.owner(ip).unwrap().is_some());
        assert!(coordinator.repo.intents().unwrap().is_empty());
    }

    #[test]
    fn persistent_store_recovers_an_unretired_intent_on_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.feox");
        let options = StoreOptions {
            path: Some(path),
            file_size_bytes: 8 * 1024 * 1024,
            max_memory_bytes: 8 * 1024 * 1024,
            hash_bits: 12,
        };
        let mac = MacAddr::parse("aabbccddeeff").unwrap();
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        {
            let mut coordinator = StateCoordinator::open(&options).unwrap();
            let (ops, _) = sample_ops(mac, ip, 1);
            coordinator.inject_fault(Fault::AfterStateFlush);
            assert!(coordinator.apply(ops, 100).is_err());
            assert!(coordinator.pending_faults() == 0);
        }
        let coordinator = StateCoordinator::open(&options).unwrap();
        assert!(coordinator.repo.intents().unwrap().is_empty());
        assert!(coordinator.lease(mac).unwrap().is_some());
        assert!(coordinator.owner(ip).unwrap().is_some());
    }
}
