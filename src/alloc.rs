//! Address eligibility, incremental/random allocation and lease transitions.
//!
//! Both allocation strategies share one eligibility policy:
//!
//! * only addresses inside the configured inclusive range,
//! * never network/broadcast/server/excluded addresses,
//! * never an address held by another MAC,
//! * never an address reserved for another MAC.
//!
//! The `dhxpro:ip-owner:v1:<ipv4>` index is authoritative for uniqueness. A
//! defensive scan of enabled reservations is also performed so a missing
//! owner-index entry cannot silently hand out a reserved address.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use rand::Rng;

use crate::config::SubnetConfig;
use crate::error::{Error, Result};
use crate::keys;
use crate::mac::MacAddr;
use crate::model::{
    encode_record, IpOwner, JournalOp, LeaseEntry, LeaseRecord, LeaseState, OwnerRole, SubnetMeta,
};
use crate::storage::StateCoordinator;

/// Result of a DISCOVER address selection.
#[derive(Debug, Clone)]
pub struct Offer {
    pub entry: LeaseEntry,
    pub reserved: bool,
    /// True when an existing durable offer/lease was reused.
    pub reused: bool,
}

struct Blocked {
    owners: HashMap<Ipv4Addr, IpOwner>,
    reserved_elsewhere: HashMap<Ipv4Addr, MacAddr>,
}

impl Blocked {
    fn eligible(&self, subnet: &SubnetConfig, ip: Ipv4Addr, mac: MacAddr, now: u64) -> bool {
        if !subnet.is_dynamic_candidate(ip) {
            return false;
        }
        if let Some(owner_mac) = self.reserved_elsewhere.get(&ip) {
            if *owner_mac != mac {
                return false;
            }
        }
        match self.owners.get(&ip) {
            None => true,
            // The requesting client's own live binding is reusable.
            Some(owner)
                if owner.mac == mac
                    && owner.subnet_id == subnet.id
                    && owner.role != OwnerRole::Decline =>
            {
                true
            }
            // Expired owners no longer reserve the address; cleanup will
            // remove the index entry lazily.
            Some(owner) if owner.is_expired_at(now) => true,
            Some(_) => false,
        }
    }
}

fn load_blocked(
    coordinator: &StateCoordinator,
    subnet: &SubnetConfig,
    requester: MacAddr,
    now: u64,
) -> Result<Blocked> {
    let mut owners = HashMap::new();
    for owner in coordinator.owners()? {
        if owner.subnet_id != subnet.id {
            continue;
        }
        if owner.is_expired_at(now) {
            continue;
        }
        owners.insert(owner.ip, owner);
    }

    let mut reserved_elsewhere = HashMap::new();
    for record in coordinator.reservations()? {
        let Some(entry) = record.entries_by_subnet.get(&subnet.id) else {
            continue;
        };
        if !entry.enabled || record.mac == requester {
            continue;
        }
        if subnet.is_valid_reservation_ip(entry.ip) {
            reserved_elsewhere.insert(entry.ip, record.mac);
        }
    }

    Ok(Blocked {
        owners,
        reserved_elsewhere,
    })
}

/// Select an address for a DHCPDISCOVER and durably record the offer.
///
/// Returns `Ok(None)` when the subnet is exhausted. Storage failures are
/// returned as errors; the caller must not send an offer in either case.
pub fn offer_address(
    coordinator: &mut StateCoordinator,
    subnet: &SubnetConfig,
    mac: MacAddr,
    client_id: Option<&[u8]>,
    hostname: Option<&str>,
    now: u64,
    rng: &mut impl Rng,
) -> Result<Option<Offer>> {
    let replay = coordinator.lease(mac)?;
    let existing = replay
        .as_ref()
        .and_then(|record| record.entries_by_subnet.get(&subnet.id))
        .cloned();

    // 1. Preserve a live offer/lease for this MAC in this subnet. Declined
    // addresses remain blocked by their independent IP-owner entries.
    if let Some(entry) = &existing {
        if entry.state == LeaseState::Active {
            if entry.is_active_at(now) && owner_matches(coordinator, subnet, mac, entry)? {
                return Ok(Some(Offer {
                    entry: entry.clone(),
                    reserved: false,
                    reused: true,
                }));
            }
        } else if entry.state == LeaseState::Offered
            && entry.is_offered_at(now)
            && owner_matches(coordinator, subnet, mac, entry)?
        {
            return Ok(Some(Offer {
                entry: entry.clone(),
                reserved: false,
                reused: true,
            }));
        }
    }

    let blocked = load_blocked(coordinator, subnet, mac, now)?;

    // 2. Honor an enabled fixed reservation.
    if let Some(reservation) = coordinator.reservation(mac)? {
        if let Some(entry) = reservation.entries_by_subnet.get(&subnet.id) {
            if entry.enabled {
                if !subnet.is_valid_reservation_ip(entry.ip) {
                    return Err(Error::state(format!(
                        "reservation for {mac} in subnet {:?} points at {} which is not a valid \
                         reservation address in {}",
                        subnet.id, entry.ip, subnet.cidr
                    )));
                }
                match blocked.owners.get(&entry.ip) {
                    Some(owner) if owner.role == OwnerRole::Decline => {
                        return Err(Error::state(format!(
                            "address {} for {mac} in subnet {:?} is quarantined after a decline until {}",
                            entry.ip, subnet.id, owner.expires_at
                        )))
                    }
                    Some(owner) if owner.mac != mac => {
                        return Err(Error::state(format!(
                            "reservation conflict: {} is reserved for {mac} in subnet {:?} but \
                             owned by {} ({:?})",
                            entry.ip, subnet.id, owner.mac, owner.role
                        )))
                    }
                    _ => {}
                }
                let lease = make_offer_entry(
                    subnet,
                    entry.ip,
                    existing.as_ref(),
                    client_id,
                    hostname,
                    now,
                );
                let owner = IpOwner {
                    ip: entry.ip,
                    subnet_id: subnet.id.clone(),
                    mac,
                    role: OwnerRole::Offer,
                    generation: lease.generation,
                    expires_at: lease.offer_expires_at,
                    updated_at: now,
                };
                commit_offer(coordinator, mac, &lease, &owner, None, now)?;
                return Ok(Some(Offer {
                    entry: lease,
                    reserved: true,
                    reused: false,
                }));
            }
        }
    }

    // 3. Run the configured allocator.
    let ip = match subnet.allocation_strategy {
        crate::config::AllocationStrategy::Incremental => {
            next_incremental(coordinator, subnet, mac, now, &blocked)?
        }
        crate::config::AllocationStrategy::Random => next_random(subnet, mac, now, &blocked, rng)?,
    };
    let Some(ip) = ip else {
        return Ok(None);
    };

    let lease = make_offer_entry(subnet, ip, existing.as_ref(), client_id, hostname, now);
    let owner = IpOwner {
        ip,
        subnet_id: subnet.id.clone(),
        mac,
        role: OwnerRole::Offer,
        generation: lease.generation,
        expires_at: lease.offer_expires_at,
        updated_at: now,
    };
    let meta = next_meta(coordinator, subnet, ip, now)?;
    commit_offer(coordinator, mac, &lease, &owner, Some(meta), now)?;
    Ok(Some(Offer {
        entry: lease,
        reserved: false,
        reused: false,
    }))
}

fn owner_matches(
    coordinator: &StateCoordinator,
    subnet: &SubnetConfig,
    mac: MacAddr,
    entry: &LeaseEntry,
) -> Result<bool> {
    match coordinator.owner(entry.ip)? {
        Some(owner) => Ok(owner.mac == mac
            && owner.subnet_id == subnet.id
            && owner.generation == entry.generation),
        None => Ok(false),
    }
}

fn make_offer_entry(
    subnet: &SubnetConfig,
    ip: Ipv4Addr,
    existing: Option<&LeaseEntry>,
    client_id: Option<&[u8]>,
    hostname: Option<&str>,
    now: u64,
) -> LeaseEntry {
    LeaseEntry {
        subnet_id: subnet.id.clone(),
        ip,
        client_id: client_id.map(ToOwned::to_owned),
        hostname: hostname.map(ToOwned::to_owned),
        state: LeaseState::Offered,
        lease_started_at: existing.map(|entry| entry.lease_started_at).unwrap_or(0),
        lease_expires_at: 0,
        offer_expires_at: now.saturating_add(u64::from(subnet.offer_hold_seconds)),
        declined_until: 0,
        generation: existing
            .map(|entry| entry.generation.saturating_add(1))
            .unwrap_or(1),
        updated_at: now,
    }
}

fn commit_offer(
    coordinator: &mut StateCoordinator,
    mac: MacAddr,
    lease: &LeaseEntry,
    owner: &IpOwner,
    meta: Option<SubnetMeta>,
    now: u64,
) -> Result<()> {
    let mut record = coordinator.lease(mac)?.unwrap_or(LeaseRecord {
        mac,
        ..Default::default()
    });
    if record.mac != mac {
        return Err(Error::state(format!(
            "lease record for {mac} claims a different MAC"
        )));
    }
    record
        .entries_by_subnet
        .insert(lease.subnet_id.clone(), lease.clone());
    let mut ops = vec![
        JournalOp::put(keys::lease_key(mac), encode_record(&record)?),
        JournalOp::put(keys::ip_owner_key(owner.ip), encode_record(owner)?),
    ];
    if let Some(meta) = meta {
        ops.push(JournalOp::put(
            keys::subnet_key(&meta.subnet_id),
            encode_record(&meta)?,
        ));
    }
    coordinator.apply(ops, now)
}

fn current_cursor(coordinator: &StateCoordinator, subnet: &SubnetConfig) -> Result<Ipv4Addr> {
    match coordinator.subnet_meta(&subnet.id)? {
        Some(meta)
            if meta.range_start == subnet.range_start
                && meta.range_end == subnet.range_end
                && meta.cursor >= subnet.range_start
                && meta.cursor <= subnet.range_end =>
        {
            Ok(meta.cursor)
        }
        _ => Ok(subnet.range_start),
    }
}

fn next_meta(
    coordinator: &StateCoordinator,
    subnet: &SubnetConfig,
    chosen: Ipv4Addr,
    now: u64,
) -> Result<SubnetMeta> {
    let generation = coordinator
        .subnet_meta(&subnet.id)?
        .map(|meta| meta.generation.saturating_add(1))
        .unwrap_or(1);
    Ok(SubnetMeta {
        subnet_id: subnet.id.clone(),
        cursor: subnet.next_cursor(chosen),
        range_start: subnet.range_start,
        range_end: subnet.range_end,
        generation,
        updated_at: now,
    })
}

fn next_incremental(
    coordinator: &StateCoordinator,
    subnet: &SubnetConfig,
    mac: MacAddr,
    now: u64,
    blocked: &Blocked,
) -> Result<Option<Ipv4Addr>> {
    let start = current_cursor(coordinator, subnet)?;
    let mut candidate = start;
    loop {
        if blocked.eligible(subnet, candidate, mac, now) {
            return Ok(Some(candidate));
        }
        candidate = subnet.next_cursor(candidate);
        if candidate == start {
            return Ok(None);
        }
    }
}

fn next_random(
    subnet: &SubnetConfig,
    mac: MacAddr,
    now: u64,
    blocked: &Blocked,
    rng: &mut impl Rng,
) -> Result<Option<Ipv4Addr>> {
    let span = subnet.range_len();
    let attempts = span.min(32);
    let start = u32::from(subnet.range_start);
    let end = u32::from(subnet.range_end);
    for _ in 0..attempts {
        let candidate = Ipv4Addr::from(rng.random_range(start..=end));
        if blocked.eligible(subnet, candidate, mac, now) {
            return Ok(Some(candidate));
        }
    }

    // Bounded attempts failed: scan the whole range for a free address.
    let mut candidate = subnet.range_start;
    loop {
        if blocked.eligible(subnet, candidate, mac, now) {
            return Ok(Some(candidate));
        }
        if candidate == subnet.range_end {
            return Ok(None);
        }
        candidate = Ipv4Addr::from(u32::from(candidate) + 1);
    }
}

/// Promote a durable offer (or renew an existing binding) to an active lease.
///
/// Revalidates the durable lease record and IP-owner index immediately before
/// writing, so a stale pending offer can never authorize an ACK.
pub fn commit_lease(
    coordinator: &mut StateCoordinator,
    subnet: &SubnetConfig,
    mac: MacAddr,
    ip: Ipv4Addr,
    client_id: Option<&[u8]>,
    hostname: Option<&str>,
    now: u64,
) -> Result<LeaseEntry> {
    let mut record = coordinator
        .lease(mac)?
        .ok_or_else(|| Error::lease_invalid(format!("no durable lease record for {mac}")))?;
    let mut entry = record
        .entries_by_subnet
        .get(&subnet.id)
        .cloned()
        .ok_or_else(|| {
            Error::lease_invalid(format!(
                "no durable lease entry for {mac} in subnet {:?}",
                subnet.id
            ))
        })?;

    if entry.ip != ip {
        return Err(Error::lease_invalid(format!(
            "requested address {ip} does not match the durable binding {} for {mac}",
            entry.ip
        )));
    }
    match entry.state {
        LeaseState::Offered if !entry.is_offered_at(now) => {
            return Err(Error::lease_invalid(format!(
                "offer for {ip} to {mac} expired at {}",
                entry.offer_expires_at
            )))
        }
        LeaseState::Declined if entry.is_declined_at(now) => {
            return Err(Error::lease_invalid(format!(
                "address {ip} is quarantined after a decline"
            )))
        }
        LeaseState::Offered | LeaseState::Active | LeaseState::Declined => {}
    }

    let owner = coordinator.owner(ip)?.ok_or_else(|| {
        Error::state(format!(
            "no IP-owner index entry for {ip}; refusing to ACK unowned state"
        ))
    })?;
    if owner.mac != mac || owner.subnet_id != subnet.id {
        return Err(Error::lease_invalid(format!(
            "address {ip} is owned by {} in subnet {:?}, not {mac}",
            owner.mac, owner.subnet_id
        )));
    }
    if owner.role == OwnerRole::Reservation {
        return Err(Error::lease_invalid(format!(
            "address {ip} is still recorded as a reservation owner for {mac}"
        )));
    }
    if owner.generation != entry.generation {
        return Err(Error::lease_invalid(format!(
            "address {ip} has a stale IP-owner generation {} for lease generation {}",
            owner.generation, entry.generation
        )));
    }

    entry.state = LeaseState::Active;
    entry.lease_started_at = now;
    entry.lease_expires_at = now.saturating_add(u64::from(subnet.lease_seconds));
    entry.offer_expires_at = 0;
    entry.declined_until = 0;
    entry.client_id = client_id.map(ToOwned::to_owned).or(entry.client_id);
    entry.hostname = hostname.map(ToOwned::to_owned).or(entry.hostname);
    entry.generation = entry.generation.saturating_add(1);
    entry.updated_at = now;

    let owner = IpOwner {
        ip,
        subnet_id: subnet.id.clone(),
        mac,
        role: OwnerRole::Lease,
        generation: entry.generation,
        expires_at: entry.lease_expires_at,
        updated_at: now,
    };
    record
        .entries_by_subnet
        .insert(subnet.id.clone(), entry.clone());

    coordinator.apply(
        vec![
            JournalOp::put(keys::lease_key(mac), encode_record(&record)?),
            JournalOp::put(keys::ip_owner_key(ip), encode_record(&owner)?),
        ],
        now,
    )?;
    Ok(entry)
}

/// Create an active lease directly from an enabled reservation.
///
/// Used for INIT-REBOOT requests where the client asks for its reserved
/// address before any offer exists in the store. The reservation itself is the
/// durable authorization; the IP-owner index must not name another MAC.
pub fn activate_reservation(
    coordinator: &mut StateCoordinator,
    subnet: &SubnetConfig,
    mac: MacAddr,
    ip: Ipv4Addr,
    client_id: Option<&[u8]>,
    hostname: Option<&str>,
    now: u64,
) -> Result<LeaseEntry> {
    let reservation = coordinator
        .reservation(mac)?
        .ok_or_else(|| Error::lease_invalid(format!("no reservation record for {mac}")))?;
    let reserved = reservation
        .entries_by_subnet
        .get(&subnet.id)
        .filter(|entry| entry.enabled)
        .ok_or_else(|| {
            Error::lease_invalid(format!(
                "no enabled reservation for {mac} in subnet {:?}",
                subnet.id
            ))
        })?;
    if reserved.ip != ip {
        return Err(Error::lease_invalid(format!(
            "reserved address {} does not match requested address {ip}",
            reserved.ip
        )));
    }
    if !subnet.is_valid_reservation_ip(ip) {
        return Err(Error::lease_invalid(format!(
            "reserved address {ip} is not valid in subnet {:?}",
            subnet.id
        )));
    }
    if let Some(owner) = coordinator.owner(ip)? {
        if owner.mac != mac || owner.role != OwnerRole::Reservation {
            return Err(Error::lease_invalid(format!(
                "reserved address {ip} is owned by {} ({:?})",
                owner.mac, owner.role
            )));
        }
    }

    let mut record = coordinator.lease(mac)?.unwrap_or(LeaseRecord {
        mac,
        ..Default::default()
    });
    let existing = record.entries_by_subnet.get(&subnet.id);
    let generation = existing
        .map(|entry| entry.generation.saturating_add(1))
        .unwrap_or(1);
    let entry = LeaseEntry {
        subnet_id: subnet.id.clone(),
        ip,
        client_id: client_id.map(ToOwned::to_owned),
        hostname: hostname.map(ToOwned::to_owned),
        state: LeaseState::Active,
        lease_started_at: now,
        lease_expires_at: now.saturating_add(u64::from(subnet.lease_seconds)),
        offer_expires_at: 0,
        declined_until: 0,
        generation,
        updated_at: now,
    };
    record
        .entries_by_subnet
        .insert(subnet.id.clone(), entry.clone());

    let owner = IpOwner {
        ip,
        subnet_id: subnet.id.clone(),
        mac,
        role: OwnerRole::Lease,
        generation,
        expires_at: entry.lease_expires_at,
        updated_at: now,
    };
    coordinator.apply(
        vec![
            JournalOp::put(keys::lease_key(mac), encode_record(&record)?),
            JournalOp::put(keys::ip_owner_key(ip), encode_record(&owner)?),
        ],
        now,
    )?;
    Ok(entry)
}

/// Delete a matching lease binding on DHCPRELEASE.
pub fn release_lease(
    coordinator: &mut StateCoordinator,
    subnet: &SubnetConfig,
    mac: MacAddr,
    ip: Ipv4Addr,
    now: u64,
) -> Result<bool> {
    let Some(mut record) = coordinator.lease(mac)? else {
        return Ok(false);
    };
    let Some(entry) = record.entries_by_subnet.get(&subnet.id).cloned() else {
        return Ok(false);
    };
    // A DECLINE must not be turned into an immediate release; the quarantine
    // deadline is the only path that makes a declined address reusable.
    if entry.ip != ip || entry.state == LeaseState::Declined {
        return Ok(false);
    }
    record.entries_by_subnet.remove(&subnet.id);
    let mut ops = Vec::new();
    if record.entries_by_subnet.is_empty() {
        ops.push(JournalOp::delete(keys::lease_key(mac)));
    } else {
        ops.push(JournalOp::put(
            keys::lease_key(mac),
            encode_record(&record)?,
        ));
    }
    if let Some(owner) = coordinator.owner(ip)? {
        if owner.mac == mac
            && owner.subnet_id == subnet.id
            && owner.role != OwnerRole::Reservation
            && owner.generation == entry.generation
        {
            ops.push(owner_cleanup_op(coordinator, &owner, now)?);
        }
    }
    coordinator.apply(ops, now)?;
    Ok(true)
}

/// Quarantine an address after DHCPDECLINE.
pub fn decline_lease(
    coordinator: &mut StateCoordinator,
    subnet: &SubnetConfig,
    mac: MacAddr,
    ip: Ipv4Addr,
    now: u64,
) -> Result<bool> {
    let Some(mut record) = coordinator.lease(mac)? else {
        return Ok(false);
    };
    let Some(current) = record.entries_by_subnet.get(&subnet.id) else {
        return Ok(false);
    };
    if current.ip != ip || !matches!(current.state, LeaseState::Offered | LeaseState::Active) {
        return Ok(false);
    }
    let Some(owner) = coordinator.owner(ip)? else {
        return Ok(false);
    };
    if owner.mac != mac
        || owner.subnet_id != subnet.id
        || owner.role == OwnerRole::Reservation
        || owner.generation != current.generation
    {
        return Ok(false);
    }
    let Some(entry) = record.entries_by_subnet.get_mut(&subnet.id) else {
        return Ok(false);
    };
    entry.state = LeaseState::Declined;
    entry.declined_until = now.saturating_add(u64::from(subnet.decline_hold_seconds));
    entry.offer_expires_at = 0;
    entry.lease_expires_at = 0;
    entry.generation = entry.generation.saturating_add(1);
    entry.updated_at = now;
    let entry = entry.clone();
    record
        .entries_by_subnet
        .insert(subnet.id.clone(), entry.clone());

    let owner = IpOwner {
        ip,
        subnet_id: subnet.id.clone(),
        mac,
        role: OwnerRole::Decline,
        generation: entry.generation,
        expires_at: entry.declined_until,
        updated_at: now,
    };
    coordinator.apply(
        vec![
            JournalOp::put(keys::lease_key(mac), encode_record(&record)?),
            JournalOp::put(keys::ip_owner_key(ip), encode_record(&owner)?),
        ],
        now,
    )?;
    Ok(true)
}

/// After an offer/lease/decline is removed, either delete the IP-owner
/// entry or restore it to the still-enabled fixed reservation for that MAC.
fn owner_cleanup_op(
    coordinator: &StateCoordinator,
    owner: &IpOwner,
    now: u64,
) -> Result<JournalOp> {
    let reserves_ip = coordinator
        .reservation(owner.mac)?
        .and_then(|record| record.entries_by_subnet.get(&owner.subnet_id).cloned())
        .map(|entry| entry.enabled && entry.ip == owner.ip)
        .unwrap_or(false);

    if reserves_ip {
        Ok(JournalOp::put(
            keys::ip_owner_key(owner.ip),
            encode_record(&IpOwner {
                ip: owner.ip,
                subnet_id: owner.subnet_id.clone(),
                mac: owner.mac,
                role: OwnerRole::Reservation,
                generation: owner.generation.saturating_add(1),
                expires_at: 0,
                updated_at: now,
            })?,
        ))
    } else {
        Ok(JournalOp::delete(keys::ip_owner_key(owner.ip)))
    }
}

/// Remove expired offers, leases and decline quarantines.
///
/// Only removes entries whose generation still matches the IP-owner record, so
/// a newer binding created for the same address is never disturbed.
pub fn expire_state(
    coordinator: &mut StateCoordinator,
    now: u64,
    max_operations: usize,
) -> Result<usize> {
    let mut ops = Vec::new();
    let mut cleaned = 0;
    for owner in coordinator.owners()? {
        if ops.len() >= max_operations {
            break;
        }
        if !owner.is_expired_at(now) {
            continue;
        }
        let Some(mut record) = coordinator.lease(owner.mac)? else {
            ops.push(owner_cleanup_op(coordinator, &owner, now)?);
            cleaned += 1;
            continue;
        };
        match record.entries_by_subnet.get(&owner.subnet_id) {
            Some(entry) if entry.ip == owner.ip && entry.generation == owner.generation => {
                if entry.blocks_at(now) {
                    // The lease record is still live; do not remove the owner.
                    continue;
                }
                record.entries_by_subnet.remove(&owner.subnet_id);
                if record.entries_by_subnet.is_empty() {
                    ops.push(JournalOp::delete(keys::lease_key(owner.mac)));
                } else {
                    ops.push(JournalOp::put(
                        keys::lease_key(owner.mac),
                        encode_record(&record)?,
                    ));
                }
                ops.push(owner_cleanup_op(coordinator, &owner, now)?);
                cleaned += 1;
            }
            Some(_) => {
                // A newer binding exists; the stale owner entry is safe to drop,
                // but only when the live entry points at a different address.
                let newer_ip = record
                    .entries_by_subnet
                    .get(&owner.subnet_id)
                    .map(|entry| entry.ip);
                if newer_ip != Some(owner.ip) {
                    ops.push(owner_cleanup_op(coordinator, &owner, now)?);
                    cleaned += 1;
                }
            }
            None => {
                ops.push(owner_cleanup_op(coordinator, &owner, now)?);
                cleaned += 1;
            }
        }
    }
    if !ops.is_empty() {
        coordinator.apply(ops, now)?;
    }
    Ok(cleaned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AllocationStrategy, Config};
    use rand::rngs::SmallRng;
    use rand::SeedableRng;

    const MAC_A: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01];
    const MAC_B: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02];
    const MAC_C: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x03];

    fn config_for(strategy: &str, start: &str, end: &str, lease: u32) -> Config {
        let yaml = format!(
            r#"
schema_version: 1
storage:
  path: /tmp/unused.feox
  file_size_mib: 8
  max_memory_mib: 8
  hash_bits: 12
authoritative: true
subnets:
  - id: lan
    interface: eth0
    cidr: 192.168.1.0/24
    server_identifier: 192.168.1.1
    range:
      start: {start}
      end: {end}
    exclusions:
      - 192.168.1.150
    routers: [192.168.1.1]
    dns_servers: [192.168.1.1]
    domain_name: lan.example
    lease_seconds: {lease}
    offer_hold_seconds: 30
    decline_hold_seconds: 60
    allocation_strategy: {strategy}
"#
        );
        Config::parse_str(&yaml).unwrap()
    }

    fn setup(config: &Config) -> StateCoordinator {
        let mut coordinator = StateCoordinator::open_memory().unwrap();
        coordinator.prepare_subnets(config, 1000).unwrap();
        coordinator
    }

    fn mac(bytes: [u8; 6]) -> MacAddr {
        MacAddr::new(bytes)
    }

    #[test]
    fn incremental_allocation_is_sequential_and_persistent() {
        let config = config_for("incremental", "192.168.1.100", "192.168.1.103", 3600);
        let subnet = config.subnet("lan").unwrap();
        let mut coordinator = setup(&config);
        let mut rng = SmallRng::seed_from_u64(7);

        let mut ips = Vec::new();
        for bytes in [MAC_A, MAC_B, MAC_C] {
            let offer = offer_address(
                &mut coordinator,
                subnet,
                mac(bytes),
                None,
                None,
                1000,
                &mut rng,
            )
            .unwrap()
            .unwrap();
            ips.push(offer.entry.ip);
        }
        assert_eq!(
            ips,
            vec![
                Ipv4Addr::new(192, 168, 1, 100),
                Ipv4Addr::new(192, 168, 1, 101),
                Ipv4Addr::new(192, 168, 1, 102)
            ]
        );
        let meta = coordinator.subnet_meta("lan").unwrap().unwrap();
        assert_eq!(meta.cursor, Ipv4Addr::new(192, 168, 1, 103));

        // The range is inclusive: the fourth address is still available, and
        // only then is the subnet exhausted.
        let fourth = offer_address(
            &mut coordinator,
            subnet,
            mac([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x04]),
            None,
            None,
            1000,
            &mut rng,
        )
        .unwrap()
        .unwrap();
        assert_eq!(fourth.entry.ip, Ipv4Addr::new(192, 168, 1, 103));
        assert!(offer_address(
            &mut coordinator,
            subnet,
            mac([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x05]),
            None,
            None,
            1000,
            &mut rng
        )
        .unwrap()
        .is_none());

        // Releasing a binding makes its address reusable.
        assert!(release_lease(
            &mut coordinator,
            subnet,
            mac(MAC_B),
            Ipv4Addr::new(192, 168, 1, 101),
            1001
        )
        .unwrap());
        let reused = offer_address(
            &mut coordinator,
            subnet,
            mac([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x06]),
            None,
            None,
            1002,
            &mut rng,
        )
        .unwrap()
        .unwrap();
        assert_eq!(reused.entry.ip, Ipv4Addr::new(192, 168, 1, 101));
    }

    #[test]
    fn incremental_cursor_wraps() {
        let config = config_for("incremental", "192.168.1.100", "192.168.1.101", 3600);
        let subnet = config.subnet("lan").unwrap();
        let mut coordinator = setup(&config);
        let mut rng = SmallRng::seed_from_u64(7);
        for bytes in [MAC_A, MAC_B] {
            offer_address(
                &mut coordinator,
                subnet,
                mac(bytes),
                None,
                None,
                1000,
                &mut rng,
            )
            .unwrap()
            .unwrap();
        }
        let meta = coordinator.subnet_meta("lan").unwrap().unwrap();
        assert_eq!(meta.cursor, Ipv4Addr::new(192, 168, 1, 100));
        assert!(offer_address(
            &mut coordinator,
            subnet,
            mac(MAC_C),
            None,
            None,
            1000,
            &mut rng
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn exclusions_are_never_allocated() {
        let config = config_for("incremental", "192.168.1.149", "192.168.1.151", 3600);
        let subnet = config.subnet("lan").unwrap();
        let mut coordinator = setup(&config);
        let mut rng = SmallRng::seed_from_u64(7);
        let first = offer_address(
            &mut coordinator,
            subnet,
            mac(MAC_A),
            None,
            None,
            1000,
            &mut rng,
        )
        .unwrap()
        .unwrap();
        let second = offer_address(
            &mut coordinator,
            subnet,
            mac(MAC_B),
            None,
            None,
            1000,
            &mut rng,
        )
        .unwrap()
        .unwrap();
        assert_eq!(first.entry.ip, Ipv4Addr::new(192, 168, 1, 149));
        assert_eq!(second.entry.ip, Ipv4Addr::new(192, 168, 1, 151));
        assert!(offer_address(
            &mut coordinator,
            subnet,
            mac(MAC_C),
            None,
            None,
            1000,
            &mut rng
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn random_allocation_stays_inside_the_range_and_falls_back() {
        let config = config_for("random", "192.168.1.100", "192.168.1.102", 3600);
        let subnet = config.subnet("lan").unwrap();
        let mut coordinator = setup(&config);
        let mut rng = SmallRng::seed_from_u64(42);
        let mut ips = Vec::new();
        for bytes in [MAC_A, MAC_B] {
            let offer = offer_address(
                &mut coordinator,
                subnet,
                mac(bytes),
                None,
                None,
                1000,
                &mut rng,
            )
            .unwrap()
            .unwrap();
            assert!(subnet.is_dynamic_candidate(offer.entry.ip));
            ips.push(offer.entry.ip);
        }
        let third = offer_address(
            &mut coordinator,
            subnet,
            mac(MAC_C),
            None,
            None,
            1000,
            &mut rng,
        )
        .unwrap()
        .unwrap();
        assert!(subnet.is_dynamic_candidate(third.entry.ip));
        assert!(!ips.contains(&third.entry.ip));
        assert!(offer_address(
            &mut coordinator,
            subnet,
            MacAddr::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x04]),
            None,
            None,
            1000,
            &mut rng
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn concurrent_requests_never_duplicate_an_ip() {
        let config = config_for("random", "192.168.1.100", "192.168.1.120", 3600);
        let subnet = config.subnet("lan").unwrap();
        let mut coordinator = setup(&config);
        let mut rng = SmallRng::seed_from_u64(3);
        let mut seen = std::collections::HashSet::new();
        // 192.168.1.100..=192.168.1.120 is 21 inclusive addresses.
        for index in 0..21u8 {
            let mut bytes = MAC_A;
            bytes[5] = index;
            let offer = offer_address(
                &mut coordinator,
                subnet,
                mac(bytes),
                None,
                None,
                1000,
                &mut rng,
            )
            .unwrap()
            .unwrap();
            assert!(seen.insert(offer.entry.ip), "duplicate {}", offer.entry.ip);
        }
        assert_eq!(seen.len(), 21);
        assert!(offer_address(
            &mut coordinator,
            subnet,
            MacAddr::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x99]),
            None,
            None,
            1000,
            &mut rng
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn retransmitted_discover_reuses_the_same_offer() {
        let config = config_for("incremental", "192.168.1.100", "192.168.1.110", 3600);
        let subnet = config.subnet("lan").unwrap();
        let mut coordinator = setup(&config);
        let mut rng = SmallRng::seed_from_u64(11);
        let first = offer_address(
            &mut coordinator,
            subnet,
            mac(MAC_A),
            None,
            None,
            1000,
            &mut rng,
        )
        .unwrap()
        .unwrap();
        let meta_before = coordinator.subnet_meta("lan").unwrap().unwrap();
        let second = offer_address(
            &mut coordinator,
            subnet,
            mac(MAC_A),
            None,
            None,
            1001,
            &mut rng,
        )
        .unwrap()
        .unwrap();
        let meta_after = coordinator.subnet_meta("lan").unwrap().unwrap();
        assert_eq!(first.entry.ip, second.entry.ip);
        assert!(second.reused);
        assert_eq!(meta_before.cursor, meta_after.cursor);
    }

    #[test]
    fn same_mac_has_independent_entries_per_subnet() {
        let config = Config::parse_str(crate::config::example_config()).unwrap();
        let lan = config.subnet("lan").unwrap();
        let guest = config.subnet("guest").unwrap();
        let mut coordinator = setup(&config);
        let mut rng = SmallRng::seed_from_u64(5);
        let offer_lan = offer_address(
            &mut coordinator,
            lan,
            mac(MAC_A),
            None,
            None,
            1000,
            &mut rng,
        )
        .unwrap()
        .unwrap();
        let offer_guest = offer_address(
            &mut coordinator,
            guest,
            mac(MAC_A),
            None,
            None,
            1000,
            &mut rng,
        )
        .unwrap()
        .unwrap();
        assert_ne!(offer_lan.entry.ip, offer_guest.entry.ip);

        let record = coordinator.lease(mac(MAC_A)).unwrap().unwrap();
        assert_eq!(record.entries_by_subnet.len(), 2);
        assert_eq!(record.entries_by_subnet["lan"].ip, offer_lan.entry.ip);
        assert_eq!(record.entries_by_subnet["guest"].ip, offer_guest.entry.ip);
        assert_eq!(keys::lease_key(mac(MAC_A)), "dhxpro:lease:v1:aabbccddee01");
    }

    #[test]
    fn reservation_is_honored_and_indexed() {
        let config = config_for("incremental", "192.168.1.100", "192.168.1.110", 3600);
        let subnet = config.subnet("lan").unwrap();
        let mut coordinator = setup(&config);
        let reserved_ip = Ipv4Addr::new(192, 168, 1, 105);
        let now = 1000;
        let mut record = crate::model::ReservationRecord {
            mac: mac(MAC_A),
            ..Default::default()
        };
        record.entries_by_subnet.insert(
            "lan".to_string(),
            crate::model::ReservationEntry {
                subnet_id: "lan".to_string(),
                ip: reserved_ip,
                enabled: true,
                hostname: None,
                client_id: None,
                created_at: now,
                updated_at: now,
            },
        );
        coordinator
            .apply(
                vec![
                    JournalOp::put(
                        keys::reservation_key(mac(MAC_A)),
                        encode_record(&record).unwrap(),
                    ),
                    JournalOp::put(
                        keys::ip_owner_key(reserved_ip),
                        encode_record(&IpOwner {
                            ip: reserved_ip,
                            subnet_id: "lan".to_string(),
                            mac: mac(MAC_A),
                            role: OwnerRole::Reservation,
                            generation: 0,
                            expires_at: 0,
                            updated_at: now,
                        })
                        .unwrap(),
                    ),
                ],
                now,
            )
            .unwrap();

        let mut rng = SmallRng::seed_from_u64(9);
        let offer = offer_address(
            &mut coordinator,
            subnet,
            mac(MAC_A),
            None,
            None,
            now,
            &mut rng,
        )
        .unwrap()
        .unwrap();
        assert_eq!(offer.entry.ip, reserved_ip);
        assert!(offer.reserved);

        // Another MAC must not receive the reserved address.
        let other = offer_address(
            &mut coordinator,
            subnet,
            mac(MAC_B),
            None,
            None,
            now,
            &mut rng,
        )
        .unwrap()
        .unwrap();
        assert_ne!(other.entry.ip, reserved_ip);
    }

    #[test]
    fn disabled_reservations_are_ignored() {
        let config = config_for("incremental", "192.168.1.100", "192.168.1.110", 3600);
        let subnet = config.subnet("lan").unwrap();
        let mut coordinator = setup(&config);
        let now = 1000;
        let reserved_ip = Ipv4Addr::new(192, 168, 1, 105);
        let mut record = crate::model::ReservationRecord {
            mac: mac(MAC_A),
            ..Default::default()
        };
        record.entries_by_subnet.insert(
            "lan".to_string(),
            crate::model::ReservationEntry {
                subnet_id: "lan".to_string(),
                ip: reserved_ip,
                enabled: false,
                hostname: None,
                client_id: None,
                created_at: now,
                updated_at: now,
            },
        );
        coordinator
            .apply(
                vec![JournalOp::put(
                    keys::reservation_key(mac(MAC_A)),
                    encode_record(&record).unwrap(),
                )],
                now,
            )
            .unwrap();
        let mut rng = SmallRng::seed_from_u64(9);
        let offer = offer_address(
            &mut coordinator,
            subnet,
            mac(MAC_A),
            None,
            None,
            now,
            &mut rng,
        )
        .unwrap()
        .unwrap();
        assert_ne!(offer.entry.ip, reserved_ip);
    }

    #[test]
    fn commit_lease_activates_and_renews() {
        let config = config_for("incremental", "192.168.1.100", "192.168.1.110", 3600);
        let subnet = config.subnet("lan").unwrap();
        let mut coordinator = setup(&config);
        let mut rng = SmallRng::seed_from_u64(1);
        let offer = offer_address(
            &mut coordinator,
            subnet,
            mac(MAC_A),
            None,
            None,
            1000,
            &mut rng,
        )
        .unwrap()
        .unwrap();
        let active = commit_lease(
            &mut coordinator,
            subnet,
            mac(MAC_A),
            offer.entry.ip,
            Some(&[1, 2, 3]),
            Some("host"),
            1010,
        )
        .unwrap();
        assert_eq!(active.state, LeaseState::Active);
        assert_eq!(active.lease_expires_at, 1010 + 3600);
        let owner = coordinator.owner(offer.entry.ip).unwrap().unwrap();
        assert_eq!(owner.role, OwnerRole::Lease);
        assert_eq!(owner.generation, active.generation);

        let renewed = commit_lease(
            &mut coordinator,
            subnet,
            mac(MAC_A),
            offer.entry.ip,
            None,
            None,
            2000,
        )
        .unwrap();
        assert_eq!(renewed.lease_expires_at, 2000 + 3600);
        assert_eq!(renewed.client_id.as_deref(), Some(&[1, 2, 3][..]));
    }

    #[test]
    fn commit_lease_rejects_a_stale_offer_after_restart() {
        let config = config_for("incremental", "192.168.1.100", "192.168.1.110", 3600);
        let subnet = config.subnet("lan").unwrap();
        let mut coordinator = setup(&config);
        let mut rng = SmallRng::seed_from_u64(1);
        let offer = offer_address(
            &mut coordinator,
            subnet,
            mac(MAC_A),
            None,
            None,
            1000,
            &mut rng,
        )
        .unwrap()
        .unwrap();
        let after_expiry = 1000 + u64::from(subnet.offer_hold_seconds) + 1;
        let error = commit_lease(
            &mut coordinator,
            subnet,
            mac(MAC_A),
            offer.entry.ip,
            None,
            None,
            after_expiry,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("expired"), "{error}");
    }

    #[test]
    fn commit_lease_refuses_an_address_owned_by_another_mac() {
        let config = config_for("incremental", "192.168.1.100", "192.168.1.110", 3600);
        let subnet = config.subnet("lan").unwrap();
        let mut coordinator = setup(&config);
        let mut rng = SmallRng::seed_from_u64(1);
        let offer = offer_address(
            &mut coordinator,
            subnet,
            mac(MAC_A),
            None,
            None,
            1000,
            &mut rng,
        )
        .unwrap()
        .unwrap();
        // Simulate a corrupted/foreign owner index entry.
        let foreign = IpOwner {
            ip: offer.entry.ip,
            subnet_id: "lan".to_string(),
            mac: mac(MAC_B),
            role: OwnerRole::Lease,
            generation: 99,
            expires_at: 99999,
            updated_at: 1000,
        };
        coordinator
            .apply(
                vec![JournalOp::put(
                    keys::ip_owner_key(offer.entry.ip),
                    encode_record(&foreign).unwrap(),
                )],
                1000,
            )
            .unwrap();
        let error = commit_lease(
            &mut coordinator,
            subnet,
            mac(MAC_A),
            offer.entry.ip,
            None,
            None,
            1010,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("owned by"), "{error}");
    }

    #[test]
    fn release_removes_binding_and_frees_the_address() {
        let config = config_for("incremental", "192.168.1.100", "192.168.1.100", 3600);
        let subnet = config.subnet("lan").unwrap();
        let mut coordinator = setup(&config);
        let mut rng = SmallRng::seed_from_u64(1);
        let offer = offer_address(
            &mut coordinator,
            subnet,
            mac(MAC_A),
            None,
            None,
            1000,
            &mut rng,
        )
        .unwrap()
        .unwrap();
        commit_lease(
            &mut coordinator,
            subnet,
            mac(MAC_A),
            offer.entry.ip,
            None,
            None,
            1010,
        )
        .unwrap();
        assert!(release_lease(&mut coordinator, subnet, mac(MAC_A), offer.entry.ip, 1020).unwrap());
        assert!(coordinator.lease(mac(MAC_A)).unwrap().is_none());
        assert!(coordinator.owner(offer.entry.ip).unwrap().is_none());

        let reallocated = offer_address(
            &mut coordinator,
            subnet,
            mac(MAC_B),
            None,
            None,
            1030,
            &mut rng,
        )
        .unwrap()
        .unwrap();
        assert_eq!(reallocated.entry.ip, offer.entry.ip);
    }

    #[test]
    fn release_restores_reservation_owner() {
        let config = config_for("incremental", "192.168.1.100", "192.168.1.100", 3600);
        let subnet = config.subnet("lan").unwrap();
        let mut coordinator = setup(&config);
        let mut rng = SmallRng::seed_from_u64(1);
        let ip = subnet.range_start;
        crate::admin::add(&mut coordinator, &config, mac(MAC_A), "lan", ip, None, 1000).unwrap();
        let offer = offer_address(
            &mut coordinator,
            subnet,
            mac(MAC_A),
            None,
            None,
            1000,
            &mut rng,
        )
        .unwrap()
        .unwrap();
        assert!(offer.reserved);
        commit_lease(&mut coordinator, subnet, mac(MAC_A), ip, None, None, 1010).unwrap();
        assert!(release_lease(&mut coordinator, subnet, mac(MAC_A), ip, 1020).unwrap());
        assert!(coordinator.lease(mac(MAC_A)).unwrap().is_none());
        let owner = coordinator.owner(ip).unwrap().unwrap();
        assert_eq!(owner.role, OwnerRole::Reservation);
        assert_eq!(owner.mac, mac(MAC_A));
        assert_eq!(owner.expires_at, 0);
        let problems = coordinator.integrity_report(&config, 1020).unwrap();
        assert!(problems.is_empty(), "{problems:?}");
    }

    #[test]
    fn declined_client_gets_replacement_while_ip_stays_quarantined() {
        for strategy in ["incremental", "random"] {
            let config = config_for(strategy, "192.168.1.100", "192.168.1.101", 3600);
            let subnet = config.subnet("lan").unwrap();
            let mut coordinator = setup(&config);
            let mut rng = SmallRng::seed_from_u64(1);
            let offer = offer_address(
                &mut coordinator,
                subnet,
                mac(MAC_A),
                None,
                None,
                1000,
                &mut rng,
            )
            .unwrap()
            .unwrap();
            assert!(
                decline_lease(&mut coordinator, subnet, mac(MAC_A), offer.entry.ip, 1010).unwrap()
            );
            let quarantine = coordinator.owner(offer.entry.ip).unwrap().unwrap();
            let replacement = offer_address(
                &mut coordinator,
                subnet,
                mac(MAC_A),
                None,
                None,
                1020,
                &mut rng,
            )
            .unwrap()
            .unwrap();
            assert_ne!(replacement.entry.ip, offer.entry.ip);
            assert_eq!(
                coordinator.owner(offer.entry.ip).unwrap().unwrap(),
                quarantine
            );
            let problems = coordinator.integrity_report(&config, 1020).unwrap();
            assert!(problems.is_empty(), "{problems:?}");
            assert!(offer_address(
                &mut coordinator,
                subnet,
                mac(MAC_B),
                None,
                None,
                1021,
                &mut rng,
            )
            .unwrap()
            .is_none());

            // Expiring the replacement must leave the longer quarantine intact,
            // even though this removes the client's lease record entirely.
            expire_state(&mut coordinator, replacement.entry.offer_expires_at, 1024).unwrap();
            assert!(coordinator.lease(mac(MAC_A)).unwrap().is_none());
            assert_eq!(
                coordinator.owner(offer.entry.ip).unwrap().unwrap(),
                quarantine
            );
            let problems = coordinator.integrity_report(&config, 1050).unwrap();
            assert!(problems.is_empty(), "{problems:?}");
            let replacement = offer_address(
                &mut coordinator,
                subnet,
                mac(MAC_A),
                None,
                None,
                1051,
                &mut rng,
            )
            .unwrap()
            .unwrap();
            assert_ne!(replacement.entry.ip, offer.entry.ip);
            expire_state(&mut coordinator, quarantine.expires_at, 1024).unwrap();
            assert!(coordinator.owner(offer.entry.ip).unwrap().is_none());
            assert_eq!(
                coordinator
                    .lease(mac(MAC_A))
                    .unwrap()
                    .unwrap()
                    .entries_by_subnet["lan"]
                    .ip,
                replacement.entry.ip
            );
            let problems = coordinator
                .integrity_report(&config, quarantine.expires_at)
                .unwrap();
            assert!(problems.is_empty(), "{problems:?}");
        }
    }

    #[test]
    fn declined_addresses_are_quarantined_and_then_reclaimed() {
        let config = config_for("incremental", "192.168.1.100", "192.168.1.100", 3600);
        let subnet = config.subnet("lan").unwrap();
        let mut coordinator = setup(&config);
        let mut rng = SmallRng::seed_from_u64(1);
        let offer = offer_address(
            &mut coordinator,
            subnet,
            mac(MAC_A),
            None,
            None,
            1000,
            &mut rng,
        )
        .unwrap()
        .unwrap();
        assert!(decline_lease(&mut coordinator, subnet, mac(MAC_A), offer.entry.ip, 1010).unwrap());

        // A release cannot shorten the decline quarantine.
        assert!(
            !release_lease(&mut coordinator, subnet, mac(MAC_A), offer.entry.ip, 1011).unwrap()
        );
        assert_eq!(
            coordinator.owner(offer.entry.ip).unwrap().unwrap().role,
            OwnerRole::Decline
        );

        // Another client cannot take the quarantined address.
        assert!(offer_address(
            &mut coordinator,
            subnet,
            mac(MAC_B),
            None,
            None,
            1020,
            &mut rng
        )
        .unwrap()
        .is_none());

        let expiry = 1010 + u64::from(subnet.decline_hold_seconds) + 1;
        let cleaned = expire_state(&mut coordinator, expiry, 1024).unwrap();
        assert!(cleaned >= 1);
        assert!(coordinator.owner(offer.entry.ip).unwrap().is_none());
        let reallocated = offer_address(
            &mut coordinator,
            subnet,
            mac(MAC_B),
            None,
            None,
            expiry,
            &mut rng,
        )
        .unwrap()
        .unwrap();
        assert_eq!(reallocated.entry.ip, offer.entry.ip);
    }

    #[test]
    fn declined_reservation_is_quarantined_and_restored() {
        use crate::admin;

        let config = config_for("incremental", "192.168.1.100", "192.168.1.100", 3600);
        let subnet = config.subnet("lan").unwrap();
        let mut coordinator = setup(&config);
        let mut rng = SmallRng::seed_from_u64(2);
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        admin::add(&mut coordinator, &config, mac(MAC_A), "lan", ip, None, 1000).unwrap();

        let offer = offer_address(
            &mut coordinator,
            subnet,
            mac(MAC_A),
            None,
            None,
            1000,
            &mut rng,
        )
        .unwrap()
        .unwrap();
        assert_eq!(offer.entry.ip, ip);
        assert!(decline_lease(&mut coordinator, subnet, mac(MAC_A), ip, 1010).unwrap());

        // The reserved client cannot bypass its own quarantine.
        let error = offer_address(
            &mut coordinator,
            subnet,
            mac(MAC_A),
            None,
            None,
            1020,
            &mut rng,
        )
        .unwrap_err();
        assert!(error.to_string().contains("quarantined"), "{error}");

        let expiry = 1010 + u64::from(subnet.decline_hold_seconds) + 1;
        assert!(expire_state(&mut coordinator, expiry, 1024).unwrap() >= 1);
        assert!(coordinator.lease(mac(MAC_A)).unwrap().is_none());
        let owner = coordinator.owner(ip).unwrap().unwrap();
        assert_eq!(owner.role, OwnerRole::Reservation);

        let reoffered = offer_address(
            &mut coordinator,
            subnet,
            mac(MAC_A),
            None,
            None,
            expiry,
            &mut rng,
        )
        .unwrap()
        .unwrap();
        assert_eq!(reoffered.entry.ip, ip);
    }

    #[test]
    fn expire_state_never_removes_a_newer_binding() {
        let config = config_for("incremental", "192.168.1.100", "192.168.1.100", 3600);
        let subnet = config.subnet("lan").unwrap();
        let mut coordinator = setup(&config);
        let mut rng = SmallRng::seed_from_u64(1);
        let offer = offer_address(
            &mut coordinator,
            subnet,
            mac(MAC_A),
            None,
            None,
            1000,
            &mut rng,
        )
        .unwrap()
        .unwrap();
        commit_lease(
            &mut coordinator,
            subnet,
            mac(MAC_A),
            offer.entry.ip,
            None,
            None,
            1010,
        )
        .unwrap();
        // Expire the previous offer owner view but keep the active lease.
        let cleaned = expire_state(&mut coordinator, 1011, 1024).unwrap();
        assert_eq!(cleaned, 0);
        assert!(coordinator.owner(offer.entry.ip).unwrap().is_some());
    }

    #[test]
    fn activate_reservation_creates_a_durable_binding() {
        let config = config_for("incremental", "192.168.1.100", "192.168.1.110", 3600);
        let subnet = config.subnet("lan").unwrap();
        let mut coordinator = setup(&config);
        let now = 1000;
        let reserved_ip = Ipv4Addr::new(192, 168, 1, 104);
        let mut record = crate::model::ReservationRecord {
            mac: mac(MAC_A),
            ..Default::default()
        };
        record.entries_by_subnet.insert(
            "lan".to_string(),
            crate::model::ReservationEntry {
                subnet_id: "lan".to_string(),
                ip: reserved_ip,
                enabled: true,
                hostname: None,
                client_id: None,
                created_at: now,
                updated_at: now,
            },
        );
        coordinator
            .apply(
                vec![JournalOp::put(
                    keys::reservation_key(mac(MAC_A)),
                    encode_record(&record).unwrap(),
                )],
                now,
            )
            .unwrap();
        let entry = activate_reservation(
            &mut coordinator,
            subnet,
            mac(MAC_A),
            reserved_ip,
            None,
            None,
            now,
        )
        .unwrap();
        assert_eq!(entry.ip, reserved_ip);
        assert_eq!(entry.state, LeaseState::Active);
        assert_eq!(
            coordinator.owner(reserved_ip).unwrap().unwrap().role,
            OwnerRole::Lease
        );
    }

    #[test]
    fn cursor_meta_is_journaled_with_the_lease() {
        let config = config_for("incremental", "192.168.1.100", "192.168.1.110", 3600);
        let subnet = config.subnet("lan").unwrap();
        let mut coordinator = setup(&config);
        let mut rng = SmallRng::seed_from_u64(1);
        let cursor_before = coordinator.subnet_meta("lan").unwrap().unwrap().cursor;
        offer_address(
            &mut coordinator,
            subnet,
            mac(MAC_A),
            None,
            None,
            1000,
            &mut rng,
        )
        .unwrap()
        .unwrap();
        let cursor_after = coordinator.subnet_meta("lan").unwrap().unwrap().cursor;
        assert_eq!(cursor_after, Ipv4Addr::from(u32::from(cursor_before) + 1));
    }

    #[test]
    fn allocation_strategy_is_used_from_config() {
        let incremental = config_for("incremental", "192.168.1.100", "192.168.1.110", 3600);
        assert_eq!(
            incremental.subnet("lan").unwrap().allocation_strategy,
            AllocationStrategy::Incremental
        );
        let random = config_for("random", "192.168.1.100", "192.168.1.110", 3600);
        assert_eq!(
            random.subnet("lan").unwrap().allocation_strategy,
            AllocationStrategy::Random
        );
    }
}
