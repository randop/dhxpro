//! Offline MAC reservation administration.
//!
//! All mutations use the same durable redo journal as the DHCP server. The
//! CLI acquires the exclusive store lock, so it can only run while the server
//! is stopped (or against a separate store).

use std::net::Ipv4Addr;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::keys;
use crate::mac::MacAddr;
use crate::model::{
    encode_record, IpOwner, JournalOp, OwnerRole, ReservationEntry, ReservationRecord,
};
use crate::storage::StateCoordinator;

/// Add an enabled reservation. Fails if the MAC already has an entry for the
/// subnet, or if the address is not safe to reserve.
pub fn add(
    coordinator: &mut StateCoordinator,
    config: &Config,
    mac: MacAddr,
    subnet_id: &str,
    ip: Ipv4Addr,
    hostname: Option<&str>,
    now: u64,
) -> Result<ReservationRecord> {
    let subnet = config.subnet_by_id(subnet_id)?;
    validate_reservation_ip(subnet, ip)?;
    ensure_available(coordinator, subnet, mac, ip, now)?;

    let mut record = coordinator.reservation(mac)?.unwrap_or(ReservationRecord {
        mac,
        ..Default::default()
    });
    if let Some(existing) = record.entries_by_subnet.get(subnet_id) {
        return Err(Error::Other(format!(
            "{mac} already has a{} reservation for subnet {subnet_id:?} at {}; \
             use `update` or `enable` instead",
            if existing.enabled { "n" } else { " disabled" },
            existing.ip
        )));
    }

    let entry = ReservationEntry {
        subnet_id: subnet_id.to_string(),
        ip,
        enabled: true,
        hostname: hostname.map(str::to_string),
        client_id: None,
        created_at: now,
        updated_at: now,
    };
    record
        .entries_by_subnet
        .insert(subnet_id.to_string(), entry);
    let owner = reservation_owner(mac, subnet_id, ip, 1, now);

    coordinator.apply(
        vec![
            JournalOp::put(keys::reservation_key(mac), encode_record(&record)?),
            JournalOp::put(keys::ip_owner_key(ip), encode_record(&owner)?),
        ],
        now,
    )?;
    Ok(record)
}

/// Change the address (and optionally the hostname) of an existing
/// reservation. The enabled/disabled state is preserved.
pub fn update(
    coordinator: &mut StateCoordinator,
    config: &Config,
    mac: MacAddr,
    subnet_id: &str,
    ip: Ipv4Addr,
    hostname: Option<Option<String>>,
    now: u64,
) -> Result<ReservationRecord> {
    let subnet = config.subnet_by_id(subnet_id)?;
    validate_reservation_ip(subnet, ip)?;

    let mut record = coordinator
        .reservation(mac)?
        .ok_or_else(|| Error::Other(format!("{mac} has no reservation record")))?;
    let existing = record
        .entries_by_subnet
        .get(subnet_id)
        .cloned()
        .ok_or_else(|| {
            Error::Other(format!("{mac} has no reservation for subnet {subnet_id:?}"))
        })?;

    if existing.ip != ip {
        ensure_available(coordinator, subnet, mac, ip, now)?;
    } else if existing.enabled {
        // Re-validating the same address must still reject a foreign owner.
        if let Some(owner) = coordinator.owner(ip)? {
            if owner.mac != mac || owner.role != OwnerRole::Reservation {
                return Err(Error::Other(format!(
                    "{ip} is currently owned by {} ({:?}) and cannot be reserved for {mac}",
                    owner.mac, owner.role
                )));
            }
        }
    }

    let mut ops = Vec::new();
    if existing.ip != ip && existing.enabled {
        if let Some(owner) = coordinator.owner(existing.ip)? {
            if owner.mac == mac
                && owner.subnet_id == subnet_id
                && owner.role == OwnerRole::Reservation
            {
                ops.push(JournalOp::delete(keys::ip_owner_key(existing.ip)));
            }
        }
    }

    let entry = ReservationEntry {
        subnet_id: subnet_id.to_string(),
        ip,
        enabled: existing.enabled,
        hostname: match hostname {
            Some(value) => value,
            None => existing.hostname,
        },
        client_id: existing.client_id,
        created_at: existing.created_at,
        updated_at: now,
    };
    record
        .entries_by_subnet
        .insert(subnet_id.to_string(), entry.clone());

    let generation = current_owner_generation(coordinator, ip, mac)?.saturating_add(1);
    if entry.enabled {
        ops.push(JournalOp::put(
            keys::ip_owner_key(ip),
            encode_record(&reservation_owner(mac, subnet_id, ip, generation, now))?,
        ));
    }
    ops.push(JournalOp::put(
        keys::reservation_key(mac),
        encode_record(&record)?,
    ));

    coordinator.apply(ops, now)?;
    Ok(record)
}

/// Re-enable a disabled reservation after re-validating its address.
pub fn enable(
    coordinator: &mut StateCoordinator,
    config: &Config,
    mac: MacAddr,
    subnet_id: &str,
    now: u64,
) -> Result<ReservationRecord> {
    let subnet = config.subnet_by_id(subnet_id)?;
    let mut record = coordinator
        .reservation(mac)?
        .ok_or_else(|| Error::Other(format!("{mac} has no reservation record")))?;
    let existing = record
        .entries_by_subnet
        .get(subnet_id)
        .cloned()
        .ok_or_else(|| {
            Error::Other(format!("{mac} has no reservation for subnet {subnet_id:?}"))
        })?;
    if existing.enabled {
        return Err(Error::Other(format!(
            "reservation for {mac} in subnet {subnet_id:?} is already enabled"
        )));
    }
    validate_reservation_ip(subnet, existing.ip)?;
    ensure_available(coordinator, subnet, mac, existing.ip, now)?;

    let ip = existing.ip;
    let entry = ReservationEntry {
        enabled: true,
        updated_at: now,
        ..existing
    };
    record
        .entries_by_subnet
        .insert(subnet_id.to_string(), entry);

    let generation = current_owner_generation(coordinator, ip, mac)?.saturating_add(1);
    let owner = reservation_owner(mac, subnet_id, ip, generation, now);
    coordinator.apply(
        vec![
            JournalOp::put(keys::reservation_key(mac), encode_record(&record)?),
            JournalOp::put(keys::ip_owner_key(ip), encode_record(&owner)?),
        ],
        now,
    )?;
    Ok(record)
}

/// Disable a reservation without deleting it. Its IP-owner entry is removed so
/// the address may be allocated dynamically again.
pub fn disable(
    coordinator: &mut StateCoordinator,
    mac: MacAddr,
    subnet_id: &str,
    now: u64,
) -> Result<ReservationRecord> {
    let mut record = coordinator
        .reservation(mac)?
        .ok_or_else(|| Error::Other(format!("{mac} has no reservation record")))?;
    let existing = record
        .entries_by_subnet
        .get(subnet_id)
        .cloned()
        .ok_or_else(|| {
            Error::Other(format!("{mac} has no reservation for subnet {subnet_id:?}"))
        })?;
    if !existing.enabled {
        return Err(Error::Other(format!(
            "reservation for {mac} in subnet {subnet_id:?} is already disabled"
        )));
    }

    let entry = ReservationEntry {
        enabled: false,
        updated_at: now,
        ..existing.clone()
    };
    record
        .entries_by_subnet
        .insert(subnet_id.to_string(), entry);

    let mut ops = vec![JournalOp::put(
        keys::reservation_key(mac),
        encode_record(&record)?,
    )];
    if let Some(owner) = coordinator.owner(existing.ip)? {
        if owner.mac == mac && owner.subnet_id == subnet_id && owner.role == OwnerRole::Reservation
        {
            ops.push(JournalOp::delete(keys::ip_owner_key(existing.ip)));
        }
    }
    coordinator.apply(ops, now)?;
    Ok(record)
}

/// Remove a reservation entry entirely.
pub fn remove(
    coordinator: &mut StateCoordinator,
    mac: MacAddr,
    subnet_id: &str,
    now: u64,
) -> Result<ReservationRecord> {
    let mut record = coordinator
        .reservation(mac)?
        .ok_or_else(|| Error::Other(format!("{mac} has no reservation record")))?;
    let existing = record.entries_by_subnet.remove(subnet_id).ok_or_else(|| {
        Error::Other(format!("{mac} has no reservation for subnet {subnet_id:?}"))
    })?;

    let mut ops = Vec::new();
    if record.entries_by_subnet.is_empty() {
        ops.push(JournalOp::delete(keys::reservation_key(mac)));
    } else {
        ops.push(JournalOp::put(
            keys::reservation_key(mac),
            encode_record(&record)?,
        ));
    }
    if let Some(owner) = coordinator.owner(existing.ip)? {
        if owner.mac == mac && owner.subnet_id == subnet_id && owner.role == OwnerRole::Reservation
        {
            ops.push(JournalOp::delete(keys::ip_owner_key(existing.ip)));
        }
    }
    coordinator.apply(ops, now)?;
    Ok(record)
}

/// All reservation records, sorted by MAC for stable CLI output.
pub fn list(coordinator: &StateCoordinator) -> Result<Vec<ReservationRecord>> {
    let mut records = coordinator.reservations()?;
    records.sort_by_key(|record| record.mac);
    Ok(records)
}

fn validate_reservation_ip(subnet: &crate::config::SubnetConfig, ip: Ipv4Addr) -> Result<()> {
    if !subnet.is_valid_reservation_ip(ip) {
        return Err(Error::Other(format!(
            "{ip} is not a valid reservation address in subnet {:?} ({}): it must be an \
             address inside the CIDR that is not the network, broadcast, server identifier \
             or an excluded address",
            subnet.id, subnet.cidr
        )));
    }
    Ok(())
}

/// Check both the authoritative owner index and the lease/reservation records
/// so a stale or missing index entry cannot produce a duplicate assignment.
fn ensure_available(
    coordinator: &StateCoordinator,
    subnet: &crate::config::SubnetConfig,
    mac: MacAddr,
    ip: Ipv4Addr,
    now: u64,
) -> Result<()> {
    if let Some(owner) = coordinator.owner(ip)? {
        let acceptable = owner.mac == mac
            && owner.subnet_id == subnet.id
            && owner.role == OwnerRole::Reservation;
        if !acceptable {
            return Err(Error::Other(format!(
                "{ip} is already owned by {} in subnet {:?} ({:?})",
                owner.mac, owner.subnet_id, owner.role
            )));
        }
    }

    for record in coordinator.leases()? {
        for entry in record.entries_by_subnet.values() {
            if entry.ip == ip && entry.subnet_id == subnet.id && entry.blocks_at(now) {
                return Err(Error::Other(format!(
                    "{ip} is held by an active lease/offer/decline for {} in subnet {:?} \
                     until {}",
                    record.mac,
                    subnet.id,
                    entry.blocking_until()
                )));
            }
        }
    }

    for record in coordinator.reservations()? {
        if record.mac == mac {
            continue;
        }
        if let Some(entry) = record.entries_by_subnet.get(&subnet.id) {
            if entry.enabled && entry.ip == ip {
                return Err(Error::Other(format!(
                    "{ip} is already reserved for {} in subnet {:?}",
                    record.mac, subnet.id
                )));
            }
        }
    }
    Ok(())
}

fn reservation_owner(
    mac: MacAddr,
    subnet_id: &str,
    ip: Ipv4Addr,
    generation: u64,
    now: u64,
) -> IpOwner {
    IpOwner {
        ip,
        subnet_id: subnet_id.to_string(),
        mac,
        role: OwnerRole::Reservation,
        generation,
        expires_at: 0,
        updated_at: now,
    }
}

fn current_owner_generation(
    coordinator: &StateCoordinator,
    ip: Ipv4Addr,
    mac: MacAddr,
) -> Result<u64> {
    Ok(coordinator
        .owner(ip)?
        .filter(|owner| owner.mac == mac && owner.role == OwnerRole::Reservation)
        .map(|owner| owner.generation)
        .unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::model::LeaseState;

    fn setup() -> (Config, StateCoordinator, MacAddr, Ipv4Addr) {
        let config = Config::parse_str(crate::config::example_config()).unwrap();
        let mut coordinator = StateCoordinator::open_memory().unwrap();
        coordinator.prepare_subnets(&config, 1000).unwrap();
        let mac = MacAddr::parse("aabbccddee01").unwrap();
        let ip = Ipv4Addr::new(192, 168, 1, 111);
        (config, coordinator, mac, ip)
    }

    #[test]
    fn add_list_update_disable_enable_remove() {
        let (config, mut coordinator, mac, ip) = setup();
        let now = 1000;

        add(
            &mut coordinator,
            &config,
            mac,
            "lan",
            ip,
            Some("printer"),
            now,
        )
        .unwrap();
        let records = list(&coordinator).unwrap();
        assert_eq!(records.len(), 1);
        let entry = &records[0].entries_by_subnet["lan"];
        assert_eq!(entry.ip, ip);
        assert!(entry.enabled);
        assert_eq!(entry.hostname.as_deref(), Some("printer"));
        assert_eq!(
            coordinator.owner(ip).unwrap().unwrap().role,
            OwnerRole::Reservation
        );

        // A duplicate reservation is rejected.
        let error = add(&mut coordinator, &config, mac, "lan", ip, None, now)
            .unwrap_err()
            .to_string();
        assert!(error.contains("already has"), "{error}");

        // A second subnet for the same MAC uses one record with two entries.
        let guest_ip = Ipv4Addr::new(10, 20, 0, 110);
        add(&mut coordinator, &config, mac, "guest", guest_ip, None, now).unwrap();
        let record = coordinator.reservation(mac).unwrap().unwrap();
        assert_eq!(record.entries_by_subnet.len(), 2);

        // Updating the hostname preserves the address.
        update(
            &mut coordinator,
            &config,
            mac,
            "lan",
            ip,
            Some(Some("printer-2".to_string())),
            now + 1,
        )
        .unwrap();
        assert_eq!(
            coordinator
                .reservation(mac)
                .unwrap()
                .unwrap()
                .entries_by_subnet["lan"]
                .hostname
                .as_deref(),
            Some("printer-2")
        );

        // Changing the address moves the IP-owner entry.
        let new_ip = Ipv4Addr::new(192, 168, 1, 112);
        update(&mut coordinator, &config, mac, "lan", new_ip, None, now + 2).unwrap();
        assert!(coordinator.owner(ip).unwrap().is_none());
        assert_eq!(
            coordinator.owner(new_ip).unwrap().unwrap().role,
            OwnerRole::Reservation
        );

        disable(&mut coordinator, mac, "lan", now + 3).unwrap();
        assert!(coordinator.owner(new_ip).unwrap().is_none());
        assert!(
            !coordinator
                .reservation(mac)
                .unwrap()
                .unwrap()
                .entries_by_subnet["lan"]
                .enabled
        );

        enable(&mut coordinator, &config, mac, "lan", now + 4).unwrap();
        assert_eq!(
            coordinator.owner(new_ip).unwrap().unwrap().role,
            OwnerRole::Reservation
        );

        remove(&mut coordinator, mac, "lan", now + 5).unwrap();
        assert!(coordinator.owner(new_ip).unwrap().is_none());
        assert_eq!(
            coordinator
                .reservation(mac)
                .unwrap()
                .unwrap()
                .entries_by_subnet
                .len(),
            1
        );

        remove(&mut coordinator, mac, "guest", now + 6).unwrap();
        assert!(coordinator.reservation(mac).unwrap().is_none());
    }

    #[test]
    fn invalid_addresses_are_rejected() {
        let (config, mut coordinator, mac, _) = setup();
        for ip in [
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(192, 168, 1, 255),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 150),
            Ipv4Addr::new(192, 168, 2, 10),
        ] {
            assert!(
                add(&mut coordinator, &config, mac, "lan", ip, None, 1000).is_err(),
                "{ip} should be rejected"
            );
        }
    }

    #[test]
    fn conflicting_owner_is_rejected() {
        let (config, mut coordinator, mac, ip) = setup();
        let now = 1000;
        let other = MacAddr::parse("aabbccddee02").unwrap();

        // Create an active lease for the other MAC at ip.
        let mut lease = crate::model::LeaseRecord {
            mac: other,
            ..Default::default()
        };
        lease.entries_by_subnet.insert(
            "lan".to_string(),
            crate::model::LeaseEntry {
                subnet_id: "lan".to_string(),
                ip,
                client_id: None,
                hostname: None,
                state: LeaseState::Active,
                lease_started_at: now,
                lease_expires_at: now + 3600,
                offer_expires_at: 0,
                declined_until: 0,
                generation: 1,
                updated_at: now,
            },
        );
        coordinator
            .apply(
                vec![
                    JournalOp::put(keys::lease_key(other), encode_record(&lease).unwrap()),
                    JournalOp::put(
                        keys::ip_owner_key(ip),
                        encode_record(&IpOwner {
                            ip,
                            subnet_id: "lan".to_string(),
                            mac: other,
                            role: OwnerRole::Lease,
                            generation: 1,
                            expires_at: now + 3600,
                            updated_at: now,
                        })
                        .unwrap(),
                    ),
                ],
                now,
            )
            .unwrap();

        let error = add(&mut coordinator, &config, mac, "lan", ip, None, now)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("owned by") || error.contains("held by"),
            "{error}"
        );
    }

    #[test]
    fn foreign_reservation_is_rejected() {
        let (config, mut coordinator, mac, ip) = setup();
        let other = MacAddr::parse("aabbccddee02").unwrap();
        add(&mut coordinator, &config, other, "lan", ip, None, 1000).unwrap();
        let error = add(&mut coordinator, &config, mac, "lan", ip, None, 1000)
            .unwrap_err()
            .to_string();
        assert!(error.contains("owned by"), "{error}");
    }

    #[test]
    fn disabled_reservation_can_be_enabled_only_when_free() {
        let (config, mut coordinator, mac, ip) = setup();
        let now = 1000;
        add(&mut coordinator, &config, mac, "lan", ip, None, now).unwrap();
        disable(&mut coordinator, mac, "lan", now + 1).unwrap();

        // Simulate a dynamic lease taking the disabled reservation's address.
        let other = MacAddr::parse("aabbccddee02").unwrap();
        coordinator
            .apply(
                vec![JournalOp::put(
                    keys::ip_owner_key(ip),
                    encode_record(&IpOwner {
                        ip,
                        subnet_id: "lan".to_string(),
                        mac: other,
                        role: OwnerRole::Lease,
                        generation: 1,
                        expires_at: now + 3600,
                        updated_at: now,
                    })
                    .unwrap(),
                )],
                now + 2,
            )
            .unwrap();
        let error = enable(&mut coordinator, &config, mac, "lan", now + 3)
            .unwrap_err()
            .to_string();
        assert!(error.contains("owned by"), "{error}");
    }

    #[test]
    fn idempotent_state_errors_are_clear() {
        let (_, mut coordinator, mac, _) = setup();
        let error = disable(&mut coordinator, mac, "lan", 1000)
            .unwrap_err()
            .to_string();
        assert!(error.contains("no reservation record"), "{error}");
    }
}
