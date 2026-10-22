//! Startup readiness checks and target smoke tests.
//!
//! `preflight` validates configuration, io_uring capabilities, interface
//! addresses and persistent storage consistency before the DHCP service is
//! started. It never falls back to a different network or storage backend.

use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fmt;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::storage::{Repo, StateCoordinator, StoreOptions};

#[derive(Debug, Clone)]
pub struct InterfaceReport {
    pub subnet_id: String,
    pub interface: String,
    pub server_identifier: Ipv4Addr,
    pub addresses: Vec<Ipv4Addr>,
}

#[derive(Debug, Clone)]
pub struct PreflightReport {
    pub io_uring_checked: bool,
    pub storage_path: PathBuf,
    pub reservations: usize,
    pub leases: usize,
    pub owners: usize,
    pub interfaces: Vec<InterfaceReport>,
    pub problems: Vec<String>,
}

impl PreflightReport {
    pub fn is_healthy(&self) -> bool {
        self.problems.is_empty()
    }
}

impl fmt::Display for PreflightReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "io_uring: RECVMSG/SENDMSG/IP_PKTINFO loopback exchange {}",
            if self.io_uring_checked {
                "passed"
            } else {
                "skipped"
            }
        )?;
        writeln!(
            f,
            "storage: {} ({} reservation(s), {} lease(s), {} IP owner(s))",
            self.storage_path.display(),
            self.reservations,
            self.leases,
            self.owners
        )?;
        for interface in &self.interfaces {
            let addresses = interface
                .addresses
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            writeln!(
                f,
                "interface {}: subnet {:?}, server identifier {} (addresses: {})",
                interface.interface,
                interface.subnet_id,
                interface.server_identifier,
                if addresses.is_empty() {
                    "none"
                } else {
                    &addresses
                }
            )?;
        }
        if self.problems.is_empty() {
            writeln!(f, "result: ready")?;
        } else {
            writeln!(f, "result: not ready")?;
            for problem in &self.problems {
                writeln!(f, "problem: {problem}")?;
            }
        }
        Ok(())
    }
}

/// Run every readiness check. The io_uring loopback probe is mandatory: no
/// DHCP traffic is served unless the kernel supports the exact operations
/// dhxpro uses.
pub fn run(config: &Config) -> Result<PreflightReport> {
    run_inner(config, true)
}

fn run_inner(config: &Config, probe_io_uring: bool) -> Result<PreflightReport> {
    if probe_io_uring {
        crate::net::io_uring_smoke_test().map_err(|error| {
            Error::IoUringUnavailable(format!(
                "preflight io_uring UDP/IP_PKTINFO probe failed: {error}"
            ))
        })?;
    }

    let options = StoreOptions::from_config(&config.storage);
    let (reservations, leases, owners, mut problems) = {
        // Opening replays any pending journal intent and takes the exclusive
        // lock, so preflight cannot run against a live server.
        let coordinator = StateCoordinator::open(&options)?;
        coordinator.verify_capabilities()?;
        let integrity = coordinator.integrity_report(config, unix_now()?)?;
        (
            coordinator.reservations()?.len(),
            coordinator.leases()?.len(),
            coordinator.owners()?.len(),
            integrity,
        )
    };

    let mut interfaces = Vec::new();
    for subnet in &config.subnets {
        let Some(interface) = &subnet.interface else {
            continue;
        };
        let addresses = interface_addresses(interface)?;
        if interface_index(interface).is_none() {
            problems.push(format!(
                "subnet {:?}: interface {interface:?} does not exist",
                subnet.id
            ));
            interfaces.push(InterfaceReport {
                subnet_id: subnet.id.clone(),
                interface: interface.clone(),
                server_identifier: subnet.server_identifier,
                addresses,
            });
            continue;
        }
        if addresses.is_empty() {
            problems.push(format!(
                "subnet {:?}: interface {interface:?} has no IPv4 address",
                subnet.id
            ));
        } else if !addresses.contains(&subnet.server_identifier) {
            problems.push(format!(
                "subnet {:?}: server identifier {} is not assigned to interface {interface:?} \
                 (assigned: {})",
                subnet.id,
                subnet.server_identifier,
                addresses
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        interfaces.push(InterfaceReport {
            subnet_id: subnet.id.clone(),
            interface: interface.clone(),
            server_identifier: subnet.server_identifier,
            addresses,
        });
    }

    // Cross-check the interface plan: each directly connected subnet must be
    // reachable on its configured interface, and no CIDR may silently overlap
    // (configuration validation already enforces the latter).
    let mut by_interface: BTreeMap<&str, usize> = BTreeMap::new();
    for subnet in &config.subnets {
        if let Some(interface) = subnet.interface.as_deref() {
            *by_interface.entry(interface).or_insert(0) += 1;
        }
    }
    for (interface, count) in by_interface {
        if count > 1 {
            eprintln!(
                "dhxpro: note: {count} subnets share interface {interface:?}; \
                 unicast destinations are required to disambiguate scopes"
            );
        }
    }

    Ok(PreflightReport {
        io_uring_checked: probe_io_uring,
        storage_path: config.storage.path.clone(),
        reservations,
        leases,
        owners,
        interfaces,
        problems,
    })
}

fn unix_now() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| Error::State("system clock is before the Unix epoch".to_string()))
}

/// IPv4 addresses assigned to an interface.
pub fn interface_addresses(name: &str) -> Result<Vec<Ipv4Addr>> {
    unsafe {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        let mut addresses = Vec::new();
        let mut cursor = head;
        while !cursor.is_null() {
            let ifa = &*cursor;
            if !ifa.ifa_addr.is_null()
                && (*ifa.ifa_addr).sa_family == libc::AF_INET as libc::sa_family_t
            {
                let interface = CStr::from_ptr(ifa.ifa_name).to_string_lossy();
                if interface == name {
                    let address = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    addresses.push(Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr)));
                }
            }
            cursor = ifa.ifa_next;
        }
        libc::freeifaddrs(head);
        addresses.sort();
        addresses.dedup();
        Ok(addresses)
    }
}

/// Interface index, or `None` when the interface does not exist.
pub fn interface_index(name: &str) -> Option<u32> {
    let name = CString::new(name).ok()?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        None
    } else {
        Some(index)
    }
}

/// Persistent storage smoke test: write a prefixed key, flush, close, reopen,
/// verify the value, then remove the probe and flush. Used by `smoke-test` on
/// the target.
pub fn storage_smoke_test(options: &StoreOptions) -> Result<()> {
    let key = b"dhxpro:probe:v1:smoke-test";
    let value = b"dhxpro-smoke-v1";

    // Replay any pending journal intent before probing, then release the lock
    // so the reopen path is exercised.
    {
        let coordinator = StateCoordinator::open(options)?;
        coordinator.verify_capabilities()?;
    }

    {
        let repo = Repo::open(options)?;
        repo.put_raw(key, value)?;
        repo.flush()?;
    }

    if options.path.is_some() {
        let repo = Repo::open(options)?;
        match repo.get_raw(key)? {
            Some(found) if found == value => {}
            Some(found) => {
                return Err(Error::State(format!(
                    "storage smoke test read back {} bytes instead of the expected value",
                    found.len()
                )))
            }
            None => {
                return Err(Error::State(
                    "storage smoke test key disappeared across reopen".to_string(),
                ))
            }
        }
    }

    let repo = Repo::open(options)?;
    repo.delete_raw(key)?;
    repo.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_interface_has_the_loopback_address() {
        let addresses = interface_addresses("lo").unwrap();
        assert!(addresses.contains(&Ipv4Addr::LOCALHOST), "{addresses:?}");
        assert!(interface_index("lo").is_some());
    }

    #[test]
    fn missing_interface_is_reported() {
        assert!(interface_index("dhxpro-no-such-interface").is_none());
        assert!(interface_addresses("dhxpro-no-such-interface")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn preflight_checks_storage_and_interfaces_without_io_uring_probe() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("state.feox");
        let yaml = format!(
            r#"
schema_version: 1
storage:
  path: {}
  file_size_mib: 8
  max_memory_mib: 8
  hash_bits: 12
authoritative: true
subnets:
  - id: loop
    interface: lo
    cidr: 127.0.0.0/24
    server_identifier: 127.0.0.1
    range:
      start: 127.0.0.100
      end: 127.0.0.110
    exclusions: []
    routers: []
    dns_servers: []
    lease_seconds: 3600
    offer_hold_seconds: 30
    decline_hold_seconds: 60
    allocation_strategy: incremental
"#,
            store.display()
        );
        let config = Config::parse_str(&yaml).unwrap();
        let report = run_inner(&config, false).unwrap();
        assert!(report.is_healthy(), "{:?}", report.problems);
        assert_eq!(report.reservations, 0);
        assert_eq!(report.owners, 0);
        assert_eq!(report.interfaces.len(), 1);
        assert!(report.interfaces[0]
            .addresses
            .contains(&Ipv4Addr::LOCALHOST));
        let rendered = report.to_string();
        assert!(rendered.contains("result: ready"), "{rendered}");
    }

    #[test]
    fn preflight_reports_a_server_identifier_not_on_the_interface() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("state.feox");
        let yaml = format!(
            r#"
schema_version: 1
storage:
  path: {}
  file_size_mib: 8
  max_memory_mib: 8
  hash_bits: 12
authoritative: true
subnets:
  - id: loop
    interface: lo
    cidr: 127.0.0.0/24
    server_identifier: 127.0.0.2
    range:
      start: 127.0.0.100
      end: 127.0.0.110
    exclusions: []
    routers: []
    dns_servers: []
    lease_seconds: 3600
    offer_hold_seconds: 30
    decline_hold_seconds: 60
    allocation_strategy: incremental
"#,
            store.display()
        );
        let config = Config::parse_str(&yaml).unwrap();
        let report = run_inner(&config, false).unwrap();
        assert!(!report.is_healthy());
        assert!(
            report
                .problems
                .iter()
                .any(|problem| problem.contains("not assigned")),
            "{:?}",
            report.problems
        );
    }

    #[test]
    fn persistent_storage_smoke_test_round_trips_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let options = StoreOptions {
            path: Some(dir.path().join("smoke.feox")),
            file_size_bytes: 8 * 1024 * 1024,
            max_memory_bytes: 8 * 1024 * 1024,
            hash_bits: 12,
        };
        storage_smoke_test(&options).unwrap();
        // The probe key must have been cleaned up.
        let repo = Repo::open(&options).unwrap();
        assert!(repo
            .get_raw(b"dhxpro:probe:v1:smoke-test")
            .unwrap()
            .is_none());
    }
}
