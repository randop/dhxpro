//! YAML configuration parsing and validation.
//!
//! Configuration is fully validated before the network or storage layers are
//! initialized. Validated values are immutable for the lifetime of the
//! process; subnet IDs are stable because they are persisted in record values
//! and subnet metadata keys.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use ipnet::Ipv4Net;
use serde::Deserialize;

use crate::error::{Error, Result};

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_LEASE_SECONDS: u32 = 2_592_000; // 30 days
pub const MIN_LEASE_SECONDS: u32 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocationStrategy {
    Incremental,
    Random,
}

impl fmt::Display for AllocationStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AllocationStrategy::Incremental => f.write_str("incremental"),
            AllocationStrategy::Random => f.write_str("random"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageConfig {
    pub path: PathBuf,
    pub file_size_mib: u64,
    pub max_memory_mib: u64,
    pub hash_bits: u32,
}

impl StorageConfig {
    pub fn file_size_bytes(&self) -> u64 {
        self.file_size_mib * 1024 * 1024
    }

    pub fn max_memory_bytes(&self) -> usize {
        (self.max_memory_mib * 1024 * 1024) as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubnetConfig {
    pub id: String,
    /// Directly connected interface. `None` means the subnet is only
    /// reachable through a configured relay mapping.
    pub interface: Option<String>,
    pub cidr: Ipv4Net,
    pub server_identifier: Ipv4Addr,
    pub range_start: Ipv4Addr,
    pub range_end: Ipv4Addr,
    /// Addresses that must never be handed out. Always includes the network
    /// address, broadcast address and server identifier.
    pub exclusions: BTreeSet<Ipv4Addr>,
    pub configured_exclusions: Vec<Ipv4Addr>,
    pub routers: Vec<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub domain_name: Option<String>,
    pub lease_seconds: u32,
    pub offer_hold_seconds: u32,
    pub decline_hold_seconds: u32,
    pub allocation_strategy: AllocationStrategy,
}

impl SubnetConfig {
    pub fn prefix_len(&self) -> u8 {
        self.cidr.prefix_len()
    }

    pub fn network(&self) -> Ipv4Addr {
        self.cidr.network()
    }

    pub fn netmask(&self) -> Ipv4Addr {
        self.cidr.netmask()
    }

    pub fn broadcast(&self) -> Ipv4Addr {
        self.cidr.broadcast()
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        self.cidr.contains(&ip)
    }

    /// Inside the CIDR and not the network or broadcast address.
    pub fn is_usable_host(&self, ip: Ipv4Addr) -> bool {
        self.contains(ip) && ip != self.network() && ip != self.broadcast()
    }

    pub fn is_excluded(&self, ip: Ipv4Addr) -> bool {
        self.exclusions.contains(&ip)
    }

    /// Candidate for dynamic allocation.
    pub fn is_dynamic_candidate(&self, ip: Ipv4Addr) -> bool {
        ip >= self.range_start
            && ip <= self.range_end
            && self.is_usable_host(ip)
            && !self.is_excluded(ip)
    }

    /// Valid target for a fixed MAC reservation. Reservations may live outside
    /// the dynamic range but must be usable addresses in the subnet.
    pub fn is_valid_reservation_ip(&self, ip: Ipv4Addr) -> bool {
        self.is_usable_host(ip) && !self.is_excluded(ip) && ip != self.server_identifier
    }

    pub fn range_len(&self) -> u64 {
        u64::from(u32::from(self.range_end)) - u64::from(u32::from(self.range_start)) + 1
    }

    /// Next address in the inclusive range, wrapping to the start.
    pub fn next_cursor(&self, current: Ipv4Addr) -> Ipv4Addr {
        if current >= self.range_end {
            self.range_start
        } else {
            Ipv4Addr::from(u32::from(current) + 1)
        }
    }

    pub fn t1(&self) -> u32 {
        (self.lease_seconds / 2).max(1)
    }

    pub fn t2(&self) -> u32 {
        (self.lease_seconds / 8 * 7)
            .max(self.t1() + 1)
            .min(self.lease_seconds.saturating_sub(1))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayConfig {
    pub giaddr: Ipv4Addr,
    pub subnet_id: String,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub schema_version: u32,
    pub storage: StorageConfig,
    pub authoritative: bool,
    pub subnets: Vec<SubnetConfig>,
    pub relays: Vec<RelayConfig>,
    subnet_index: HashMap<String, usize>,
    relay_index: HashMap<Ipv4Addr, usize>,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = fs::read_to_string(path).map_err(|source| Error::ConfigIo {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse_str(&text).map_err(|error| match error {
            Error::Config(message) => Error::Config(format!("{}: {message}", path.display())),
            other => other,
        })
    }

    pub fn parse_str(text: &str) -> Result<Self> {
        let raw: RawConfig = serde_yaml::from_str(text).map_err(|source| Error::ConfigParse {
            path: PathBuf::from("<memory>"),
            source,
        })?;
        Self::from_raw(raw)
    }

    pub fn subnet(&self, id: &str) -> Option<&SubnetConfig> {
        self.subnet_index.get(id).map(|index| &self.subnets[*index])
    }

    pub fn subnet_by_id(&self, id: &str) -> Result<&SubnetConfig> {
        self.subnet(id)
            .ok_or_else(|| Error::config(format!("unknown subnet id {id:?}")))
    }

    /// Resolve a relay-agent request scope. Returns `None` when the `giaddr`
    /// does not have an explicit mapping; callers must reject such packets
    /// rather than guessing from requested addresses.
    pub fn relay_subnet(&self, giaddr: Ipv4Addr) -> Option<&SubnetConfig> {
        self.relay_index
            .get(&giaddr)
            .map(|index| &self.subnets[*index])
    }

    pub fn subnets_on_interface<'a>(
        &'a self,
        interface: &'a str,
    ) -> impl Iterator<Item = &'a SubnetConfig> + 'a {
        self.subnets
            .iter()
            .filter(move |subnet| subnet.interface.as_deref() == Some(interface))
    }

    pub fn configured_interfaces(&self) -> BTreeSet<&str> {
        self.subnets
            .iter()
            .filter_map(|subnet| subnet.interface.as_deref())
            .collect()
    }

    pub fn summary(&self) -> String {
        let direct = self
            .subnets
            .iter()
            .filter(|subnet| subnet.interface.is_some())
            .count();
        let relay_only = self.subnets.len() - direct;
        format!(
            "{} subnet(s) ({} direct, {} relay-only), {} relay mapping(s), store {}",
            self.subnets.len(),
            direct,
            relay_only,
            self.relays.len(),
            self.storage.path.display()
        )
    }

    fn from_raw(raw: RawConfig) -> Result<Self> {
        if raw.schema_version != SCHEMA_VERSION {
            return Err(Error::config(format!(
                "schema_version must be {SCHEMA_VERSION}, got {}",
                raw.schema_version
            )));
        }
        if raw.subnets.is_empty() {
            return Err(Error::config("at least one subnet must be configured"));
        }

        let storage = validate_storage(&raw.storage)?;
        let mut subnets = Vec::with_capacity(raw.subnets.len());
        let mut subnet_index = HashMap::new();
        let mut server_ids: HashMap<Ipv4Addr, String> = HashMap::new();

        for (position, raw_subnet) in raw.subnets.into_iter().enumerate() {
            let subnet = validate_subnet(raw_subnet)
                .map_err(|error| Error::config(format!("subnets[{position}]: {error}")))?;
            if subnet_index.insert(subnet.id.clone(), position).is_some() {
                return Err(Error::config(format!(
                    "duplicate subnet id {:?}",
                    subnet.id
                )));
            }
            if let Some(previous) = server_ids.insert(subnet.server_identifier, subnet.id.clone()) {
                return Err(Error::config(format!(
                    "server_identifier {} is used by both subnet {:?} and {:?}",
                    subnet.server_identifier, previous, subnet.id
                )));
            }
            subnets.push(subnet);
        }

        for (left_index, left) in subnets.iter().enumerate() {
            for right in subnets.iter().skip(left_index + 1) {
                if cidrs_overlap(&left.cidr, &right.cidr) {
                    return Err(Error::config(format!(
                        "subnet {:?} ({}) overlaps subnet {:?} ({})",
                        left.id, left.cidr, right.id, right.cidr
                    )));
                }
            }
        }

        let mut relays = Vec::with_capacity(raw.relays.len());
        let mut relay_index = HashMap::new();
        let mut seen_giaddr: HashMap<Ipv4Addr, String> = HashMap::new();
        for (position, raw_relay) in raw.relays.into_iter().enumerate() {
            let giaddr = parse_ipv4(&raw_relay.giaddr)
                .map_err(|error| Error::config(format!("relays[{position}].giaddr: {error}")))?;
            let subnet_position =
                subnet_index
                    .get(&raw_relay.subnet_id)
                    .copied()
                    .ok_or_else(|| {
                        Error::config(format!(
                            "relays[{position}].subnet_id references unknown subnet {:?}",
                            raw_relay.subnet_id
                        ))
                    })?;
            let subnet = &subnets[subnet_position];
            if subnet.interface.is_some() {
                return Err(Error::config(format!(
                    "relays[{position}]: subnet {:?} is directly connected (interface {:?}); \
                     relay mappings may only target relay-only subnets",
                    subnet.id, subnet.interface
                )));
            }
            if !subnet.is_usable_host(giaddr) {
                return Err(Error::config(format!(
                    "relays[{position}].giaddr {giaddr} is not a usable host address in subnet {:?} ({})",
                    subnet.id, subnet.cidr
                )));
            }
            // A relay gateway is infrastructure on the remote subnet. Never
            // put it in the dynamic pool or allow a fixed reservation for it.
            let relay_subnet_id = subnet.id.clone();
            if let Some(previous) = seen_giaddr.insert(giaddr, relay_subnet_id.clone()) {
                return Err(Error::config(format!(
                    "giaddr {giaddr} is mapped to both subnet {previous:?} and {relay_subnet_id:?}"
                )));
            }
            subnets[subnet_position].exclusions.insert(giaddr);
            relay_index.insert(giaddr, subnet_position);
            relays.push(RelayConfig {
                giaddr,
                subnet_id: relay_subnet_id,
            });
        }

        for subnet in &subnets {
            if subnet.interface.is_none()
                && !relays.iter().any(|relay| relay.subnet_id == subnet.id)
            {
                return Err(Error::config(format!(
                    "relay-only subnet {:?} has no relay mapping and is unreachable",
                    subnet.id
                )));
            }
        }

        Ok(Self {
            schema_version: raw.schema_version,
            storage,
            authoritative: raw.authoritative,
            subnets,
            relays,
            subnet_index,
            relay_index,
        })
    }
}

fn validate_storage(raw: &RawStorage) -> Result<StorageConfig> {
    if raw.path.trim().is_empty() {
        return Err(Error::config("storage.path must not be empty"));
    }
    if raw.file_size_mib == 0 || raw.file_size_mib > 4096 {
        return Err(Error::config(format!(
            "storage.file_size_mib must be in 1..=4096, got {}",
            raw.file_size_mib
        )));
    }
    if raw.max_memory_mib < 4 || raw.max_memory_mib > 1024 {
        return Err(Error::config(format!(
            "storage.max_memory_mib must be in 4..=1024, got {}",
            raw.max_memory_mib
        )));
    }
    if raw.hash_bits < 8 || raw.hash_bits > 24 {
        return Err(Error::config(format!(
            "storage.hash_bits must be in 8..=24, got {}",
            raw.hash_bits
        )));
    }
    Ok(StorageConfig {
        path: PathBuf::from(&raw.path),
        file_size_mib: raw.file_size_mib,
        max_memory_mib: raw.max_memory_mib,
        hash_bits: raw.hash_bits,
    })
}

fn validate_subnet(raw: RawSubnet) -> Result<SubnetConfig> {
    validate_subnet_id(&raw.id)?;

    let cidr = parse_cidr(&raw.cidr)?;
    if cidr.prefix_len() > 30 {
        return Err(Error::config(format!(
            "cidr {cidr} is too small for DHCPv4 (prefix must be /8../30)"
        )));
    }
    if cidr.prefix_len() < 8 {
        return Err(Error::config(format!(
            "cidr {cidr} is too large (prefix must be /8../30)"
        )));
    }
    if cidr.addr() != cidr.network() {
        return Err(Error::config(format!(
            "cidr {cidr} has host bits set; use {}",
            cidr.trunc()
        )));
    }

    let server_identifier = parse_ipv4(&raw.server_identifier)
        .map_err(|error| Error::config(format!("server_identifier: {error}")))?;
    let network = cidr.network();
    let broadcast = cidr.broadcast();
    if server_identifier == network || server_identifier == broadcast {
        return Err(Error::config(format!(
            "server_identifier {server_identifier} may not be the network or broadcast address of {cidr}"
        )));
    }
    if !cidr.contains(&server_identifier) {
        return Err(Error::config(format!(
            "server_identifier {server_identifier} is outside cidr {cidr}"
        )));
    }

    let range_start = parse_ipv4(&raw.range.start)
        .map_err(|error| Error::config(format!("range.start: {error}")))?;
    let range_end =
        parse_ipv4(&raw.range.end).map_err(|error| Error::config(format!("range.end: {error}")))?;
    if range_start > range_end {
        return Err(Error::config(format!(
            "range.start {range_start} is greater than range.end {range_end}"
        )));
    }
    for (name, ip) in [("range.start", range_start), ("range.end", range_end)] {
        if !cidr.contains(&ip) {
            return Err(Error::config(format!("{name} {ip} is outside cidr {cidr}")));
        }
        if ip == network || ip == broadcast {
            return Err(Error::config(format!(
                "{name} {ip} is the network or broadcast address of {cidr}"
            )));
        }
    }
    if range_start <= server_identifier && server_identifier <= range_end {
        // A server address inside the dynamic range is only acceptable when it
        // is explicitly excluded; otherwise it could be allocated.
        let explicitly_excluded = raw
            .exclusions
            .iter()
            .any(|value| value == &server_identifier.to_string());
        if !explicitly_excluded {
            return Err(Error::config(format!(
                "server_identifier {server_identifier} is inside the dynamic range \
                 {range_start}..={range_end}; exclude it explicitly or move the range"
            )));
        }
    }

    let mut configured_exclusions = Vec::with_capacity(raw.exclusions.len());
    let mut exclusions = BTreeSet::new();
    for (position, value) in raw.exclusions.iter().enumerate() {
        let ip = parse_ipv4(value)
            .map_err(|error| Error::config(format!("exclusions[{position}]: {error}")))?;
        if !cidr.contains(&ip) {
            return Err(Error::config(format!(
                "exclusions[{position}] {ip} is outside cidr {cidr}"
            )));
        }
        if ip == network || ip == broadcast {
            return Err(Error::config(format!(
                "exclusions[{position}] {ip} is the network or broadcast address of {cidr}"
            )));
        }
        if !exclusions.insert(ip) {
            return Err(Error::config(format!(
                "exclusions[{position}] {ip} is listed more than once"
            )));
        }
        configured_exclusions.push(ip);
    }
    // The server's own address is never allocatable.
    exclusions.insert(server_identifier);
    exclusions.insert(network);
    exclusions.insert(broadcast);

    let mut eligible = 0u64;
    let mut candidate = range_start;
    loop {
        if !exclusions.contains(&candidate) {
            eligible += 1;
        }
        if candidate == range_end {
            break;
        }
        candidate = Ipv4Addr::from(u32::from(candidate) + 1);
    }
    if eligible == 0 {
        return Err(Error::config(format!(
            "range {range_start}..={range_end} has no allocatable addresses after exclusions"
        )));
    }

    let routers = parse_ipv4_list(&raw.routers, "routers")?;
    for router in &routers {
        if !cidr.contains(router) {
            return Err(Error::config(format!(
                "router {router} is outside cidr {cidr}"
            )));
        }
    }
    let dns_servers = parse_ipv4_list(&raw.dns_servers, "dns_servers")?;
    if let Some(domain) = &raw.domain_name {
        validate_domain_name(domain)?;
    }

    if !(MIN_LEASE_SECONDS..=MAX_LEASE_SECONDS).contains(&raw.lease_seconds) {
        return Err(Error::config(format!(
            "lease_seconds must be in {MIN_LEASE_SECONDS}..={MAX_LEASE_SECONDS}, got {}",
            raw.lease_seconds
        )));
    }
    if raw.offer_hold_seconds == 0 || raw.offer_hold_seconds > raw.lease_seconds {
        return Err(Error::config(format!(
            "offer_hold_seconds must be in 1..=lease_seconds ({}), got {}",
            raw.lease_seconds, raw.offer_hold_seconds
        )));
    }
    if raw.decline_hold_seconds == 0 || raw.decline_hold_seconds > MAX_LEASE_SECONDS {
        return Err(Error::config(format!(
            "decline_hold_seconds must be in 1..={MAX_LEASE_SECONDS}, got {}",
            raw.decline_hold_seconds
        )));
    }

    let allocation_strategy = match raw.allocation_strategy.as_str() {
        "incremental" => AllocationStrategy::Incremental,
        "random" => AllocationStrategy::Random,
        other => {
            return Err(Error::config(format!(
                "allocation_strategy must be \"incremental\" or \"random\", got {other:?}"
            )))
        }
    };

    let interface = match raw.interface {
        Some(name) if name.trim().is_empty() => {
            return Err(Error::config("interface must not be empty"));
        }
        Some(name) => Some(name),
        None => None,
    };

    Ok(SubnetConfig {
        id: raw.id,
        interface,
        cidr,
        server_identifier,
        range_start,
        range_end,
        exclusions,
        configured_exclusions,
        routers,
        dns_servers,
        domain_name: raw.domain_name,
        lease_seconds: raw.lease_seconds,
        offer_hold_seconds: raw.offer_hold_seconds,
        decline_hold_seconds: raw.decline_hold_seconds,
        allocation_strategy,
    })
}

fn validate_subnet_id(id: &str) -> Result<()> {
    let valid = !id.is_empty()
        && id.len() <= 64
        && id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        })
        && id.as_bytes()[0].is_ascii_alphanumeric();
    if !valid {
        return Err(Error::config(format!(
            "subnet id {id:?} must be 1..=64 characters of [a-z0-9_-] and start alphanumeric"
        )));
    }
    Ok(())
}

fn validate_domain_name(domain: &str) -> Result<()> {
    if domain.is_empty() || domain.len() > 253 {
        return Err(Error::config(
            "domain_name must be 1..=253 characters".to_string(),
        ));
    }
    if domain.ends_with('.') {
        return Err(Error::config(
            "domain_name must not have a trailing dot".to_string(),
        ));
    }
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(Error::config(format!(
                "domain_name {domain:?} contains an empty or overlong label"
            )));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(Error::config(format!(
                "domain_name {domain:?} has a label that starts or ends with '-'"
            )));
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(Error::config(format!(
                "domain_name {domain:?} contains an invalid character"
            )));
        }
    }
    Ok(())
}

fn parse_cidr(value: &str) -> Result<Ipv4Net> {
    Ipv4Net::from_str(value.trim())
        .map_err(|error| Error::config(format!("invalid cidr {value:?}: {error}")))
}

fn parse_ipv4(value: &str) -> Result<Ipv4Addr> {
    Ipv4Addr::from_str(value.trim())
        .map_err(|error| Error::config(format!("invalid IPv4 address {value:?}: {error}")))
}

fn parse_ipv4_list(values: &[String], field: &str) -> Result<Vec<Ipv4Addr>> {
    values
        .iter()
        .enumerate()
        .map(|(position, value)| {
            parse_ipv4(value)
                .map_err(|error| Error::config(format!("{field}[{position}]: {error}")))
        })
        .collect()
}

fn cidrs_overlap(left: &Ipv4Net, right: &Ipv4Net) -> bool {
    left.contains(&right.network())
        || left.contains(&right.broadcast())
        || right.contains(&left.network())
        || right.contains(&left.broadcast())
}

// ---------------------------------------------------------------------------
// Raw serde models
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    schema_version: u32,
    storage: RawStorage,
    #[serde(default = "default_true")]
    authoritative: bool,
    subnets: Vec<RawSubnet>,
    #[serde(default)]
    relays: Vec<RawRelay>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStorage {
    path: String,
    file_size_mib: u64,
    max_memory_mib: u64,
    hash_bits: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSubnet {
    id: String,
    #[serde(default)]
    interface: Option<String>,
    cidr: String,
    server_identifier: String,
    range: RawRange,
    #[serde(default)]
    exclusions: Vec<String>,
    #[serde(default)]
    routers: Vec<String>,
    #[serde(default)]
    dns_servers: Vec<String>,
    #[serde(default)]
    domain_name: Option<String>,
    lease_seconds: u32,
    offer_hold_seconds: u32,
    decline_hold_seconds: u32,
    allocation_strategy: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRange {
    start: String,
    end: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRelay {
    giaddr: String,
    subnet_id: String,
}

fn default_true() -> bool {
    true
}

/// Parse the checked-in example configuration. Used by tests and docs.
pub fn example_config() -> &'static str {
    include_str!("../config/dhxpro.example.yaml")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_yaml() -> String {
        example_config().to_string()
    }

    fn mutate(yaml: &str, from: &str, to: &str) -> String {
        yaml.replacen(from, to, 1)
    }

    #[test]
    fn example_config_is_valid() {
        let config = Config::parse_str(&valid_yaml()).expect("example config must validate");
        assert_eq!(config.schema_version, 1);
        assert_eq!(config.subnets.len(), 2);
        assert_eq!(config.relays.len(), 1);
        let lan = config.subnet("lan").unwrap();
        assert_eq!(lan.interface.as_deref(), Some("eth0"));
        assert_eq!(lan.range_start, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(lan.range_end, Ipv4Addr::new(192, 168, 1, 200));
        assert!(lan.is_excluded(Ipv4Addr::new(192, 168, 1, 150)));
        assert!(lan.is_excluded(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!lan.is_dynamic_candidate(Ipv4Addr::new(192, 168, 1, 150)));
        assert!(lan.is_dynamic_candidate(Ipv4Addr::new(192, 168, 1, 101)));
        assert_eq!(lan.t1(), 1800);
        assert_eq!(lan.t2(), 3150);
        let guest = config.subnet("guest").unwrap();
        assert!(guest.interface.is_none());
        assert_eq!(
            config.relay_subnet(Ipv4Addr::new(10, 20, 0, 1)).unwrap().id,
            "guest"
        );
        assert!(config.relay_subnet(Ipv4Addr::new(10, 20, 0, 200)).is_none());
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let yaml = mutate(
            &valid_yaml(),
            "authoritative: true",
            "authoritative: true\ntypo_field: 1",
        );
        let error = Config::parse_str(&yaml).unwrap_err().to_string();
        assert!(error.contains("unknown field"), "{error}");
    }

    #[test]
    fn duplicate_subnet_ids_are_rejected() {
        let yaml = mutate(&valid_yaml(), "id: guest", "id: lan");
        let error = Config::parse_str(&yaml).unwrap_err().to_string();
        assert!(error.contains("duplicate subnet id"), "{error}");
    }

    #[test]
    fn duplicate_server_identifiers_are_rejected() {
        let yaml = mutate(
            &valid_yaml(),
            "server_identifier: 10.20.0.1",
            "server_identifier: 192.168.1.1",
        );
        let error = Config::parse_str(&yaml).unwrap_err().to_string();
        assert!(error.contains("server_identifier"), "{error}");
    }

    #[test]
    fn overlapping_cidrs_are_rejected() {
        let yaml = mutate(&valid_yaml(), "cidr: 10.20.0.0/24", "cidr: 192.168.1.0/25");
        let yaml = mutate(
            &yaml,
            "server_identifier: 10.20.0.1",
            "server_identifier: 192.168.1.2",
        );
        let yaml = mutate(&yaml, "start: 10.20.0.50", "start: 192.168.1.50");
        let yaml = mutate(&yaml, "end: 10.20.0.150", "end: 192.168.1.60");
        let yaml = mutate(&yaml, "- 10.20.0.1", "- 192.168.1.2");
        let yaml = &yaml[..yaml.find("relays:").unwrap()];
        let error = Config::parse_str(yaml).unwrap_err().to_string();
        assert!(error.contains("overlaps"), "{error}");
    }

    #[test]
    fn range_must_be_ordered_and_inside_cidr() {
        let yaml = mutate(
            &valid_yaml(),
            "start: 192.168.1.100",
            "start: 192.168.2.100",
        );
        let yaml = mutate(&yaml, "end: 192.168.1.200", "end: 192.168.2.200");
        let error = Config::parse_str(&yaml).unwrap_err().to_string();
        assert!(error.contains("outside cidr"), "{error}");

        let yaml = mutate(
            &valid_yaml(),
            "start: 192.168.1.100",
            "start: 192.168.1.201",
        );
        let error = Config::parse_str(&yaml).unwrap_err().to_string();
        assert!(error.contains("greater than range.end"), "{error}");
    }

    #[test]
    fn network_and_broadcast_cannot_be_in_range() {
        let yaml = mutate(&valid_yaml(), "start: 192.168.1.100", "start: 192.168.1.0");
        let error = Config::parse_str(&yaml).unwrap_err().to_string();
        assert!(error.contains("network or broadcast"), "{error}");
    }

    #[test]
    fn server_identifier_inside_range_must_be_excluded() {
        let yaml = mutate(&valid_yaml(), "start: 192.168.1.100", "start: 192.168.1.1");
        let yaml = mutate(&yaml, "end: 192.168.1.200", "end: 192.168.1.50");
        let error = Config::parse_str(&yaml).unwrap_err().to_string();
        assert!(error.contains("inside the dynamic range"), "{error}");
    }

    #[test]
    fn unknown_strategy_is_rejected() {
        let yaml = mutate(
            &valid_yaml(),
            "allocation_strategy: incremental",
            "allocation_strategy: sequential",
        );
        let error = Config::parse_str(&yaml).unwrap_err().to_string();
        assert!(error.contains("allocation_strategy"), "{error}");
    }

    #[test]
    fn exclusion_outside_cidr_is_rejected() {
        let yaml = mutate(&valid_yaml(), "- 192.168.1.150", "- 192.168.2.150");
        let error = Config::parse_str(&yaml).unwrap_err().to_string();
        assert!(error.contains("outside cidr"), "{error}");
    }

    #[test]
    fn relay_gateway_inside_the_dynamic_range_is_excluded() {
        let yaml = mutate(
            &mutate(
                &valid_yaml(),
                "server_identifier: 10.20.0.1",
                "server_identifier: 10.20.0.254",
            ),
            "start: 10.20.0.50",
            "start: 10.20.0.1",
        );
        let config = Config::parse_str(&yaml).unwrap();
        let guest = config.subnet("guest").unwrap();
        let gateway = Ipv4Addr::new(10, 20, 0, 1);
        assert_eq!(guest.range_start, gateway);
        assert!(!guest.is_dynamic_candidate(gateway));
        assert!(!guest.is_valid_reservation_ip(gateway));
        assert!(guest.is_dynamic_candidate(Ipv4Addr::new(10, 20, 0, 2)));
    }

    #[test]
    fn relay_mapping_must_match_relay_only_subnet() {
        let yaml = mutate(&valid_yaml(), "subnet_id: guest", "subnet_id: lan");
        let error = Config::parse_str(&yaml).unwrap_err().to_string();
        assert!(error.contains("directly connected"), "{error}");

        let yaml = mutate(&valid_yaml(), "subnet_id: guest", "subnet_id: nope");
        let error = Config::parse_str(&yaml).unwrap_err().to_string();
        assert!(error.contains("unknown subnet"), "{error}");

        let yaml = mutate(&valid_yaml(), "giaddr: 10.20.0.1", "giaddr: 10.20.0.255");
        let error = Config::parse_str(&yaml).unwrap_err().to_string();
        assert!(error.contains("not a usable host"), "{error}");
    }

    #[test]
    fn relay_only_subnet_needs_a_mapping() {
        let yaml = valid_yaml();
        let index = yaml.find("relays:").unwrap();
        let yaml = &yaml[..index];
        let error = Config::parse_str(yaml).unwrap_err().to_string();
        assert!(error.contains("no relay mapping"), "{error}");
    }

    #[test]
    fn invalid_timings_are_rejected() {
        let yaml = mutate(&valid_yaml(), "lease_seconds: 3600", "lease_seconds: 10");
        let error = Config::parse_str(&yaml).unwrap_err().to_string();
        assert!(error.contains("lease_seconds"), "{error}");

        let yaml = mutate(
            &valid_yaml(),
            "offer_hold_seconds: 60",
            "offer_hold_seconds: 999999",
        );
        let error = Config::parse_str(&yaml).unwrap_err().to_string();
        assert!(error.contains("offer_hold_seconds"), "{error}");

        let yaml = mutate(
            &valid_yaml(),
            "decline_hold_seconds: 3600",
            "decline_hold_seconds: 0",
        );
        let error = Config::parse_str(&yaml).unwrap_err().to_string();
        assert!(error.contains("decline_hold_seconds"), "{error}");
    }

    #[test]
    fn invalid_subnet_ids_are_rejected() {
        for id in ["", "Lan", "lan:1", "-lan", "lan/subnet"] {
            let yaml = mutate(&valid_yaml(), "id: lan", &format!("id: {id:?}"));
            let error = Config::parse_str(&yaml).unwrap_err().to_string();
            assert!(error.contains("subnet id"), "id {id:?}: {error}");
        }
    }

    #[test]
    fn host_bits_in_cidr_are_rejected() {
        let yaml = mutate(
            &valid_yaml(),
            "cidr: 192.168.1.0/24",
            "cidr: 192.168.1.5/24",
        );
        let error = Config::parse_str(&yaml).unwrap_err().to_string();
        assert!(error.contains("host bits"), "{error}");
    }

    #[test]
    fn too_small_cidr_is_rejected() {
        let yaml = mutate(
            &valid_yaml(),
            "cidr: 192.168.1.0/24",
            "cidr: 192.168.1.0/31",
        );
        let error = Config::parse_str(&yaml).unwrap_err().to_string();
        assert!(error.contains("too small"), "{error}");
    }

    #[test]
    fn invalid_domain_name_is_rejected() {
        let yaml = mutate(
            &valid_yaml(),
            "domain_name: lan.example",
            "domain_name: -bad..name",
        );
        let error = Config::parse_str(&yaml).unwrap_err().to_string();
        assert!(error.contains("domain_name"), "{error}");
    }

    #[test]
    fn missing_required_field_is_reported() {
        let yaml = mutate(&valid_yaml(), "    server_identifier: 192.168.1.1\n", "");
        let error = Config::parse_str(&yaml).unwrap_err().to_string();
        assert!(error.contains("server_identifier"), "{error}");
    }

    #[test]
    fn full_range_exhaustion_by_exclusions_is_rejected() {
        let yaml = mutate(
            &valid_yaml(),
            "start: 192.168.1.100\n      end: 192.168.1.200",
            "start: 192.168.1.100\n      end: 192.168.1.100",
        );
        let yaml = mutate(&yaml, "- 192.168.1.150", "- 192.168.1.100");
        let error = Config::parse_str(&yaml).unwrap_err().to_string();
        assert!(error.contains("no allocatable addresses"), "{error}");
    }

    #[test]
    fn cursor_wraps_within_range() {
        let config = Config::parse_str(&valid_yaml()).unwrap();
        let lan = config.subnet("lan").unwrap();
        assert_eq!(
            lan.next_cursor(Ipv4Addr::new(192, 168, 1, 100)),
            Ipv4Addr::new(192, 168, 1, 101)
        );
        assert_eq!(
            lan.next_cursor(Ipv4Addr::new(192, 168, 1, 200)),
            Ipv4Addr::new(192, 168, 1, 100)
        );
    }

    #[test]
    fn storage_sizes_are_computed_safely() {
        let config = Config::parse_str(&valid_yaml()).unwrap();
        assert_eq!(config.storage.file_size_bytes(), 64 * 1024 * 1024);
        assert_eq!(config.storage.max_memory_bytes(), 64 * 1024 * 1024);
    }

    #[test]
    fn summary_mentions_everything_important() {
        let config = Config::parse_str(&valid_yaml()).unwrap();
        let summary = config.summary();
        assert!(summary.contains("2 subnet(s)"), "{summary}");
        assert!(summary.contains("1 relay mapping"), "{summary}");
        assert!(summary.contains("state.feox"), "{summary}");
    }
}
