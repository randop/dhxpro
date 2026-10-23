//! DHCPv4 server state machine.
//!
//! The server is transport agnostic: [`DhcpServer::handle_datagram`] consumes
//! bytes plus receive metadata and returns outbound datagrams. The io_uring
//! layer in [`crate::net`] is responsible for delivering and transmitting
//! them. This separation keeps the protocol testable without privileges.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::net::{Ipv4Addr, SocketAddrV4};

use crate::dhcp::MessageType;
use rand::rngs::SmallRng;
use rand::SeedableRng;

use crate::alloc;
use crate::config::{Config, SubnetConfig};
use crate::dhcp::{self, ParsedRequest};
use crate::error::{Error, Result};
use crate::model::LeaseEntry;
use crate::storage::{Clock, StateCoordinator, StoreHealth, StoreOptions};

pub const DHCP_SERVER_PORT: u16 = 67;
pub const DHCP_CLIENT_PORT: u16 = 68;

/// Metadata captured by the receive path for one datagram.
#[derive(Debug, Clone)]
pub struct Ingress {
    /// Interface index from `IP_PKTINFO`.
    pub ifindex: u32,
    /// Interface name resolved from the index.
    pub interface: String,
    /// Packet destination address (`ipi_addr`).
    pub destination: Ipv4Addr,
    /// Local address selected by the kernel (`ipi_spec_dst`).
    pub local_address: Ipv4Addr,
    pub source: SocketAddrV4,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outbound {
    /// Send directly on a configured interface with a fixed source address.
    Direct {
        destination: Ipv4Addr,
        ifindex: u32,
        source: Ipv4Addr,
        payload: Vec<u8>,
    },
    /// Send back to the relay agent (`giaddr:67`); the kernel selects the
    /// outgoing interface and source address.
    Relay {
        destination: Ipv4Addr,
        payload: Vec<u8>,
    },
}

impl Outbound {
    pub fn payload(&self) -> &[u8] {
        match self {
            Outbound::Direct { payload, .. } | Outbound::Relay { payload, .. } => payload,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestForm {
    Selecting,
    InitReboot,
    Renewing,
    Invalid,
}

pub struct DhcpServer {
    config: Config,
    coordinator: StateCoordinator,
    clock: Clock,
    rng: SmallRng,
    next_expiry_scan: u64,
    next_recovery_attempt: u64,
}

impl DhcpServer {
    /// Open persistent state and prepare the allocator cursors. This is the
    /// startup path used by `serve`; pending journal intents are replayed
    /// before this returns.
    pub fn new(config: Config, store: StoreOptions) -> Result<Self> {
        let coordinator = StateCoordinator::open(&store)?;
        let clock = Clock::system()?;
        Self::build(config, coordinator, clock)
    }

    /// Constructor used by tests and by callers that already opened storage
    /// (for example the preflight path).
    pub fn with_store(config: Config, coordinator: StateCoordinator, clock: Clock) -> Result<Self> {
        Self::build(config, coordinator, clock)
    }

    fn build(config: Config, mut coordinator: StateCoordinator, clock: Clock) -> Result<Self> {
        let mut clock = clock;
        let now = clock.now();

        // Corrupt or inconsistent ownership state is a startup failure, not a
        // warning: serving from it could duplicate assignments or bypass a
        // quarantine. Check before initializing or resetting subnet cursors.
        let problems = coordinator.integrity_report(&config, now)?;
        if !problems.is_empty() {
            for problem in problems.iter().take(10) {
                eprintln!("dhxpro: storage consistency problem: {problem}");
            }
            return Err(Error::State(format!(
                "storage integrity check found {} problem(s); refusing to serve (run \
                 `dhxpro preflight` for the full report)",
                problems.len()
            )));
        }
        coordinator.prepare_subnets(&config, now)?;

        Ok(Self {
            config,
            coordinator,
            clock,
            rng: SmallRng::from_os_rng(),
            next_expiry_scan: now,
            next_recovery_attempt: now,
        })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn health(&self) -> &StoreHealth {
        self.coordinator.health()
    }

    pub fn coordinator(&self) -> &StateCoordinator {
        &self.coordinator
    }

    /// Periodic work driven by the io_uring timer: expire stale bindings and
    /// retry storage recovery after transient failures.
    pub fn tick(&mut self) -> Result<()> {
        let now = self.clock.now();
        if !self.coordinator.is_healthy() {
            if now >= self.next_recovery_attempt {
                self.next_recovery_attempt = now.saturating_add(5);
                if let Err(error) = self.coordinator.recover_health() {
                    eprintln!("dhxpro: storage still unhealthy: {error}");
                }
            }
            return Ok(());
        }

        if now >= self.next_expiry_scan {
            self.next_expiry_scan = now.saturating_add(10);
            match alloc::expire_state(&mut self.coordinator, now, 256) {
                Ok(cleaned) if cleaned > 0 => {
                    eprintln!("dhxpro: expired {cleaned} stale offer/lease/decline entr(ies)");
                }
                Ok(_) => {}
                Err(error) => {
                    eprintln!("dhxpro: failed to expire stale state: {error}");
                }
            }
        }
        Ok(())
    }

    /// Handle one received DHCP datagram. Returns zero or more replies.
    pub fn handle_datagram(&mut self, data: &[u8], ingress: &Ingress) -> Vec<Outbound> {
        let request = match dhcp::parse_request(data) {
            Ok(request) => request,
            Err(error) => {
                eprintln!(
                    "dhxpro: dropping malformed packet from {} on {}: {error}",
                    ingress.source, ingress.interface
                );
                return Vec::new();
            }
        };

        let Some(subnet) = self.select_subnet(&request, ingress).cloned() else {
            return Vec::new();
        };

        if !self.coordinator.is_healthy() {
            eprintln!(
                "dhxpro: storage is unhealthy; dropping {} from {}",
                dhcp::message_type_name(request.message_type),
                request.mac
            );
            return Vec::new();
        }

        match request.message_type {
            MessageType::Discover => self.handle_discover(&request, &subnet, ingress),
            MessageType::Request => self.handle_request(&request, &subnet, ingress),
            MessageType::Decline => self.handle_decline(&request, &subnet),
            MessageType::Release => self.handle_release(&request, &subnet),
            MessageType::Inform => self.handle_inform(&request, &subnet, ingress),
            other => {
                eprintln!(
                    "dhxpro: ignoring unsupported message type {} from {}",
                    dhcp::message_type_name(other),
                    request.mac
                );
                Vec::new()
            }
        }
    }

    fn select_subnet<'a>(
        &'a self,
        request: &ParsedRequest,
        ingress: &'a Ingress,
    ) -> Option<&'a SubnetConfig> {
        // Relay scopes are selected exclusively by the configured giaddr
        // mapping. The relay may arrive on a router-facing interface that has
        // no direct DHCP subnet of its own, so the direct-interface allowlist
        // applies only to non-relayed traffic.
        if request.is_relayed() {
            return match self.config.relay_subnet(request.giaddr) {
                Some(subnet) => Some(subnet),
                None => {
                    eprintln!(
                        "dhxpro: no configured subnet for relay giaddr {} (from {})",
                        request.giaddr, ingress.source
                    );
                    None
                }
            };
        }

        if !self
            .config
            .configured_interfaces()
            .contains(ingress.interface.as_str())
        {
            eprintln!(
                "dhxpro: ignoring packet on unconfigured interface {:?}",
                ingress.interface
            );
            return None;
        }

        let candidates: Vec<&SubnetConfig> = self
            .config
            .subnets_on_interface(&ingress.interface)
            .collect();
        match candidates.len() {
            0 => {
                eprintln!(
                    "dhxpro: interface {:?} has no configured direct subnet",
                    ingress.interface
                );
                None
            }
            1 => Some(candidates[0]),
            _ => {
                // Multiple addressed subnets on one interface: the local
                // destination address disambiguates. A broadcast that cannot
                // be resolved is rejected rather than guessed.
                let by_local: Vec<&SubnetConfig> = candidates
                    .iter()
                    .copied()
                    .filter(|subnet| subnet.server_identifier == ingress.local_address)
                    .collect();
                if by_local.len() == 1 {
                    return Some(by_local[0]);
                }
                let by_destination: Vec<&SubnetConfig> = candidates
                    .iter()
                    .copied()
                    .filter(|subnet| subnet.contains(ingress.destination))
                    .collect();
                if by_destination.len() == 1 {
                    return Some(by_destination[0]);
                }
                eprintln!(
                    "dhxpro: ambiguous subnet selection on interface {:?} \
                     (destination {}, local {}); dropping packet",
                    ingress.interface, ingress.destination, ingress.local_address
                );
                None
            }
        }
    }

    fn handle_discover(
        &mut self,
        request: &ParsedRequest,
        subnet: &SubnetConfig,
        ingress: &Ingress,
    ) -> Vec<Outbound> {
        let now = self.clock.now();
        let result = alloc::offer_address(
            &mut self.coordinator,
            subnet,
            request.mac,
            request.client_id.as_deref(),
            request.hostname.as_deref(),
            now,
            &mut self.rng,
        );

        match result {
            Ok(Some(offer)) => {
                eprintln!(
                    "dhxpro: DISCOVER {} subnet {:?} -> OFFER {}{}",
                    request.mac,
                    subnet.id,
                    offer.entry.ip,
                    if offer.reserved { " (reserved)" } else { "" }
                );
                match dhcp::build_offer(request, subnet, offer.entry.ip) {
                    Ok(payload) => vec![self.outbound(request, subnet, ingress, payload)],
                    Err(error) => {
                        eprintln!("dhxpro: failed to build OFFER: {error}");
                        Vec::new()
                    }
                }
            }
            Ok(None) => {
                eprintln!(
                    "dhxpro: subnet {:?} exhausted; no OFFER for {}",
                    subnet.id, request.mac
                );
                Vec::new()
            }
            Err(error) => {
                eprintln!(
                    "dhxpro: refusing OFFER in subnet {:?} for {}: {error}",
                    subnet.id, request.mac
                );
                Vec::new()
            }
        }
    }

    fn handle_request(
        &mut self,
        request: &ParsedRequest,
        subnet: &SubnetConfig,
        ingress: &Ingress,
    ) -> Vec<Outbound> {
        let form = classify(request);
        let now = self.clock.now();

        if form == RequestForm::Invalid {
            eprintln!(
                "dhxpro: ignoring malformed REQUEST from {} (no server id, ciaddr or requested ip)",
                request.mac
            );
            return Vec::new();
        }

        if form == RequestForm::Selecting {
            if let Some(server_id) = request.server_identifier {
                if server_id != subnet.server_identifier {
                    // The client selected a different server. Silence is
                    // required; sending a NAK would disrupt the other server.
                    return Vec::new();
                }
            }
        }

        match self.client_identity_conflict(request, subnet) {
            Ok(true) => {
                eprintln!(
                    "dhxpro: {} from {} presents a client identifier that does not match \
                     the durable binding",
                    dhcp::message_type_name(request.message_type),
                    request.mac
                );
                return match form {
                    RequestForm::Selecting | RequestForm::InitReboot => {
                        self.nak(request, subnet, ingress, "client identifier mismatch")
                    }
                    _ => Vec::new(),
                };
            }
            Ok(false) => {}
            Err(error) => {
                eprintln!("dhxpro: failed to validate client identity: {error}");
                return Vec::new();
            }
        }

        let requested = match form {
            RequestForm::Selecting => match request.requested_ip {
                Some(ip) => ip,
                None => {
                    eprintln!(
                        "dhxpro: selecting REQUEST from {} has no requested address",
                        request.mac
                    );
                    return Vec::new();
                }
            },
            RequestForm::InitReboot => match request.requested_ip {
                Some(ip) => ip,
                None => return Vec::new(),
            },
            RequestForm::Renewing => request.ciaddr,
            RequestForm::Invalid => return Vec::new(),
        };

        if !subnet.contains(requested) {
            return match form {
                RequestForm::Renewing => {
                    eprintln!(
                        "dhxpro: renewal from {} for {} is outside subnet {:?}",
                        request.mac, requested, subnet.id
                    );
                    Vec::new()
                }
                _ => self.nak(
                    request,
                    subnet,
                    ingress,
                    "requested address is outside this subnet",
                ),
            };
        }

        let commit = self.activate_binding(request, subnet, requested, now);
        let entry = match commit {
            Ok(entry) => entry,
            Err(error) => {
                if error.is_storage_failure() {
                    eprintln!(
                        "dhxpro: storage failure while activating {} for {}: {error}",
                        requested, request.mac
                    );
                    return Vec::new();
                }
                if matches!(error, Error::LeaseInvalid(_)) {
                    return match form {
                        // Never NAK a renewal based on missing state; the
                        // client may be rebinding after a server-side loss.
                        RequestForm::Renewing => {
                            eprintln!(
                                "dhxpro: ignoring renewal from {} for {}: {error}",
                                request.mac, requested
                            );
                            Vec::new()
                        }
                        _ if self.config.authoritative => {
                            eprintln!("dhxpro: NAK {} for {}: {error}", requested, request.mac);
                            self.nak(request, subnet, ingress, &error.to_string())
                        }
                        _ => Vec::new(),
                    };
                }
                eprintln!(
                    "dhxpro: refusing to ACK {} for {}: {error}",
                    requested, request.mac
                );
                return Vec::new();
            }
        };

        // The lease and IP-owner state have been durably flushed by the
        // coordinator at this point; only now may the ACK be built.
        match dhcp::build_ack(request, subnet, entry.ip, true) {
            Ok(payload) => {
                eprintln!(
                    "dhxpro: {} {} subnet {:?} -> ACK {}",
                    dhcp::message_type_name(request.message_type),
                    request.mac,
                    subnet.id,
                    entry.ip
                );
                vec![self.outbound(request, subnet, ingress, payload)]
            }
            Err(error) => {
                eprintln!("dhxpro: failed to build ACK: {error}");
                Vec::new()
            }
        }
    }

    fn activate_binding(
        &mut self,
        request: &ParsedRequest,
        subnet: &SubnetConfig,
        ip: Ipv4Addr,
        now: u64,
    ) -> Result<LeaseEntry> {
        let committed = alloc::commit_lease(
            &mut self.coordinator,
            subnet,
            request.mac,
            ip,
            request.client_id.as_deref(),
            request.hostname.as_deref(),
            now,
        );
        match committed {
            Ok(entry) => Ok(entry),
            Err(Error::LeaseInvalid(first)) => {
                match alloc::activate_reservation(
                    &mut self.coordinator,
                    subnet,
                    request.mac,
                    ip,
                    request.client_id.as_deref(),
                    request.hostname.as_deref(),
                    now,
                ) {
                    Ok(entry) => Ok(entry),
                    Err(Error::LeaseInvalid(_)) => Err(Error::LeaseInvalid(first)),
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error),
        }
    }

    fn client_identity_conflict(
        &self,
        request: &ParsedRequest,
        subnet: &SubnetConfig,
    ) -> Result<bool> {
        let Some(present) = request.client_id.as_deref() else {
            return Ok(false);
        };
        if let Some(record) = self.coordinator.lease(request.mac)? {
            if let Some(entry) = record.entries_by_subnet.get(&subnet.id) {
                if let Some(stored) = entry.client_id.as_deref() {
                    if stored != present {
                        return Ok(true);
                    }
                }
            }
        }
        if let Some(record) = self.coordinator.reservation(request.mac)? {
            if let Some(entry) = record.entries_by_subnet.get(&subnet.id) {
                if let Some(stored) = entry.client_id.as_deref() {
                    if stored != present {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }

    fn handle_decline(&mut self, request: &ParsedRequest, subnet: &SubnetConfig) -> Vec<Outbound> {
        if let Some(server_id) = request.server_identifier {
            if server_id != subnet.server_identifier {
                return Vec::new();
            }
        }
        let Some(ip) = request.requested_ip else {
            eprintln!(
                "dhxpro: DECLINE from {} has no requested address",
                request.mac
            );
            return Vec::new();
        };
        let now = self.clock.now();
        match alloc::decline_lease(&mut self.coordinator, subnet, request.mac, ip, now) {
            Ok(true) => {
                eprintln!(
                    "dhxpro: DECLINE {} subnet {:?} quarantined {} for {}s",
                    request.mac, subnet.id, ip, subnet.decline_hold_seconds
                );
            }
            Ok(false) => {
                eprintln!(
                    "dhxpro: ignoring DECLINE from {} for {}; no matching binding",
                    request.mac, ip
                );
            }
            Err(error) => {
                eprintln!("dhxpro: failed to record DECLINE for {ip}: {error}");
            }
        }
        Vec::new()
    }

    fn handle_release(&mut self, request: &ParsedRequest, subnet: &SubnetConfig) -> Vec<Outbound> {
        if request.ciaddr.is_unspecified() {
            return Vec::new();
        }
        if let Some(server_id) = request.server_identifier {
            if server_id != subnet.server_identifier {
                return Vec::new();
            }
        }
        let now = self.clock.now();
        match alloc::release_lease(
            &mut self.coordinator,
            subnet,
            request.mac,
            request.ciaddr,
            now,
        ) {
            Ok(true) => {
                eprintln!(
                    "dhxpro: RELEASE {} subnet {:?} released {}",
                    request.mac, subnet.id, request.ciaddr
                );
            }
            Ok(false) => {
                eprintln!(
                    "dhxpro: ignoring RELEASE from {} for {}; no matching binding",
                    request.mac, request.ciaddr
                );
            }
            Err(error) => {
                eprintln!(
                    "dhxpro: failed to record RELEASE for {}: {error}",
                    request.ciaddr
                );
            }
        }
        Vec::new()
    }

    fn handle_inform(
        &mut self,
        request: &ParsedRequest,
        subnet: &SubnetConfig,
        ingress: &Ingress,
    ) -> Vec<Outbound> {
        if request.ciaddr.is_unspecified() {
            eprintln!(
                "dhxpro: ignoring INFORM from {} without ciaddr",
                request.mac
            );
            return Vec::new();
        }
        if !subnet.contains(request.ciaddr) {
            eprintln!(
                "dhxpro: INFORM from {} claims {} outside subnet {:?}",
                request.mac, request.ciaddr, subnet.id
            );
            return Vec::new();
        }
        match dhcp::build_ack(request, subnet, Ipv4Addr::UNSPECIFIED, false) {
            Ok(payload) => vec![self.outbound(request, subnet, ingress, payload)],
            Err(error) => {
                eprintln!("dhxpro: failed to build INFORM ACK: {error}");
                Vec::new()
            }
        }
    }

    fn nak(
        &self,
        request: &ParsedRequest,
        subnet: &SubnetConfig,
        ingress: &Ingress,
        reason: &str,
    ) -> Vec<Outbound> {
        if !self.config.authoritative {
            return Vec::new();
        }
        match dhcp::build_nak(request, subnet, reason) {
            Ok(payload) => vec![self.outbound(request, subnet, ingress, payload)],
            Err(error) => {
                eprintln!("dhxpro: failed to build NAK: {error}");
                Vec::new()
            }
        }
    }

    fn outbound(
        &self,
        request: &ParsedRequest,
        subnet: &SubnetConfig,
        ingress: &Ingress,
        payload: Vec<u8>,
    ) -> Outbound {
        if request.is_relayed() {
            return Outbound::Relay {
                destination: request.giaddr,
                payload,
            };
        }

        let destination = if !request.ciaddr.is_unspecified() {
            request.ciaddr
        } else {
            Ipv4Addr::BROADCAST
        };

        Outbound::Direct {
            destination,
            ifindex: ingress.ifindex,
            source: subnet.server_identifier,
            payload,
        }
    }
}

fn classify(request: &ParsedRequest) -> RequestForm {
    if request.server_identifier.is_some() {
        RequestForm::Selecting
    } else if !request.ciaddr.is_unspecified() {
        RequestForm::Renewing
    } else if request.requested_ip.is_some() {
        RequestForm::InitReboot
    } else {
        RequestForm::Invalid
    }
}

/// Deterministic seeding helper for environments where `OsRng` is not
/// available. `SmallRng::from_os_rng` is used in production; this exists so
/// the server can be constructed in constrained tests if needed.
#[allow(dead_code)]
fn fallback_seed() -> u64 {
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u32(std::process::id());
    hasher.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos() as u64)
            .unwrap_or(0),
    );
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::dhcp::test_support::*;
    use crate::dhcp::{DhcpOption, Message, OptionCode};
    use crate::keys;
    use crate::mac::MacAddr;
    use crate::model::{encode_record, IpOwner, OwnerRole, ReservationEntry};
    use crate::storage::Fault;

    fn test_config() -> Config {
        Config::parse_str(crate::config::example_config()).unwrap()
    }

    fn server_with_config(config: Config) -> DhcpServer {
        let mut coordinator = StateCoordinator::open_memory().unwrap();
        coordinator.prepare_subnets(&config, 1000).unwrap();
        DhcpServer::with_store(config, coordinator, Clock::manual(1000)).unwrap()
    }

    fn test_server() -> DhcpServer {
        server_with_config(test_config())
    }

    fn ingress() -> Ingress {
        Ingress {
            ifindex: 2,
            interface: "eth0".to_string(),
            destination: Ipv4Addr::BROADCAST,
            local_address: Ipv4Addr::new(192, 168, 1, 1),
            source: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 68),
        }
    }

    fn reply(outbound: &Outbound) -> Message {
        Message::decode(outbound.payload()).unwrap()
    }

    fn option_ip(message: &Message, code: OptionCode) -> Ipv4Addr {
        match message.opts().get(code) {
            Some(DhcpOption::ServerIdentifier(ip))
            | Some(DhcpOption::RequestedIpAddress(ip))
            | Some(DhcpOption::SubnetMask(ip))
            | Some(DhcpOption::BroadcastAddr(ip)) => *ip,
            other => panic!("unexpected option {code:?}: {other:?}"),
        }
    }

    #[test]
    fn discover_produces_a_valid_offer() {
        let mut server = test_server();
        let replies = server.handle_datagram(&discover(), &ingress());
        assert_eq!(replies.len(), 1);
        let outbound = &replies[0];
        match outbound {
            Outbound::Direct {
                destination,
                source,
                ifindex,
                ..
            } => {
                assert_eq!(*destination, Ipv4Addr::BROADCAST);
                assert_eq!(*source, Ipv4Addr::new(192, 168, 1, 1));
                assert_eq!(*ifindex, 2);
            }
            other => panic!("expected direct reply, got {other:?}"),
        }
        let message = reply(outbound);
        assert_eq!(
            message.opts().get(OptionCode::MessageType),
            Some(&DhcpOption::MessageType(MessageType::Offer))
        );
        let offered = message.yiaddr();
        assert!(test_config()
            .subnet("lan")
            .unwrap()
            .is_dynamic_candidate(offered));
        assert_eq!(
            option_ip(&message, OptionCode::ServerIdentifier),
            Ipv4Addr::new(192, 168, 1, 1)
        );

        let lease = server
            .coordinator
            .lease(MacAddr::parse("aabbccddeeff").unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(lease.entries_by_subnet["lan"].ip, offered);
        assert_eq!(
            lease.entries_by_subnet["lan"].state,
            crate::model::LeaseState::Offered
        );
    }

    #[test]
    fn offer_and_ack_broadcast_without_ciaddr_or_broadcast_flag() {
        let mut server = test_server();
        let mut discover = discover();
        discover[10..12].fill(0); // Clear the flags in the wire packet.
        let replies = server.handle_datagram(&discover, &ingress());
        assert_eq!(replies.len(), 1);
        assert!(matches!(
            replies[0],
            Outbound::Direct {
                destination: Ipv4Addr::BROADCAST,
                ..
            }
        ));
        let offered = reply(&replies[0]).yiaddr();
        let request = selecting_request(offered, Ipv4Addr::new(192, 168, 1, 1), CLIENT_MAC);
        let replies = server.handle_datagram(&request, &ingress());
        assert_eq!(replies.len(), 1);
        assert!(matches!(
            replies[0],
            Outbound::Direct {
                destination: Ipv4Addr::BROADCAST,
                ..
            }
        ));
        assert_eq!(reply(&replies[0]).yiaddr(), offered);
    }

    #[test]
    fn selecting_request_acknowledges_the_offered_address() {
        let mut server = test_server();
        let replies = server.handle_datagram(&discover(), &ingress());
        let offered = reply(&replies[0]).yiaddr();
        let request = selecting_request(offered, Ipv4Addr::new(192, 168, 1, 1), CLIENT_MAC);
        let replies = server.handle_datagram(&request, &ingress());
        assert_eq!(replies.len(), 1);
        let message = reply(&replies[0]);
        assert_eq!(
            message.opts().get(OptionCode::MessageType),
            Some(&DhcpOption::MessageType(MessageType::Ack))
        );
        assert_eq!(message.yiaddr(), offered);

        let lease = server
            .coordinator
            .lease(MacAddr::parse("aabbccddeeff").unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(
            lease.entries_by_subnet["lan"].state,
            crate::model::LeaseState::Active
        );
        assert_eq!(
            server.coordinator.owner(offered).unwrap().unwrap().role,
            OwnerRole::Lease
        );
    }

    #[test]
    fn selecting_another_server_is_silently_ignored() {
        let mut server = test_server();
        let request = selecting_request(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 254),
            CLIENT_MAC,
        );
        assert!(server.handle_datagram(&request, &ingress()).is_empty());
        assert!(server
            .coordinator
            .lease(MacAddr::parse("aabbccddeeff").unwrap())
            .unwrap()
            .is_none());
    }

    #[test]
    fn init_reboot_for_the_offered_address_is_acked() {
        let mut server = test_server();
        let replies = server.handle_datagram(&discover(), &ingress());
        let offered = reply(&replies[0]).yiaddr();
        let request = init_reboot_request(offered, CLIENT_MAC);
        let replies = server.handle_datagram(&request, &ingress());
        assert_eq!(replies.len(), 1);
        assert_eq!(
            reply(&replies[0]).opts().get(OptionCode::MessageType),
            Some(&DhcpOption::MessageType(MessageType::Ack))
        );
    }

    #[test]
    fn init_reboot_for_an_unknown_address_is_naked() {
        let mut server = test_server();
        let request = init_reboot_request(Ipv4Addr::new(192, 168, 1, 42), CLIENT_MAC);
        let replies = server.handle_datagram(&request, &ingress());
        assert_eq!(replies.len(), 1);
        match &replies[0] {
            Outbound::Direct { destination, .. } => {
                assert_eq!(*destination, Ipv4Addr::BROADCAST)
            }
            other => panic!("expected broadcast NAK, got {other:?}"),
        }
        assert_eq!(
            reply(&replies[0]).opts().get(OptionCode::MessageType),
            Some(&DhcpOption::MessageType(MessageType::Nak))
        );
    }

    #[test]
    fn renewal_extends_the_active_lease() {
        let mut server = test_server();
        let replies = server.handle_datagram(&discover(), &ingress());
        let offered = reply(&replies[0]).yiaddr();
        let request = selecting_request(offered, Ipv4Addr::new(192, 168, 1, 1), CLIENT_MAC);
        server.handle_datagram(&request, &ingress());

        server.clock.set(2000);
        let renew = renew_request(offered, CLIENT_MAC);
        let replies = server.handle_datagram(&renew, &ingress());
        assert_eq!(replies.len(), 1);
        assert_eq!(
            reply(&replies[0]).opts().get(OptionCode::MessageType),
            Some(&DhcpOption::MessageType(MessageType::Ack))
        );
        assert!(
            matches!(replies[0], Outbound::Direct { destination, .. } if destination == offered)
        );
        let lease = server
            .coordinator
            .lease(MacAddr::parse("aabbccddeeff").unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(lease.entries_by_subnet["lan"].lease_expires_at, 2000 + 3600);
    }

    #[test]
    fn renewal_for_an_unknown_binding_is_ignored() {
        let mut server = test_server();
        let renew = renew_request(Ipv4Addr::new(192, 168, 1, 42), CLIENT_MAC);
        assert!(server.handle_datagram(&renew, &ingress()).is_empty());
    }

    #[test]
    fn decline_quarantines_the_address() {
        let mut server = test_server();
        let replies = server.handle_datagram(&discover(), &ingress());
        let offered = reply(&replies[0]).yiaddr();
        let request = selecting_request(offered, Ipv4Addr::new(192, 168, 1, 1), CLIENT_MAC);
        server.handle_datagram(&request, &ingress());

        let decline = decline(offered, Ipv4Addr::new(192, 168, 1, 1), CLIENT_MAC);
        assert!(server.handle_datagram(&decline, &ingress()).is_empty());

        let lease = server
            .coordinator
            .lease(MacAddr::parse("aabbccddeeff").unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(
            lease.entries_by_subnet["lan"].state,
            crate::model::LeaseState::Declined
        );
        let owner = server.coordinator.owner(offered).unwrap().unwrap();
        assert_eq!(owner.role, OwnerRole::Decline);

        // Another client is offered a different address.
        let other_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02];
        let replies = server.handle_datagram(&discover_mac(other_mac), &ingress());
        assert_eq!(replies.len(), 1);
        assert_ne!(reply(&replies[0]).yiaddr(), offered);
    }

    #[test]
    fn release_for_another_server_is_ignored() {
        let mut server = test_server();
        let replies = server.handle_datagram(&discover(), &ingress());
        let offered = reply(&replies[0]).yiaddr();
        let request = selecting_request(offered, Ipv4Addr::new(192, 168, 1, 1), CLIENT_MAC);
        server.handle_datagram(&request, &ingress());

        let release = release_with_server(offered, Some(Ipv4Addr::new(192, 168, 1, 2)), CLIENT_MAC);
        assert!(server.handle_datagram(&release, &ingress()).is_empty());
        assert!(server
            .coordinator
            .lease(MacAddr::parse("aabbccddeeff").unwrap())
            .unwrap()
            .is_some());
    }

    #[test]
    fn release_removes_the_binding() {
        let mut server = test_server();
        let replies = server.handle_datagram(&discover(), &ingress());
        let offered = reply(&replies[0]).yiaddr();
        let request = selecting_request(offered, Ipv4Addr::new(192, 168, 1, 1), CLIENT_MAC);
        server.handle_datagram(&request, &ingress());

        let release = release(offered, CLIENT_MAC);
        assert!(server.handle_datagram(&release, &ingress()).is_empty());
        assert!(server
            .coordinator
            .lease(MacAddr::parse("aabbccddeeff").unwrap())
            .unwrap()
            .is_none());
        assert!(server.coordinator.owner(offered).unwrap().is_none());
    }

    #[test]
    fn inform_gets_configuration_without_a_lease() {
        let mut server = test_server();
        let inform = inform(Ipv4Addr::new(192, 168, 1, 42), CLIENT_MAC);
        let replies = server.handle_datagram(&inform, &ingress());
        assert_eq!(replies.len(), 1);
        let message = reply(&replies[0]);
        assert_eq!(
            message.opts().get(OptionCode::MessageType),
            Some(&DhcpOption::MessageType(MessageType::Ack))
        );
        assert!(message.opts().get(OptionCode::AddressLeaseTime).is_none());
        assert_eq!(message.yiaddr(), Ipv4Addr::UNSPECIFIED);
        assert!(server
            .coordinator
            .lease(MacAddr::parse("aabbccddeeff").unwrap())
            .unwrap()
            .is_none());
    }

    #[test]
    fn relayed_discover_is_answered_to_the_relay() {
        let mut server = test_server();
        let replies =
            server.handle_datagram(&relayed_discover(Ipv4Addr::new(10, 20, 0, 1)), &ingress());
        assert_eq!(replies.len(), 1);
        match &replies[0] {
            Outbound::Relay { destination, .. } => {
                assert_eq!(*destination, Ipv4Addr::new(10, 20, 0, 1))
            }
            other => panic!("expected relay reply, got {other:?}"),
        }
        let message = reply(&replies[0]);
        let offered = message.yiaddr();
        assert!(test_config()
            .subnet("guest")
            .unwrap()
            .is_dynamic_candidate(offered));
        assert_eq!(
            option_ip(&message, OptionCode::ServerIdentifier),
            Ipv4Addr::new(10, 20, 0, 1)
        );
    }

    #[test]
    fn unknown_relay_is_rejected() {
        let mut server = test_server();
        let replies =
            server.handle_datagram(&relayed_discover(Ipv4Addr::new(10, 20, 0, 99)), &ingress());
        assert!(replies.is_empty());
    }

    #[test]
    fn relay_is_accepted_on_an_interface_without_a_direct_subnet() {
        let mut server = test_server();
        let mut relay_ingress = ingress();
        relay_ingress.interface = "eth9".to_string();
        relay_ingress.ifindex = 9;
        let replies = server.handle_datagram(
            &relayed_discover(Ipv4Addr::new(10, 20, 0, 1)),
            &relay_ingress,
        );
        assert_eq!(replies.len(), 1);
        assert!(matches!(replies[0], Outbound::Relay { .. }));
    }

    #[test]
    fn unconfigured_interface_is_ignored() {
        let mut server = test_server();
        let mut bad = ingress();
        bad.interface = "eth9".to_string();
        assert!(server.handle_datagram(&discover(), &bad).is_empty());
    }

    #[test]
    fn broadcast_on_a_multi_subnet_interface_is_ambiguous() {
        let yaml = r#"
schema_version: 1
storage: { path: /tmp/x.feox, file_size_mib: 8, max_memory_mib: 8, hash_bits: 12 }
authoritative: true
subnets:
  - id: one
    interface: eth0
    cidr: 192.168.1.0/24
    server_identifier: 192.168.1.1
    range: { start: 192.168.1.100, end: 192.168.1.110 }
    exclusions: []
    routers: [192.168.1.1]
    dns_servers: []
    lease_seconds: 3600
    offer_hold_seconds: 30
    decline_hold_seconds: 60
    allocation_strategy: incremental
  - id: two
    interface: eth0
    cidr: 192.168.2.0/24
    server_identifier: 192.168.2.1
    range: { start: 192.168.2.100, end: 192.168.2.110 }
    exclusions: []
    routers: [192.168.2.1]
    dns_servers: []
    lease_seconds: 3600
    offer_hold_seconds: 30
    decline_hold_seconds: 60
    allocation_strategy: incremental
"#;
        let config = Config::parse_str(yaml).unwrap();
        let mut server = server_with_config(config);
        let mut ambiguous = ingress();
        ambiguous.local_address = Ipv4Addr::UNSPECIFIED;
        assert!(server.handle_datagram(&discover(), &ambiguous).is_empty());
        // The local address resolves the scope.
        let mut resolved = ingress();
        resolved.local_address = Ipv4Addr::new(192, 168, 2, 1);
        let replies = server.handle_datagram(&discover(), &resolved);
        assert_eq!(replies.len(), 1);
        assert!(reply(&replies[0])
            .yiaddr()
            .octets()
            .starts_with(&[192, 168, 2]));
    }

    #[test]
    fn reservation_lease_passes_integrity_check() {
        let mut server = test_server();
        let mac = MacAddr::parse("aabbccddeeff").unwrap();
        let reserved_ip = Ipv4Addr::new(192, 168, 1, 50);
        crate::admin::add(
            &mut server.coordinator,
            &server.config,
            mac,
            "lan",
            reserved_ip,
            None,
            1000,
        )
        .unwrap();

        let replies = server.handle_datagram(&discover(), &ingress());
        assert_eq!(reply(&replies[0]).yiaddr(), reserved_ip);
        let request = selecting_request(reserved_ip, Ipv4Addr::new(192, 168, 1, 1), CLIENT_MAC);
        let replies = server.handle_datagram(&request, &ingress());
        assert_eq!(
            reply(&replies[0]).opts().get(OptionCode::MessageType),
            Some(&DhcpOption::MessageType(MessageType::Ack))
        );

        let problems = server
            .coordinator
            .integrity_report(&server.config, 1001)
            .unwrap();
        assert!(problems.is_empty(), "{problems:?}");
    }

    #[test]
    fn startup_refuses_inconsistent_storage() {
        let config = test_config();
        let mac = MacAddr::parse("aabbccddeeff").unwrap();
        let ip = Ipv4Addr::new(192, 168, 1, 50);
        let mut coordinator = StateCoordinator::open_memory().unwrap();
        crate::admin::add(&mut coordinator, &config, mac, "lan", ip, None, 1000).unwrap();
        let owner_key = keys::ip_owner_key(ip);
        coordinator
            .apply(vec![crate::model::JournalOp::delete(owner_key)], 1000)
            .unwrap();
        let error = match DhcpServer::with_store(config, coordinator, Clock::manual(1000)) {
            Ok(_) => panic!("inconsistent store was accepted"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("integrity"), "{error}");
    }

    #[test]
    fn storage_failure_produces_no_offer() {
        let mut server = test_server();
        server.coordinator.inject_fault(Fault::FailIntentFlush);
        assert!(server.handle_datagram(&discover(), &ingress()).is_empty());
        assert!(!server.coordinator.is_healthy());
        // While unhealthy, even a valid request must not be acknowledged.
        server.clock.set(1001);
        assert!(server.handle_datagram(&discover(), &ingress()).is_empty());
    }

    #[test]
    fn client_identifier_mismatch_is_naked() {
        let mut server = test_server();
        let replies = server.handle_datagram(&discover(), &ingress());
        let offered = reply(&replies[0]).yiaddr();
        let request = selecting_request(offered, Ipv4Addr::new(192, 168, 1, 1), CLIENT_MAC);
        server.handle_datagram(&request, &ingress());

        let mut conflicting = Message::new(
            0x1234_5678,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            &CLIENT_MAC,
        );
        conflicting
            .opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Request));
        conflicting
            .opts_mut()
            .insert(DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 168, 1, 1)));
        conflicting
            .opts_mut()
            .insert(DhcpOption::RequestedIpAddress(offered));
        conflicting
            .opts_mut()
            .insert(DhcpOption::ClientIdentifier(vec![9, 9, 9, 9]));
        let replies = server.handle_datagram(&encode(&conflicting), &ingress());
        assert_eq!(replies.len(), 1);
        assert_eq!(
            reply(&replies[0]).opts().get(OptionCode::MessageType),
            Some(&DhcpOption::MessageType(MessageType::Nak))
        );
    }

    #[test]
    fn non_authoritative_server_never_naks() {
        let yaml =
            crate::config::example_config().replace("authoritative: true", "authoritative: false");
        let config = Config::parse_str(&yaml).unwrap();
        let mut server = server_with_config(config);
        let request = init_reboot_request(Ipv4Addr::new(192, 168, 1, 42), CLIENT_MAC);
        assert!(server.handle_datagram(&request, &ingress()).is_empty());
    }

    #[test]
    fn tick_expires_offers_and_restores_health() {
        let mut server = test_server();
        server.coordinator.inject_fault(Fault::FailIntentFlush);
        assert!(server.handle_datagram(&discover(), &ingress()).is_empty());
        assert!(!server.coordinator.is_healthy());
        server.clock.set(2000);
        server.tick().unwrap();
        // The first failed mutation is repaired by replay, so health returns.
        assert!(server.coordinator.is_healthy());
    }

    #[test]
    fn tick_reclaims_expired_offers() {
        let mut server = test_server();
        let replies = server.handle_datagram(&discover(), &ingress());
        let offered = reply(&replies[0]).yiaddr();
        server.clock.set(1000 + 60 + 1);
        server.tick().unwrap();
        assert!(server.coordinator.owner(offered).unwrap().is_none());
    }

    #[test]
    fn offered_lease_is_revalidated_before_ack() {
        let mut server = test_server();
        let replies = server.handle_datagram(&discover(), &ingress());
        let offered = reply(&replies[0]).yiaddr();
        // Simulate a restart with an expired offer: advance well past the hold.
        server.clock.set(1000 + 60 + 1);
        let request = selecting_request(offered, Ipv4Addr::new(192, 168, 1, 1), CLIENT_MAC);
        let replies = server.handle_datagram(&request, &ingress());
        assert_eq!(replies.len(), 1);
        assert_eq!(
            reply(&replies[0]).opts().get(OptionCode::MessageType),
            Some(&DhcpOption::MessageType(MessageType::Nak))
        );
    }

    #[test]
    fn reservation_is_offered_and_acked() {
        let mut server = test_server();
        let now = 1000;
        let mac = MacAddr::parse("aabbccddeeff").unwrap();
        let ip = Ipv4Addr::new(192, 168, 1, 111);
        let mut record = crate::model::ReservationRecord {
            mac,
            ..Default::default()
        };
        record.entries_by_subnet.insert(
            "lan".to_string(),
            ReservationEntry {
                subnet_id: "lan".to_string(),
                ip,
                enabled: true,
                hostname: None,
                client_id: None,
                created_at: now,
                updated_at: now,
            },
        );
        server
            .coordinator
            .apply(
                vec![
                    crate::model::JournalOp::put(
                        keys::reservation_key(mac),
                        encode_record(&record).unwrap(),
                    ),
                    crate::model::JournalOp::put(
                        keys::ip_owner_key(ip),
                        encode_record(&IpOwner {
                            ip,
                            subnet_id: "lan".to_string(),
                            mac,
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

        let replies = server.handle_datagram(&discover(), &ingress());
        assert_eq!(replies.len(), 1);
        let offered = reply(&replies[0]).yiaddr();
        assert_eq!(offered, ip);
        let request = selecting_request(ip, Ipv4Addr::new(192, 168, 1, 1), CLIENT_MAC);
        let replies = server.handle_datagram(&request, &ingress());
        assert_eq!(replies.len(), 1);
        assert_eq!(
            reply(&replies[0]).opts().get(OptionCode::MessageType),
            Some(&DhcpOption::MessageType(MessageType::Ack))
        );
    }
}
