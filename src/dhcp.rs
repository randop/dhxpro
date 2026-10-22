//! DHCPv4 packet parsing, validation and response encoding.
//!
//! This is a small, purpose-built DHCPv4 codec for the options dhxpro needs.
//! It performs no network I/O. Packets delivered by the io_uring receive path
//! are parsed here, and response bytes are produced for the send path.
//!
//! The codec deliberately rejects ambiguous wire input rather than guessing:
//! truncated options, critical-option duplicates, option overload and invalid
//! fixed-width option values are protocol errors.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use crate::config::SubnetConfig;
use crate::error::{Error, Result};
use crate::mac::MacAddr;

/// BOOTP fixed header plus magic cookie. DHCP packets smaller than this are
/// rejected before decoding.
pub const MIN_PACKET_LEN: usize = 240;
/// RFC 2131 requires server messages to be padded to at least 300 octets.
pub const MIN_REPLY_LEN: usize = 300;
/// Smallest reply size dhxpro will honor from client option 57.
pub const MIN_CLIENT_MESSAGE_SIZE: u16 = 300;

pub const BOOTREQUEST: u8 = 1;
pub const BOOTREPLY: u8 = 2;

const HTYPE_ETHERNET: u8 = 1;
const BROADCAST_FLAG: u16 = 0x8000;
const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];
const OPTION_PAD: u8 = 0;
const OPTION_END: u8 = 255;
const OPTION_OVERLOAD: u8 = 52;

/// DHCP option codes used by dhxpro. Unknown codes are retained when needed,
/// for example in a client parameter-request list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OptionCode {
    SubnetMask,
    Router,
    DomainNameServer,
    Hostname,
    DomainName,
    BroadcastAddr,
    RequestedIpAddress,
    AddressLeaseTime,
    MessageType,
    ServerIdentifier,
    ParameterRequestList,
    Message,
    MaxMessageSize,
    Renewal,
    Rebinding,
    ClientIdentifier,
    RelayAgentInformation,
    Unknown(u8),
}

impl OptionCode {
    pub const fn from_u8(code: u8) -> Self {
        match code {
            1 => Self::SubnetMask,
            3 => Self::Router,
            6 => Self::DomainNameServer,
            12 => Self::Hostname,
            15 => Self::DomainName,
            28 => Self::BroadcastAddr,
            50 => Self::RequestedIpAddress,
            51 => Self::AddressLeaseTime,
            53 => Self::MessageType,
            54 => Self::ServerIdentifier,
            55 => Self::ParameterRequestList,
            56 => Self::Message,
            57 => Self::MaxMessageSize,
            58 => Self::Renewal,
            59 => Self::Rebinding,
            61 => Self::ClientIdentifier,
            82 => Self::RelayAgentInformation,
            other => Self::Unknown(other),
        }
    }

    pub const fn as_u8(self) -> u8 {
        match self {
            Self::SubnetMask => 1,
            Self::Router => 3,
            Self::DomainNameServer => 6,
            Self::Hostname => 12,
            Self::DomainName => 15,
            Self::BroadcastAddr => 28,
            Self::RequestedIpAddress => 50,
            Self::AddressLeaseTime => 51,
            Self::MessageType => 53,
            Self::ServerIdentifier => 54,
            Self::ParameterRequestList => 55,
            Self::Message => 56,
            Self::MaxMessageSize => 57,
            Self::Renewal => 58,
            Self::Rebinding => 59,
            Self::ClientIdentifier => 61,
            Self::RelayAgentInformation => 82,
            Self::Unknown(code) => code,
        }
    }
}

/// DHCP message type (option 53).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
    ForceRenew,
    Unknown(u8),
}

impl MessageType {
    pub const fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Discover,
            2 => Self::Offer,
            3 => Self::Request,
            4 => Self::Decline,
            5 => Self::Ack,
            6 => Self::Nak,
            7 => Self::Release,
            8 => Self::Inform,
            9 => Self::ForceRenew,
            other => Self::Unknown(other),
        }
    }

    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Discover => 1,
            Self::Offer => 2,
            Self::Request => 3,
            Self::Decline => 4,
            Self::Ack => 5,
            Self::Nak => 6,
            Self::Release => 7,
            Self::Inform => 8,
            Self::ForceRenew => 9,
            Self::Unknown(value) => value,
        }
    }
}

/// A decoded DHCP option value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhcpOption {
    SubnetMask(Ipv4Addr),
    Router(Vec<Ipv4Addr>),
    DomainNameServer(Vec<Ipv4Addr>),
    Hostname(String),
    DomainName(String),
    BroadcastAddr(Ipv4Addr),
    RequestedIpAddress(Ipv4Addr),
    AddressLeaseTime(u32),
    MessageType(MessageType),
    ServerIdentifier(Ipv4Addr),
    ParameterRequestList(Vec<OptionCode>),
    Message(String),
    MaxMessageSize(u16),
    Renewal(u32),
    Rebinding(u32),
    ClientIdentifier(Vec<u8>),
    RelayAgentInformation(Vec<u8>),
    Unknown { code: u8, data: Vec<u8> },
}

impl DhcpOption {
    pub fn code(&self) -> u8 {
        match self {
            Self::SubnetMask(_) => OptionCode::SubnetMask.as_u8(),
            Self::Router(_) => OptionCode::Router.as_u8(),
            Self::DomainNameServer(_) => OptionCode::DomainNameServer.as_u8(),
            Self::Hostname(_) => OptionCode::Hostname.as_u8(),
            Self::DomainName(_) => OptionCode::DomainName.as_u8(),
            Self::BroadcastAddr(_) => OptionCode::BroadcastAddr.as_u8(),
            Self::RequestedIpAddress(_) => OptionCode::RequestedIpAddress.as_u8(),
            Self::AddressLeaseTime(_) => OptionCode::AddressLeaseTime.as_u8(),
            Self::MessageType(_) => OptionCode::MessageType.as_u8(),
            Self::ServerIdentifier(_) => OptionCode::ServerIdentifier.as_u8(),
            Self::ParameterRequestList(_) => OptionCode::ParameterRequestList.as_u8(),
            Self::Message(_) => OptionCode::Message.as_u8(),
            Self::MaxMessageSize(_) => OptionCode::MaxMessageSize.as_u8(),
            Self::Renewal(_) => OptionCode::Renewal.as_u8(),
            Self::Rebinding(_) => OptionCode::Rebinding.as_u8(),
            Self::ClientIdentifier(_) => OptionCode::ClientIdentifier.as_u8(),
            Self::RelayAgentInformation(_) => OptionCode::RelayAgentInformation.as_u8(),
            Self::Unknown { code, .. } => *code,
        }
    }

    fn encode_value(&self, out: &mut Vec<u8>) {
        match self {
            Self::SubnetMask(ip)
            | Self::BroadcastAddr(ip)
            | Self::RequestedIpAddress(ip)
            | Self::ServerIdentifier(ip) => out.extend_from_slice(&ip.octets()),
            Self::Router(addresses) | Self::DomainNameServer(addresses) => {
                for address in addresses {
                    out.extend_from_slice(&address.octets());
                }
            }
            Self::Hostname(value) | Self::DomainName(value) | Self::Message(value) => {
                out.extend_from_slice(value.as_bytes());
            }
            Self::AddressLeaseTime(value) | Self::Renewal(value) | Self::Rebinding(value) => {
                out.extend_from_slice(&value.to_be_bytes());
            }
            Self::MessageType(kind) => out.push(kind.as_u8()),
            Self::ParameterRequestList(codes) => {
                for code in codes {
                    out.push(code.as_u8());
                }
            }
            Self::MaxMessageSize(value) => out.extend_from_slice(&value.to_be_bytes()),
            Self::ClientIdentifier(value) | Self::RelayAgentInformation(value) => {
                out.extend_from_slice(value);
            }
            Self::Unknown { data, .. } => out.extend_from_slice(data),
        }
    }
}

/// DHCP options keyed by their wire code. Iteration is deterministic by code.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Options {
    entries: BTreeMap<u8, DhcpOption>,
}

impl Options {
    pub fn insert(&mut self, option: DhcpOption) {
        self.entries.insert(option.code(), option);
    }

    pub fn get(&self, code: OptionCode) -> Option<&DhcpOption> {
        self.entries.get(&code.as_u8())
    }

    pub fn remove(&mut self, code: OptionCode) {
        self.entries.remove(&code.as_u8());
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        for option in self.entries.values() {
            let code = option.code();
            if code == OPTION_PAD || code == OPTION_END {
                return Err(Error::protocol(format!(
                    "option {code} cannot be encoded as a valued option"
                )));
            }
            let mut value = Vec::new();
            option.encode_value(&mut value);
            if value.len() > usize::from(u8::MAX) {
                return Err(Error::protocol(format!(
                    "option {code} is {} bytes; the DHCP option length is limited to 255",
                    value.len()
                )));
            }
            out.push(code);
            out.push(value.len() as u8);
            out.extend_from_slice(&value);
        }
        out.push(OPTION_END);
        Ok(())
    }
}

/// A decoded DHCP/BOOTP message.
#[derive(Debug, Clone)]
pub struct Message {
    op: u8,
    htype: u8,
    hlen: u8,
    hops: u8,
    xid: u32,
    secs: u16,
    flags: u16,
    ciaddr: Ipv4Addr,
    yiaddr: Ipv4Addr,
    siaddr: Ipv4Addr,
    giaddr: Ipv4Addr,
    chaddr: [u8; 16],
    options: Options,
}

impl Message {
    /// Construct a BOOTREQUEST with an Ethernet client address.
    pub fn new(
        xid: u32,
        ciaddr: Ipv4Addr,
        yiaddr: Ipv4Addr,
        siaddr: Ipv4Addr,
        giaddr: Ipv4Addr,
        chaddr: &[u8; MacAddr::LEN],
    ) -> Self {
        let mut client = [0u8; 16];
        client[..MacAddr::LEN].copy_from_slice(chaddr);
        Self {
            op: BOOTREQUEST,
            htype: HTYPE_ETHERNET,
            hlen: MacAddr::LEN as u8,
            hops: 0,
            xid,
            secs: 0,
            flags: 0,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr: client,
            options: Options::default(),
        }
    }

    pub fn opcode(&self) -> u8 {
        self.op
    }

    pub fn htype(&self) -> u8 {
        self.htype
    }

    pub fn hlen(&self) -> u8 {
        self.hlen
    }

    pub fn hops(&self) -> u8 {
        self.hops
    }

    pub fn xid(&self) -> u32 {
        self.xid
    }

    pub fn flags(&self) -> u16 {
        self.flags
    }

    pub fn broadcast(&self) -> bool {
        self.flags & BROADCAST_FLAG != 0
    }

    pub fn ciaddr(&self) -> Ipv4Addr {
        self.ciaddr
    }

    pub fn yiaddr(&self) -> Ipv4Addr {
        self.yiaddr
    }

    pub fn siaddr(&self) -> Ipv4Addr {
        self.siaddr
    }

    pub fn giaddr(&self) -> Ipv4Addr {
        self.giaddr
    }

    pub fn chaddr(&self) -> &[u8; 16] {
        &self.chaddr
    }

    pub fn opts(&self) -> &Options {
        &self.options
    }

    pub fn opts_mut(&mut self) -> &mut Options {
        &mut self.options
    }

    /// Encode a complete DHCP message, including the magic cookie and END
    /// option. The caller is responsible for any minimum-size padding.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(512);
        out.push(self.op);
        out.push(self.htype);
        out.push(self.hlen);
        out.push(self.hops);
        out.extend_from_slice(&self.xid.to_be_bytes());
        out.extend_from_slice(&self.secs.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&self.ciaddr.octets());
        out.extend_from_slice(&self.yiaddr.octets());
        out.extend_from_slice(&self.siaddr.octets());
        out.extend_from_slice(&self.giaddr.octets());
        out.extend_from_slice(&self.chaddr);
        out.resize(108, 0); // sname
        out.resize(236, 0); // file
        out.extend_from_slice(&MAGIC_COOKIE);
        self.options.encode(&mut out)?;
        Ok(out)
    }

    /// Decode a DHCP message and its option area. Request-specific validation
    /// (BOOTREQUEST, Ethernet, message type, client identity) is performed by
    /// [`parse_request`].
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < MIN_PACKET_LEN {
            return Err(Error::protocol(format!(
                "packet is {} bytes, shorter than the {MIN_PACKET_LEN}-byte BOOTP header",
                bytes.len()
            )));
        }
        if bytes.get(236..240) != Some(&MAGIC_COOKIE[..]) {
            return Err(Error::protocol(
                "DHCP magic cookie is missing or incorrect".to_string(),
            ));
        }

        let mut chaddr = [0u8; 16];
        chaddr.copy_from_slice(&bytes[28..44]);
        Ok(Self {
            op: bytes[0],
            htype: bytes[1],
            hlen: bytes[2],
            hops: bytes[3],
            xid: read_u32(&bytes[4..8]),
            secs: read_u16(&bytes[8..10]),
            flags: read_u16(&bytes[10..12]),
            ciaddr: read_ipv4(&bytes[12..16]),
            yiaddr: read_ipv4(&bytes[16..20]),
            siaddr: read_ipv4(&bytes[20..24]),
            giaddr: read_ipv4(&bytes[24..28]),
            chaddr,
            options: decode_options(&bytes[MIN_PACKET_LEN..])?,
        })
    }
}

/// An inbound DHCPv4 client request.
#[derive(Debug, Clone)]
pub struct ParsedRequest {
    pub message_type: MessageType,
    pub mac: MacAddr,
    pub client_id: Option<Vec<u8>>,
    pub hostname: Option<String>,
    pub requested_ip: Option<Ipv4Addr>,
    pub server_identifier: Option<Ipv4Addr>,
    pub max_message_size: Option<u16>,
    pub parameter_request_list: Vec<OptionCode>,
    pub relay_agent: Option<Vec<u8>>,
    pub broadcast: bool,
    pub giaddr: Ipv4Addr,
    pub ciaddr: Ipv4Addr,
    xid: u32,
    flags: u16,
}

impl ParsedRequest {
    pub fn xid(&self) -> u32 {
        self.xid
    }

    pub fn is_relayed(&self) -> bool {
        !self.giaddr.is_unspecified()
    }
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn read_ipv4(bytes: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
}

fn decode_options(bytes: &[u8]) -> Result<Options> {
    let mut options = Options::default();
    let mut seen_critical = [false; 256];
    let mut index = 0usize;

    while index < bytes.len() {
        let code = bytes[index];
        index += 1;
        if code == OPTION_PAD {
            continue;
        }
        if code == OPTION_END {
            break;
        }
        let Some(&length) = bytes.get(index) else {
            return Err(Error::protocol(format!(
                "DHCP option {code} is missing its length byte"
            )));
        };
        let length = usize::from(length);
        index += 1;
        let end = index
            .checked_add(length)
            .ok_or_else(|| Error::protocol(format!("DHCP option {code} has an invalid length")))?;
        if end > bytes.len() {
            return Err(Error::protocol(format!(
                "DHCP option {code} claims {length} bytes but only {} remain",
                bytes.len() - index
            )));
        }
        if code == OPTION_OVERLOAD {
            return Err(Error::protocol(
                "DHCP option 52 (option overload) is not supported".to_string(),
            ));
        }
        if matches!(code, 50 | 53 | 54 | 57 | 61) {
            if seen_critical[usize::from(code)] {
                return Err(Error::protocol(format!(
                    "DHCP option {code} appears more than once"
                )));
            }
            seen_critical[usize::from(code)] = true;
        }
        options.insert(decode_option(code, &bytes[index..end])?);
        index = end;
    }

    Ok(options)
}

fn decode_option(code: u8, value: &[u8]) -> Result<DhcpOption> {
    let fixed = |expected: usize| {
        if value.len() == expected {
            Ok(())
        } else {
            Err(Error::protocol(format!(
                "DHCP option {code} must be exactly {expected} bytes, got {}",
                value.len()
            )))
        }
    };

    Ok(match code {
        1 => {
            fixed(4)?;
            DhcpOption::SubnetMask(read_ipv4(value))
        }
        3 => DhcpOption::Router(decode_ipv4_list(code, value)?),
        6 => DhcpOption::DomainNameServer(decode_ipv4_list(code, value)?),
        12 => DhcpOption::Hostname(decode_text(value)),
        15 => DhcpOption::DomainName(decode_text(value)),
        28 => {
            fixed(4)?;
            DhcpOption::BroadcastAddr(read_ipv4(value))
        }
        50 => {
            fixed(4)?;
            DhcpOption::RequestedIpAddress(read_ipv4(value))
        }
        51 => {
            fixed(4)?;
            DhcpOption::AddressLeaseTime(read_u32(value))
        }
        52 => {
            return Err(Error::protocol(
                "DHCP option 52 (option overload) is not supported".to_string(),
            ))
        }
        53 => {
            fixed(1)?;
            DhcpOption::MessageType(MessageType::from_u8(value[0]))
        }
        54 => {
            fixed(4)?;
            DhcpOption::ServerIdentifier(read_ipv4(value))
        }
        55 => DhcpOption::ParameterRequestList(
            value
                .iter()
                .copied()
                .map(OptionCode::from_u8)
                .collect::<Vec<_>>(),
        ),
        56 => DhcpOption::Message(decode_text(value)),
        57 => {
            fixed(2)?;
            DhcpOption::MaxMessageSize(read_u16(value))
        }
        58 => {
            fixed(4)?;
            DhcpOption::Renewal(read_u32(value))
        }
        59 => {
            fixed(4)?;
            DhcpOption::Rebinding(read_u32(value))
        }
        61 => {
            if value.is_empty() {
                return Err(Error::protocol(
                    "DHCP option 61 must not be empty".to_string(),
                ));
            }
            DhcpOption::ClientIdentifier(value.to_vec())
        }
        82 => DhcpOption::RelayAgentInformation(value.to_vec()),
        other => DhcpOption::Unknown {
            code: other,
            data: value.to_vec(),
        },
    })
}

fn decode_ipv4_list(code: u8, value: &[u8]) -> Result<Vec<Ipv4Addr>> {
    if value.is_empty() || !value.len().is_multiple_of(4) {
        return Err(Error::protocol(format!(
            "DHCP option {code} length {} is not a non-empty list of IPv4 addresses",
            value.len()
        )));
    }
    Ok(value.chunks_exact(4).map(read_ipv4).collect::<Vec<_>>())
}

fn decode_text(value: &[u8]) -> String {
    String::from_utf8_lossy(value).into_owned()
}

/// Parse and validate an inbound DHCPv4 client message.
pub fn parse_request(bytes: &[u8]) -> Result<ParsedRequest> {
    let message = Message::decode(bytes)?;

    if message.op != BOOTREQUEST {
        return Err(Error::protocol(format!(
            "unexpected opcode {}; only client BOOTREQUEST packets are accepted",
            message.op
        )));
    }
    if message.htype != HTYPE_ETHERNET {
        return Err(Error::protocol(format!(
            "unsupported hardware type {}; only Ethernet is supported",
            message.htype
        )));
    }
    if message.hlen != MacAddr::LEN as u8 {
        return Err(Error::protocol(format!(
            "unsupported hardware address length {}",
            message.hlen
        )));
    }
    let mac = MacAddr::from_slice(&message.chaddr[..MacAddr::LEN])?;
    if !mac.is_usable_client() {
        return Err(Error::protocol(format!(
            "client hardware address {mac} is not a usable unicast address"
        )));
    }

    let message_type = match message.options.get(OptionCode::MessageType) {
        Some(DhcpOption::MessageType(kind)) => *kind,
        _ => {
            return Err(Error::protocol(
                "DHCP message is missing option 53 (message type)",
            ))
        }
    };

    let client_id = match message.options.get(OptionCode::ClientIdentifier) {
        Some(DhcpOption::ClientIdentifier(value)) => {
            if value.is_empty() || value.len() > usize::from(u8::MAX) {
                return Err(Error::protocol(format!(
                    "option 61 client identifier has invalid length {}",
                    value.len()
                )));
            }
            Some(value.clone())
        }
        Some(_) => return Err(Error::protocol("option 61 has the wrong wire type")),
        None => None,
    };

    let hostname = match message.options.get(OptionCode::Hostname) {
        Some(DhcpOption::Hostname(value)) => Some(value.clone()),
        _ => None,
    };

    let requested_ip = match message.options.get(OptionCode::RequestedIpAddress) {
        Some(DhcpOption::RequestedIpAddress(ip)) => Some(*ip),
        Some(_) => return Err(Error::protocol("option 50 has the wrong wire type")),
        None => None,
    };

    let server_identifier = match message.options.get(OptionCode::ServerIdentifier) {
        Some(DhcpOption::ServerIdentifier(ip)) => Some(*ip),
        Some(_) => return Err(Error::protocol("option 54 has the wrong wire type")),
        None => None,
    };

    let max_message_size = match message.options.get(OptionCode::MaxMessageSize) {
        Some(DhcpOption::MaxMessageSize(size)) => Some((*size).max(MIN_CLIENT_MESSAGE_SIZE)),
        Some(_) => return Err(Error::protocol("option 57 has the wrong wire type")),
        None => None,
    };

    let parameter_request_list = match message.options.get(OptionCode::ParameterRequestList) {
        Some(DhcpOption::ParameterRequestList(list)) => list.clone(),
        _ => Vec::new(),
    };

    let relay_agent = match message.options.get(OptionCode::RelayAgentInformation) {
        Some(DhcpOption::RelayAgentInformation(value)) => Some(value.clone()),
        _ => None,
    };

    Ok(ParsedRequest {
        mac,
        client_id,
        hostname,
        requested_ip,
        server_identifier,
        max_message_size,
        parameter_request_list,
        relay_agent,
        broadcast: message.broadcast(),
        giaddr: message.giaddr,
        ciaddr: message.ciaddr,
        message_type,
        xid: message.xid,
        flags: message.flags,
    })
}

/// Build a DHCPOFFER for `ip`.
pub fn build_offer(
    request: &ParsedRequest,
    subnet: &SubnetConfig,
    ip: Ipv4Addr,
) -> Result<Vec<u8>> {
    build_reply(request, subnet, MessageType::Offer, ip, true, None)
}

/// Build a DHCPACK. `yiaddr` is zero for DHCPINFORM replies.
pub fn build_ack(
    request: &ParsedRequest,
    subnet: &SubnetConfig,
    yiaddr: Ipv4Addr,
    include_lease: bool,
) -> Result<Vec<u8>> {
    build_reply(
        request,
        subnet,
        MessageType::Ack,
        yiaddr,
        include_lease,
        None,
    )
}

pub fn build_nak(request: &ParsedRequest, subnet: &SubnetConfig, reason: &str) -> Result<Vec<u8>> {
    // Option 56 carries at most 255 bytes. Diagnostics can include IDs and
    // addresses, so bound the text instead of refusing to send the NAK.
    let reason = truncate_text(reason, usize::from(u8::MAX));
    build_reply(
        request,
        subnet,
        MessageType::Nak,
        Ipv4Addr::UNSPECIFIED,
        false,
        Some(reason),
    )
}

fn truncate_text(value: &str, max: usize) -> &str {
    if value.len() <= max {
        return value;
    }
    let mut end = max;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn build_reply(
    request: &ParsedRequest,
    subnet: &SubnetConfig,
    kind: MessageType,
    yiaddr: Ipv4Addr,
    include_lease: bool,
    message: Option<&str>,
) -> Result<Vec<u8>> {
    let mut reply = Message::new(
        request.xid,
        request.ciaddr,
        yiaddr,
        Ipv4Addr::UNSPECIFIED,
        request.giaddr,
        request.mac.as_bytes(),
    );
    reply.op = BOOTREPLY;
    reply.flags = request.flags;

    {
        let options = reply.opts_mut();
        options.insert(DhcpOption::MessageType(kind));
        options.insert(DhcpOption::ServerIdentifier(subnet.server_identifier));

        if matches!(kind, MessageType::Offer | MessageType::Ack) {
            options.insert(DhcpOption::SubnetMask(subnet.netmask()));
            if !subnet.routers.is_empty() {
                options.insert(DhcpOption::Router(subnet.routers.clone()));
            }
            if !subnet.dns_servers.is_empty() {
                options.insert(DhcpOption::DomainNameServer(subnet.dns_servers.clone()));
            }
            if let Some(domain) = &subnet.domain_name {
                options.insert(DhcpOption::DomainName(domain.clone()));
            }
            options.insert(DhcpOption::BroadcastAddr(subnet.broadcast()));
            if include_lease {
                options.insert(DhcpOption::AddressLeaseTime(subnet.lease_seconds));
                options.insert(DhcpOption::Renewal(subnet.t1()));
                options.insert(DhcpOption::Rebinding(subnet.t2()));
            }
        }

        if let Some(text) = message {
            options.insert(DhcpOption::Message(text.to_string()));
        }

        // RFC 3046: echo the relay agent information option back to the relay.
        if request.is_relayed() {
            if let Some(relay) = &request.relay_agent {
                options.insert(DhcpOption::RelayAgentInformation(relay.clone()));
            }
        }
    }

    // Optional options are dropped, least important first, when a client
    // advertises a small maximum message size (option 57). Required options
    // and the mandatory 300-octet padding are never removed.
    let mut removable = vec![
        OptionCode::DomainName,
        OptionCode::Renewal,
        OptionCode::Rebinding,
        OptionCode::BroadcastAddr,
        OptionCode::DomainNameServer,
        OptionCode::Router,
        // NAK diagnostics are optional; drop them before failing to fit.
        OptionCode::Message,
    ];
    loop {
        let mut buf = reply.encode()?;
        if buf.len() < MIN_REPLY_LEN {
            buf.resize(MIN_REPLY_LEN, 0);
        }

        let Some(max) = request.max_message_size else {
            return Ok(buf);
        };
        if buf.len() <= usize::from(max) {
            return Ok(buf);
        }
        let Some(code) = removable.pop() else {
            return Err(Error::protocol(format!(
                "reply is {} bytes but the client accepts at most {max}",
                buf.len()
            )));
        };
        reply.opts_mut().remove(code);
    }
}

/// DHCP message-type name for logging.
pub fn message_type_name(kind: MessageType) -> &'static str {
    match kind {
        MessageType::Discover => "DISCOVER",
        MessageType::Offer => "OFFER",
        MessageType::Request => "REQUEST",
        MessageType::Decline => "DECLINE",
        MessageType::Ack => "ACK",
        MessageType::Nak => "NAK",
        MessageType::Release => "RELEASE",
        MessageType::Inform => "INFORM",
        MessageType::ForceRenew => "FORCERENEW",
        MessageType::Unknown(_) => "UNKNOWN",
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub const CLIENT_MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

    pub fn encode(message: &Message) -> Vec<u8> {
        let mut buf = message.encode().unwrap();
        if buf.len() < MIN_PACKET_LEN {
            buf.resize(MIN_PACKET_LEN, 0);
        }
        buf
    }

    pub fn base(kind: MessageType) -> Message {
        let mut message = Message::new(
            0x1234_5678,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            &CLIENT_MAC,
        );
        message.opts_mut().insert(DhcpOption::MessageType(kind));
        message.flags = BROADCAST_FLAG;
        message
    }

    pub fn discover() -> Vec<u8> {
        let mut message = base(MessageType::Discover);
        message.opts_mut().insert(DhcpOption::ClientIdentifier(
            [vec![1], CLIENT_MAC.to_vec()].concat(),
        ));
        message
            .opts_mut()
            .insert(DhcpOption::Hostname("client-one".to_string()));
        message
            .opts_mut()
            .insert(DhcpOption::ParameterRequestList(vec![
                OptionCode::SubnetMask,
                OptionCode::Router,
                OptionCode::DomainNameServer,
            ]));
        encode(&message)
    }

    pub fn discover_mac(mac: [u8; 6]) -> Vec<u8> {
        let mut message = base(MessageType::Discover);
        message.chaddr[..MacAddr::LEN].copy_from_slice(&mac);
        encode(&message)
    }

    pub fn selecting_request(requested: Ipv4Addr, server: Ipv4Addr, mac: [u8; 6]) -> Vec<u8> {
        let mut message = Message::new(
            0x1234_5678,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            &mac,
        );
        message
            .opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Request));
        message
            .opts_mut()
            .insert(DhcpOption::ServerIdentifier(server));
        message
            .opts_mut()
            .insert(DhcpOption::RequestedIpAddress(requested));
        encode(&message)
    }

    pub fn init_reboot_request(requested: Ipv4Addr, mac: [u8; 6]) -> Vec<u8> {
        let mut message = Message::new(
            0x1234_5678,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            &mac,
        );
        message
            .opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Request));
        message
            .opts_mut()
            .insert(DhcpOption::RequestedIpAddress(requested));
        encode(&message)
    }

    pub fn renew_request(ciaddr: Ipv4Addr, mac: [u8; 6]) -> Vec<u8> {
        let mut message = Message::new(
            0x1234_5678,
            ciaddr,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            &mac,
        );
        message
            .opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Request));
        encode(&message)
    }

    pub fn decline(ip: Ipv4Addr, server: Ipv4Addr, mac: [u8; 6]) -> Vec<u8> {
        let mut message = Message::new(
            0x1234_5678,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            &mac,
        );
        message
            .opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Decline));
        message
            .opts_mut()
            .insert(DhcpOption::ServerIdentifier(server));
        message
            .opts_mut()
            .insert(DhcpOption::RequestedIpAddress(ip));
        encode(&message)
    }

    pub fn release(ip: Ipv4Addr, mac: [u8; 6]) -> Vec<u8> {
        release_with_server(ip, None, mac)
    }

    pub fn release_with_server(ip: Ipv4Addr, server: Option<Ipv4Addr>, mac: [u8; 6]) -> Vec<u8> {
        let mut message = Message::new(
            0x1234_5678,
            ip,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            &mac,
        );
        message
            .opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Release));
        if let Some(server) = server {
            message
                .opts_mut()
                .insert(DhcpOption::ServerIdentifier(server));
        }
        encode(&message)
    }

    pub fn inform(ciaddr: Ipv4Addr, mac: [u8; 6]) -> Vec<u8> {
        let mut message = Message::new(
            0x1234_5678,
            ciaddr,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            &mac,
        );
        message
            .opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Inform));
        encode(&message)
    }

    pub fn relayed_discover(giaddr: Ipv4Addr) -> Vec<u8> {
        let mut message = base(MessageType::Discover);
        message.giaddr = giaddr;
        message.hops = 1;
        encode(&message)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    fn test_subnet() -> SubnetConfig {
        let config = crate::config::Config::parse_str(crate::config::example_config()).unwrap();
        config.subnet("lan").unwrap().clone()
    }

    /// Hand-built BOOTP/DHCP wire fixture. This intentionally does not use
    /// `Message::encode` so it checks the decoder against the RFC layout.
    fn golden_discover() -> Vec<u8> {
        let mut packet = vec![0u8; MIN_PACKET_LEN];
        packet[0] = BOOTREQUEST;
        packet[1] = HTYPE_ETHERNET;
        packet[2] = 6;
        packet[4..8].copy_from_slice(&0x3903_f326u32.to_be_bytes());
        packet[10..12].copy_from_slice(&BROADCAST_FLAG.to_be_bytes());
        packet[28..34].copy_from_slice(&CLIENT_MAC);
        packet[236..240].copy_from_slice(&MAGIC_COOKIE);
        packet.extend_from_slice(&[
            53, 1, 1, // DHCPDISCOVER
            61, 7, 1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // client identifier
            12, 10, b'c', b'l', b'i', b'e', b'n', b't', b'-', b'o', b'n', b'e', // hostname
            55, 3, 1, 3, 6, // parameter request list
            255,
        ]);
        packet.resize(MIN_REPLY_LEN, 0);
        packet
    }

    fn raw_option(packet: &[u8], wanted: u8) -> Option<&[u8]> {
        let mut index = MIN_PACKET_LEN;
        while index < packet.len() {
            let code = packet[index];
            index += 1;
            if code == OPTION_END {
                return None;
            }
            if code == OPTION_PAD {
                continue;
            }
            let length = usize::from(packet[index]);
            index += 1;
            let end = index + length;
            if code == wanted {
                return Some(&packet[index..end]);
            }
            index = end;
        }
        None
    }

    #[test]
    fn parses_golden_wire_fixture() {
        let parsed = parse_request(&golden_discover()).unwrap();
        assert_eq!(parsed.message_type, MessageType::Discover);
        assert_eq!(parsed.mac, MacAddr::new(CLIENT_MAC));
        assert_eq!(parsed.xid(), 0x3903_f326);
        assert_eq!(parsed.hostname.as_deref(), Some("client-one"));
        assert_eq!(
            parsed.client_id,
            Some([vec![1], CLIENT_MAC.to_vec()].concat())
        );
        assert_eq!(
            parsed.parameter_request_list,
            vec![
                OptionCode::SubnetMask,
                OptionCode::Router,
                OptionCode::DomainNameServer
            ]
        );
        assert!(parsed.broadcast);
        assert!(!parsed.is_relayed());
    }

    #[test]
    fn offer_matches_golden_wire_layout() {
        let request = parse_request(&golden_discover()).unwrap();
        let subnet = test_subnet();
        let ip = Ipv4Addr::new(192, 168, 1, 101);
        let bytes = build_offer(&request, &subnet, ip).unwrap();

        assert_eq!(bytes[0], BOOTREPLY);
        assert_eq!(bytes[1], HTYPE_ETHERNET);
        assert_eq!(bytes[2], 6);
        assert_eq!(bytes[3], 0);
        assert_eq!(&bytes[4..8], &0x3903_f326u32.to_be_bytes());
        assert_eq!(&bytes[8..10], &[0, 0]);
        assert_eq!(&bytes[10..12], &BROADCAST_FLAG.to_be_bytes());
        assert_eq!(&bytes[12..16], &[0, 0, 0, 0]);
        assert_eq!(&bytes[16..20], &ip.octets());
        assert_eq!(&bytes[20..24], &[0, 0, 0, 0]);
        assert_eq!(&bytes[24..28], &[0, 0, 0, 0]);
        assert_eq!(&bytes[28..34], &CLIENT_MAC);
        assert_eq!(&bytes[236..240], &MAGIC_COOKIE);
        assert!(bytes.len() >= MIN_REPLY_LEN);

        assert_eq!(raw_option(&bytes, 53), Some(&[2][..]));
        assert_eq!(
            raw_option(&bytes, 54),
            Some(subnet.server_identifier.octets().as_slice())
        );
        assert_eq!(
            raw_option(&bytes, 1),
            Some(subnet.netmask().octets().as_slice())
        );
        assert_eq!(
            raw_option(&bytes, 51),
            Some(subnet.lease_seconds.to_be_bytes().as_slice())
        );
    }

    #[test]
    fn parses_a_discover() {
        let parsed = parse_request(&discover()).unwrap();
        assert_eq!(parsed.message_type, MessageType::Discover);
        assert_eq!(parsed.mac, MacAddr::parse("aabbccddeeff").unwrap());
        assert_eq!(parsed.hostname.as_deref(), Some("client-one"));
        assert_eq!(
            parsed.client_id.as_deref(),
            Some([vec![1], CLIENT_MAC.to_vec()].concat().as_slice())
        );
        assert_eq!(parsed.parameter_request_list.len(), 3);
        assert!(!parsed.is_relayed());
    }

    #[test]
    fn rejects_truncated_and_malformed_packets() {
        assert!(parse_request(&[0u8; 100]).is_err());
        assert!(parse_request(&[0u8; 240]).is_err());
        let mut bytes = discover();
        bytes.truncate(200);
        assert!(parse_request(&bytes).is_err());

        let bytes = encode(&base(MessageType::Discover));
        let mut malformed = bytes.clone();
        malformed[241] = 250;
        let error = parse_request(&malformed).unwrap_err().to_string();
        assert!(error.contains("remain"), "{error}");
    }

    #[test]
    fn rejects_server_messages_and_wrong_hardware() {
        let mut message = base(MessageType::Discover);
        message.op = BOOTREPLY;
        let error = parse_request(&encode(&message)).unwrap_err().to_string();
        assert!(error.contains("opcode"), "{error}");

        let mut message = base(MessageType::Discover);
        message.htype = 6;
        let error = parse_request(&encode(&message)).unwrap_err().to_string();
        assert!(error.contains("hardware type"), "{error}");

        let mut message = base(MessageType::Discover);
        message.chaddr = [0u8; 16];
        message.hlen = 4;
        let error = parse_request(&encode(&message)).unwrap_err().to_string();
        assert!(error.contains("length"), "{error}");
    }

    #[test]
    fn rejects_missing_message_type() {
        let message = Message::new(
            1,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            &CLIENT_MAC,
        );
        let error = parse_request(&encode(&message)).unwrap_err().to_string();
        assert!(error.contains("option 53"), "{error}");
    }

    #[test]
    fn rejects_zero_and_multicast_macs() {
        for mac in [[0u8; 6], [1, 2, 3, 4, 5, 6]] {
            assert!(parse_request(&discover_mac(mac)).is_err());
        }
    }

    #[test]
    fn offer_round_trips_with_expected_options() {
        let request = parse_request(&discover()).unwrap();
        let subnet = test_subnet();
        let ip = Ipv4Addr::new(192, 168, 1, 101);
        let bytes = build_offer(&request, &subnet, ip).unwrap();
        assert!(bytes.len() >= MIN_REPLY_LEN);
        let reply = Message::decode(&bytes).unwrap();
        assert_eq!(reply.opcode(), BOOTREPLY);
        assert_eq!(reply.htype(), HTYPE_ETHERNET);
        assert_eq!(reply.hlen(), 6);
        assert_eq!(reply.xid(), request.xid());
        assert_eq!(reply.yiaddr(), ip);
        assert_eq!(&reply.chaddr()[..6], request.mac.as_bytes());
        assert_eq!(
            reply.opts().get(OptionCode::MessageType),
            Some(&DhcpOption::MessageType(MessageType::Offer))
        );
        assert_eq!(
            reply.opts().get(OptionCode::ServerIdentifier),
            Some(&DhcpOption::ServerIdentifier(subnet.server_identifier))
        );
        assert_eq!(
            reply.opts().get(OptionCode::SubnetMask),
            Some(&DhcpOption::SubnetMask(subnet.netmask()))
        );
        assert_eq!(
            reply.opts().get(OptionCode::AddressLeaseTime),
            Some(&DhcpOption::AddressLeaseTime(subnet.lease_seconds))
        );
        assert_eq!(
            reply.opts().get(OptionCode::Renewal),
            Some(&DhcpOption::Renewal(subnet.t1()))
        );
        assert_eq!(
            reply.opts().get(OptionCode::Rebinding),
            Some(&DhcpOption::Rebinding(subnet.t2()))
        );
    }

    #[test]
    fn nak_contains_reason_and_no_lease_time() {
        let request = parse_request(&init_reboot_request(
            Ipv4Addr::new(192, 168, 1, 55),
            CLIENT_MAC,
        ))
        .unwrap();
        let subnet = test_subnet();
        let bytes = build_nak(&request, &subnet, "requested address not available").unwrap();
        let reply = Message::decode(&bytes).unwrap();
        assert_eq!(reply.yiaddr(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(
            reply.opts().get(OptionCode::MessageType),
            Some(&DhcpOption::MessageType(MessageType::Nak))
        );
        assert!(matches!(
            reply.opts().get(OptionCode::Message),
            Some(DhcpOption::Message(text)) if text.contains("not available")
        ));
        assert!(reply.opts().get(OptionCode::AddressLeaseTime).is_none());
    }

    #[test]
    fn inform_ack_has_no_lease_time_or_yiaddr() {
        let request = parse_request(&inform(Ipv4Addr::new(192, 168, 1, 77), CLIENT_MAC)).unwrap();
        let subnet = test_subnet();
        let bytes = build_ack(&request, &subnet, Ipv4Addr::UNSPECIFIED, false).unwrap();
        let reply = Message::decode(&bytes).unwrap();
        assert_eq!(reply.yiaddr(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(
            reply.opts().get(OptionCode::MessageType),
            Some(&DhcpOption::MessageType(MessageType::Ack))
        );
        assert!(reply.opts().get(OptionCode::AddressLeaseTime).is_none());
        assert!(reply.opts().get(OptionCode::SubnetMask).is_some());
    }

    #[test]
    fn relayed_replies_echo_option_82() {
        let mut message = base(MessageType::Discover);
        message.giaddr = Ipv4Addr::new(10, 20, 0, 1);
        message.hops = 1;
        // Relay agent information: circuit-id suboption 1.
        let relay = [vec![1, 6], b"port-1".to_vec()].concat();
        message
            .opts_mut()
            .insert(DhcpOption::RelayAgentInformation(relay.clone()));
        let request = parse_request(&encode(&message)).unwrap();
        assert!(request.is_relayed());
        let subnet = test_subnet();
        let bytes = build_offer(&request, &subnet, Ipv4Addr::new(192, 168, 1, 101)).unwrap();
        let reply = Message::decode(&bytes).unwrap();
        assert_eq!(
            reply.opts().get(OptionCode::RelayAgentInformation),
            Some(&DhcpOption::RelayAgentInformation(relay))
        );
    }

    #[test]
    fn rejects_wrong_magic_cookie() {
        let mut bytes = encode(&base(MessageType::Discover));
        bytes[236..240].copy_from_slice(&[0, 0, 0, 0]);
        let error = parse_request(&bytes).unwrap_err().to_string();
        assert!(error.contains("magic cookie"), "{error}");
    }

    #[test]
    fn rejects_duplicate_critical_options() {
        let bytes = encode(&base(MessageType::Discover));
        let end = bytes[MIN_PACKET_LEN..]
            .iter()
            .position(|byte| *byte == 255)
            .map(|position| MIN_PACKET_LEN + position)
            .expect("encoded packet has an END option");
        let mut duplicate = bytes[..end].to_vec();
        // A second message-type option with a different value.
        duplicate.extend_from_slice(&[53, 1, 2, 255]);
        let error = parse_request(&duplicate).unwrap_err().to_string();
        assert!(error.contains("more than once"), "{error}");
    }

    #[test]
    fn rejects_overloaded_options() {
        let bytes = encode(&base(MessageType::Discover));
        let end = bytes[MIN_PACKET_LEN..]
            .iter()
            .position(|byte| *byte == 255)
            .map(|position| MIN_PACKET_LEN + position)
            .expect("encoded packet has an END option");
        let mut overloaded = bytes[..end].to_vec();
        overloaded.extend_from_slice(&[52, 1, 1, 255]);
        let error = parse_request(&overloaded).unwrap_err().to_string();
        assert!(error.contains("option overload"), "{error}");
    }

    #[test]
    fn rejects_invalid_fixed_option_lengths() {
        let packet = |option: &[u8]| {
            let mut bytes = encode(&base(MessageType::Discover));
            let end = bytes[MIN_PACKET_LEN..]
                .iter()
                .position(|byte| *byte == 255)
                .map(|position| MIN_PACKET_LEN + position)
                .unwrap();
            bytes.truncate(end);
            bytes.extend_from_slice(option);
            bytes.push(255);
            bytes
        };

        for option in [
            &[50, 3, 192, 168, 1][..],
            &[54, 2, 192, 168][..],
            &[57, 1, 0][..],
            &[61, 0][..],
        ] {
            let error = parse_request(&packet(option)).unwrap_err().to_string();
            assert!(error.contains("option"), "{option:?}: {error}");
        }
    }

    #[test]
    fn oversized_reply_is_rejected_for_small_clients() {
        let mut message = base(MessageType::Discover);
        message
            .opts_mut()
            .insert(DhcpOption::MaxMessageSize(MIN_CLIENT_MESSAGE_SIZE));
        let request = parse_request(&encode(&message)).unwrap();
        let subnet = test_subnet();
        let reply = build_offer(&request, &subnet, Ipv4Addr::new(192, 168, 1, 101)).unwrap();
        assert!(reply.len() <= usize::from(MIN_CLIENT_MESSAGE_SIZE));
    }

    #[test]
    fn long_nak_reason_is_truncated_and_removable() {
        let subnet = test_subnet();
        let request = parse_request(&encode(&base(MessageType::Request))).unwrap();
        let long_reason = "x".repeat(400);

        let bytes = build_nak(&request, &subnet, &long_reason).unwrap();
        let reply = Message::decode(&bytes).unwrap();
        assert!(matches!(
            reply.opts().get(OptionCode::Message),
            Some(DhcpOption::Message(text)) if text.len() == usize::from(u8::MAX)
        ));

        let mut message = base(MessageType::Request);
        message
            .opts_mut()
            .insert(DhcpOption::MaxMessageSize(MIN_CLIENT_MESSAGE_SIZE));
        let request = parse_request(&encode(&message)).unwrap();
        let bytes = build_nak(&request, &subnet, &long_reason).unwrap();
        assert!(bytes.len() <= usize::from(MIN_CLIENT_MESSAGE_SIZE));
        let reply = Message::decode(&bytes).unwrap();
        assert!(reply.opts().get(OptionCode::Message).is_none());
        assert_eq!(
            reply.opts().get(OptionCode::MessageType),
            Some(&DhcpOption::MessageType(MessageType::Nak))
        );
        assert!(reply.opts().get(OptionCode::ServerIdentifier).is_some());
    }

    #[test]
    fn unknown_options_round_trip_and_do_not_block_requests() {
        let mut message = base(MessageType::Discover);
        message.opts_mut().insert(DhcpOption::Unknown {
            code: 200,
            data: vec![0xde, 0xad, 0xbe, 0xef],
        });
        let parsed = parse_request(&encode(&message)).unwrap();
        assert_eq!(parsed.message_type, MessageType::Discover);

        let decoded = Message::decode(&encode(&message)).unwrap();
        assert_eq!(
            decoded.opts().get(OptionCode::Unknown(200)),
            Some(&DhcpOption::Unknown {
                code: 200,
                data: vec![0xde, 0xad, 0xbe, 0xef],
            })
        );
    }

    #[test]
    fn parameter_request_list_preserves_unknown_codes() {
        let mut message = base(MessageType::Discover);
        message
            .opts_mut()
            .insert(DhcpOption::ParameterRequestList(vec![
                OptionCode::SubnetMask,
                OptionCode::Unknown(200),
            ]));
        let request = parse_request(&encode(&message)).unwrap();
        assert_eq!(
            request.parameter_request_list,
            vec![OptionCode::SubnetMask, OptionCode::Unknown(200)]
        );
    }
}
