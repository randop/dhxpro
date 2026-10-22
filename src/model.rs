//! Versioned FeOxDB record types.
//!
//! Every value is encoded as a one-byte record format version followed by a
//! deterministic postcard payload. Unknown versions and malformed payloads are
//! rejected instead of being interpreted optimistically.
//!
//! Reservation and lease records are keyed by MAC only. One MAC has exactly
//! one reservation key and one lease key; the value carries an
//! `entries_by_subnet` map so the same MAC can hold independent state in
//! several configured subnet scopes.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::mac::MacAddr;

/// Current encoded record format version.
pub const RECORD_VERSION: u8 = 1;

pub const MAX_JOURNAL_OPS: usize = 1024;
pub const MAX_JOURNAL_KEY_LEN: usize = 512;
pub const MAX_JOURNAL_VALUE_LEN: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error("empty record")]
    Empty,
    #[error("unsupported record version {0}")]
    UnsupportedVersion(u8),
    #[error("malformed record payload: {0}")]
    Malformed(#[from] postcard::Error),
    #[error("record failed validation: {0}")]
    Invalid(String),
}

impl From<RecordError> for Error {
    fn from(value: RecordError) -> Self {
        Error::State(format!("persistent record error: {value}"))
    }
}

pub fn encode_record<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let payload = postcard::to_allocvec(value)
        .map_err(|error| Error::State(format!("failed to encode record: {error}")))?;
    let mut out = Vec::with_capacity(payload.len() + 1);
    out.push(RECORD_VERSION);
    out.extend_from_slice(&payload);
    Ok(out)
}

pub fn decode_record<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let (version, payload) = bytes.split_first().ok_or(RecordError::Empty)?;
    if *version != RECORD_VERSION {
        return Err(RecordError::UnsupportedVersion(*version).into());
    }
    postcard::from_bytes(payload).map_err(|error| RecordError::Malformed(error).into())
}

/// Lease lifecycle state. A lease record may hold one entry per subnet for
/// the same MAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseState {
    /// An address has been offered and is waiting for DHCPREQUEST. It blocks
    /// the address for other clients until `offer_expires_at`.
    Offered,
    /// A DHCPACK has been committed. The binding blocks the address until
    /// `lease_expires_at`.
    Active,
    /// The client reported an address conflict. The address stays quarantined
    /// until `declined_until`.
    Declined,
}

/// Role recorded in the IP-owner index. The index is the authoritative
/// uniqueness check for every IPv4 address in a configured subnet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OwnerRole {
    Reservation,
    Offer,
    Lease,
    Decline,
}

impl OwnerRole {
    pub fn is_permanent(self) -> bool {
        matches!(self, OwnerRole::Reservation)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReservationEntry {
    pub subnet_id: String,
    pub ip: Ipv4Addr,
    pub enabled: bool,
    pub hostname: Option<String>,
    pub client_id: Option<Vec<u8>>,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReservationRecord {
    pub mac: MacAddr,
    pub entries_by_subnet: BTreeMap<String, ReservationEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseEntry {
    pub subnet_id: String,
    pub ip: Ipv4Addr,
    pub client_id: Option<Vec<u8>>,
    pub hostname: Option<String>,
    pub state: LeaseState,
    pub lease_started_at: u64,
    pub lease_expires_at: u64,
    pub offer_expires_at: u64,
    pub declined_until: u64,
    /// Monotonic binding generation, incremented for every transition.
    pub generation: u64,
    pub updated_at: u64,
}

impl LeaseEntry {
    pub fn is_active_at(&self, now: u64) -> bool {
        self.state == LeaseState::Active && self.lease_expires_at > now
    }

    pub fn is_offered_at(&self, now: u64) -> bool {
        self.state == LeaseState::Offered && self.offer_expires_at > now
    }

    pub fn is_declined_at(&self, now: u64) -> bool {
        self.state == LeaseState::Declined && self.declined_until > now
    }

    /// True when this entry still prevents the address from being given to
    /// another client.
    pub fn blocks_at(&self, now: u64) -> bool {
        self.is_active_at(now) || self.is_offered_at(now) || self.is_declined_at(now)
    }

    /// Absolute time at which this entry stops blocking the address.
    pub fn blocking_until(&self) -> u64 {
        match self.state {
            LeaseState::Offered => self.offer_expires_at,
            LeaseState::Active => self.lease_expires_at,
            LeaseState::Declined => self.declined_until,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseRecord {
    pub mac: MacAddr,
    pub entries_by_subnet: BTreeMap<String, LeaseEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpOwner {
    pub ip: Ipv4Addr,
    pub subnet_id: String,
    pub mac: MacAddr,
    pub role: OwnerRole,
    /// Binding generation copied from the lease entry. Cleanup only removes
    /// an owner whose generation still matches the live binding.
    pub generation: u64,
    /// `0` means the entry does not expire on its own (reservations).
    pub expires_at: u64,
    pub updated_at: u64,
}

impl IpOwner {
    pub fn is_expired_at(&self, now: u64) -> bool {
        !self.role.is_permanent() && self.expires_at != 0 && self.expires_at <= now
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubnetMeta {
    pub subnet_id: String,
    /// Next candidate used by the incremental allocator.
    pub cursor: Ipv4Addr,
    /// Inclusive configured range the cursor belongs to. When the configured
    /// range changes, the cursor is reset through the journal.
    pub range_start: Ipv4Addr,
    pub range_end: Ipv4Addr,
    pub generation: u64,
    pub updated_at: u64,
}

/// A single put or delete belonging to a journaled logical mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum JournalOp {
    Put { key: Vec<u8>, value: Vec<u8> },
    Delete { key: Vec<u8> },
}

impl JournalOp {
    pub fn put(key: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> Self {
        Self::Put {
            key: key.into(),
            value: value.into(),
        }
    }

    pub fn delete(key: impl Into<Vec<u8>>) -> Self {
        Self::Delete { key: key.into() }
    }

    pub fn key(&self) -> &[u8] {
        match self {
            JournalOp::Put { key, .. } | JournalOp::Delete { key } => key,
        }
    }

    fn validate(&self) -> std::result::Result<(), RecordError> {
        let key = self.key();
        if key.is_empty() || key.len() > MAX_JOURNAL_KEY_LEN {
            return Err(RecordError::Invalid(format!(
                "journal key length {} is outside 1..={MAX_JOURNAL_KEY_LEN}",
                key.len()
            )));
        }
        if !key.starts_with(b"dhxpro:") {
            return Err(RecordError::Invalid(
                "journal key does not use the dhxpro namespace".to_string(),
            ));
        }
        if let JournalOp::Put { value, .. } = self {
            if value.is_empty() || value.len() > MAX_JOURNAL_VALUE_LEN {
                return Err(RecordError::Invalid(format!(
                    "journal value length {} is outside 1..={MAX_JOURNAL_VALUE_LEN}",
                    value.len()
                )));
            }
        }
        Ok(())
    }
}

/// Durable redo intent. Written and flushed before any of its operations are
/// applied; replayed idempotently at startup until it can be retired.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalIntent {
    pub sequence: u64,
    pub created_at: u64,
    pub ops: Vec<JournalOp>,
}

impl JournalIntent {
    pub fn validate(&self) -> std::result::Result<(), RecordError> {
        if self.ops.is_empty() {
            return Err(RecordError::Invalid(
                "journal intent contains no operations".to_string(),
            ));
        }
        if self.ops.len() > MAX_JOURNAL_OPS {
            return Err(RecordError::Invalid(format!(
                "journal intent contains {} operations (max {MAX_JOURNAL_OPS})",
                self.ops.len()
            )));
        }
        for op in &self.ops {
            op.validate()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry() -> LeaseEntry {
        LeaseEntry {
            subnet_id: "lan".to_string(),
            ip: Ipv4Addr::new(192, 168, 1, 100),
            client_id: Some(vec![1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            hostname: Some("host1".to_string()),
            state: LeaseState::Active,
            lease_started_at: 100,
            lease_expires_at: 3700,
            offer_expires_at: 0,
            declined_until: 0,
            generation: 4,
            updated_at: 100,
        }
    }

    #[test]
    fn lease_record_round_trips() {
        let mac = MacAddr::parse("aabbccddeeff").unwrap();
        let mut record = LeaseRecord {
            mac,
            ..Default::default()
        };
        record
            .entries_by_subnet
            .insert("lan".to_string(), sample_entry());
        record.entries_by_subnet.insert(
            "guest".to_string(),
            LeaseEntry {
                subnet_id: "guest".to_string(),
                ip: Ipv4Addr::new(10, 20, 0, 50),
                ..sample_entry()
            },
        );
        let encoded = encode_record(&record).unwrap();
        assert_eq!(encoded[0], RECORD_VERSION);
        let decoded: LeaseRecord = decode_record(&encoded).unwrap();
        assert_eq!(decoded, record);
        assert_eq!(decoded.entries_by_subnet.len(), 2);
    }

    #[test]
    fn same_mac_can_have_entries_in_multiple_subnets() {
        let mac = MacAddr::parse("aabbccddeeff").unwrap();
        let mut record = LeaseRecord {
            mac,
            ..Default::default()
        };
        for (subnet, octet) in [("lan", 100u8), ("guest", 50u8)] {
            record.entries_by_subnet.insert(
                subnet.to_string(),
                LeaseEntry {
                    subnet_id: subnet.to_string(),
                    ip: Ipv4Addr::new(192, 168, 1, octet),
                    ..sample_entry()
                },
            );
        }
        let decoded: LeaseRecord = decode_record(&encode_record(&record).unwrap()).unwrap();
        assert_eq!(decoded.entries_by_subnet["lan"].ip.octets()[3], 100);
        assert_eq!(decoded.entries_by_subnet["guest"].ip.octets()[3], 50);
        assert_eq!(decoded.mac, mac);
    }

    #[test]
    fn rejects_unknown_version() {
        let mac = MacAddr::parse("aabbccddeeff").unwrap();
        let encoded = encode_record(&LeaseRecord {
            mac,
            ..Default::default()
        })
        .unwrap();
        let mut bad = encoded;
        bad[0] = 9;
        let error = decode_record::<LeaseRecord>(&bad).unwrap_err();
        assert!(error.to_string().contains("unsupported record version 9"));
    }

    #[test]
    fn rejects_empty_and_truncated_records() {
        assert!(decode_record::<LeaseRecord>(&[]).is_err());
        let mac = MacAddr::parse("aabbccddeeff").unwrap();
        let encoded = encode_record(&LeaseRecord {
            mac,
            ..Default::default()
        })
        .unwrap();
        assert!(decode_record::<LeaseRecord>(&encoded[..encoded.len() - 1]).is_err());
    }

    #[test]
    fn journal_validation_bounds_operations() {
        let intent = JournalIntent {
            sequence: 1,
            created_at: 0,
            ops: vec![JournalOp::put("dhxpro:lease:v1:aabbccddeeff", vec![1])],
        };
        assert!(intent.validate().is_ok());

        let empty = JournalIntent {
            sequence: 1,
            created_at: 0,
            ops: vec![],
        };
        assert!(empty.validate().is_err());

        let foreign = JournalIntent {
            sequence: 1,
            created_at: 0,
            ops: vec![JournalOp::put("other:key", vec![1])],
        };
        assert!(foreign.validate().is_err());
    }

    #[test]
    fn blocking_windows_use_the_right_timestamp() {
        let mut entry = sample_entry();
        assert!(entry.is_active_at(3699));
        assert!(!entry.is_active_at(3700));
        assert!(!entry.blocks_at(3700));

        entry.state = LeaseState::Offered;
        entry.offer_expires_at = 150;
        assert!(entry.blocks_at(149));
        assert!(!entry.blocks_at(150));

        entry.state = LeaseState::Declined;
        entry.declined_until = 500;
        assert!(entry.blocks_at(499));
        assert!(!entry.blocks_at(500));
    }
}
