//! Canonical FeOxDB key formats.
//!
//! MAC-keyed reservation and lease keys contain only the normalized MAC
//! address. Subnet scope is a field inside the versioned value
//! (`entries_by_subnet`), never part of the key.

use std::net::Ipv4Addr;

use crate::mac::MacAddr;

pub const RESERVATION_PREFIX: &str = "dhxpro:reservation:v1:";
pub const LEASE_PREFIX: &str = "dhxpro:lease:v1:";
pub const IP_OWNER_PREFIX: &str = "dhxpro:ip-owner:v1:";
pub const SUBNET_PREFIX: &str = "dhxpro:subnet:v1:";
pub const TXN_PREFIX: &str = "dhxpro:txn:v1:";

/// Width of the zero-padded journal sequence so that lexicographic order in
/// the store matches numeric order.
const TXN_SEQUENCE_WIDTH: usize = 20;

pub fn reservation_key(mac: MacAddr) -> String {
    format!("{RESERVATION_PREFIX}{}", mac.to_hex())
}

pub fn lease_key(mac: MacAddr) -> String {
    format!("{LEASE_PREFIX}{}", mac.to_hex())
}

/// The IPv4 component is canonical dotted-decimal.
pub fn ip_owner_key(ip: Ipv4Addr) -> String {
    format!("{IP_OWNER_PREFIX}{ip}")
}

pub fn subnet_key(subnet_id: &str) -> String {
    format!("{SUBNET_PREFIX}{subnet_id}")
}

pub fn txn_key(sequence: u64) -> String {
    format!("{TXN_PREFIX}{sequence:0TXN_SEQUENCE_WIDTH$}")
}

/// Parse a journal sequence from a full transaction key.
pub fn txn_sequence(key: &[u8]) -> Option<u64> {
    let suffix = key.strip_prefix(TXN_PREFIX.as_bytes())?;
    let suffix = std::str::from_utf8(suffix).ok()?;
    if suffix.is_empty() || !suffix.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    suffix.parse().ok()
}

/// Exclusive upper bound for a prefix scan.
///
/// Every dhxpro prefix is ASCII and none of them end in `0xff`, so
/// incrementing the final byte yields a bound that is greater than every key
/// sharing the prefix and smaller than any key belonging to a later prefix.
pub fn prefix_end(prefix: &str) -> Vec<u8> {
    let mut bytes = prefix.as_bytes().to_vec();
    for index in (0..bytes.len()).rev() {
        if bytes[index] != 0xff {
            bytes[index] += 1;
            bytes.truncate(index + 1);
            return bytes;
        }
    }
    // All bytes were 0xff: the only safe bound is "all keys".
    vec![0xff; 512]
}

/// Scan bounds `(start, end)` for an inclusive FeOxDB range query.
pub fn prefix_bounds(prefix: &str) -> (Vec<u8>, Vec<u8>) {
    (prefix.as_bytes().to_vec(), prefix_end(prefix))
}

pub fn is_dhxpro_key(key: &[u8]) -> bool {
    key.starts_with(b"dhxpro:")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_key_formats() {
        let mac = MacAddr::parse("AA:BB:CC:DD:EE:FF").unwrap();
        assert_eq!(reservation_key(mac), "dhxpro:reservation:v1:aabbccddeeff");
        assert_eq!(lease_key(mac), "dhxpro:lease:v1:aabbccddeeff");
        assert_eq!(
            ip_owner_key(Ipv4Addr::new(192, 168, 1, 100)),
            "dhxpro:ip-owner:v1:192.168.1.100"
        );
        assert_eq!(subnet_key("lan"), "dhxpro:subnet:v1:lan");
        assert_eq!(txn_key(42), "dhxpro:txn:v1:00000000000000000042");
    }

    #[test]
    fn mac_key_suffix_never_contains_subnet() {
        let mac = MacAddr::parse("aabbccddeeff").unwrap();
        let key = lease_key(mac);
        assert!(!key.contains("lan"));
        assert_eq!(key.rsplit(':').next().unwrap(), "aabbccddeeff");
        assert_eq!(key.rsplit(':').next().unwrap().len(), 12);
    }

    #[test]
    fn prefix_bounds_cover_the_prefix_only() {
        let (start, end) = prefix_bounds(LEASE_PREFIX);
        assert!(start < end);
        assert!(start <= b"dhxpro:lease:v1:aabbccddeeff".to_vec());
        assert!(b"dhxpro:lease:v1:aabbccddeeff".to_vec() < end);
        assert!(end <= b"dhxpro:subnet:v1:lan".to_vec());
    }

    #[test]
    fn transaction_sequence_round_trips() {
        for sequence in [0u64, 1, 42, u64::MAX] {
            assert_eq!(txn_sequence(txn_key(sequence).as_bytes()), Some(sequence));
        }
        assert_eq!(txn_sequence(b"dhxpro:txn:v1:nope"), None);
    }
}
