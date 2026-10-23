use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// A six-octet Ethernet hardware address.
///
/// The canonical textual representation is 12 lowercase hexadecimal
/// characters without separators, e.g. `aabbccddeeff`. This form is used
/// verbatim in the FeOxDB reservation and lease keys.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MacAddr([u8; 6]);

impl Default for MacAddr {
    /// The all-zero address. Records use this only as a placeholder until the
    /// real MAC is filled in; it is never accepted from the wire or used as a
    /// stored key.
    fn default() -> Self {
        Self([0; 6])
    }
}

impl MacAddr {
    pub const LEN: usize = 6;

    pub const fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; 6] = bytes.try_into().map_err(|_| Error::Mac {
            input: hex_lower(bytes),
            reason: format!("expected {} bytes, got {}", Self::LEN, bytes.len()),
        })?;
        Ok(Self(bytes))
    }

    /// Parse a MAC address from common textual forms:
    /// `aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff`, `aabb.ccdd.eeff` or
    /// `aabbccddeeff`. Parsing is case insensitive.
    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        let mut digits = String::with_capacity(12);
        for ch in trimmed.chars() {
            match ch {
                ':' | '-' | '.' => {}
                c if c.is_ascii_hexdigit() => digits.push(c.to_ascii_lowercase()),
                _ => {
                    return Err(Error::Mac {
                        input: trimmed.to_string(),
                        reason: format!("unexpected character {ch:?}"),
                    })
                }
            }
        }
        if digits.len() != 12 {
            return Err(Error::Mac {
                input: trimmed.to_string(),
                reason: format!("expected 12 hexadecimal digits, got {}", digits.len()),
            });
        }
        let mut bytes = [0u8; 6];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let start = index * 2;
            *byte = u8::from_str_radix(&digits[start..start + 2], 16).map_err(|_| Error::Mac {
                input: trimmed.to_string(),
                reason: "invalid hexadecimal byte".to_string(),
            })?;
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }

    pub fn octets(&self) -> [u8; 6] {
        self.0
    }

    /// Canonical key suffix: 12 lowercase hex characters, no separators.
    pub fn to_hex(&self) -> String {
        hex_lower(&self.0)
    }

    /// Reject addresses that cannot identify a DHCP client: the all-zero
    /// address, the broadcast address and multicast group addresses.
    pub fn is_usable_client(&self) -> bool {
        if self.0 == [0u8; 6] || self.0 == [0xffu8; 6] {
            return false;
        }
        // The least significant bit of the first octet marks group addresses.
        self.0[0] & 0x01 == 0
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddr({})", self.to_hex())
    }
}

impl fmt::LowerHex for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_separator_styles() {
        let expected = MacAddr::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        for input in [
            "aa:bb:cc:dd:ee:ff",
            "AA-BB-CC-DD-EE-FF",
            "aabb.ccdd.eeff",
            "aabbccddeeff",
            " AA:BB:CC:DD:EE:FF ",
        ] {
            assert_eq!(MacAddr::parse(input).unwrap(), expected, "{input}");
        }
    }

    #[test]
    fn rejects_malformed_input() {
        for input in ["", "aa:bb:cc:dd:ee", "aabbccddeefg", "aa:bb:cc:dd:ee:ff:00"] {
            assert!(MacAddr::parse(input).is_err(), "{input}");
        }
    }

    #[test]
    fn canonical_hex_is_lowercase_and_unseparated() {
        let mac = MacAddr::parse("AA:BB:CC:DD:EE:0F").unwrap();
        assert_eq!(mac.to_hex(), "aabbccddee0f");
        assert_eq!(mac.to_string(), "aabbccddee0f");
    }

    #[test]
    fn rejects_non_unicast_addresses() {
        assert!(!MacAddr::new([0; 6]).is_usable_client());
        assert!(!MacAddr::new([0xff; 6]).is_usable_client());
        assert!(!MacAddr::new([0x01, 0, 0, 0, 0, 0]).is_usable_client());
        assert!(MacAddr::new([0x02, 0, 0, 0, 0, 0]).is_usable_client());
    }
}
