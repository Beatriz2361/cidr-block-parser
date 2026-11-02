//! CIDR block parsing and validation for IPv4 and IPv6.
//!
//! This crate provides a small, dependency-free type for representing a CIDR
//! block. It parses textual notation, validates the prefix length, and exposes
//! the network address, broadcast address, and the first/last host addresses.
//!
//! The implementation is deliberately strict: it rejects host bits set outside
//! the prefix (for example `192.168.1.5/24`), because silently masking them
//! would hide configuration mistakes. If you need to normalise such input,
//! call [`CidrBlock::parse`] is the wrong tool; use a dedicated normaliser.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Errors returned when parsing a CIDR block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CidrError {
    /// The input did not contain exactly one `/`.
    MissingSlash,
    /// The address part could not be parsed as an IP address.
    InvalidAddress,
    /// The prefix length was not a valid decimal integer.
    InvalidPrefix,
    /// The prefix length was outside the range allowed for the address family.
    PrefixOutOfRange,
    /// The address has bits set outside the prefix.
    HostBitsSet,
}

impl fmt::Display for CidrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            CidrError::MissingSlash => "CIDR block must contain exactly one '/' separator",
            CidrError::InvalidAddress => "invalid IP address",
            CidrError::InvalidPrefix => "invalid prefix length",
            CidrError::PrefixOutOfRange => "prefix length out of range for address family",
            CidrError::HostBitsSet => "address contains host bits outside the prefix",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for CidrError {}

/// A parsed and validated CIDR block.
///
/// The address stored is the network address: host bits are guaranteed to be
/// zero. The broadcast address is derived from the network address and the
/// prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CidrBlock {
    network: IpAddr,
    prefix: u8,
}

impl CidrBlock {
    /// Parse a CIDR block from its textual representation.
    ///
    /// The input must be `<address>/<prefix>`, where `<address>` is a valid
    /// IPv4 or IPv6 literal and `<prefix>` is a decimal integer within the
    /// range for that family. The address must not have host bits set outside
    /// the prefix.
    pub fn parse(s: &str) -> Result<Self, CidrError> {
        let (addr_part, prefix_part) = split_once_slash(s)?;

        let addr: IpAddr = addr_part
            .parse()
            .map_err(|_| CidrError::InvalidAddress)?;

        let prefix: u8 = prefix_part
            .parse()
            .map_err(|_| CidrError::InvalidPrefix)?;

        let max_prefix = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };

        if prefix > max_prefix {
            return Err(CidrError::PrefixOutOfRange);
        }

        let network = match addr {
            IpAddr::V4(v4) => {
                let mask = ipv4_mask(prefix);
                let raw = u32::from(v4);
                if raw & !mask != 0 {
                    return Err(CidrError::HostBitsSet);
                }
                IpAddr::V4(Ipv4Addr::from(raw))
            }
            IpAddr::V6(v6) => {
                let mask = ipv6_mask(prefix);
                let raw = u128::from(v6);
                if raw & !mask != 0 {
                    return Err(CidrError::HostBitsSet);
                }
                IpAddr::V6(Ipv6Addr::from(raw))
            }
        };

        Ok(CidrBlock { network, prefix })
    }

    /// The network address of the block.
    pub fn network(&self) -> IpAddr {
        self.network
    }

    /// The prefix length in bits.
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// The broadcast address of the block.
    ///
    /// For IPv4 this is the highest address in the block. For IPv6 the term
    /// "broadcast" is not used by the standard, but the value returned is the
    /// highest address in the block, which is the analogue.
    pub fn broadcast(&self) -> IpAddr {
        match self.network {
            IpAddr::V4(v4) => {
                let mask = ipv4_mask(self.prefix);
                let raw = u32::from(v4);
                let broadcast = raw | !mask;
                IpAddr::V4(Ipv4Addr::from(broadcast))
            }
            IpAddr::V6(v6) => {
                let mask = ipv6_mask(self.prefix);
                let raw = u128::from(v6);
                let broadcast = raw | !mask;
                IpAddr::V6(Ipv6Addr::from(broadcast))
            }
        }
    }

    /// The first usable host address in the block.
    ///
    /// For IPv4 blocks with a prefix shorter than 31, this is the network
    /// address plus one. For `/31` and `/32` there is no separate host range
    /// in the traditional sense, so the network address itself is returned.
    /// For IPv6 the first address after the network address is returned.
    pub fn first_host(&self) -> IpAddr {
        match self.network {
            IpAddr::V4(v4) => {
                if self.prefix >= 31 {
                    return self.network;
                }
                let raw = u32::from(v4);
                IpAddr::V4(Ipv4Addr::from(raw + 1))
            }
            IpAddr::V6(v6) => {
                let raw = u128::from(v6);
                IpAddr::V6(Ipv6Addr::from(raw + 1))
            }
        }
    }

    /// The last usable host address in the block.
    ///
    /// For IPv4 blocks with a prefix shorter than 31, this is the broadcast
    /// address minus one. For `/31` and `/32` the broadcast address itself is
    /// returned. For IPv6 the address before the broadcast address is returned.
    pub fn last_host(&self) -> IpAddr {
        match self.network {
            IpAddr::V4(v4) => {
                if self.prefix >= 31 {
                    return self.broadcast();
                }
                let mask = ipv4_mask(self.prefix);
                let raw = u32::from(v4);
                let broadcast = raw | !mask;
                IpAddr::V4(Ipv4Addr::from(broadcast - 1))
            }
            IpAddr::V6(v6) => {
                let mask = ipv6_mask(self.prefix);
                let raw = u128::from(v6);
                let broadcast = raw | !mask;
                IpAddr::V6(Ipv6Addr::from(broadcast - 1))
            }
        }
    }

    /// Returns `true` if `addr` falls within this block.
    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self.network, addr) {
            (IpAddr::V4(net), IpAddr::V4(a)) => {
                let mask = ipv4_mask(self.prefix);
                (u32::from(net) & mask) == (u32::from(a) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(a)) => {
                let mask = ipv6_mask(self.prefix);
                (u128::from(net) & mask) == (u128::from(a) & mask)
            }
            _ => false,
        }
    }
}

impl FromStr for CidrBlock {
    type Err = CidrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        CidrBlock::parse(s)
    }
}

impl fmt::Display for CidrBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

/// Split the input at the single `/` separator.
///
/// Returns an error if there is no slash or if there is more than one.
fn split_once_slash(s: &str) -> Result<(&str, &str), CidrError> {
    let mut parts = s.splitn(2, '/');
    let addr = parts.next().ok_or(CidrError::MissingSlash)?;
    let prefix = parts.next().ok_or(CidrError::MissingSlash)?;
    if prefix.contains('/') {
        return Err(CidrError::MissingSlash);
    }
    Ok((addr, prefix))
}

/// Build the IPv4 netmask for a prefix length.
fn ipv4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

/// Build the IPv6 netmask for a prefix length.
fn ipv6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_block() {
        let block = CidrBlock::parse("192.168.1.0/24").unwrap();
        assert_eq!(block.network(), "192.168.1.0".parse::<IpAddr>().unwrap());
        assert_eq!(block.prefix(), 24);
        assert_eq!(block.broadcast(), "192.168.1.255".parse::<IpAddr>().unwrap());
        assert_eq!(block.first_host(), "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(block.last_host(), "192.168.1.254".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parses_ipv6_block() {
        let block = CidrBlock::parse("2001:db8::/32").unwrap();
        assert_eq!(block.network(), "2001:db8::".parse::<IpAddr>().unwrap());
        assert_eq!(block.prefix(), 32);
        assert_eq!(
            block.broadcast(),
            "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            block.first_host(),
            "2001:db8::1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn rejects_host_bits_set() {
        assert_eq!(
            CidrBlock::parse("192.168.1.5/24").unwrap_err(),
            CidrError::HostBitsSet
        );
    }

    #[test]
    fn rejects_invalid_address() {
        assert_eq!(
            CidrBlock::parse("not-an-ip/24").unwrap_err(),
            CidrError::InvalidAddress
        );
    }

    #[test]
    fn rejects_invalid_prefix() {
        assert_eq!(
            CidrBlock::parse("10.0.0.0/abc").unwrap_err(),
            CidrError::InvalidPrefix
        );
    }

    #[test]
    fn rejects_prefix_out_of_range() {
        assert_eq!(
            CidrBlock::parse("10.0.0.0/33").unwrap_err(),
            CidrError::PrefixOutOfRange
        );
        assert_eq!(
            CidrBlock::parse("::1/129").unwrap_err(),
            CidrError::PrefixOutOfRange
        );
    }

    #[test]
    fn rejects_missing_slash() {
        assert_eq!(
            CidrBlock::parse("10.0.0.0").unwrap_err(),
            CidrError::MissingSlash
        );
    }

    #[test]
    fn rejects_multiple_slashes() {
        assert_eq!(
            CidrBlock::parse("10.0.0.0/24/8").unwrap_err(),
            CidrError::MissingSlash
        );
    }

    #[test]
    fn handles_zero_prefix_ipv4() {
        let block = CidrBlock::parse("0.0.0.0/0").unwrap();
        assert_eq!(block.network(), "0.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(block.broadcast(), "255.255.255.255".parse::<IpAddr>().unwrap());
        assert_eq!(block.first_host(), "0.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(block.last_host(), "255.255.255.254".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn handles_slash_32_ipv4() {
        let block = CidrBlock::parse("192.168.1.1/32").unwrap();
        assert_eq!(block.network(), "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(block.broadcast(), "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(block.first_host(), "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(block.last_host(), "192.168.1.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn handles_slash_31_ipv4() {
        let block = CidrBlock::parse("192.168.1.0/31").unwrap();
        assert_eq!(block.network(), "192.168.1.0".parse::<IpAddr>().unwrap());
        assert_eq!(block.broadcast(), "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(block.first_host(), "192.168.1.0".parse::<IpAddr>().unwrap());
        assert_eq!(block.last_host(), "192.168.1.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn contains_ipv4() {
        let block = CidrBlock::parse("10.0.0.0/8").unwrap();
        assert!(block.contains("10.1.2.3".parse().unwrap()));
        assert!(!block.contains("11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn contains_ipv6() {
        let block = CidrBlock::parse("2001:db8::/32").unwrap();
        assert!(block.contains("2001:db8::1".parse().unwrap()));
        assert!(!block.contains("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn contains_mixed_families_is_false() {
        let block = CidrBlock::parse("10.0.0.0/8").unwrap();
        assert!(!block.contains("::1".parse().unwrap()));
    }

    #[test]
    fn display_round_trips() {
        let block = CidrBlock::parse("172.16.0.0/12").unwrap();
        assert_eq!(block.to_string(), "172.16.0.0/12");
    }

    #[test]
    fn from_str_works() {
        let block: CidrBlock = "192.0.2.0/24".parse().unwrap();
        assert_eq!(block.prefix(), 24);
    }
}
