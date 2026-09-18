//! An address or a prefix of them, as a trusted-proxy list is written.
//!
//! `10.0.0.5` is one address; `10.0.0.0/8` is every address whose first
//! eight bits match; `2001:db8::/32` the same for IPv6. A prefix never
//! contains an address of the other family.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use identify::IdentifyError;

/// One address, or every address under a prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Network {
    address: IpAddr,
    prefix: u8,
}

impl Network {
    /// Read `address` or `address/prefix`.
    ///
    /// # Errors
    ///
    /// Where the address does not parse or the prefix is longer than the
    /// address has bits.
    pub fn parse(text: &str) -> Result<Self, IdentifyError> {
        let text = text.trim();
        let (address, prefix) = match text.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (text, None),
        };

        let address = address
            .parse::<IpAddr>()
            .map_err(|_| IdentifyError::new(format!("{text:?} is not an address or a prefix")))?;
        let bits = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix = match prefix {
            Some(prefix) => prefix
                .parse::<u8>()
                .ok()
                .filter(|length| *length <= bits)
                .ok_or_else(|| {
                    IdentifyError::new(format!("{text:?} has a prefix longer than {bits} bits"))
                })?,
            None => bits,
        };

        Ok(Self { address, prefix })
    }

    /// Whether the address is this one, or under this prefix.
    #[must_use]
    pub fn contains(&self, candidate: IpAddr) -> bool {
        match (self.address, candidate) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => {
                masked_v4(network, self.prefix) == masked_v4(candidate, self.prefix)
            }
            (IpAddr::V6(network), IpAddr::V6(candidate)) => {
                masked_v6(network, self.prefix) == masked_v6(candidate, self.prefix)
            }
            _ => false,
        }
    }
}

impl FromStr for Network {
    type Err = IdentifyError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

fn masked_v4(address: Ipv4Addr, prefix: u8) -> u32 {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    u32::from(address) & mask
}

fn masked_v6(address: Ipv6Addr, prefix: u8) -> u128 {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    };
    u128::from(address) & mask
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(text: &str) -> IpAddr {
        text.parse().expect("an address")
    }

    #[test]
    fn a_prefix_contains_what_is_under_it_and_nothing_of_the_other_family() {
        let ten: Network = "10.0.0.0/8".parse().expect("a prefix");
        let documentation: Network = "2001:db8::/32".parse().expect("a prefix");

        assert!(ten.contains(address("10.255.1.2")));
        assert!(!ten.contains(address("11.0.0.1")));
        assert!(documentation.contains(address("2001:db8:cafe::17")));
        assert!(!documentation.contains(address("2001:db9::1")));
        assert!(!ten.contains(address("::ffff:10.0.0.1")));
    }

    #[test]
    fn a_bare_address_is_a_prefix_of_one() {
        let one = Network::parse("192.0.2.1").expect("an address");

        assert!(one.contains(address("192.0.2.1")));
        assert!(!one.contains(address("192.0.2.2")));
    }

    #[test]
    fn a_prefix_longer_than_the_address_is_refused_by_name() {
        let failure = Network::parse("192.0.2.0/33").expect_err("too long");

        assert_eq!(
            failure.to_string(),
            "\"192.0.2.0/33\" has a prefix longer than 32 bits"
        );
        assert!(Network::parse("partner.example").is_err());
    }
}
