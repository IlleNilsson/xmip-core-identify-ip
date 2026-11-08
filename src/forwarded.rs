//! The forwarded chain: the addresses a proxy says a request passed through.
//!
//! Two headers carry it. `Forwarded` (RFC 7239) is a list of elements, each a
//! `;`-separated set of `name=value` pairs, of which `for` names a hop; the
//! value may be quoted, and an IPv6 address is bracketed with an optional
//! port. `X-Forwarded-For` is the older comma-separated list of bare
//! addresses. Both read client first, proxy last: each proxy appends itself
//! to the right, so the right end is the only end anyone this side of the
//! proxy can vouch for.
//!
//! A proxy writes one of the two, and the client may write either: a
//! `Forwarded` the client sent passes a proxy that only appends to
//! `X-Forwarded-For` untouched. So the header read is the one the proxy is
//! configured as writing, and the other is never read.

use std::net::IpAddr;

use context::property::{HTTP_FORWARDED, HTTP_X_FORWARDED_FOR};
use identify::{IdentifyError, StreamArrival};

/// The header a trusted proxy writes the chain into.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForwardedHeader {
    /// `Forwarded`, RFC 7239.
    Forwarded,
    /// `X-Forwarded-For`.
    XForwardedFor,
}

impl ForwardedHeader {
    /// The name the evidence gives it: `forwarded`, `x-forwarded-for`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Forwarded => "forwarded",
            Self::XForwardedFor => "x-forwarded-for",
        }
    }

    const fn property(self) -> &'static str {
        match self {
            Self::Forwarded => HTTP_FORWARDED,
            Self::XForwardedFor => HTTP_X_FORWARDED_FOR,
        }
    }
}

/// The chain `header` carries on the arrival, client first; `None` where
/// the arrival does not carry that header. The other header is not read.
///
/// # Errors
///
/// Where a hop in the header is not an address — RFC 7239 permits `unknown`
/// and obfuscated identifiers, and a chain with one in it cannot name a
/// client.
pub fn chain(
    arrival: &StreamArrival<'_>,
    header: ForwardedHeader,
) -> Result<Option<Vec<IpAddr>>, IdentifyError> {
    let Some(value) = arrival.property(header.property()) else {
        return Ok(None);
    };
    match header {
        ForwardedHeader::Forwarded => forwarded_for(value),
        ForwardedHeader::XForwardedFor => x_forwarded_for(value),
    }
    .map(Some)
}

/// The client in a chain: the first hop from the proxy end that is not a
/// trusted proxy. Where every hop is trusted, the leftmost is the client —
/// the proxies had nothing before them to name.
#[must_use]
pub fn client(chain: &[IpAddr], trusted: impl Fn(IpAddr) -> bool) -> Option<IpAddr> {
    chain
        .iter()
        .rev()
        .copied()
        .find(|hop| !trusted(*hop))
        .or_else(|| chain.first().copied())
}

/// The `for` hops of an RFC 7239 `Forwarded` value.
///
/// # Errors
///
/// Where a `for` value is not an address.
pub fn forwarded_for(value: &str) -> Result<Vec<IpAddr>, IdentifyError> {
    value
        .split(',')
        .filter_map(|element| {
            element.split(';').find_map(|pair| {
                let (name, hop) = pair.trim().split_once('=')?;
                name.trim()
                    .eq_ignore_ascii_case("for")
                    .then_some(hop.trim())
            })
        })
        .map(|hop| hop_address(hop.trim_matches('"'), "Forwarded"))
        .collect()
}

/// The hops of an `X-Forwarded-For` value.
///
/// # Errors
///
/// Where a hop is not an address.
pub fn x_forwarded_for(value: &str) -> Result<Vec<IpAddr>, IdentifyError> {
    value
        .split(',')
        .map(|hop| hop_address(hop.trim(), "X-Forwarded-For"))
        .collect()
}

fn hop_address(hop: &str, header: &str) -> Result<IpAddr, IdentifyError> {
    net::address::parse(hop).map_err(|_| {
        IdentifyError::new(format!(
            "the {header} header names {hop:?}, which is not an address"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use xcore::Arriving;

    fn address(text: &str) -> IpAddr {
        text.parse().expect("an address")
    }

    #[test]
    fn a_forwarded_element_names_its_hop_in_the_for_parameter() {
        let chain = forwarded_for(
            "for=192.0.2.60;proto=http;by=203.0.113.43, FOR=\"[2001:db8:cafe::17]:4711\"",
        )
        .expect("read");

        assert_eq!(
            chain,
            vec![address("192.0.2.60"), address("2001:db8:cafe::17")]
        );
    }

    #[test]
    fn an_obfuscated_hop_cannot_name_a_client() {
        let failure = forwarded_for("for=_hidden, for=192.0.2.60").expect_err("not an address");

        assert_eq!(
            failure.to_string(),
            "the Forwarded header names \"_hidden\", which is not an address"
        );
    }

    #[test]
    fn only_the_header_asked_for_is_read() {
        let facts = vec![
            (HTTP_FORWARDED.to_string(), "for=192.0.2.60".to_string()),
            (
                HTTP_X_FORWARDED_FOR.to_string(),
                "198.51.100.17".to_string(),
            ),
        ];
        let arrival = StreamArrival::new(Arriving::Pushed, "https://xmip/in", &facts);
        let bare = StreamArrival::new(Arriving::Pushed, "https://xmip/in", &[]);

        assert_eq!(
            chain(&arrival, ForwardedHeader::XForwardedFor).expect("read"),
            Some(vec![address("198.51.100.17")])
        );
        assert_eq!(
            chain(&arrival, ForwardedHeader::Forwarded).expect("read"),
            Some(vec![address("192.0.2.60")])
        );
        assert_eq!(
            chain(&bare, ForwardedHeader::Forwarded).expect("read"),
            None
        );
    }

    #[test]
    fn the_client_is_read_from_the_proxy_end_and_the_leftmost_when_all_are_ours() {
        let chain = [address("1.2.3.4"), address("10.0.0.1"), address("10.0.0.2")];
        let ours = |hop: IpAddr| hop.to_string().starts_with("10.");

        assert_eq!(client(&chain, ours), Some(address("1.2.3.4")));
        assert_eq!(client(&chain[1..], ours), Some(address("10.0.0.1")));
        assert_eq!(client(&[], ours), None);
    }
}
