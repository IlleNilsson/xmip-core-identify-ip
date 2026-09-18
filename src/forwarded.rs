//! The forwarded chain: the addresses a proxy says a request passed through.
//!
//! Two headers carry it. `Forwarded` (RFC 7239) is a list of elements, each a
//! `;`-separated set of `name=value` pairs, of which `for` names a hop; the
//! value may be quoted, and an IPv6 address is bracketed with an optional
//! port. `X-Forwarded-For` is the older comma-separated list of bare
//! addresses. Both read client first, proxy last: each proxy appends itself
//! to the right, so the right end is the only end anyone this side of the
//! proxy can vouch for.

use std::net::IpAddr;

use identify::{IdentifyError, StreamArrival};

/// The arrival property carrying RFC 7239 `Forwarded`.
pub const FORWARDED: &str = "http.header.forwarded";
/// The arrival property carrying `X-Forwarded-For`.
pub const X_FORWARDED_FOR: &str = "http.header.x-forwarded-for";

/// The chain the arrival carries, client first, and which header carried it.
/// `Forwarded` wins where both are present, being the standard one.
///
/// # Errors
///
/// Where a hop in the header is not an address — RFC 7239 permits `unknown`
/// and obfuscated identifiers, and a chain with one in it cannot name a
/// client.
pub fn chain(
    arrival: &StreamArrival<'_>,
) -> Result<Option<(&'static str, Vec<IpAddr>)>, IdentifyError> {
    if let Some(value) = arrival.property(FORWARDED) {
        return Ok(Some(("forwarded", forwarded_for(value)?)));
    }
    if let Some(value) = arrival.property(X_FORWARDED_FOR) {
        return Ok(Some(("x-forwarded-for", x_forwarded_for(value)?)));
    }

    Ok(None)
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
    crate::parse_address(hop).map_err(|_| {
        IdentifyError::new(format!(
            "the {header} header names {hop:?}, which is not an address"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn the_client_is_read_from_the_proxy_end_and_the_leftmost_when_all_are_ours() {
        let chain = [address("1.2.3.4"), address("10.0.0.1"), address("10.0.0.2")];
        let ours = |hop: IpAddr| hop.to_string().starts_with("10.");

        assert_eq!(client(&chain, ours), Some(address("1.2.3.4")));
        assert_eq!(client(&chain[1..], ours), Some(address("10.0.0.1")));
        assert_eq!(client(&[], ours), None);
    }
}
