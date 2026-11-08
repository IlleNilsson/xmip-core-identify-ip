#![forbid(unsafe_code)]

//! Identify by ip: the peer address is the claim.
//!
//! The commonest allow-list there is, and spoofable on most networks, which
//! is why the mechanism identifies and never authenticates
//! ([`xcore::mechanism::ip`]). The transport puts the socket peer on the
//! arrival as [`context::property::PEER_ADDRESS`] — `192.0.2.10:4711`, `[2001:db8::1]:443` or a
//! bare address — and this presents the address without its port, passed.
//!
//! A load balancer or reverse proxy in front of the node makes the socket
//! peer the proxy. The identifier takes a list of trusted proxies, as
//! addresses or prefixes, each with the one header it writes: `Forwarded`
//! (RFC 7239, the `for` parameter) or `X-Forwarded-For`. Only where the
//! socket peer is one of them is that proxy's header read off the arrival:
//! walking the chain from the proxy end, the first address that is not a
//! trusted proxy is the client. A forwarded header from an untrusted peer,
//! and the header a trusted proxy does not write, are ignored, because the
//! client can write either and a proxy passes the one it does not write
//! untouched.
//!
//! Only a pushed Stream has a peer. A detected or scheduled arrival presents
//! nothing here however the property reads: nobody connected, and the
//! address on it is a broker's or a server's, not a sender's.
//!
//! Property names this technology defines for the transports:
//! `peer.address`, `http.header.forwarded`, `http.header.x-forwarded-for`.
//! Evidence it writes: `peer.address` (the socket peer, where the claim came
//! through a proxy) and `ip.forwarded-by` (which header said so).

pub mod forwarded;

pub use forwarded::ForwardedHeader;

use std::net::IpAddr;

use context::property::PEER_ADDRESS;
use identify::{IdentifyError, Presented, StreamArrival, TransportIdentifier};
use net::Network;
use xcore::{Arriving, Mechanism};

/// Reads the peer address, through a trusted proxy where there is one.
#[derive(Clone, Debug, Default)]
pub struct IpIdentifier {
    trusted: Vec<(Network, ForwardedHeader)>,
}

impl IpIdentifier {
    /// Trusts no proxy: the socket peer is always the claim.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Trust a proxy that writes `header`. That header is read only where
    /// the socket peer is this proxy, and no other header from it is; the
    /// client is the first hop from the proxy end that is not trusted.
    #[must_use]
    pub fn trusting(mut self, proxy: Network, header: ForwardedHeader) -> Self {
        self.trusted.push((proxy, header));
        self
    }

    /// Whether this address is one of the trusted proxies.
    #[must_use]
    pub fn trusts(&self, address: IpAddr) -> bool {
        self.header_of(address).is_some()
    }

    /// The header the trusted proxy at `address` writes, the first entry
    /// naming it deciding.
    fn header_of(&self, address: IpAddr) -> Option<ForwardedHeader> {
        self.trusted
            .iter()
            .find(|(proxy, _)| proxy.contains(address))
            .map(|(_, header)| *header)
    }
}

impl TransportIdentifier for IpIdentifier {
    fn mechanism(&self) -> Mechanism {
        xcore::mechanism::ip()
    }

    fn identify(&self, arrival: &StreamArrival<'_>) -> Result<Option<Presented>, IdentifyError> {
        if arrival.arriving() != Arriving::Pushed {
            return Ok(None);
        }

        let Some(peer) = arrival.property(PEER_ADDRESS) else {
            return Ok(None);
        };
        let peer = net::address::parse(peer)?;

        if let Some(header) = self.header_of(peer)
            && let Some(chain) = forwarded::chain(arrival, header)?
            && let Some(client) = forwarded::client(&chain, |hop| self.trusts(hop))
        {
            return Ok(Some(
                Presented::passed(self.mechanism(), client.to_string())
                    .with_evidence(PEER_ADDRESS, peer.to_string())
                    .with_evidence("ip.forwarded-by", header.name()),
            ));
        }

        Ok(Some(Presented::passed(self.mechanism(), peer.to_string())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect()
    }

    fn behind_proxies() -> IpIdentifier {
        IpIdentifier::new()
            .trusting(
                Network::parse("10.0.0.0/8").expect("a prefix"),
                ForwardedHeader::Forwarded,
            )
            .trusting(
                Network::parse("2001:db8::1").expect("an address"),
                ForwardedHeader::XForwardedFor,
            )
    }

    #[test]
    fn a_header_the_trusted_proxy_does_not_write_is_the_clients_and_ignored() {
        // The attack: the proxy at 2001:db8::1 appends to X-Forwarded-For
        // and passes a Forwarded the client wrote untouched.
        let spoofed = facts(&[
            ("peer.address", "[2001:db8::1]:443"),
            ("http.header.forwarded", "for=192.0.2.1"),
            ("http.header.x-forwarded-for", "198.51.100.17"),
        ]);
        let arrival = StreamArrival::new(Arriving::Pushed, "https://xmip/in", &spoofed);

        let claim = behind_proxies()
            .identify(&arrival)
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.value, "198.51.100.17");
        assert_eq!(claim.evidence[1].1, "x-forwarded-for");

        // And the other way round: a proxy that writes Forwarded does not
        // make an X-Forwarded-For the client wrote the claim.
        let spoofed = facts(&[
            ("peer.address", "10.1.2.3:80"),
            ("http.header.forwarded", "for=198.51.100.17"),
            ("http.header.x-forwarded-for", "192.0.2.1"),
        ]);
        let arrival = StreamArrival::new(Arriving::Pushed, "https://xmip/in", &spoofed);

        let claim = behind_proxies()
            .identify(&arrival)
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.value, "198.51.100.17");
        assert_eq!(claim.evidence[1].1, "forwarded");

        // Only the header it does not write: the peer itself is the claim.
        let alone = facts(&[
            ("peer.address", "10.1.2.3:80"),
            ("http.header.x-forwarded-for", "192.0.2.1"),
        ]);
        let arrival = StreamArrival::new(Arriving::Pushed, "https://xmip/in", &alone);

        let claim = behind_proxies()
            .identify(&arrival)
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.value, "10.1.2.3");
    }

    #[test]
    fn the_socket_peer_is_the_claim_without_its_port() {
        let facts = facts(&[("peer.address", "192.0.2.10:4711")]);
        let arrival = StreamArrival::new(Arriving::Pushed, "https://xmip/in", &facts);

        let claim = IpIdentifier::new()
            .identify(&arrival)
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.value, "192.0.2.10");
        assert_eq!(claim.mechanism.name(), "ip");
        assert!(claim.evidence.is_empty(), "no proxy, nothing to explain");
    }

    #[test]
    fn a_forwarded_header_is_read_only_behind_a_trusted_proxy() {
        let through_proxy = facts(&[
            ("peer.address", "10.1.2.3:80"),
            ("http.header.forwarded", "for=198.51.100.17;proto=https"),
        ]);
        let arrival = StreamArrival::new(Arriving::Pushed, "https://xmip/in", &through_proxy);

        let claim = behind_proxies()
            .identify(&arrival)
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.value, "198.51.100.17");
        assert_eq!(
            claim.evidence,
            vec![
                ("peer.address".to_string(), "10.1.2.3".to_string()),
                ("ip.forwarded-by".to_string(), "forwarded".to_string()),
            ]
        );

        // The same header from a peer nobody trusts is just text.
        let from_anyone = facts(&[
            ("peer.address", "203.0.113.9:80"),
            ("http.header.forwarded", "for=198.51.100.17"),
        ]);
        let arrival = StreamArrival::new(Arriving::Pushed, "https://xmip/in", &from_anyone);

        let claim = behind_proxies()
            .identify(&arrival)
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.value, "203.0.113.9");
    }

    #[test]
    fn the_client_is_the_first_untrusted_hop_from_the_proxy_end() {
        // Two proxies of ours appended themselves; the hop before them is the
        // client, and whatever the client itself wrote to the left is ignored.
        let facts = facts(&[
            ("peer.address", "[2001:db8::1]:443"),
            (
                "http.header.x-forwarded-for",
                "1.2.3.4, 198.51.100.17, 10.0.0.5",
            ),
        ]);
        let arrival = StreamArrival::new(Arriving::Pushed, "https://xmip/in", &facts);

        let claim = behind_proxies()
            .identify(&arrival)
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.value, "198.51.100.17");
        assert_eq!(claim.evidence[1].1, "x-forwarded-for");
    }

    #[test]
    fn an_arrival_with_no_peer_presents_nothing() {
        let arrival = StreamArrival::new(Arriving::Pushed, "file:///in/x", &[]);

        assert!(
            IpIdentifier::new()
                .identify(&arrival)
                .expect("read")
                .is_none()
        );
    }

    #[test]
    fn a_peer_that_is_not_an_address_is_an_error() {
        let facts = facts(&[("peer.address", "party.example")]);
        let arrival = StreamArrival::new(Arriving::Pushed, "https://xmip/in", &facts);

        let failure = IpIdentifier::new()
            .identify(&arrival)
            .expect_err("not an address");

        assert_eq!(
            failure.to_string(),
            "the peer address \"party.example\" is not an IP address"
        );
    }

    #[test]
    fn a_scheduled_pickup_has_no_peer_to_present() {
        // Xmip was the client; the address on the arrival is the server's.
        let facts = facts(&[("peer.address", "192.0.2.10:21")]);
        let arrival = StreamArrival::new(Arriving::Scheduled, "ftp://party/out", &facts);

        assert!(
            IpIdentifier::new()
                .identify(&arrival)
                .expect("read")
                .is_none()
        );
    }
}
