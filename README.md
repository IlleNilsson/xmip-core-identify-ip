# xmip-core-identify-ip

Identify by ip: the peer address, read behind a trusted proxy from the one header that proxy writes; a transport-layer claim, passed. A technology of [xmip-core-identify](https://github.com/IlleNilsson/xmip-core-identify).

A trusted proxy is configured with the header it writes,
`IpIdentifier::new().trusting(network, ForwardedHeader::XForwardedFor)` or
`ForwardedHeader::Forwarded`. Behind it only that header is read; the other
is the client's own text, which the proxy passes untouched, and is ignored.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
