//! The testbed support library: config files and the local web UI server.
//!
//! [`config`] needs no feature flag. It parses the `keys/*.ini` app configs and is
//! tested in the default suite. [`server`] is the local web UI that picks, adds,
//! and runs those apps. It needs the real provider, loopback and HTTP edges, so it
//! sits behind the same feature flags as the `oauth_testbed` binary.
//!
//! This code is in the library, not the binary, on purpose: the binary stays a
//! short `main` that parses arguments and calls in here, and the config logic gets
//! library-level test coverage.

pub mod config;

#[cfg(all(feature = "reqwest-transport", feature = "loopback-flow"))]
mod page;
#[cfg(all(feature = "reqwest-transport", feature = "loopback-flow"))]
pub mod server;
