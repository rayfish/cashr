//! Relay-backed [`Transport`] for the signer, over yawc websockets.
//!
//! [`Transport`]: signer_core::transport::Transport

#![forbid(unsafe_code)]

mod auth;
mod connection;
pub mod transport;

pub use transport::RelayTransport;
