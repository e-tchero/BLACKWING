//! Session layer: connection lifecycle and secure encrypted connections.
//!
//! Provides [`Lifecycle`] state tracking and [`SecureConnection`] for
//! authenticated, encrypted sessions built on `bw-transport`.

pub mod lifecycle;
pub mod secure_conn;
pub mod wire;

pub use lifecycle::{ConnectionState, Lifecycle};
pub use secure_conn::{SecureConnError, SecureConnection};
