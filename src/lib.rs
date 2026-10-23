//! dhxpro — a small DHCPv4 server for embedded Linux.
//!
//! The server is deliberately split into independent layers:
//!
//! * [`config`] parses and validates the YAML configuration.
//! * [`keys`] and [`model`] define the versioned FeOxDB record layout.
//! * [`storage`] is the single-writer FeOxDB coordinator with a durable,
//!   idempotent redo journal.
//! * [`alloc`] implements address eligibility and the incremental/random
//!   allocators.
//! * [`dhcp`] parses and builds DHCPv4 packets without performing any I/O.
//! * [`net`] is the only module that touches DHCP network I/O. It uses
//!   `io_uring` exclusively (`RECVMSG`/`SENDMSG`).
//! * [`server`] implements the DHCPv4 state machine on top of the allocator
//!   and storage layer.

pub mod admin;
pub mod alloc;
pub mod config;
pub mod dhcp;
pub mod error;
pub mod keys;
pub mod mac;
pub mod model;
pub mod net;
pub mod preflight;
pub mod server;
pub mod storage;

pub use error::{Error, Result};
