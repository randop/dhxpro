//! FeOxDB-backed storage.
//!
//! Every mutation goes through [`StateCoordinator`], which owns the single
//! writer and the durable redo journal. [`Repo`] is the typed key-value layer.

mod coordinator;
mod repo;

pub use coordinator::{Clock, StateCoordinator, StoreHealth, MIN_VALID_TIME};
pub use repo::{Repo, StoreLock, StoreOptions};

#[cfg(test)]
pub use coordinator::Fault;
