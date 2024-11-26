//! Dynamic routing implementation.
//!
//! This is an internal unstable feature. The guts of this system are not subject to semver and are likely to change.

pub mod dynamic_route_provider;
/// Health check implementation.
pub mod health_check;
/// Messages used in dynamic routing.
pub(super) mod messages;
/// Node implementation.
pub mod node;
/// Nodes fetch implementation.
pub mod nodes_fetch;
/// Routing snapshot implementation.
pub mod snapshot;
#[cfg(test)]
pub(super) mod test_utils;
/// Type aliases used in dynamic routing.
pub(super) mod type_aliases;
