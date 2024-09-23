//! Dynamic routing implementation.
//!
//! This is an internal unstable feature. It works, but it's still in the oven; its design will go through drastic changes before it is released.

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
