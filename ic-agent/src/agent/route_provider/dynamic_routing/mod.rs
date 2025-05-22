//! A dynamic routing provider for the Internet Computer (IC) Agent that enables resilient, adaptive request routing through API boundary nodes.
//!
//! The `DynamicRouteProvider` is an implementation of the [`RouteProvider`](super::RouteProvider) trait. It dynamically discovers and monitors API boundary nodes, filters out unhealthy nodes, and routes API calls across healthy nodes using configurable strategies such as round-robin or latency-based routing.
//! This ensures robust and performant interactions with the IC network by adapting to changes in node availability and topology.
//!
//! # Overview
//! The IC Agent is capable of dispatching API calls to destination endpoints exposing an [HTTPS interface](https://internetcomputer.org/docs/references/ic-interface-spec#http-interface). These endpoints can be:
//! 1. **Replica nodes**: part of the ICP.
//! 2. **API boundary nodes**: part of the ICP.
//! 3. **HTTP Gateways**: Third-party services that proxy requests to API boundary nodes, e.g., gateways hosted on the `ic0.app` domain.
//!
//! The Agent uses the [`RouteProvider`](super::RouteProvider) trait, namely its [`route()`](super::RouteProvider::route()) method to determine the destination endpoint for each call.
//! For example this trait is implemented for [`Url`](https://docs.rs/url/latest/url/) and [`RoundRobinRouteProvider`](super::RoundRobinRouteProvider).
//! The `DynamicRouteProvider` is a more complex implementation, which is intended to be used only for option (2), it provides:
//! - **Automatic API Node Discovery**: periodically fetches the latest API boundary node topology.
//! - **Health Monitoring**: Continuously checks health of all nodes in the topology.
//! - **Flexible Routing**: Directs requests to healthy nodes using built-in or custom strategies:
//!   - [`RoundRobinRoutingSnapshot`](snapshot::round_robin_routing::RoundRobinRoutingSnapshot): Evenly distributes requests across healthy nodes.
//!   - [`LatencyRoutingSnapshot`](snapshot::latency_based_routing::LatencyRoutingSnapshot): Prioritizes low-latency nodes via weighted round-robin, with optional penalties if nodes are unavailable within a sliding time window.
//! - **Customizability**: Supports custom node fetchers, health checkers, and routing logic.
//! # Usage
//! The `DynamicRouteProvider` can be used standalone or injected into the agent to enable dynamic routing. There are several ways to instantiate it:
//! 1. **Via high-Level Agent API**: Initializes the agent with built-in dynamic routing. This method is user-friendly but provides limited customization options.
//! 2. **Via [`DynamicRouteProviderBuilder`](dynamic_route_provider::DynamicRouteProviderBuilder)**: Creates a customized `DynamicRouteProvider` with a specific routing strategy and parameters.
//! This instance can be used standalone or integrated into the agent via [`AgentBuilder::with_route_provider()`](super::super::AgentBuilder::with_route_provider).
//! ## Example: High-Level Agent API
//! ```rust
//! use anyhow::Result;
//! use ic_agent::Agent;
//! use url::Url;
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     // Use the URL of an IC HTTP Gateway or even better - API boundary node as the initial seed
//!     let seed_url = Url::parse("https://ic0.app")?;
//!
//!     // The agent starts with the seed node and discovers healthy API nodes dynamically
//!     // Until then, requests go through the seed, but only if it's healthy.
//!     let agent = Agent::builder()
//!         .with_url(seed_url)
//!         .with_background_dynamic_routing()
//!         .build()?;
//!
//!     // ... use the agent for API calls
//!
//!     Ok(())
//! }
//! ```
//! **Note**: In the example above, `ic0.app` is used as a seed for initial topology discovery. However, it is not a true seed, as it is not an API boundary node in the ICP topology.
//! It will be discarded after the first successful discovery.
//! ## Example: Customized instantiation
//! ```rust
//! use std::{sync::Arc, time::Duration};
//!
//! use anyhow::Result;
//! use ic_agent::{
//!     agent::route_provider::{
//!         dynamic_routing::{
//!             dynamic_route_provider::{DynamicRouteProvider, DynamicRouteProviderBuilder},
//!             node::Node,
//!             snapshot::latency_based_routing::LatencyRoutingSnapshot,
//!         },
//!         RouteProvider,
//!     },
//!     Agent,
//! };
//! use reqwest::Client;
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     // Choose a routing strategy: top 3 lowest-latency API boundary nodes selected via weighted round-robin
//!     let routing_strategy = LatencyRoutingSnapshot::new().set_k_top_nodes(3);
//!
//!     // Alternatively, use a basic round-robin routing across all healthy API boundary nodes
//!     // let routing_strategy = RoundRobinRoutingSnapshot::new();
//!
//!     // Or implement and provide your own custom routing strategy
//!
//!     // Seed nodes for initial topology discovery
//!     let seed_nodes = vec![
//!         Node::new("ic0.app")?,
//!         // Optional: add known API boundary nodes to improve resilience
//!         // Node::new("<api-boundary-node-domain>")?,
//!     ];
//!
//!     // HTTP client for health checks and topology discovery
//!     let client = Client::builder().build()?;
//!
//!     // Build dynamic route provider
//!     let route_provider: DynamicRouteProvider<LatencyRoutingSnapshot> =
//!         DynamicRouteProviderBuilder::new(routing_strategy, seed_nodes, Arc::new(client))
//!             // Set how often to fetch the latest API boundary node topology
//!             .with_fetch_period(Duration::from_secs(10))
//!             // Set how often to perform health checks on the API boundary nodes
//!             .with_check_period(Duration::from_secs(2))
//!             // Or optionally provide a custom node health checker implementation
//!             // .with_checker(custom_checker)
//!             // Or optionally provide a custom topology fetcher implementation
//!             // .with_fetcher(custom_fetcher)
//!             .build()
//!             .await;
//!
//!     // Example: generate routing URLs
//!     let url_1 = route_provider.route().expect("failed to get routing URL");
//!     eprintln!("Generated URL: {url_1}");
//!
//!     let url_2 = route_provider.route().expect("failed to get routing URL");
//!     eprintln!("Generated URL: {url_2}");
//!
//!     // Or inject route_provider into the agent for dynamic routing
//!     let agent = Agent::builder()
//!         .with_route_provider(route_provider)
//!         .build()?;
//!
//!     // ... use the agent for API calls
//!
//!     Ok(())
//! }
//! ```
//! # Implementation Details
//! The `DynamicRouteProvider` spawns two background services:
//! 1. `NodesFetchActor`: Periodically fetches the latest API boundary node topology and sends updates to the `HealthManagerActor`.
//! 2. `HealthManagerActor`: Manages health checks for nodes, starts and stops `HealthCheckActor`s and updates the routing table (routing snapshot) with health information.
//!
//! These background services ensure the routing table remains up-to-date.
//! # Configuration
//! The [`DynamicRouteProviderBuilder`](dynamic_route_provider::DynamicRouteProviderBuilder) allows customized instantiation of `DynamicRouteProvider`:
//! - **Fetch Period**: How often to fetch node topology (default: 5 seconds).
//! - **Health Check Period**: How often to check node health (default: 1 second).
//! - **Nodes Fetcher**: Custom implementation of the [`Fetch`](nodes_fetch::Fetch) trait for node discovery.
//! - **Health Checker**: Custom implementation of the [`HealthCheck`](health_check::HealthCheck) trait for health monitoring.
//! - **Routing Strategy**: Custom implementation of the [`RoutingSnapshot`](snapshot::routing_snapshot::RoutingSnapshot) trait for routing logic.
//! Two built-in strategies are available: [`LatencyRoutingSnapshot`](snapshot::latency_based_routing::LatencyRoutingSnapshot) and [`RoundRobinRoutingSnapshot`](snapshot::round_robin_routing::RoundRobinRoutingSnapshot).
//!
//! # Error Handling
//! Errors during node fetching or health checking are encapsulated in the [`DynamicRouteProviderError`](dynamic_route_provider::DynamicRouteProviderError) enum:
//! - `NodesFetchError`: Occurs when fetching the topology fails.
//! - `HealthCheckError`: Occurs when node health checks fail.
//! These errors are not propagated to the caller. Instead, they are logged internally using the `tracing` crate. To capture these errors, configure a `tracing` subscriber in your application.
//! If no healthy nodes are available, the [`route()`](super::RouteProvider::route()) method returns an [`AgentError::RouteProviderError`](super::super::agent_error::AgentError::RouteProviderError).
//! # Testing
//! The module includes comprehensive tests covering:
//! - Mainnet integration with dynamic node discovery.
//! - Routing behavior with topology and health updates.
//! - Edge cases like initially unhealthy seeds, no healthy nodes, and empty topology fetches.
//!
//! These tests ensure the `DynamicRouteProvider` behaves correctly in various scenarios.
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
#[cfg_attr(target_family = "wasm", allow(unused))]
pub(super) mod test_utils;
/// Type aliases used in dynamic routing.
pub(super) mod type_aliases;
