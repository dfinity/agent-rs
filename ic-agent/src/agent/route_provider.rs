//! A [`RouteProvider`] for dynamic generation of routing urls.
use arc_swap::ArcSwapOption;
use dynamic_routing::{
    dynamic_route_provider::DynamicRouteProviderBuilder,
    node::Node,
    snapshot::{
        latency_based_routing::LatencyRoutingSnapshot,
        round_robin_routing::RoundRobinRoutingSnapshot,
    },
};
use std::{
    future::Future,
    str::FromStr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use url::Url;

use crate::agent::AgentError;

use super::HttpService;
#[cfg(not(feature = "_internal_dynamic-routing"))]
pub(crate) mod dynamic_routing;
#[cfg(feature = "_internal_dynamic-routing")]
pub mod dynamic_routing;

const IC0_DOMAIN: &str = "ic0.app";
const ICP0_DOMAIN: &str = "icp0.io";
const ICP_API_DOMAIN: &str = "icp-api.io";
const LOCALHOST_DOMAIN: &str = "localhost";
const IC0_SUB_DOMAIN: &str = ".ic0.app";
const ICP0_SUB_DOMAIN: &str = ".icp0.io";
const ICP_API_SUB_DOMAIN: &str = ".icp-api.io";
const LOCALHOST_SUB_DOMAIN: &str = ".localhost";

/// A [`RouteProvider`] for dynamic generation of routing urls.
pub trait RouteProvider: std::fmt::Debug + Send + Sync {
    /// Generates the next routing URL based on the internal routing logic.
    ///
    /// This method returns a single `Url` that can be used for routing.
    /// The logic behind determining the next URL can vary depending on the implementation
    fn route(&self) -> Result<Url, AgentError>;

    /// Generates up to `n` different routing URLs in order of priority.
    ///
    /// This method returns a vector of `Url` instances, each representing a routing
    /// endpoint. The URLs are ordered by priority, with the most preferred route
    /// appearing first. The returned vector can contain fewer than `n` URLs if
    /// fewer are available.
    fn n_ordered_routes(&self, n: usize) -> Result<Vec<Url>, AgentError>;

    /// Returns the total number of routes and healthy routes as a tuple.
    ///
    /// - First element is the total number of routes available (both healthy and unhealthy)
    /// - Second element is the number of currently healthy routes, or None if health status information is unavailable
    ///
    /// A healthy route is one that is available and ready to receive traffic.
    /// The specific criteria for what constitutes a "healthy" route is implementation dependent.
    fn routes_stats(&self) -> (usize, Option<usize>);
}

/// A simple implementation of the [`RouteProvider`] which produces an even distribution of the urls from the input ones.
#[derive(Debug)]
pub struct RoundRobinRouteProvider {
    routes: Vec<Url>,
    current_idx: AtomicUsize,
}

impl RouteProvider for RoundRobinRouteProvider {
    /// Generates a url for the given endpoint.
    fn route(&self) -> Result<Url, AgentError> {
        if self.routes.is_empty() {
            return Err(AgentError::RouteProviderError(
                "No routing urls provided".to_string(),
            ));
        }
        // This operation wraps around an overflow, i.e. after max is reached the value is reset back to 0.
        let prev_idx = self.current_idx.fetch_add(1, Ordering::Relaxed);
        Ok(self.routes[prev_idx % self.routes.len()].clone())
    }

    fn n_ordered_routes(&self, n: usize) -> Result<Vec<Url>, AgentError> {
        if n == 0 {
            return Ok(Vec::new());
        }

        if n >= self.routes.len() {
            return Ok(self.routes.clone());
        }

        let idx = self.current_idx.fetch_add(n, Ordering::Relaxed) % self.routes.len();
        let mut urls = Vec::with_capacity(n);

        if self.routes.len() - idx >= n {
            urls.extend_from_slice(&self.routes[idx..idx + n]);
        } else {
            urls.extend_from_slice(&self.routes[idx..]);
            urls.extend_from_slice(&self.routes[..n - urls.len()]);
        }

        Ok(urls)
    }

    fn routes_stats(&self) -> (usize, Option<usize>) {
        (self.routes.len(), None)
    }
}

impl RoundRobinRouteProvider {
    /// Construct [`RoundRobinRouteProvider`] from a vector of urls.
    pub fn new<T: AsRef<str>>(routes: Vec<T>) -> Result<Self, AgentError> {
        let routes: Result<Vec<Url>, _> = routes
            .into_iter()
            .map(|url| {
                Url::from_str(url.as_ref()).and_then(|mut url| {
                    // rewrite *.ic0.app to ic0.app
                    if let Some(domain) = url.domain() {
                        if domain.ends_with(IC0_SUB_DOMAIN) {
                            url.set_host(Some(IC0_DOMAIN))?;
                        } else if domain.ends_with(ICP0_SUB_DOMAIN) {
                            url.set_host(Some(ICP0_DOMAIN))?;
                        } else if domain.ends_with(ICP_API_SUB_DOMAIN) {
                            url.set_host(Some(ICP_API_DOMAIN))?;
                        } else if domain.ends_with(LOCALHOST_SUB_DOMAIN) {
                            url.set_host(Some(LOCALHOST_DOMAIN))?;
                        }
                    }
                    Ok(url)
                })
            })
            .collect();
        Ok(Self {
            routes: routes?,
            current_idx: AtomicUsize::new(0),
        })
    }
}

impl RouteProvider for Url {
    fn route(&self) -> Result<Url, AgentError> {
        Ok(self.clone())
    }
    fn n_ordered_routes(&self, _: usize) -> Result<Vec<Url>, AgentError> {
        Ok(vec![self.route()?])
    }
    fn routes_stats(&self) -> (usize, Option<usize>) {
        (1, None)
    }
}

/// A [`RouteProvider`] that will attempt to discover new boundary nodes and cycle through them, optionally prioritizing those with low latency.
#[derive(Debug)]
pub struct DynamicRouteProvider {
    inner: Box<dyn RouteProvider>,
}

impl DynamicRouteProvider {
    /// Create a new `DynamicRouter` from a list of seed domains and a routing strategy.
    pub async fn run_in_background(
        seed_domains: Vec<String>,
        client: Arc<dyn HttpService>,
        strategy: DynamicRoutingStrategy,
    ) -> Result<Self, AgentError> {
        let seed_nodes: Result<Vec<_>, _> = seed_domains.into_iter().map(Node::new).collect();
        let boxed = match strategy {
            DynamicRoutingStrategy::ByLatency => Box::new(
                DynamicRouteProviderBuilder::new(
                    LatencyRoutingSnapshot::new(),
                    seed_nodes?,
                    client,
                )
                .build()
                .await,
            ) as Box<dyn RouteProvider>,
            DynamicRoutingStrategy::RoundRobin => Box::new(
                DynamicRouteProviderBuilder::new(
                    RoundRobinRoutingSnapshot::new(),
                    seed_nodes?,
                    client,
                )
                .build()
                .await,
            ),
        };
        Ok(Self { inner: boxed })
    }
    /// Same as [`run_in_background`](Self::run_in_background), but with custom intervals for refreshing the routing list and health-checking nodes.
    pub async fn run_in_background_with_intervals(
        seed_domains: Vec<String>,
        client: Arc<dyn HttpService>,
        strategy: DynamicRoutingStrategy,
        list_update_interval: Duration,
        health_check_interval: Duration,
    ) -> Result<Self, AgentError> {
        let seed_nodes: Result<Vec<_>, _> = seed_domains.into_iter().map(Node::new).collect();
        let boxed = match strategy {
            DynamicRoutingStrategy::ByLatency => Box::new(
                DynamicRouteProviderBuilder::new(
                    LatencyRoutingSnapshot::new(),
                    seed_nodes?,
                    client,
                )
                .with_fetch_period(list_update_interval)
                .with_check_period(health_check_interval)
                .build()
                .await,
            ) as Box<dyn RouteProvider>,
            DynamicRoutingStrategy::RoundRobin => Box::new(
                DynamicRouteProviderBuilder::new(
                    RoundRobinRoutingSnapshot::new(),
                    seed_nodes?,
                    client,
                )
                .with_fetch_period(list_update_interval)
                .with_check_period(health_check_interval)
                .build()
                .await,
            ),
        };
        Ok(Self { inner: boxed })
    }
}

impl RouteProvider for DynamicRouteProvider {
    fn route(&self) -> Result<Url, AgentError> {
        self.inner.route()
    }
    fn n_ordered_routes(&self, n: usize) -> Result<Vec<Url>, AgentError> {
        self.inner.n_ordered_routes(n)
    }
    fn routes_stats(&self) -> (usize, Option<usize>) {
        self.inner.routes_stats()
    }
}

/// Strategy for [`DynamicRouteProvider`]'s routing mechanism.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum DynamicRoutingStrategy {
    /// Prefer nodes with low latency.
    ByLatency,
    /// Cycle through discovered nodes with no regard for latency.
    RoundRobin,
}

#[derive(Debug)]
pub(crate) struct UrlUntilReady<R> {
    url: Url,
    router: ArcSwapOption<R>,
}

impl<R: RouteProvider + 'static> UrlUntilReady<R> {
    pub(crate) fn new<
        #[cfg(not(target_family = "wasm"))] F: Future<Output = R> + Send + 'static,
        #[cfg(target_family = "wasm")] F: Future<Output = R> + 'static,
    >(
        url: Url,
        fut: F,
    ) -> Arc<Self> {
        let s = Arc::new(Self {
            url,
            router: ArcSwapOption::empty(),
        });
        let weak = Arc::downgrade(&s);
        crate::util::spawn(async move {
            let router = fut.await;
            if let Some(outer) = weak.upgrade() {
                outer.router.store(Some(Arc::new(router)))
            }
        });
        s
    }
}

impl<R: RouteProvider> RouteProvider for UrlUntilReady<R> {
    fn n_ordered_routes(&self, n: usize) -> Result<Vec<Url>, AgentError> {
        if let Some(r) = &*self.router.load() {
            r.n_ordered_routes(n)
        } else {
            self.url.n_ordered_routes(n)
        }
    }
    fn route(&self) -> Result<Url, AgentError> {
        if let Some(r) = &*self.router.load() {
            r.route()
        } else {
            self.url.route()
        }
    }
    fn routes_stats(&self) -> (usize, Option<usize>) {
        (1, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_routes() {
        let provider = RoundRobinRouteProvider::new::<&str>(vec![])
            .expect("failed to create a route provider");
        let result = provider.route().unwrap_err();
        assert_eq!(
            result,
            AgentError::RouteProviderError("No routing urls provided".to_string())
        );
    }

    #[test]
    fn test_routes_rotation() {
        let provider = RoundRobinRouteProvider::new(vec!["https://url1.com", "https://url2.com"])
            .expect("failed to create a route provider");
        let url_strings = ["https://url1.com", "https://url2.com", "https://url1.com"];
        let expected_urls: Vec<Url> = url_strings
            .iter()
            .map(|url_str| Url::parse(url_str).expect("Invalid URL"))
            .collect();
        let urls: Vec<Url> = (0..3)
            .map(|_| provider.route().expect("failed to get next url"))
            .collect();
        assert_eq!(expected_urls, urls);
    }

    #[test]
    fn test_n_routes() {
        // Test with an empty list of urls
        let provider = RoundRobinRouteProvider::new(Vec::<&str>::new())
            .expect("failed to create a route provider");
        let urls_iter = provider.n_ordered_routes(1).expect("failed to get urls");
        assert!(urls_iter.is_empty());
        // Test with non-empty list of urls
        let provider = RoundRobinRouteProvider::new(vec![
            "https://url1.com",
            "https://url2.com",
            "https://url3.com",
            "https://url4.com",
            "https://url5.com",
        ])
        .expect("failed to create a route provider");
        // First call
        let urls: Vec<_> = provider.n_ordered_routes(3).expect("failed to get urls");
        let expected_urls: Vec<Url> = ["https://url1.com", "https://url2.com", "https://url3.com"]
            .iter()
            .map(|url_str| Url::parse(url_str).expect("invalid URL"))
            .collect();
        assert_eq!(urls, expected_urls);
        // Second call
        let urls: Vec<_> = provider.n_ordered_routes(3).expect("failed to get urls");
        let expected_urls: Vec<Url> = ["https://url4.com", "https://url5.com", "https://url1.com"]
            .iter()
            .map(|url_str| Url::parse(url_str).expect("invalid URL"))
            .collect();
        assert_eq!(urls, expected_urls);
        // Third call
        let urls: Vec<_> = provider.n_ordered_routes(2).expect("failed to get urls");
        let expected_urls: Vec<Url> = ["https://url2.com", "https://url3.com"]
            .iter()
            .map(|url_str| Url::parse(url_str).expect("invalid URL"))
            .collect();
        assert_eq!(urls, expected_urls);
        // Fourth call
        let urls: Vec<_> = provider.n_ordered_routes(5).expect("failed to get urls");
        let expected_urls: Vec<Url> = [
            "https://url1.com",
            "https://url2.com",
            "https://url3.com",
            "https://url4.com",
            "https://url5.com",
        ]
        .iter()
        .map(|url_str| Url::parse(url_str).expect("invalid URL"))
        .collect();
        assert_eq!(urls, expected_urls);
    }
}
