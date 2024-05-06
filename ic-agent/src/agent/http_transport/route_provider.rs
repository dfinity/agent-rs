//! A [`RouteProvider`] for dynamic generation of routing urls.
use candid::Principal;
use std::{
    str::FromStr,
    sync::atomic::{AtomicUsize, Ordering},
};
use url::Url;

use crate::agent::{
    http_transport::{
        IC0_DOMAIN, IC0_SUB_DOMAIN, ICP0_DOMAIN, ICP0_SUB_DOMAIN, ICP_API_DOMAIN,
        ICP_API_SUB_DOMAIN, LOCALHOST_DOMAIN, LOCALHOST_SUB_DOMAIN,
    },
    AgentError,
};

/// The different HTTP endpoints that the agent can interact with as per the [IC-spec](https://internetcomputer.org/docs/current/references/ic-interface-spec#http-interface).
pub enum Endpoint {
    /// The [call](https://internetcomputer.org/docs/current/references/ic-interface-spec#http-call) endpoint.
    Call(Principal),
    /// The [query](https://internetcomputer.org/docs/current/references/ic-interface-spec#http-query) endpoint.
    Query(Principal),
    /// The [read_state](https://internetcomputer.org/docs/current/references/ic-interface-spec#http-read-state) endpoint for canisters.
    ReadStateCanister(Principal),
    /// The [read_state](https://internetcomputer.org/docs/current/references/ic-interface-spec#http-read-state) endpoint for subnets.
    ReadStateSubnet(Principal),
    /// The [status](https://internetcomputer.org/docs/current/references/ic-interface-spec#api-status) endpoint.
    Status,
}

/// A [`RouteProvider`] for dynamic generation of routing urls.
pub trait RouteProvider: std::fmt::Debug + Send + Sync {
    /// Generate next routing url
    fn route(&self, endpoint: Endpoint) -> Result<Url, AgentError>;
}

/// A simple implementation of the [`RouteProvider`] which produces an even distribution of the urls from the input ones.
#[derive(Debug)]
pub struct RoundRobinRouteProvider {
    routes: Vec<Url>,
    current_idx: AtomicUsize,
}

impl RoundRobinRouteProvider {
    fn base_url(&self) -> Result<Url, AgentError> {
        if self.routes.is_empty() {
            return Err(AgentError::RouteProviderError(
                "No routing urls provided".to_string(),
            ));
        }
        // This operation wraps around an overflow, i.e. after max is reached the value is reset back to 0.
        let prev_idx = self.current_idx.fetch_add(1, Ordering::Relaxed);

        Ok(self.routes[prev_idx % self.routes.len()].clone())
    }
}

impl RouteProvider for RoundRobinRouteProvider {
    /// Generates a url for the given endpoint.
    fn route(&self, endpoint: Endpoint) -> Result<Url, AgentError> {
        let base_url = self.base_url()?;

        let endpoint = match endpoint {
            Endpoint::Call(effective_canister_id) => {
                format!("api/v3/canister/{}/call", effective_canister_id.to_text())
            }
            Endpoint::Query(effective_canister_id) => {
                format!("api/v2/canister/{}/query", effective_canister_id.to_text())
            }
            Endpoint::ReadStateCanister(principal) => {
                format!("api/v2/canister/{}/read_state", principal.to_text())
            }
            Endpoint::ReadStateSubnet(principal) => {
                format!("api/v2/subnet/{}/read_state", principal.to_text())
            }
            Endpoint::Status => {
                format!("api/v2/status")
            }
        };

        Ok(base_url.join(&endpoint)?)
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
                            url.set_host(Some(IC0_DOMAIN))?
                        } else if domain.ends_with(ICP0_SUB_DOMAIN) {
                            url.set_host(Some(ICP0_DOMAIN))?
                        } else if domain.ends_with(ICP_API_SUB_DOMAIN) {
                            url.set_host(Some(ICP_API_DOMAIN))?
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_routes() {
        let provider = RoundRobinRouteProvider::new::<&str>(vec![])
            .expect("failed to create a route provider");
        let result = provider.base_url().unwrap_err();
        assert_eq!(
            result,
            AgentError::RouteProviderError("No routing urls provided".to_string())
        );
    }

    #[test]
    fn test_routes_rotation() {
        let provider = RoundRobinRouteProvider::new(vec!["https://url1.com", "https://url2.com"])
            .expect("failed to create a route provider");
        let url_strings = vec!["https://url1.com", "https://url2.com", "https://url1.com"];
        let expected_urls: Vec<Url> = url_strings
            .iter()
            .map(|url_str| Url::parse(url_str).expect("Invalid URL"))
            .collect();
        let urls: Vec<Url> = (0..3)
            .map(|_| provider.base_url().expect("failed to get next url"))
            .collect();
        assert_eq!(expected_urls, urls);
    }

    #[test]
    fn test_call_endpoint() {
        let canister = Principal::from_text("224od-giaaa-aaaao-ae5vq-cai").unwrap();

        let provider = RoundRobinRouteProvider::new(vec!["https://url1.com", "https://url2.com"])
            .expect("failed to create a route provider");

        let url_strings = vec![
            format!(
                "https://url1.com/api/v3/canister/{}/call",
                canister.to_text()
            ),
            format!(
                "https://url2.com/api/v3/canister/{}/call",
                canister.to_text()
            ),
            format!(
                "https://url1.com/api/v3/canister/{}/call",
                canister.to_text()
            ),
        ];

        let expected_urls: Vec<Url> = url_strings
            .iter()
            .map(|url_str| Url::parse(url_str).expect("Invalid URL"))
            .collect();

        let urls: Vec<Url> = (0..3)
            .map(|_| {
                provider
                    .route(Endpoint::Call(canister))
                    .expect("failed to get next url")
            })
            .collect();

        assert_eq!(expected_urls, urls);
    }

    #[test]
    fn test_query_endpoint() {
        let canister = Principal::from_text("224od-giaaa-aaaao-ae5vq-cai").unwrap();

        let provider = RoundRobinRouteProvider::new(vec!["https://url1.com", "https://url2.com"])
            .expect("failed to create a route provider");

        let url_strings = vec![
            format!(
                "https://url1.com/api/v2/canister/{}/query",
                canister.to_text()
            ),
            format!(
                "https://url2.com/api/v2/canister/{}/query",
                canister.to_text()
            ),
            format!(
                "https://url1.com/api/v2/canister/{}/query",
                canister.to_text()
            ),
        ];

        let expected_urls: Vec<Url> = url_strings
            .iter()
            .map(|url_str| Url::parse(url_str).expect("Invalid URL"))
            .collect();
        let urls: Vec<Url> = (0..3)
            .map(|_| {
                provider
                    .route(Endpoint::Query(canister))
                    .expect("failed to get next url")
            })
            .collect();
        assert_eq!(expected_urls, urls);
    }

    #[test]
    fn test_read_state_canister_endpoint() {
        let canister = Principal::from_text("224od-giaaa-aaaao-ae5vq-cai").unwrap();

        let provider = RoundRobinRouteProvider::new(vec!["https://url1.com", "https://url2.com"])
            .expect("failed to create a route provider");

        let url_strings = vec![
            format!(
                "https://url1.com/api/v2/canister/{}/read_state",
                canister.to_text()
            ),
            format!(
                "https://url2.com/api/v2/canister/{}/read_state",
                canister.to_text()
            ),
            format!(
                "https://url1.com/api/v2/canister/{}/read_state",
                canister.to_text()
            ),
        ];

        let expected_urls: Vec<Url> = url_strings
            .iter()
            .map(|url_str| Url::parse(url_str).expect("Invalid URL"))
            .collect();
        let urls: Vec<Url> = (0..3)
            .map(|_| {
                provider
                    .route(Endpoint::ReadStateCanister(canister))
                    .expect("failed to get next url")
            })
            .collect();
        assert_eq!(expected_urls, urls);
    }

    #[test]
    fn test_read_state_subnet_endpoint() {
        let subnet = Principal::from_text("224od-giaaa-aaaao-ae5vq-cai").unwrap();

        let provider = RoundRobinRouteProvider::new(vec!["https://url1.com", "https://url2.com"])
            .expect("failed to create a route provider");

        let url_strings = vec![
            format!(
                "https://url1.com/api/v2/subnet/{}/read_state",
                subnet.to_text()
            ),
            format!(
                "https://url2.com/api/v2/subnet/{}/read_state",
                subnet.to_text()
            ),
            format!(
                "https://url1.com/api/v2/subnet/{}/read_state",
                subnet.to_text()
            ),
        ];

        let expected_urls: Vec<Url> = url_strings
            .iter()
            .map(|url_str| Url::parse(url_str).expect("Invalid URL"))
            .collect();
        let urls: Vec<Url> = (0..3)
            .map(|_| {
                provider
                    .route(Endpoint::ReadStateSubnet(subnet))
                    .expect("failed to get next url")
            })
            .collect();
        assert_eq!(expected_urls, urls);
    }

    #[test]
    fn test_status_endpoint() {
        let provider = RoundRobinRouteProvider::new(vec!["https://url1.com", "https://url2.com"])
            .expect("failed to create a route provider");

        let url_strings = vec![
            "https://url1.com/api/v2/status",
            "https://url2.com/api/v2/status",
            "https://url1.com/api/v2/status",
        ];

        let expected_urls: Vec<Url> = url_strings
            .iter()
            .map(|url_str| Url::parse(url_str).expect("Invalid URL"))
            .collect();
        let urls: Vec<Url> = (0..3)
            .map(|_| {
                provider
                    .route(Endpoint::Status)
                    .expect("failed to get next url")
            })
            .collect();
        assert_eq!(expected_urls, urls);
    }
}
