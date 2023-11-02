//! A [`RouteProvider`] for dynamic generation of routing urls.
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

/// A [`RouteProvider`] for dynamic generation of routing urls.
pub trait RouteProvider: std::fmt::Debug + Send + Sync {
    /// Generate next routing url
    fn route(&self) -> Result<Url, AgentError>;
}

/// A simple implementation of the [`RouteProvider`] which produces an even distribution of the urls from the input ones.
#[derive(Debug)]
pub struct RoundRobinRouteProvider {
    routes: Vec<Url>,
    current_idx: AtomicUsize,
}

impl RouteProvider for RoundRobinRouteProvider {
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
                            url.set_scheme("https").unwrap()
                        }
                    }
                    url.join("api/v2/")
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
        let url_strings = vec![
            "https://url1.com/api/v2/",
            "https://url2.com/api/v2/",
            "https://url1.com/api/v2/",
        ];
        let expected_urls: Vec<Url> = url_strings
            .iter()
            .map(|url_str| Url::parse(url_str).expect("Invalid URL"))
            .collect();
        let urls: Vec<Url> = (0..3)
            .map(|_| provider.route().expect("failed to get next url"))
            .collect();
        assert_eq!(expected_urls, urls);
    }
}
