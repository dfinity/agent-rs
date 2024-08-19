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
