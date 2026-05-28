//! This module has been deprecated in favor of builder methods on `AgentBuilder`.
#![allow(deprecated)]
pub use reqwest;
use std::sync::Arc;

use reqwest::Client;

use crate::{
    agent::{
        route_provider::{RoundRobinRouteProvider, RouteProvider},
        AgentBuilder,
    },
    AgentError,
};

/// A legacy configuration object. `AgentBuilder::with_transport` will apply these settings to the builder.
#[derive(Debug, Clone)]
pub struct ReqwestTransport {
    route_provider: Arc<dyn RouteProvider>,
    client: Client,
    max_response_body_size: Option<usize>,
    max_tcp_error_retries: usize,
}

impl ReqwestTransport {
    /// Equivalent to [`AgentBuilder::with_url`].
    #[deprecated(since = "0.38.0", note = "Use AgentBuilder::with_url")]
    pub fn create<U: Into<String>>(url: U) -> Result<Self, AgentError> {
        #[cfg(not(target_family = "wasm"))]
        {
            Self::create_with_client(
                url,
                Client::builder()
                    .use_rustls_tls()
                    .timeout(std::time::Duration::from_secs(360))
                    .build()
                    .expect("Could not create HTTP client."),
            )
        }
        #[cfg(all(target_family = "wasm", feature = "wasm-bindgen"))]
        {
            Self::create_with_client(url, Client::new())
        }
    }

    /// Equivalent to [`AgentBuilder::with_url`] and [`AgentBuilder::with_http_client`].
    #[deprecated(
        since = "0.38.0",
        note = "Use AgentBuilder::with_url and AgentBuilder::with_http_client"
    )]
    pub fn create_with_client<U: Into<String>>(url: U, client: Client) -> Result<Self, AgentError> {
        let route_provider = Arc::new(RoundRobinRouteProvider::new(vec![url.into()])?);
        Self::create_with_client_route(route_provider, client)
    }

    /// Equivalent to [`AgentBuilder::with_http_client`] and [`AgentBuilder::with_route_provider`].
    #[deprecated(
        since = "0.38.0",
        note = "Use AgentBuilder::with_http_client and AgentBuilder::with_arc_route_provider"
    )]
    pub fn create_with_client_route(
        route_provider: Arc<dyn RouteProvider>,
        client: Client,
    ) -> Result<Self, AgentError> {
        Ok(Self {
            route_provider,
            client,
            max_response_body_size: None,
            max_tcp_error_retries: 0,
        })
    }

    /// Equivalent to [`AgentBuilder::with_max_response_body_size`].
    #[deprecated(
        since = "0.38.0",
        note = "Use AgentBuilder::with_max_response_body_size"
    )]
    pub fn with_max_response_body_size(self, max_response_body_size: usize) -> Self {
        ReqwestTransport {
            max_response_body_size: Some(max_response_body_size),
            ..self
        }
    }

    /// Equivalent to [`AgentBuilder::with_max_tcp_error_retries`].
    #[deprecated(
        since = "0.38.0",
        note = "Use AgentBuilder::with_max_tcp_error_retries"
    )]
    pub fn with_max_tcp_errors_retries(self, retries: usize) -> Self {
        ReqwestTransport {
            max_tcp_error_retries: retries,
            ..self
        }
    }
}

impl AgentBuilder {
    #[doc(hidden)]
    #[deprecated(since = "0.38.0", note = "Use the dedicated methods on AgentBuilder")]
    pub fn with_transport(self, transport: ReqwestTransport) -> Self {
        let mut builder = self
            .with_arc_route_provider(transport.route_provider)
            .with_http_client(transport.client)
            .with_max_tcp_error_retries(transport.max_tcp_error_retries);
        if let Some(max_size) = transport.max_response_body_size {
            builder = builder.with_max_response_body_size(max_size);
        }
        builder
    }
    #[doc(hidden)]
    #[deprecated(since = "0.38.0", note = "Use the dedicated methods on AgentBuilder")]
    pub fn with_arc_transport(self, transport: Arc<ReqwestTransport>) -> Self {
        self.with_transport((*transport).clone())
    }
}
