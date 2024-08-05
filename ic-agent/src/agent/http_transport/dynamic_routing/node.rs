use url::Url;

use crate::agent::{
    http_transport::dynamic_routing::dynamic_route_provider::DynamicRouteProviderError,
    ApiBoundaryNode,
};

/// Represents a node in the dynamic routing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Node {
    domain: String,
}

impl Node {
    /// Creates a new `Node` instance from the domain name.
    pub fn new(domain: &str) -> Result<Self, DynamicRouteProviderError> {
        if !is_valid_domain(domain) {
            return Err(DynamicRouteProviderError::InvalidDomainName(
                domain.to_string(),
            ));
        }
        Ok(Self {
            domain: domain.to_string(),
        })
    }

    /// Returns the domain name of the node.
    pub fn domain(&self) -> String {
        self.domain.clone()
    }
}

impl Node {
    /// Converts the node to a routing URL.
    pub fn to_routing_url(&self) -> Url {
        Url::parse(&format!("https://{}", self.domain)).expect("failed to parse URL")
    }
}

impl From<&Node> for Url {
    fn from(node: &Node) -> Self {
        // Parsing can't fail, as the domain was checked at node instantiation.
        Url::parse(&format!("https://{}", node.domain)).expect("failed to parse URL")
    }
}

impl TryFrom<&ApiBoundaryNode> for Node {
    type Error = DynamicRouteProviderError;

    fn try_from(value: &ApiBoundaryNode) -> Result<Self, Self::Error> {
        Node::new(&value.domain)
    }
}

/// Checks if the given domain is a valid URL.
fn is_valid_domain<S: AsRef<str>>(domain: S) -> bool {
    // Prepend scheme to make it a valid URL
    let url_string = format!("http://{}", domain.as_ref());
    Url::parse(&url_string).is_ok()
}
