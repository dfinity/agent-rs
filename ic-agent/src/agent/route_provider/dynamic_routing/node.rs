use url::Url;

use crate::agent::ApiBoundaryNode;

/// Represents a node in the dynamic routing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Node {
    domain: String,
}

impl Node {
    /// Creates a new `Node` instance from the domain name.
    pub fn new(domain: impl Into<String>) -> Result<Self, url::ParseError> {
        let domain = domain.into();
        check_valid_domain(&domain)?;
        Ok(Self { domain })
    }

    /// Returns the domain name of the node.
    pub fn domain(&self) -> &str {
        &self.domain
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

impl TryFrom<ApiBoundaryNode> for Node {
    type Error = url::ParseError;

    fn try_from(value: ApiBoundaryNode) -> Result<Self, Self::Error> {
        Node::new(value.domain)
    }
}

/// Checks if the given domain is a valid URL.
fn check_valid_domain<S: AsRef<str>>(domain: S) -> Result<(), url::ParseError> {
    // Prepend scheme to make it a valid URL
    let url_string = format!("http://{}", domain.as_ref());
    Url::parse(&url_string)?;
    Ok(())
}
