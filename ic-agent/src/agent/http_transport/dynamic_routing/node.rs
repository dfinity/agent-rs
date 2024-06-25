use url::Url;

use crate::agent::ApiBoundaryNode;
use anyhow::anyhow;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Node {
    pub domain: String,
}

impl Node {
    pub fn new(domain: &str) -> anyhow::Result<Self> {
        if !is_valid_domain(domain) {
            return Err(anyhow!("Invalid domain name {domain}"));
        }
        Ok(Self {
            domain: domain.to_string(),
        })
    }
}

impl Node {
    pub fn to_routing_url(&self) -> Url {
        Url::parse(&format!("https://{}/api/v2/", self.domain)).expect("failed to parse URL")
    }
}

impl From<&Node> for Url {
    fn from(node: &Node) -> Self {
        Url::parse(&format!("https://{}", node.domain)).expect("failed to parse URL")
    }
}

impl From<&ApiBoundaryNode> for Node {
    fn from(api_bn: &ApiBoundaryNode) -> Self {
        Node::new(api_bn.domain.as_str()).unwrap()
    }
}

pub fn is_valid_domain<S: AsRef<str>>(domain: S) -> bool {
    // TODO
    true
}
