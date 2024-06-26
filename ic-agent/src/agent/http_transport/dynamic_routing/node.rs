use url::Url;

use crate::agent::ApiBoundaryNode;
use anyhow::anyhow;

///
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Node {
    domain: String,
}

impl Node {
    ///
    pub fn new(domain: &str) -> anyhow::Result<Self> {
        if !is_valid_domain(domain) {
            return Err(anyhow!("Invalid domain name {domain}"));
        }
        Ok(Self {
            domain: domain.to_string(),
        })
    }

    ///
    pub fn domain(&self) -> String {
        self.domain.clone()
    }
}

impl Node {
    ///
    pub fn to_routing_url(&self) -> Url {
        Url::parse(&format!("https://{}/api/v2/", self.domain)).expect("failed to parse URL")
    }
}

impl From<&Node> for Url {
    fn from(node: &Node) -> Self {
        // Parsing can't fail, as the domain was checked at node instantiation.
        Url::parse(&format!("https://{}", node.domain)).expect("failed to parse URL")
    }
}

impl TryFrom<&ApiBoundaryNode> for Node {
    type Error = anyhow::Error;

    fn try_from(value: &ApiBoundaryNode) -> Result<Self, Self::Error> {
        Node::new(&value.domain)
    }
}

///
pub fn is_valid_domain<S: AsRef<str>>(domain: S) -> bool {
    // Prepend scheme to make it a valid URL
    let url_string = format!("http://{}", domain.as_ref());
    Url::parse(&url_string).is_ok()
}
