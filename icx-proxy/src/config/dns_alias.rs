use ic_types::Principal;

use anyhow::anyhow;

const FORMAT_HELP: &str = "Format is dns.alias:principal-id";

#[derive(Clone, Debug)]
pub struct DnsAlias {
    pub domain_name: String,
    pub dns_suffix: Vec<String>,
    pub principal: Principal,
}

impl DnsAlias {
    /// Create a DnsAlias from an entry of the form dns.alias:canister-id
    pub fn new(dns_alias: &str) -> anyhow::Result<DnsAlias> {
        let (domain_name, principal) = parse_dns_alias(dns_alias)?;
        let dns_suffix: Vec<String> = domain_name
            .split('.')
            .map(|s| String::from(s).to_ascii_lowercase())
            .collect();
        Ok(DnsAlias { domain_name, dns_suffix, principal })
    }
}

fn parse_dns_alias(alias: &str) -> Result<(String, Principal), anyhow::Error> {
    match alias.find(':') {
        Some(0) => Err(anyhow!(
            r#"No domain specifed in DNS alias "{}".  {}"#,
            alias.to_string(),
            FORMAT_HELP
        )),
        Some(index) if index == alias.len() - 1 => Err(anyhow!(
            r#"No canister ID specifed in DNS alias "{}".  {}"#,
            alias.to_string(),
            FORMAT_HELP
        )),
        Some(index) => {
            let (domain_name, principal) = alias.split_at(index);
            let principal = &principal[1..];
            let principal = Principal::from_text(principal)?;
            Ok((domain_name.to_string(), principal))
        }
        None => Err(anyhow!(
            r#"Unrecognized DNS alias "{}".  {}"#,
            alias.to_string(),
            FORMAT_HELP,
        )),
    }
}
