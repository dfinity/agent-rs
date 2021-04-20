use ic_types::Principal;

use anyhow::anyhow;

const FORMAT_HELP: &str = "Format is dns.alias:principal-id";

/// A mapping from a domain name to a Principal.  The domain name must
/// match the last portion, as split by '.', of the host specified in the request.
#[derive(Clone, Debug)]
pub struct DnsAlias {
    domain_name: String,

    /// The hostname parts that must match the right-hand side of the domain name.  Lower case.
    pub dns_suffix: Vec<String>,

    /// The principal associated with the domain name.
    pub principal: Principal,
}

impl DnsAlias {
    /// Create a DnsAlias from an entry of the form dns.alias:canister-id
    pub fn new(dns_alias: &str) -> anyhow::Result<DnsAlias> {
        let (domain_name, principal) = split_dns_alias(dns_alias)?;
        let dns_suffix: Vec<String> = domain_name
            .split('.')
            .map(|s| s.to_ascii_lowercase())
            .collect();
        Ok(DnsAlias {
            domain_name,
            dns_suffix,
            principal,
        })
    }
}

fn split_dns_alias(alias: &str) -> Result<(String, Principal), anyhow::Error> {
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

#[cfg(test)]
mod tests {
    use crate::config::dns_alias::DnsAlias;

    #[test]
    fn parse_error_no_colon() {
        let e = parse_dns_alias("happy.little.domain.name!r7inp-6aaaa-aaaaa-aaabq-cai")
            .expect_err("expected failure due to missing colon");
        assert_eq!(
            e.to_string(),
            r#"Unrecognized DNS alias "happy.little.domain.name!r7inp-6aaaa-aaaaa-aaabq-cai".  Format is dns.alias:principal-id"#
        )
    }

    #[test]
    fn parse_error_nothing_after_colon() {
        let e = parse_dns_alias("happy.little.domain.name:")
            .expect_err("expected failure due to nothing after colon");
        assert_eq!(
            e.to_string(),
            r#"No canister ID specifed in DNS alias "happy.little.domain.name:".  Format is dns.alias:principal-id"#
        )
    }

    #[test]
    fn parse_error_nothing_before_colon() {
        let e = parse_dns_alias(":r7inp-6aaaa-aaaaa-aaabq-cai")
            .expect_err("expected failure due to nothing after colon");
        assert_eq!(
            e.to_string(),
            r#"No domain specifed in DNS alias ":r7inp-6aaaa-aaaaa-aaabq-cai".  Format is dns.alias:principal-id"#
        )
    }

    fn parse_dns_alias(alias: &str) -> anyhow::Result<DnsAlias> {
        DnsAlias::new(alias)
    }
}
