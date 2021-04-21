use ic_types::Principal;

use anyhow::anyhow;

const DNS_ALIAS_FORMAT_HELP: &str = "Format is dns.alias:principal-id";

#[derive(Clone, Debug)]
enum PrincipalDeterminationStrategy {
    // A domain name which matches the suffix is an alias for this specific Principal.
    Alias(Principal),
}

/// A mapping from a domain name to a Principal.  The domain name must
/// match the last portion, as split by '.', of the host specified in the request.
#[derive(Clone, Debug)]
pub struct CanisterDnsRule {
    domain_name: String,

    /// The hostname parts that must match the right-hand side of the domain name.  Lower case.
    pub dns_suffix: Vec<String>,

    strategy: PrincipalDeterminationStrategy,
}

impl CanisterDnsRule {
    /// Create a DnsAlias from an entry of the form dns.alias:canister-id
    pub fn new_alias(dns_alias: &str) -> anyhow::Result<CanisterDnsRule> {
        let (domain_name, principal) = split_dns_alias(dns_alias)?;
        let dns_suffix: Vec<String> = domain_name
            .split('.')
            .map(|s| s.to_ascii_lowercase())
            .collect();
        Ok(CanisterDnsRule {
            domain_name,
            dns_suffix,
            strategy: PrincipalDeterminationStrategy::Alias(principal),
        })
    }

    /// Return the associated principal if this rule applies to the domain name.
    pub fn lookup(&self, split_hostname_lowercase: &[String]) -> Option<Principal> {
        if split_hostname_lowercase.ends_with(&self.dns_suffix) {
            match &self.strategy {
                PrincipalDeterminationStrategy::Alias(principal) => Some(principal.clone()),
            }
        } else {
            None
        }
    }
}

fn split_dns_alias(alias: &str) -> Result<(String, Principal), anyhow::Error> {
    match alias.find(':') {
        Some(0) => Err(anyhow!(
            r#"No domain specifed in DNS alias "{}".  {}"#,
            alias.to_string(),
            DNS_ALIAS_FORMAT_HELP
        )),
        Some(index) if index == alias.len() - 1 => Err(anyhow!(
            r#"No canister ID specifed in DNS alias "{}".  {}"#,
            alias.to_string(),
            DNS_ALIAS_FORMAT_HELP
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
            DNS_ALIAS_FORMAT_HELP,
        )),
    }
}

#[cfg(test)]
mod tests {
    use crate::config::canister_dns_rule::CanisterDnsRule;

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

    fn parse_dns_alias(alias: &str) -> anyhow::Result<CanisterDnsRule> {
        CanisterDnsRule::new_alias(alias)
    }
}
