use ic_agent::ic_types::Principal;

use anyhow::anyhow;

const DNS_ALIAS_FORMAT_HELP: &str = "Format is dns.alias:principal-id";

#[derive(Clone, Debug)]
enum PrincipalDeterminationStrategy {
    // A domain name which matches the suffix is an alias for this specific Principal.
    Alias(Principal),

    // The subdomain to the immediate left of the suffix is the Principal,
    // if it parses as a valid Principal.
    PrecedingDomainName,
}

/// A mapping from a domain name to a Principal.  The domain name must
/// match the last portion, as split by '.', of the host specified in the request.
#[derive(Clone, Debug)]
pub struct DnsCanisterRule {
    domain_name: String,

    /// The hostname parts that must match the right-hand side of the domain name.  Lower case.
    pub dns_suffix: Vec<String>,

    strategy: PrincipalDeterminationStrategy,
}

impl DnsCanisterRule {
    /// Create a rule for a domain name alias with form dns.alias:canister-id
    pub fn new_alias(dns_alias: &str) -> anyhow::Result<DnsCanisterRule> {
        let (domain_name, principal) = split_dns_alias(dns_alias)?;
        let dns_suffix = split_hostname_lowercase(&domain_name);
        Ok(DnsCanisterRule {
            domain_name,
            dns_suffix,
            strategy: PrincipalDeterminationStrategy::Alias(principal),
        })
    }

    /// Create a rule which for domain names that match the specified suffix,
    /// if the preceding subdomain parses as a principal, return that principal.
    pub fn new_suffix(suffix: &str) -> DnsCanisterRule {
        let dns_suffix: Vec<String> = split_hostname_lowercase(suffix);
        DnsCanisterRule {
            domain_name: suffix.to_string(),
            dns_suffix,
            strategy: PrincipalDeterminationStrategy::PrecedingDomainName,
        }
    }

    /// Return the associated principal if this rule applies to the domain name.
    pub fn lookup(&self, split_hostname_lowercase: &[String]) -> Option<Principal> {
        if split_hostname_lowercase.ends_with(&self.dns_suffix) {
            match &self.strategy {
                PrincipalDeterminationStrategy::Alias(principal) => Some(*principal),
                PrincipalDeterminationStrategy::PrecedingDomainName => {
                    if split_hostname_lowercase.len() > self.dns_suffix.len() {
                        let subdomain = &split_hostname_lowercase
                            [split_hostname_lowercase.len() - self.dns_suffix.len() - 1];
                        Principal::from_text(subdomain).ok()
                    } else {
                        None
                    }
                }
            }
        } else {
            None
        }
    }
}

fn split_hostname_lowercase(hostname: &str) -> Vec<String> {
    hostname
        .split('.')
        .map(|s| s.to_ascii_lowercase())
        .collect()
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
    use crate::config::dns_canister_rule::DnsCanisterRule;

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

    fn parse_dns_alias(alias: &str) -> anyhow::Result<DnsCanisterRule> {
        DnsCanisterRule::new_alias(alias)
    }
}
