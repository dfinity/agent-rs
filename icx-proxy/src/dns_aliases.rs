use ic_types::Principal;

use anyhow::anyhow;
use std::error::Error;
use std::ops::Deref;

#[derive(Clone, Debug)]
struct DnsAlias {
    domain_name: String,
    dns_suffix: Vec<String>,
    principal: Principal,
}

#[derive(Clone, Debug)]
pub struct DnsAliases {
    dns_aliases: Vec<DnsAlias>,
}

impl DnsAliases {
    /// todo comment
    pub fn new(arg: &[String]) -> Result<DnsAliases, anyhow::Error> {
        let dns_aliases = arg
            .iter()
            .map(|alias| {
                let (domain_name, principal) = parse_dns_alias(&alias)?;
                let dns_suffix: Vec<String> = domain_name.split('.').map(String::from).collect();
                Ok(DnsAlias {
                    domain_name,
                    dns_suffix,
                    principal,
                })
            })
            .collect::<Result<Vec<DnsAlias>, anyhow::Error>>()?;
        Ok(DnsAliases { dns_aliases })
    }

    /// todo comment
    pub fn resolve_canister_id_from_host_parts(&self, host_parts: &[&str]) -> Option<Principal> {
        self.dns_aliases
            .iter()
            .find(|dns_alias| {
                // todo: replace with loop
                let suffix: Vec<&str> = dns_alias.dns_suffix.iter().map(Deref::deref).collect();
                host_parts.ends_with(suffix.as_slice())
            })
            .map(|dns_alias| dns_alias.principal.clone())
    }
}

fn parse_dns_alias(alias: &str) -> Result<(String, Principal), anyhow::Error> {
    match alias.find(':') {
        Some(index) => {
            let (domain_name, principal) = alias.split_at(index);
            let principal = &principal[1..];
            let principal = Principal::from_text(principal)?;
            Ok((domain_name.to_string(), principal))
        }
        None => Err(anyhow!(
            r#"Unrecognized DNS alias "{0}".  Format is dns.alias:principal-id"#,
            alias.to_string(),
        )),
    }
}

// todo: unit tests
