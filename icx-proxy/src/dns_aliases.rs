use ic_types::Principal;

use anyhow::anyhow;

const FORMAT_HELP: &str = "Format is dns.alias:principal-id";

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
    /// Parse 0 or more DNS aliases in the form of dns.alias:canister-id
    pub fn new(arg: &[String]) -> Result<DnsAliases, anyhow::Error> {
        let dns_aliases = arg
            .iter()
            .map(|alias| {
                let (domain_name, principal) = parse_dns_alias(&alias)?;
                let dns_suffix: Vec<String> = domain_name
                    .split('.')
                    .map(|s| String::from(s).to_ascii_lowercase())
                    .collect();
                Ok(DnsAlias {
                    domain_name,
                    dns_suffix,
                    principal,
                })
            })
            .collect::<Result<Vec<DnsAlias>, anyhow::Error>>()?;
        Ok(DnsAliases { dns_aliases })
    }

    /// Find the first DNS alias that exactly matches the end of the given host name,
    /// and return the associated Principal.
    /// host_parts is expected to be split by '.',
    /// but may contain upper- or lower-case characters.
    pub fn resolve_canister_id_from_host_parts(&self, host_parts: &[&str]) -> Option<Principal> {
        let host_parts_lowercase: Vec<_> =
            host_parts.iter().map(|s| s.to_ascii_lowercase()).collect();
        self.dns_aliases
            .iter()
            .find(|dns_alias| {
                // if dns_alias.dns_suffix.len() > host_parts.len() {
                //     false
                // } else {
                //     let mut dns_alias_rev_iter = dns_alias.dns_suffix.iter().rev();
                //     host_parts_lowercase.iter().rev().find(|host_part| match (host_part, dns_alias_rev_iter.next()) {
                //         (&host_part, Some(dns_part)) => {
                //             host_part != dns_part
                //         },
                //         _ => {
                //             println!("oh no");
                //             unreachable!()
                //         },
                //     }).is_some()
                // }
                // todo: replace with loop
                // let suffix: Vec<&str> = dns_alias.dns_suffix.iter().map(Deref::deref).collect();
                // host_parts.ends_with(suffix.as_slice())
                host_parts_lowercase.ends_with(&dns_alias.dns_suffix)
            })
            .map(|dns_alias| dns_alias.principal.clone())
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

#[cfg(test)]
mod tests {
    use crate::dns_aliases::DnsAliases;
    use ic_types::Principal;

    #[test]
    fn parse_error_no_colon() {
        let e = parse_dns_aliases(vec!["happy.little.domain.name!r7inp-6aaaa-aaaaa-aaabq-cai"])
            .expect_err("expected failure due to missing colon");
        assert_eq!(
            e.to_string(),
            r#"Unrecognized DNS alias "happy.little.domain.name!r7inp-6aaaa-aaaaa-aaabq-cai".  Format is dns.alias:principal-id"#
        )
    }

    #[test]
    fn parse_error_nothing_after_colon() {
        let e = parse_dns_aliases(vec!["happy.little.domain.name:"])
            .expect_err("expected failure due to nothing after colon");
        assert_eq!(
            e.to_string(),
            r#"No canister ID specifed in DNS alias "happy.little.domain.name:".  Format is dns.alias:principal-id"#
        )
    }
    #[test]
    fn parse_error_nothing_before_colon() {
        let e = parse_dns_aliases(vec![":r7inp-6aaaa-aaaaa-aaabq-cai"])
            .expect_err("expected failure due to nothing after colon");
        assert_eq!(
            e.to_string(),
            r#"No domain specifed in DNS alias ":r7inp-6aaaa-aaaaa-aaabq-cai".  Format is dns.alias:principal-id"#
        )
    }

    #[test]
    fn matches_whole_hostname() {
        let dns_aliases =
            parse_dns_aliases(vec!["happy.little.domain.name:r7inp-6aaaa-aaaaa-aaabq-cai"])
                .unwrap();

        assert_eq!(
            dns_aliases.resolve_canister_id_from_host_parts(&["happy", "little", "domain", "name"]),
            Some(Principal::from_text("r7inp-6aaaa-aaaaa-aaabq-cai").unwrap())
        )
    }

    #[test]
    fn matches_partial_hostname() {
        let dns_aliases =
            parse_dns_aliases(vec!["little.domain.name:r7inp-6aaaa-aaaaa-aaabq-cai"]).unwrap();

        assert_eq!(
            dns_aliases.resolve_canister_id_from_host_parts(&["happy", "little", "domain", "name"]),
            Some(Principal::from_text("r7inp-6aaaa-aaaaa-aaabq-cai").unwrap())
        )
    }

    #[test]
    fn extraneous_does_not_match() {
        let dns_aliases = parse_dns_aliases(vec![
            "very.happy.little.domain.name:r7inp-6aaaa-aaaaa-aaabq-cai",
        ])
        .unwrap();

        assert_eq!(
            dns_aliases.resolve_canister_id_from_host_parts(&["happy", "little", "domain", "name"]),
            None
        )
    }

    #[test]
    fn case_insensitive_match() {
        let dns_aliases =
            parse_dns_aliases(vec!["lItTlE.doMain.nAMe:r7inp-6aaaa-aaaaa-aaabq-cai"]).unwrap();

        assert_eq!(
            dns_aliases.resolve_canister_id_from_host_parts(&["hAPpy", "littLE", "doMAin", "NAme"]),
            Some(Principal::from_text("r7inp-6aaaa-aaaaa-aaabq-cai").unwrap())
        )
    }

    fn parse_dns_aliases(aliases: Vec<&str>) -> anyhow::Result<DnsAliases> {
        let v = aliases.iter().map(|&s| String::from(s)).collect::<Vec<_>>();
        DnsAliases::new(&v)
    }
}
