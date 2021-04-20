use crate::config::dns_alias::DnsAlias;
use ic_types::Principal;

#[derive(Clone, Debug)]
pub struct CanisterDnsConfig {
    dns_aliases: Vec<DnsAlias>,
}

impl CanisterDnsConfig {
    /// Create a CanisterDnsConfig instance from command-line configuration.
    /// dns_aliases: 0 or more entries of the form of dns.alias:canister-id
    pub fn new(dns_aliases: &[String]) -> anyhow::Result<CanisterDnsConfig> {
        let dns_aliases = dns_aliases
            .iter()
            .map(|alias| DnsAlias::new(alias))
            .collect::<Result<Vec<DnsAlias>, anyhow::Error>>()?;
        Ok(CanisterDnsConfig { dns_aliases })
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
            .find(|dns_alias| host_parts_lowercase.ends_with(&dns_alias.dns_suffix))
            .map(|dns_alias| dns_alias.principal.clone())
    }
}

#[cfg(test)]
mod tests {
    use crate::config::canister_dns_config::CanisterDnsConfig;
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

    fn parse_dns_aliases(aliases: Vec<&str>) -> anyhow::Result<CanisterDnsConfig> {
        let v = aliases.iter().map(|&s| String::from(s)).collect::<Vec<_>>();
        CanisterDnsConfig::new(&v)
    }
}
