use crate::config::dns_alias::DnsAlias;
use ic_types::Principal;

/// Configuration for determination of Domain Name to Principal
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
            .collect::<anyhow::Result<Vec<DnsAlias>>>()?;
        Ok(CanisterDnsConfig { dns_aliases })
    }

    /// Return the Principal of the canister that matches the host name.
    ///
    /// split_hostname is expected to be the hostname split by '.',
    /// but may contain upper- or lower-case characters.
    pub fn resolve_canister_id_from_split_hostname(
        &self,
        split_hostname: &[&str],
    ) -> Option<Principal> {
        let split_hostname_lowercase: Vec<String> = split_hostname
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
        self.dns_aliases
            .iter()
            .find(|dns_alias| split_hostname_lowercase.ends_with(&dns_alias.dns_suffix))
            .map(|dns_alias| dns_alias.principal.clone())
    }
}

#[cfg(test)]
mod tests {
    use crate::config::canister_dns_config::CanisterDnsConfig;
    use ic_types::Principal;

    #[test]
    fn matches_whole_hostname() {
        let dns_aliases =
            parse_dns_aliases(vec!["happy.little.domain.name:r7inp-6aaaa-aaaaa-aaabq-cai"])
                .unwrap();

        assert_eq!(
            dns_aliases
                .resolve_canister_id_from_split_hostname(&["happy", "little", "domain", "name"]),
            Some(Principal::from_text("r7inp-6aaaa-aaaaa-aaabq-cai").unwrap())
        )
    }

    #[test]
    fn matches_partial_hostname() {
        let dns_aliases =
            parse_dns_aliases(vec!["little.domain.name:r7inp-6aaaa-aaaaa-aaabq-cai"]).unwrap();

        assert_eq!(
            dns_aliases
                .resolve_canister_id_from_split_hostname(&["happy", "little", "domain", "name"]),
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
            dns_aliases
                .resolve_canister_id_from_split_hostname(&["happy", "little", "domain", "name"]),
            None
        )
    }

    #[test]
    fn case_insensitive_match() {
        let dns_aliases =
            parse_dns_aliases(vec!["lItTlE.doMain.nAMe:r7inp-6aaaa-aaaaa-aaabq-cai"]).unwrap();

        assert_eq!(
            dns_aliases
                .resolve_canister_id_from_split_hostname(&["hAPpy", "littLE", "doMAin", "NAme"]),
            Some(Principal::from_text("r7inp-6aaaa-aaaaa-aaabq-cai").unwrap())
        )
    }

    #[test]
    fn chooses_among_many() {
        let dns_aliases = parse_dns_aliases(vec![
            "happy.little.domain.name:r7inp-6aaaa-aaaaa-aaabq-cai",
            "ecstatic.domain.name:rrkah-fqaaa-aaaaa-aaaaq-cai",
        ])
        .unwrap();

        assert_eq!(
            dns_aliases
                .resolve_canister_id_from_split_hostname(&["happy", "little", "domain", "name"]),
            Some(Principal::from_text("r7inp-6aaaa-aaaaa-aaabq-cai").unwrap())
        );

        assert_eq!(
            dns_aliases.resolve_canister_id_from_split_hostname(&["ecstatic", "domain", "name"]),
            Some(Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap())
        );

        assert_eq!(
            dns_aliases
                .resolve_canister_id_from_split_hostname(&["super", "ecstatic", "domain", "name"]),
            Some(Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap())
        )
    }

    #[test]
    fn chooses_first_match() {
        let dns_aliases = parse_dns_aliases(vec![
            "specific.of.many:r7inp-6aaaa-aaaaa-aaabq-cai",
            "of.many:rrkah-fqaaa-aaaaa-aaaaq-cai",
        ])
        .unwrap();

        assert_eq!(
            dns_aliases.resolve_canister_id_from_split_hostname(&["specific", "of", "many"]),
            Some(Principal::from_text("r7inp-6aaaa-aaaaa-aaabq-cai").unwrap())
        );
        assert_eq!(
            dns_aliases
                .resolve_canister_id_from_split_hostname(&["more", "specific", "of", "many"]),
            Some(Principal::from_text("r7inp-6aaaa-aaaaa-aaabq-cai").unwrap())
        );

        assert_eq!(
            dns_aliases.resolve_canister_id_from_split_hostname(&["another", "of", "many"]),
            Some(Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap())
        )
    }

    fn parse_dns_aliases(aliases: Vec<&str>) -> anyhow::Result<CanisterDnsConfig> {
        let v = aliases.iter().map(|&s| String::from(s)).collect::<Vec<_>>();
        CanisterDnsConfig::new(&v)
    }
}
