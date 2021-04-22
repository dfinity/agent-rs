use crate::config::dns_canister_rule::DnsCanisterRule;
use ic_types::Principal;
use std::cmp::Reverse;

/// Configuration for determination of Domain Name to Principal
#[derive(Clone, Debug)]
pub struct DnsCanisterConfig {
    rules: Vec<DnsCanisterRule>,
}

impl DnsCanisterConfig {
    /// Create a DnsCanisterConfig instance from command-line configuration.
    /// dns_aliases: 0 or more entries of the form of dns.alias:canister-id
    pub fn new(dns_aliases: &[String]) -> anyhow::Result<DnsCanisterConfig> {
        let mut rules = dns_aliases
            .iter()
            .map(|alias| DnsCanisterRule::new_alias(&alias))
            .collect::<anyhow::Result<Vec<DnsCanisterRule>>>()?;
        rules.sort_by_key(|x| Reverse(x.dns_suffix.len()));
        Ok(DnsCanisterConfig { rules })
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
        self.rules
            .iter()
            .find_map(|rule| rule.lookup(&split_hostname_lowercase))
    }
}

#[cfg(test)]
mod tests {
    use crate::config::dns_canister_config::DnsCanisterConfig;
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

    #[test]
    fn searches_longest_to_shortest() {
        // If we checked these in the order passed, a.b.c would erroneously resolve
        // to the canister id associated with b.c
        let dns_aliases = parse_dns_aliases(vec![
            "b.c:rrkah-fqaaa-aaaaa-aaaaq-cai",
            "a.b.c:r7inp-6aaaa-aaaaa-aaabq-cai",
        ])
        .unwrap();

        assert_eq!(
            dns_aliases.resolve_canister_id_from_split_hostname(&["a", "b", "c"]),
            Some(Principal::from_text("r7inp-6aaaa-aaaaa-aaabq-cai").unwrap())
        );
        assert_eq!(
            dns_aliases.resolve_canister_id_from_split_hostname(&["d", "b", "c"]),
            Some(Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap())
        );
    }

    #[test]
    fn searches_longest_to_shortest_even_if_already_ordered() {
        // Similar to searches_longest_to_shortest, just to ensure that
        // we do the right thing no matter which order they are passed.
        let dns_aliases = parse_dns_aliases(vec![
            "a.b.c:r7inp-6aaaa-aaaaa-aaabq-cai",
            "b.c:rrkah-fqaaa-aaaaa-aaaaq-cai",
        ])
        .unwrap();

        assert_eq!(
            dns_aliases.resolve_canister_id_from_split_hostname(&["a", "b", "c"]),
            Some(Principal::from_text("r7inp-6aaaa-aaaaa-aaabq-cai").unwrap())
        );
        assert_eq!(
            dns_aliases.resolve_canister_id_from_split_hostname(&["d", "b", "c"]),
            Some(Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap())
        );
    }

    #[test]
    fn searches_longest_to_shortest_not_alpha() {
        // Similar to searches_longest_to_shortest, but make sure we
        // don't happen to get there by sorting alphabetically
        let dns_aliases = parse_dns_aliases(vec![
            "x.c:rrkah-fqaaa-aaaaa-aaaaq-cai",
            "a.x.c:r7inp-6aaaa-aaaaa-aaabq-cai",
        ])
        .unwrap();

        assert_eq!(
            dns_aliases.resolve_canister_id_from_split_hostname(&["a", "x", "c"]),
            Some(Principal::from_text("r7inp-6aaaa-aaaaa-aaabq-cai").unwrap())
        );
        assert_eq!(
            dns_aliases.resolve_canister_id_from_split_hostname(&["d", "x", "c"]),
            Some(Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap())
        );
    }

    #[test]
    fn searches_longest_to_shortest_not_alpha_reversed() {
        // Similar to searches_longest_to_shortest, but make sure we
        // don't happen to get there by sorting alphabetically/reversed
        let dns_aliases = parse_dns_aliases(vec![
            "a.c:rrkah-fqaaa-aaaaa-aaaaq-cai",
            "x.a.c:r7inp-6aaaa-aaaaa-aaabq-cai",
        ])
        .unwrap();

        assert_eq!(
            dns_aliases.resolve_canister_id_from_split_hostname(&["x", "a", "c"]),
            Some(Principal::from_text("r7inp-6aaaa-aaaaa-aaabq-cai").unwrap())
        );
        assert_eq!(
            dns_aliases.resolve_canister_id_from_split_hostname(&["d", "a", "c"]),
            Some(Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap())
        );
    }

    fn parse_dns_aliases(aliases: Vec<&str>) -> anyhow::Result<DnsCanisterConfig> {
        let v = aliases.iter().map(|&s| String::from(s)).collect::<Vec<_>>();
        DnsCanisterConfig::new(&v)
    }
}
