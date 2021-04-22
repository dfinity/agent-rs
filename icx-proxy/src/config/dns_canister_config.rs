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
    /// dns_suffixes: 0 or more domain names which will match as a suffix
    pub fn new(
        dns_aliases: &[String],
        dns_suffixes: &[String],
    ) -> anyhow::Result<DnsCanisterConfig> {
        let mut rules = vec![];
        for suffix in dns_suffixes {
            rules.push(DnsCanisterRule::new_suffix(suffix));
        }
        for alias in dns_aliases {
            rules.push(DnsCanisterRule::new_alias(alias)?);
        }
        // Check suffixes first (via stable sort), because they will only match
        // if actually preceded by a canister id.
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

    #[test]
    fn dns_suffix_localhost_canister_found() {
        let config = parse_config(vec![], vec!["localhost"]).unwrap();

        assert_eq!(
            config.resolve_canister_id_from_split_hostname(&[
                "rrkah-fqaaa-aaaaa-aaaaq-cai",
                "localhost"
            ]),
            Some(Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap())
        );
        assert_eq!(
            config.resolve_canister_id_from_split_hostname(&[
                "r7inp-6aaaa-aaaaa-aaabq-cai",
                "localhost"
            ]),
            Some(Principal::from_text("r7inp-6aaaa-aaaaa-aaabq-cai").unwrap())
        )
    }

    #[test]
    fn dns_suffix_localhost_more_domain_names_ok() {
        let config = parse_config(vec![], vec!["localhost"]).unwrap();

        assert_eq!(
            config.resolve_canister_id_from_split_hostname(&[
                "more",
                "rrkah-fqaaa-aaaaa-aaaaq-cai",
                "localhost"
            ]),
            Some(Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap())
        );
        assert_eq!(
            config.resolve_canister_id_from_split_hostname(&[
                "even",
                "more",
                "r7inp-6aaaa-aaaaa-aaabq-cai",
                "localhost"
            ]),
            Some(Principal::from_text("r7inp-6aaaa-aaaaa-aaabq-cai").unwrap())
        )
    }

    #[test]
    fn dns_suffix_must_immediately_precede_suffix() {
        let config = parse_config(vec![], vec!["localhost"]).unwrap();

        assert_eq!(
            config.resolve_canister_id_from_split_hostname(&[
                "rrkah-fqaaa-aaaaa-aaaaq-cai",
                "nope",
                "localhost"
            ]),
            None
        );
    }

    #[test]
    fn dns_suffix_longer_suffix_ok() {
        let config = parse_config(vec![], vec!["a.b.c"]).unwrap();

        assert_eq!(
            config.resolve_canister_id_from_split_hostname(&[
                "rrkah-fqaaa-aaaaa-aaaaq-cai",
                "a",
                "b",
                "c"
            ]),
            Some(Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap())
        );
    }

    #[test]
    fn dns_suffix_longer_suffix_still_requires_exact_positionok() {
        let config = parse_config(vec![], vec!["a.b.c"]).unwrap();

        assert_eq!(
            config.resolve_canister_id_from_split_hostname(&[
                "rrkah-fqaaa-aaaaa-aaaaq-cai",
                "no",
                "a",
                "b",
                "c"
            ]),
            None
        );
    }

    #[test]
    fn dns_suffix_longer_suffix_can_be_preceded_by_more() {
        let config = parse_config(vec![], vec!["a.b.c"]).unwrap();

        assert_eq!(
            config.resolve_canister_id_from_split_hostname(&[
                "yes",
                "rrkah-fqaaa-aaaaa-aaaaq-cai",
                "a",
                "b",
                "c"
            ]),
            Some(Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap())
        );
    }

    #[test]
    fn dns_suffix_ignores_earlier_canister_ids() {
        let config = parse_config(vec![], vec!["a.b.c"]).unwrap();

        assert_eq!(
            config.resolve_canister_id_from_split_hostname(&[
                "r7inp-6aaaa-aaaaa-aaabq-cai", // not seen/returned
                "rrkah-fqaaa-aaaaa-aaaaq-cai",
                "a",
                "b",
                "c"
            ]),
            Some(Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap())
        );
    }

    #[test]
    fn aliases_and_suffixes() {
        let config = parse_config(
            vec![
                "a.b.c:r7inp-6aaaa-aaaaa-aaabq-cai",
                "d.e:rrkah-fqaaa-aaaaa-aaaaq-cai",
            ],
            vec!["g.h.i"],
        )
        .unwrap();

        assert_eq!(
            config.resolve_canister_id_from_split_hostname(&["a", "b", "c"]),
            Some(Principal::from_text("r7inp-6aaaa-aaaaa-aaabq-cai").unwrap())
        );
        assert_eq!(
            config.resolve_canister_id_from_split_hostname(&["d", "e",]),
            Some(Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap())
        );
        assert_eq!(
            config.resolve_canister_id_from_split_hostname(&[
                "ryjl3-tyaaa-aaaaa-aaaba-cai",
                "g",
                "h",
                "i",
            ]),
            Some(Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap())
        );
    }

    #[test]
    fn same_alias_and_suffix_prefers_alias() {
        // because the suffix will only match if preceded by a canister id
        let config =
            parse_config(vec!["a.b.c:r7inp-6aaaa-aaaaa-aaabq-cai"], vec!["a.b.c"]).unwrap();

        assert_eq!(
            config.resolve_canister_id_from_split_hostname(&["a", "b", "c"]),
            Some(Principal::from_text("r7inp-6aaaa-aaaaa-aaabq-cai").unwrap())
        );
        assert_eq!(
            config.resolve_canister_id_from_split_hostname(&[
                "ryjl3-tyaaa-aaaaa-aaaba-cai",
                "a",
                "b",
                "c"
            ]),
            Some(Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap())
        );
    }

    fn parse_dns_aliases(aliases: Vec<&str>) -> anyhow::Result<DnsCanisterConfig> {
        let aliases: Vec<String> = aliases.iter().map(|&s| String::from(s)).collect();
        DnsCanisterConfig::new(&aliases, &[])
    }

    fn parse_config(aliases: Vec<&str>, suffixes: Vec<&str>) -> anyhow::Result<DnsCanisterConfig> {
        let aliases: Vec<String> = aliases.iter().map(|&s| String::from(s)).collect();
        let suffixes: Vec<String> = suffixes.iter().map(|&s| String::from(s)).collect();
        DnsCanisterConfig::new(&aliases, &suffixes)
    }
}
