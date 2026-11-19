# Wordlists and rules

Wordlists supply candidate passwords; rules mutate those candidates to cover
additional patterns. Neither a single wordlist nor a single ruleset is best
for every environment. Select combinations according to the assessment,
available hardware, and time budget.

## Wordlists

For UK-based Active Directory assessments, HashMob Combined Full,
`weakpass_4a.policy`, and `weakpass_4.merged` are useful starting points
before larger corpora. Actual results vary by organisation, so review
recovery rates and runtime rather than assuming a dataset will perform best.

The following sizes are indicative snapshots in GB; downloads and extracted
datasets can change over time and may require different amounts of disk space.

| Wordlist | Size (GB) | Notes |
| --- | ---: | --- |
| [weakpass_4a.latin.txt](https://weakpass.com/wordlists/weakpass_4a.latin.txt) | 79.43 | Large Latin-only corpus prioritising coverage over efficiency. |
| [weakpass_4.merged.txt](https://weakpass.com/wordlists/weakpass_4.merged.txt) | 37.72 | Combines `weakpass_4` and `weakpass_4a.policy.txt`, with duplicates removed. |
| [HashMob Combined Full](https://hashmob.net/api/v2/downloads/research/official/hashmob.net_2026-11-08.found.7z) | 29.72 | Combined official and community-submitted password recoveries. |
| [weakpass_4.latin.txt](https://weakpass.com/wordlists/weakpass_4.latin.txt) | 22.03 | Latin-only corpus balancing coverage and dataset size. |
| [weakpass_4a.policy.txt](https://weakpass.com/wordlists/weakpass_4a.policy.txt) | 19.17 | Passwords with at least eight characters, Latin-only characters, and at least three character classes. |

## Rules

Rules can substantially increase the coverage of a wordlist, but large
rulesets also increase runtime and may generate duplicate candidates.
`OneRuleToRuleThemStill` is a strong established starting point;
`hashmob.50k.rule` is a promising alternative, particularly with HashMob
wordlists, but should be benchmarked against the established choice for the
assessment. `best66` is a smaller option for a fast baseline.

Sizes and rule counts below are indicative snapshots and may change with
upstream versions.

| Rule | Size (bytes) | Rule count | Notes |
| --- | ---: | ---: | --- |
| [hashmob.50k.rule](https://hashmob.net/api/v2/downloads/research/official/hashmob_rules/HashMob.50k.rule) | 767,750 | 48,439 | Set-coverage-optimised ruleset intended to increase unique recoveries while limiting redundant mutations. |
| [OneRuleToRuleThemStill](https://in.security/2023/01/10/oneruletorulethemstill-new-and-improved/) | 486,474 | 50,000 | Community ruleset focused on recovery from real-world datasets. |
| [best66](https://github.com/hashcat/hashcat/blob/master/rules/best66.rule) | 766 | 66 | Small ruleset for a fast baseline. |

## Using combinations

Start with a suitable wordlist and ruleset, measure recovery and runtime,
then add complementary combinations where the expected benefit justifies the
cost. Avoid unnecessarily repeating candidates across phases. For campaign
syntax and wordlist/rule path resolution, see
[Campaign configuration](../crack.md#campaign-configuration).
