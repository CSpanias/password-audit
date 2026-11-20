# LM Hashes

Identifies accounts with legacy LAN Manager (LM) password hashes and reports
LM password recovery where results are available.

## What it checks

The organiser identifies enabled, unfiltered user accounts with an LM hash
other than the well-known empty LM value. Analysis reports the affected
accounts, distinct and duplicate hashes, and fully and partially recovered
LM passwords. It also checks recovered LM passwords against the Domain Admin
list.

## How it works

LM hashing converts passwords to uppercase and processes two independent
seven-character halves. This design makes offline password recovery much
easier than attacking the original password as a single case-sensitive value.

LM hash presence does not require successful cracking. When LM recovery
results are supplied, Hashcat's `--show` output is used to reconstruct and
map recovered halves to accounts. See [LM workflows](../lm.md) for details.

## Why it matters

An exposed LM hash can substantially reduce the effort needed to recover a
password. This is especially concerning for accounts with privileged access.

## Interpreting results

LM recovery does not preserve the password's original case. Partial recovery
does not necessarily reveal the complete password. The Domain Administrator
LM finding is based on mapped LM recovery results matched to the DA list; it
is not an independent inventory of every DA storing an LM hash. DA matching
uses normalised names, so confirm identities where domains contain duplicate
names.

Missing LM inputs in standalone analysis limit the conclusions that can be
drawn. Duplicate LM hashes indicate matching LM values, but differences in
password case are not represented by LM hashing.

## Findings

| Finding ID | Title |
| --- | --- |
| LM-AUTH-001 | LM Hashes Present |
| DOMAIN-ADMIN-002 | Domain Administrator LM Hashes |

## References

- [Microsoft: do not store LM hash values](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-do-not-store-lan-manager-hash-value-on-next-password-change)
