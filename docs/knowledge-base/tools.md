# Password audit tools

These tools can be used throughout an Active Directory password assessment.
Use `ad-kit` to collect the inputs before running `password-audit`; the latter 
does not launch the collection tools itself.

| Tool | Purpose |
| --- | --- |
| [ad-kit](https://github.com/CSpanias/ad-kit) | Coordinates domain enumeration and collection of NTDS and BloodHound data. |
| [NetExec](https://github.com/Pennyw0rth/NetExec) | Discovers domain information, validates accounts, and exports user and computer lists during enumeration. |
| [Impacket SecretsDump](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py) | Extracts password hashes from Active Directory. |
| [RustHound-CE](https://github.com/g0h4n/RustHound-CE) | Collects Active Directory relationship and policy data for BloodHound. |
| [Hashcat](https://github.com/hashcat/hashcat) | Recovers plaintext passwords from extracted hashes. |
| [Password Audit](https://github.com/CSpanias/password-audit) | Organises datasets, runs recovery campaigns, and analyses and reports on recovered credentials. |

## ad-kit enumeration

Run `ad-kit`'s interactive enumeration workflow:

```bash
ad-kit enum
```

Provide the Domain Controller (DC) IP and account details when prompted, then
select **Run RustHound collection** and **Dump NTDS hashes**.

The NTDS option is offered when Domain Admin (DA) validation is selected and 
requires a successfully validated DA account. `ad-kit` uses `nxc` to discover
the domain, validate accounts, and enumerate domain data before collection. The 
resulting NTDS export and BloodHound ZIP are written under `ad-kit/`.

Supply the `.ntds` file to `--ntds` and the ZIP to `--bloodhound` in
`password-audit`. The NTDS file is a text hash export, not the raw `NTDS.dit`
database.

For the full workflow and prerequisites, see the
[ad-kit enumeration guide](https://cspanias.github.io/ad-kit/commands/enum/).

### SecretsDump

For the NTDS dump, `ad-kit` invokes
[SecretsDump](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py)
from its `ad-kit/` artefacts directory with this command shape:

```text
secretsdump.py <domain>/<da_user>:<da_password>@<dc_ip> \
    -user-status -just-dc-ntlm -outputfile <domain>
```

`-user-status` includes account status in the export, which `password-audit` 
uses to identify enabled accounts, while `-just-dc-ntlm` limits the dump to 
domain NTLM-related hash data. The `-outputfile` uses the discovered domain as 
the output prefix, producing `<domain>.ntds`.

SecretsDump uses the DC's directory replication interface for this collection.
For more on extraction methods, see [Password Audits Part 1](https://mollysec.com/posts/password-audits-part-1/).

### RustHound-CE

[RustHound-CE](https://github.com/g0h4n/RustHound-CE) collects directory
objects and relationships for BloodHound. `password-audit` reads the resulting
ZIP to identify supporting information such as enabled users, DAs, and domain 
password policy.

`ad-kit` runs the collector from its `ad-kit/` artefacts directory:

```text
rusthound-ce -d <domain> -u <ldap_user> -p <ldap_password> \
    -i <dc_ip> -c LdapOnly -z
```

It uses the validated standard user when available, otherwise the validated
DA account. `-i` selects the DC, `-c LdapOnly`
limits collection to LDAP, and `-z` creates the ZIP of JSON files.

If LDAP requires stronger authentication, `ad-kit` retries with `--ldaps`.

## Hashcat

Password Audit invokes [Hashcat](https://github.com/hashcat/hashcat) for each
enabled campaign phase. It selects the hash mode, hash dataset, wordlist,
optional rule, potfile, configured flags, and a session name. 

A phase with a rule has the following command shape:

```text
<hashcat_binary> -m <hash_mode> <hash_file> <wordlist> \
    --potfile-path <potfile> -r <rule> <configured_flags> \
    --status --status-timer=5 --session <campaign_name>-<run_id>-<phase_id>
```

The `-r` arguments are omitted when a wordlist phase has no rule. NTLM uses
mode `1000` and LM uses mode `3000`. Standalone `crack run` sessions omit the
run ID.

`password-audit` executes phases in order, tracks their progress and recovery 
statistics, and uses the potfile to map recoveries. A loopback phase builds a 
wordlist from passwords already in the potfile and passes it to Hashcat as 
another wordlist phase.

When LM hashes are present, the audit also runs the following command and
writes its output for LM password mapping:

```text
<hashcat_binary> -m 3000 --show <lm_hash_file> --potfile-path <potfile>
```

The actual paths and flags come from the campaign and workflow; use
`password-audit crack run --debug` to display the generated phase command.
See [Crack campaigns](../crack.md) and [LM](../lm.md) for details.

## Password Audit

The recommended `audit` command ties the collected datasets and recovery
campaign together:

```bash
password-audit audit \
    --ntds ad-kit/DOMAIN.LOCAL.ntds \
    --bloodhound ad-kit/bloodhound.zip \
    --campaign campaign.json \
    --campaign-name internal-audit
```

It organises the exports, runs the configured NTLM and, when applicable, LM
phases, maps recovered passwords to accounts, and generates the analysis
report.
