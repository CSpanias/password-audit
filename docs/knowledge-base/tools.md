# Password audit tools

These tools can be used throughout an Active Directory password
assessment. Collection is performed separately from the Password Audit
workflow; Password Audit does not launch SecretsDump or RustHound-CE.

| Tool | Purpose |
| --- | --- |
| [Impacket SecretsDump](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py) | Extracts password hashes from Active Directory. |
| [RustHound-CE](https://github.com/g0h4n/RustHound-CE) | Collects Active Directory relationship and policy data for BloodHound. |
| [Hashcat](https://github.com/hashcat/hashcat) | Recovers plaintext passwords from extracted hashes. |
| [Password Audit](https://github.com/CSpanias/password-audit) | Organises datasets, runs recovery campaigns, and analyses and reports on recovered credentials. |

## SecretsDump

[SecretsDump](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py)
can retrieve domain credential data through the domain controller's directory
replication interface. The following is an example collection command, run
separately before Password Audit:

```bash
secretsdump.py -just-dc -outputfile company 'DOMAIN/username@dc'
```

Replace the domain, username, and domain controller with the appropriate
values. SecretsDump prompts for a password when one is not supplied. The
`-just-dc` option limits collection to domain data, and `-outputfile`
specifies the output prefix. Use the resulting `company.ntds` hash export as
the `--ntds` input; this is a text export, not the raw `NTDS.dit` database.
For more on extraction methods, see
[Password Audits Part 1](https://mollysec.com/posts/password-audits-part-1/).

## RustHound-CE

[RustHound-CE](https://github.com/g0h4n/RustHound-CE) collects directory
objects and relationships for BloodHound. Password Audit reads the resulting
ZIP to identify supporting information such as enabled users, Domain
Administrators, and domain password policy.

For example, run the collector separately with:

```bash
rusthound-ce -d DOMAIN.LOCAL -u USERNAME@DOMAIN.LOCAL -z
```

The `-z` option creates a ZIP of the collected JSON files. Supply that
archive as the `--bloodhound` input. Authentication and collection options
depend on the environment; consult the
[RustHound-CE documentation](https://github.com/g0h4n/RustHound-CE/blob/main/HELP.md)
for details.

## Hashcat

Password Audit invokes [Hashcat](https://github.com/hashcat/hashcat) for each
enabled campaign phase. It selects the hash mode, hash dataset, wordlist,
optional rule, potfile, configured flags, and a session name. A phase with a
rule has this command shape:

```text
<hashcat_binary> -m <hash_mode> <hash_file> <wordlist> \
    --potfile-path <potfile> -r <rule> <configured_flags> \
    --status --status-timer=5 --session <campaign_name>-<phase_id>
```

The `-r` arguments are omitted when a wordlist phase has no rule. NTLM uses
mode `1000` and LM uses mode `3000`. Password Audit executes phases in order,
tracks their progress and recovery statistics, and uses the potfile to map
recoveries. A loopback phase builds a wordlist from passwords already in the
potfile and passes it to Hashcat as another wordlist phase.

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
    --ntds company.ntds \
    --bloodhound bloodhound.zip \
    --campaign campaign.json \
    --campaign-name internal-audit
```

It organises the exports, runs the configured NTLM and, when applicable, LM
phases, maps recovered passwords to accounts, and generates the analysis
report. These stages are orchestrated within Password Audit; they are not
separate SecretsDump or RustHound-CE commands. See the
[audit guide](../audit.md) for inputs and options.
