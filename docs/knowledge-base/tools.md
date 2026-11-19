# Password audit tools

These tools can be used throughout an Active Directory password
assessment. Collection is performed separately from the Password Audit
workflow.

| Tool | Purpose |
| --- | --- |
| [Impacket SecretsDump](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py) | Extracts password hashes from Active Directory. |
| [RustHound-CE](https://github.com/g0h4n/RustHound-CE) | Collects Active Directory relationship and policy data for BloodHound. |
| [Hashcat](https://github.com/hashcat/hashcat) | Recovers plaintext passwords from extracted hashes. |
| [Password Audit](https://github.com/CSpanias/password-audit) | Organises datasets, runs recovery campaigns, and analyses and reports on recovered credentials. |

See the [password audit overview](password-audits.md) for the workflow and
the [audit guide](../audit.md) for the required inputs.
