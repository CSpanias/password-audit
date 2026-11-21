# Password Audit

Password Audit is a command-line toolkit for auditing Active Directory
passwords. It brings together data organisation, password recovery, and
analysis to make it easier to turn assessment data into actionable findings.

The project was created to streamline a workflow that often involves several
separate tools, combining a practical need for password auditing with an
interest in password cracking.

It brings together and extends the earlier `ntds-organiser`,
`hashcat-scheduler`, and `password-analyser` projects.

## What it does

- Organises NTDS and BloodHound exports into datasets for an audit.
- Runs configurable Hashcat campaigns to recover NTLM and, optionally, LM
  passwords.
- Maps recovered passwords to accounts and analyses password patterns, reuse,
  privileged accounts, and other [checks](checks/index.md).
- Optionally compares enabled-account NT hashes against a local
  [Pwned Passwords dataset](checks/breached-passwords.md) with `--hibp`,
  including hashes whose passwords were not recovered.
- Produces a self-contained HTML report and structured JSON findings.

## Get started

[Install Password Audit](installation.md), then follow the
[password audit workflow](knowledge-base/password-audits.md). The recommended
[`audit`](audit.md) command runs the complete workflow after the input data
has been collected.

For advanced or partial workflows, the [Organise](organise.md), [Crack](crack.md),
[Analyse](analyse.md), and [LM](lm.md) commands are also available separately.

See [Wordlists and rules](knowledge-base/wordlists-and-rules.md) for password
recovery resources.
