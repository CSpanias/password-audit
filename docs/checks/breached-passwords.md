# Passwords in Breach Data

The optional `--hibp` check compares enabled user NT hashes against a local
[Have I Been Pwned Pwned Passwords](https://haveibeenpwned.com/Passwords)
dataset. It does not require password recovery or make network requests.

## Input

Provide a directory of NTLM ranges downloaded from the Pwned Passwords API.
Each range must be named with its five-character uppercase hexadecimal
prefix, either without an extension (as with the curl download) or with
`.txt` (as with the official downloader). Each line contains a 27-character
hexadecimal NT hash suffix, a colon, and a positive occurrence count.
SHA-1 ranges and a single full-hash file are not supported.

```bash
password-audit analyse \
    --mapped-ntlm-passwords password-audit/mapped-ntlm-passwords.txt \
    --hibp /path/to/ntlm-ranges
```

The `audit` command also accepts `--hibp`. For `analyse`, the organiser's
enabled NTDS records must be auto-detected or supplied using `--ntds-users`.
The check opens only ranges needed for the supplied accounts. Missing, empty,
or malformed required ranges stop report generation with an error.

## Interpreting results

Verify the download is complete and uncorrupted before using it. Checking the
syntax and presence of required files cannot detect every truncated or
outdated file. Results depend on the supplied dataset's completeness and
age; a non-match does not establish that a password is safe.

A matching hash indicates that the password is represented in the dataset,
not that the account itself appeared in a breach. Hash collisions are
theoretically possible. Counts refer to affected accounts, not unique
passwords or distinct breaches, and may overlap with other findings.

## Findings

| Finding ID | Title |
| --- | --- |
| PWD-BREACH-001 | Passwords Found in Known Breach Data |

## References

- [Have I Been Pwned: Pwned Passwords](https://haveibeenpwned.com/Passwords)
- [Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords)
