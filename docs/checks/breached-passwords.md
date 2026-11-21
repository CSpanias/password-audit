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

### Downloading NTLM ranges

The [Pwned Passwords Downloader](https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader#what-is-haveibeenpwned-downloader)
provides an offline dataset. Alternatively, use `curl.exe` in PowerShell to
download the NTLM ranges. Choose a new, empty destination directory and
adjust the path for your system:

```powershell
curl.exe --fail --silent --show-error --retry 10 --retry-all-errors --parallel --parallel-max 20 --output 'C:\tools\hashcat\hibp-ntlm\#1#2#3#4#5' 'https://api.pwnedpasswords.com/range/{0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F}{0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F}{0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F}{0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F}{0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F}?mode=ntlm'
```

The full download contains 1,048,576 range files. Check for download errors
and verify the dataset before use; counting files alone does not establish
their integrity.

### Running the check

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
