# LM Hashes

## Why the Extra Step?

Unlike NTLM hashes, [LM passwords are processed in two independent 7-character halves](https://learn.microsoft.com/en-us/archive/blogs/miriamxyra/stop-using-lan-manager-and-ntlmv1#but-there-is-also-another-vulnerability-caused-by-the-first-implementation-of-this-protocol). Each half produces a separate LM hash value, resulting in a 32-character LM hash composed of two 16-character hash halves:

![](images/lm-hashing.jpg)

Hashcat [stores recovered LM hash (16-character) halves](https://hashcat.net/wiki/doku.php?id=example_hashes#:~:text=3000) in the potfile rather than the full 32-character values. Consequently, the potfile cannot be used directly to map recovered LM passwords back to user accounts:

```bash
# Full 32-character hash within the LM dataset
$ head -1 ntds-organiser/lm-hashes.txt
c23413a8a1e7665f1bf3ece46b279e12

# Stored halves within the potfile
$ grep 'c23413a8a1e7665f' hashcat.potfile
c23413a8a1e7665f:WELCOME
$ grep '1bf3ece46b279e12' hashcat.potfile
1bf3ece46b279e12:123!
```

As a result, an additional `hashcat --show` step is required to reconstruct the full LM hash and map recovered passwords back to user accounts:

!!! warning
    Do this step via Bash; PowerShell breaks the potfile encoding format and needs extra steps to address it.

```bash
# Validate that the full LM hash is shown
$ hashcat -m3000 \
    --show ntds-organiser/lm-hashes.txt \
    --potfile-path hashcat.potfile \
    | grep 'WELCOME'
c23413a8a1e7665f1bf3ece46b279e12:WELCOME123!
```

## Workflow

If LM hashes are present within NTDS, `organise` identifies and extracts them:

```bash
 $ password-audit organise -N example.ntds -B bloodhound.zip
[*] NTDS Organiser

    Enabled Accounts    : 24718
    Disabled Accounts   : 18943
    User Accounts       : 16327
    Machine Accounts    : 8391
    NTLM Hashes         : 15502
    LM Hashes           : 147 # exported to lm-hashes.txt
    Company Words       : 22
    Domain Admins       : 11

    Output Directory    : ntds-organiser
```

These can be cracked as normal using the `crack run` command:

!!! info
    For an example JSON file see [Campaign Structure](crack.md#campaign-structure).

```bash
password-audit crack run \
    -C example-lm-config.json \
    -H ntds-organiser/lm-hashes.txt \
    -G example-lm-test
```

After cracking is complete, `organise` maps the recovered passwords back to their users:

!!! note
    The number of mapped LM passwords may exceed the number of recovered LM hashes due to the hash's structure and/or password reuse.
  

```bash
# Write the LM dataset to a file
$ hashcat -m3000 \
    --show ntds-organiser/lm-hashes.txt \
    --potfile-path hashcat.potfile \
    > lm-results.txt

# Map recovered passwords back to their users
$ password-audit organise \
    -N example.ntds \
    -P hashcat.potfile \
    -L ntds-organiser/lm-results.txt

[*] NTDS Organiser

    Enabled Accounts    : 21840
    Disabled Accounts   : 21196
    User Accounts       : 14584
    Machine Accounts    : 7256
    NTLM Hashes         : 13866
    LM Hashes           : 132
    Company Words       : 17
    Mapped Passwords    : 4026
    Mapped LM Passwords : 242 # exported to mapped-lm-passwords.txt

    Output Directory    : ntds-organiser
```

The generated dataset will contain the record with the password in uppercase format:

```bash
$ grep 'WELCOME123!' ntds-organiser/mapped-lm-passwords.txt
domain.local\mike:WELCOME123!
```

## Reporting

The LM datasets can be analysed and have LM-related findings added to the final report (alongside the NTLM dataset):

```bash
password-audit analyse \
    -M ntds-organiser/mapped-ntlm-passwords.txt \
    -U ntds-organiser/lm-users.txt \
    -L ntds-organiser/mapped-lm-passwords.txt
```

The following LM findings are currently present:

* LM hash exposure
* Unique and duplicate LM hash analysis
* LM password recovery statistics
* LM Domain Administrator exposure

## Domain Administrator Candidate Generation

The LM dataset can be processed further using the `lm` module.

Because LM hashes do not preserve character casing, recovered passwords are presented in uppercase form and may not reflect the user's original password. The `lm` module identifies recovered LM passwords belonging to Domain Administrator accounts and generates all possible capitalisation variants, enabling recovery of the original password casing through password spraying:

!!! note
    The recovered password `WELCOME123!` contains nine alphabetic characters, each of which can be either uppercase or lowercase. As a result,
    `2^9 = 512` possible capitalisation variants are generated, one of which represents the user's original password.

```bash
$ password-audit lm \
    -L ntds-organiser/mapped-lm-passwords.txt \
    -D ntds-organiser/domain-admins.txt

[*] LM Candidate Generation

    Domain Admins    : 14
    LM DA Passwords  : 1
    LM DA Users      : 1
    LM DA Candidates : 512

# Recovered LM passwords belonging to Domain Administrators
$ head lm-da-passwords.txt
domain.local\mike:WELCOME123!

# Generated capitalisation variants
$ head -n5 lm-da-candidates.txt
WELCOME123!
WELCOMe123!
WELCOmE123!
WELCoME123!
WELcOME123!
```

The generated user and candidate files can then be used directly for password spraying (e.g. [`conpass`](https://github.com/login-securite/conpass)) to determine the original password capitalisation:

```bash
conpass -d <domain> \
    -u <user> \
    -p <pass> \
    -U lm-da-users.txt \
    -P lm-da-candidates.txt \
    --dc-ip <dc-ip>
```