# LM Hashes

## Overview

Unlike NTLM hashes, [LM passwords are processed in two independent 7-character halves](https://learn.microsoft.com/en-us/archive/blogs/miriamxyra/stop-using-lan-manager-and-ntlmv1#but-there-is-also-another-vulnerability-caused-by-the-first-implementation-of-this-protocol). Each half produces a separate LM hash value, resulting in a 32-character LM hash composed of two 16-character hash halves:

![](images/lm-hashing.jpg)

Hashcat [stores recovered LM hash halves](https://hashcat.net/wiki/doku.php?id=example_hashes#:~:text=3000) in the potfile rather than the original 32-character LM hash values. Consequently, the potfile cannot be used directly to map recovered LM passwords back to user accounts:

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

!!! Warning
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
    LM Hashes           : 147 # LM hashes extracted (lm-hashes.txt)
    Company Words       : 22
    Domain Admins       : 11

    Output Directory    : ntds-organiser
```

These can be cracked as normal using the `crack run` command:

```bash
password-audit crack run \
    -C example-lm-config.json \
    -H ntds-organiser/lm-hashes.txt \
    -G example-lm-test
```

The JSON file could look like this:

```json
{
"parameters": {
    "hashcatDir": "/mnt/c/tools/hashcat",
    "hashMode": "3000",
    "flags": [
      "-O",
      "-w", "3",
      "-d", "1",
      "--status",
      "--status-timer", "300"
    ]
  },

  "phases": [
    {
      "id": "rockyou",
      "type": "wordlist",
      "wordlist": "rockyou.txt",
      "rule": "",
      "enabled": true
    },
    {
      "id": "rockyou-rule",
      "type": "wordlist",
      "wordlist": "rockyou.txt",
      "rule": "OneRuleToRuleThemStill.rule",
      "enabled": true
    },
    {
      "id": "hashmob-rule",
      "type": "wordlist",
      "wordlist": "hashmob.net_2026-06-07.combined.txt",
      "rule": "OneRuleToRuleThemStill.rule",
      "enabled": true
    },
    {
      "id": "loopback-rule",
      "type": "loopback",
      "wordlist": "loopback.txt",
      "rule": "OneRuleToRuleThemStill.rule",
      "enabled": true
    }
  ]
}
```

After cracking is complete, `organise` maps the recovered passwords back to their users:

!!! note
    The number of mapped LM passwords may exceed the number of recovered LM hashes. A single recovered LM hash can be shared across multiple users, resulting in multiple password mappings from a single recovered hash.
  

```bash
# Write the LM dataset to a file
$ hashcat -m3000 \
    --show ntds-organiser/lm-hashes.txt \
    --potfile-path hashcat.potfile \
    > lm-results.txt

# Map recovered password back to their users
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
    Mapped LM Passwords : 242 # LM passwords mapped (mapped-lm-passwords.txt)

    Output Directory    : ntds-organiser
```

The generated dataset will contain the record with the password in uppercase format:

```bash
$ grep 'WELCOME123!' ntds-organiser/mapped-lm-passwords.txt
domain.local\mike:WELCOME123!
```

!!! warning
    LM password analysis and reporting functionality is currently under development and is not yet available.

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
* LM password recovery
* LM Domain Administrator exposure

### Password Spraying

The LM dataset can be also processed further along with the BloodHound ZIP file. This will check if a record belongs to a Domain Admin and if it does, it will generate password candidates (all capitalisation variations): `lm-da-hashes.txt`, `lm-da-users.txt`, and `lm-da-candidates.txt`.

```bash
$ password-audit organise \
    -N domain.ntds \
    -P hashcat.potfile \
    -B bloodhound.zip
```

The users and candidates files can be then used for password spraying (e.g. with [`conpass`](https://github.com/login-securite/conpass)) in order to enumerate the valid capitalisation:

```bash
conpass -d <domain> \
    -u <user> \
    -p <pass> \
    -U lm-da-users.txt \
    -P lm-da-candidates.txt \
    --dc-ip <dc-ip>
```