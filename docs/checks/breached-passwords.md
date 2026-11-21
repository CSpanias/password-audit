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
provides an offline dataset. Alternatively, use `curl.exe` from PowerShell.
The script below downloads missing ranges in batches, so it can be run again
after an interruption. Adjust `$dir` if needed. Use a new directory or an
existing partial curl download, not a directory containing `.txt` ranges from
the official downloader. Do not run multiple downloads into it at once:

```powershell
$dir = 'C:\pentest\tools\hashcat\hibp-ntlm'
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $dir -Force | Out-Null

$letters = '0123456789ABCDEF'.ToCharArray()
$batch = New-Object 'System.Collections.Generic.List[string]'
$config = Join-Path $dir '.hibp-resume.curl'

function Invoke-RangeBatch {
    if ($batch.Count -eq 0) { return }

    $lines = New-Object 'System.Collections.Generic.List[string]'
    for ($i = 0; $i -lt $batch.Count; $i++) {
        $prefix = $batch[$i]
        $part = Join-Path $dir "$prefix.part"
        if (Test-Path -LiteralPath $part) { Remove-Item -LiteralPath $part }
        $escapedPart = $part.Replace('\', '\\')

        $lines.Add('fail')
        $lines.Add('silent')
        $lines.Add('show-error')
        $lines.Add('retry = 10')
        $lines.Add('retry-all-errors')
        $lines.Add('remove-on-error')
        $lines.Add(('url = "https://api.pwnedpasswords.com/range/{0}?mode=ntlm"' -f $prefix))
        $lines.Add(('output = "{0}"' -f $escapedPart))
        if ($i -lt $batch.Count - 1) { $lines.Add('next') }
    }

    [IO.File]::WriteAllLines($config, $lines.ToArray(), [Text.Encoding]::ASCII)
    Write-Host "Requesting a batch of $($batch.Count) ranges..."
    & curl.exe --parallel --parallel-max 8 --config $config
    $curlExit = $LASTEXITCODE

    $failed = 0
    foreach ($prefix in $batch) {
        $part = Join-Path $dir "$prefix.part"
        if ((Test-Path -LiteralPath $part -PathType Leaf) -and
            (Get-Item -LiteralPath $part).Length -gt 0) {
            Move-Item -LiteralPath $part -Destination (Join-Path $dir $prefix) -Force
        } else {
            $failed++
            if (Test-Path -LiteralPath $part) { Remove-Item -LiteralPath $part }
        }
    }

    if ($curlExit -ne 0 -or $failed -gt 0) {
        throw "Batch failed (curl exit code $curlExit; $failed invalid or missing files). Rerun the script to resume."
    }
    $batch.Clear()
}

foreach ($a in $letters) {
    foreach ($b in $letters) {
        foreach ($c in $letters) {
            foreach ($d in $letters) {
                foreach ($e in $letters) {
                    $prefix = "$a$b$c$d$e"
                    if (-not (Test-Path -LiteralPath (Join-Path $dir $prefix) -PathType Leaf)) {
                        $batch.Add($prefix)
                        if ($batch.Count -ge 500) { Invoke-RangeBatch }
                    }
                }
            }
        }
    }
}
Invoke-RangeBatch
if (Test-Path -LiteralPath $config) { Remove-Item -LiteralPath $config }
```

The full download contains 1,048,576 range files. The script skips existing
range files and writes new downloads to temporary `.part` files before moving
them into place. If interrupted, run it again. Existing files are not verified
and may include incomplete downloads from earlier attempts; for a reliable
dataset, download them again into a new, empty directory. Counting files alone
does not establish their integrity.

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
