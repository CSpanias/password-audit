"""
NTDS export functions.

This module is responsible for writing NTDS-derived datasets
to disk.

Functions in this module should focus on data export and
avoid performing analysis or transformation operations.
"""


def write_lines(path, lines):
    """
    Write a collection of lines to a text file.

    Args:
        path (str | Path):
            Output file path.

        lines (iterable):
            Collection of values to write.

    Returns:
        None
    """

    with open(path, "w", encoding="utf-8") as f:

        for line in lines:
            f.write(f"{line}\n")


def export_results(results, output_dir):
    """
    Export NTDS analysis results to disk.

    Args:
        results (dict):
            NTDS analysis results.

        output_dir (Path):
            Output directory.

    Returns:
        None
    """

    write_lines(
        output_dir / "enabled-users.txt",
        sorted(
            entry["username"]
            for entry in results["enabled_users"]
        )
    )

    write_lines(
        output_dir / ".ntds-enabled.txt",
        [entry["raw"] for entry in results["enabled"]]
    )

    write_lines(
        output_dir / ".ntds-disabled.txt",
        [entry["raw"] for entry in results["disabled"]]
    )

    write_lines(
        output_dir / ".ntds-machines.txt",
        [entry["raw"] for entry in results["machines"]]
    )

    write_lines(
        output_dir / "ntds-users-clean.txt",
        [entry["raw"] for entry in results["enabled_users"]]
    )

    write_lines(
        output_dir / "ntlm-hashes.txt",
        results["ntlm_hashes"]
    )

    if results["lm_users"]:
        write_lines(
            output_dir / "lm-users.txt",
            [entry["raw"] for entry in results["lm_users"]]
        )

        write_lines(
            output_dir / "lm-hashes.txt",
            results["lm_hashes"]
        )

    if results["filtered_users"]:
        write_lines(
            output_dir / ".testing-accounts.txt",
            [entry["raw"] for entry in results["filtered_users"]]
        )

    if results["domain_admins"]:
        write_lines(
            output_dir / "domain-admins.txt",
            results["domain_admins"]
        )

    if results["mapped_ntlm_passwords"]:
        write_lines(
            output_dir / "mapped-ntlm-passwords.txt",
            results["mapped_ntlm_passwords"]
        )

    if results["mapped_lm_passwords"]:
        write_lines(
            output_dir / "mapped-lm-passwords.txt",
            results["mapped_lm_passwords"]
        )

    if results["mapped_lm_da_passwords"]:

        write_lines(
            output_dir / "lm-da-hashes.txt",
            results["mapped_lm_da_passwords"]
        )

        write_lines(
            output_dir / "lm-da-users.txt",
            results["lm_da_users"]
        )

        write_lines(
            output_dir / "lm-da-candidates.txt",
            results["lm_da_candidates"]
        )

    if results["company_words"]:
        write_lines(
            output_dir / "company-words.txt",
            results["company_words"]
        )

    if results["policy"]:

        policy = results["policy"]

        write_lines(
            output_dir / "domain-policy.txt",
            [
                f"Domain: {policy['domain']}",
                "",
                f"Minimum Password Length : {policy['minpwdlength']}",
                f"Password History Length : {policy['pwdhistorylength']}",
                f"Lockout Threshold       : {policy['lockoutthreshold']}",
                f"Minimum Password Age    : {policy['minpwdage']}",
                f"Maximum Password Age    : {policy['maxpwdage']}",
            ]
        )