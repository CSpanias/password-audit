"""
Loopback dictionary generation.

This module generates loopback dictionaries from recovered
passwords stored within Hashcat potfiles.
"""

import os

from common.console import (
    ok,
    summary
)


def generate_loopback_wordlist(hashcat_potfile, hash_file):
    """
    Generate a loopback dictionary from recovered passwords.

    All unique passwords recovered within the supplied Hashcat
    potfile are extracted and written to a loopback dictionary
    suitable for use in subsequent cracking phases.

    Args:
        hashcat_potfile:
            Path to the Hashcat potfile.

        hash_file:
            Target hash dataset used to determine the output
            location of the loopback dictionary.

    Returns:
        str | None:
            Path to the generated loopback dictionary, or
            None if no recovered passwords are available.
    """

    loopback_file = os.path.join(os.path.dirname(hash_file), "loopback.txt")
    passwords = set()

    if not os.path.exists(hashcat_potfile):
        return None

    with open(
        hashcat_potfile,
        encoding="utf-8",
        errors="ignore",
    ) as potfile:

        for line in potfile:

            line = line.rstrip()

            if ":" not in line:
                continue

            password = line.split(":", 1)[1]

            if password:
                passwords.add(password)

    if not passwords:
        return None

    with open(loopback_file, "w", encoding="utf-8") as handle:

        for password in sorted(passwords):
            handle.write(password + "\n")

    print()

    ok("Loopback dictionary generated")

    summary("Passwords", len(passwords))
    summary("File", loopback_file)

    return loopback_file