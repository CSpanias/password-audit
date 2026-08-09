def remediation_guidance(results):

    lines = []

    # ------------------------
    # Introductory Text
    # ------------------------

    lines.append("The password audit identified a number of conditions that increase susceptibility to "
        "password guessing, password spraying, and offline password-cracking attacks. The recommendations "
        "below should be considered as part of an ongoing programme of identity and access management improvement.\n")

    # ------------------------
    # Administrative Accounts
    # ------------------------

    if (results["admins"]["count"] or results["password_reuse"]["count"]):

        lines.append("Administrative and other highly privileged accounts should utilise unique, high-entropy passwords that "
            "are not shared with standard user accounts. Where possible, a separate password policy should be "
            "applied to privileged identities, enforcing a minimum password length of at least 15 "
            "characters and preventing password reuse between account types.\n")

    # -------------------------------
    # Password Length and Complexity
    # -------------------------------

    if results["password_length"]["count"]:

        lines.append("Several recovered passwords did not comply with the configured minimum password length requirement. "
            "Password policy settings should be reviewed to ensure that all accounts meet the organisation's "
            "baseline security requirements and that legacy or non-compliant credentials are remediated. Longer passwords and "
            "passphrases generally provide greater resistance to offline password-cracking attacks and should be encouraged wherever possible.\n")

    # ---------------
    # Password Reuse
    # ---------------

    reused = any(count > 1 for _, count in results["password_frequency"]["passwords"])

    if reused:

        lines.append("Password reuse was identified across multiple accounts. Users should be encouraged to maintain "
            "unique passwords for all accounts and services. Where appropriate, password managers should be "
            "implemented to reduce credential reuse and support the adoption of unique passwords.\n")

    # ----------------------
    # Password Construction
    # ----------------------

    if (
        results["company_words"]["count"]
        or results["username_passwords"]["count"]
        or results["date_passwords"]["count"]
        or results["common_passwords"]["count"]
        or results["keyboard_walks"]["count"]
    ):

        lines.append("A number of recovered passwords were identified as containing predictable elements, including commonly "
            "used password terms, organisation-related terminology, date-related references, keyboard sequences, and username-derived content. "
            "Users should select passwords that are unrelated to personal information, organisational terminology, or other "
            "predictable patterns. Technical controls such as password filtering solutions should also be considered to prevent the use of "
            "insecure or commonly observed password constructions.\n")

    # ----------------------------
    # Multi-Factor Authentication
    # ----------------------------

    lines.append("Regardless of the specific weaknesses identified, multi-factor authentication (MFA) should be enforced for "
        "all externally accessible services and privileged accounts wherever technically feasible. Whilst strong "
        "passwords remain important, MFA provides additional protection against password-based attacks and reduces the "
        "likelihood of account compromise following credential exposure.\n")

    return "\n".join(lines)