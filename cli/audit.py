"""
Audit workflow command-line interface.

This module provides the command-line entry point for the
end-to-end password audit workflow.
"""

from auditing.workflow import run_audit


def run_audit_workflow(args):
    """
    Execute the audit workflow.

    Args:
        args:
            Parsed command-line arguments.

    Returns:
        None
    """

    run_audit(
        ntds_file=args.ntds,
        bloodhound_file=args.bloodhound,
        campaign_file=args.campaign,
        campaign_name=args.campaign_name,
        mapped_passwords=args.mapped_passwords,
        domain_admins=args.domain_admins,
        company_words=args.company_words,
        enabled_users=args.enabled_users,
        pass_policy=args.pass_policy,
        username_filter=args.filter
    )