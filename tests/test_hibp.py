import json
import sys
import xml.etree.ElementTree as ET
from unittest.mock import DEFAULT, patch

import pytest

from analysis.hibp import HibpDataError, check_hibp
from analysis.technical_commentary import commentary_hibp
import auditing.workflow as audit_workflow
from cli import audit, main


def test_hibp_commentary_includes_up_to_five_account_examples():
    accounts = [
        "DOMAIN\\ali|ce", "DOMAIN\\bob", "DOMAIN\\carol",
        "DOMAIN\\dave", "DOMAIN\\eve", "DOMAIN\\frank",
    ]
    text = commentary_hibp({"hibp": {"checked": 10, "count": 6, "accounts": accounts}})

    assert (
        "Have I Been Pwned (HIBP) maintains Pwned Passwords, a dataset of "
        "passwords exposed in known data breaches."
    ) in text
    assert "against a locally downloaded copy of the dataset." in text
    assert "A total of six accounts had matching password hashes." in text
    assert "the account itself appeared in a breach." in text
    assert "A non-match does not establish" not in text
    assert "| Username |\n| ---------- |\n| ali\\|ce |" in text
    assert "| eve |" in text
    assert "frank" not in text

    assert "| Username |" not in commentary_hibp(
        {"hibp": {"checked": 1, "count": 0, "accounts": []}}
    )
    assert commentary_hibp({}) == ""


def test_audit_separates_company_word_notice_from_analysis_progress(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    with patch.multiple(
        audit_workflow,
        validate_audit_inputs=DEFAULT, organise_dataset=DEFAULT,
        load_campaign=DEFAULT, has_enabled_phases=DEFAULT,
        analyse_passwords=DEFAULT,
    ) as mocks:
        mocks["organise_dataset"].side_effect = [
            {"filtered_users": [], "enabled_users": [], "ntlm_hashes": [],
             "lm_hashes": [], "domain_admins": [],
             "privileged_users": {"status": "available", "accounts": []}},
            {"mapped_ntlm_passwords": []},
        ]
        mocks["load_campaign"].return_value = {"ntlm": {"parameters": {}, "phases": []}}
        mocks["has_enabled_phases"].return_value = False
        mocks["analyse_passwords"].side_effect = lambda **kwargs: print(
            "Loading and analyzing datasets"
        )
        audit_workflow.run_audit("ntds", "zip", "config", "run")

    output = capsys.readouterr().out
    assert "This list is optional.\n\nLoading and analyzing datasets" in output


def test_range_matching_deduplicates_hashes_and_supports_both_filenames(tmp_path):
    a = "ABCDE" + "1" * 27
    b = "ABCDE" + "2" * 27
    c = "12345" + "3" * 27
    accounts = [
        {"username": "alice", "ntlm": a.lower()},
        {"username": "bob", "ntlm": a},
        {"username": "carol", "ntlm": b},
        {"username": "dave", "ntlm": c},
    ]
    (tmp_path / "ABCDE").write_text(f"{'1' * 27}:8\n{'4' * 27}:1\n")
    (tmp_path / "12345.txt").write_text(f"{'3' * 27}:1\n")

    assert check_hibp(accounts, tmp_path) == {
        "checked": 4, "count": 3, "accounts": ["alice", "bob", "dave"],
    }


@pytest.mark.parametrize(
    "content",
    ["", "not a range", "1" * 35 + ":1", "1" * 27 + ":0", "1" * 27 + ":1\nbroken"],
)
def test_invalid_or_incomplete_range_is_rejected(tmp_path, content):
    (tmp_path / "ABCDE").write_text(content)
    with pytest.raises(ValueError, match="HIBP"):
        check_hibp([{"username": "alice", "ntlm": "ABCDE" + "1" * 27}], tmp_path)


def test_missing_range_and_missing_ntds_are_rejected(tmp_path):
    with pytest.raises(ValueError, match="dataset is incomplete or still downloading"):
        check_hibp([{"username": "alice", "ntlm": "ABCDE" + "1" * 27}], tmp_path)
    with pytest.raises(ValueError, match="requires organised NTDS"):
        check_hibp(None, tmp_path)
    with pytest.raises(ValueError, match="does not exist"):
        check_hibp([], tmp_path / "missing")


def test_cli_shows_clear_message_for_dataset_still_downloading(capsys):
    args = [
        "password-audit", "analyse", "-M", "mapped.txt", "--hibp", "ranges",
    ]
    with patch.object(sys, "argv", args), patch.object(
        main, "run_password_analysis",
        side_effect=HibpDataError(
            "HIBP dataset is incomplete or still downloading: required NTLM "
            "range B1C58 is missing from ranges. Complete and verify the "
            "download, then run the check again."
        ),
    ), pytest.raises(SystemExit) as exc:
        main.main()

    assert exc.value.code == 2
    error_output = capsys.readouterr().err
    assert "HIBP dataset is incomplete or still downloading" in error_output
    assert "Usage:" not in error_output
    assert "-h" not in error_output


def test_duplicate_matching_suffix_is_rejected(tmp_path):
    line = "1" * 27 + ":1\n"
    (tmp_path / "ABCDE").write_text(line * 2)
    with pytest.raises(ValueError, match="Duplicate HIBP"):
        check_hibp([{"username": "alice", "ntlm": "ABCDE" + "1" * 27}], tmp_path)


def test_analyse_reports_matches_without_recovered_passwords(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "ranges").mkdir()
    (tmp_path / "ranges" / "ABCDE").write_text("1" * 27 + ":2\n")
    (tmp_path / "mapped.txt").write_text("")
    (tmp_path / "users.txt").write_text("alice\nbob\n")
    (tmp_path / "admins.txt").write_text("")
    (tmp_path / "policy.txt").write_text(
        "Domain: example.test\nMinimum Password Length: 12\n"
    )
    (tmp_path / "ntds.txt").write_text(
        "alice:1000:unused:" + "ABCDE" + "1" * 27 + ":::\n"
        "bob:1001:unused:" + "ABCDE" + "2" * 27 + ":::\n"
    )
    args = [
        "password-audit", "analyse", "-M", "mapped.txt", "-D", "admins.txt",
        "-E", "users.txt", "-P", "policy.txt", "--ntds-users", "ntds.txt",
        "--hibp", "ranges",
    ]
    with patch.object(sys, "argv", args):
        main.main()
    report = (tmp_path / "password-audit-report.html").read_text(encoding="utf-8")
    findings = json.loads((tmp_path / "password-audit-findings.json").read_text())
    finding = next(f for f in findings["findings"] if f["id"] == "PWD-BREACH-001")
    assert finding["affected_assets"] == ["alice"]
    assert "A total of one enabled user account was" in finding["description"]
    assert "A total of two enabled user accounts were checked" in report
    assert "A total of one account had matching password hashes" in report
    assert "did not identify any significant" not in report
    assert "ABCDE" + "1" * 27 not in report
    assert "ABCDE" + "1" * 27 not in json.dumps(finding)

    with patch.object(sys, "argv", args + ["--csacyber"]):
        main.main()
    xml = ET.parse(tmp_path / "password-audit-findings.xml")
    assert xml.find(".//vulnerability[@id='SC-3308']") is not None

    (tmp_path / "ranges" / "ABCDE").write_text("3" * 27 + ":1\n")
    with patch.object(sys, "argv", args):
        main.main()
    findings = json.loads((tmp_path / "password-audit-findings.json").read_text())
    assert "PWD-BREACH-001" not in [f["id"] for f in findings["findings"]]


@pytest.mark.parametrize("command", ["audit", "analyse"])
def test_hibp_option_is_forwarded(command):
    args = (
        ["password-audit", "audit", "-N", "ntds", "-B", "zip", "-C", "config", "-G", "test"]
        if command == "audit" else ["password-audit", "analyse", "-M", "mapped.txt"]
    ) + ["--hibp", "ranges"]
    handler = "run_audit_workflow" if command == "audit" else "run_password_analysis"
    with patch.object(sys, "argv", args), patch.object(main, handler) as run:
        main.main()
    assert run.call_args.args[0].hibp == "ranges"
    if command == "audit":
        with patch.object(audit, "run_audit") as workflow:
            audit.run_audit_workflow(run.call_args.args[0])
        assert workflow.call_args.kwargs["hibp"] == "ranges"
