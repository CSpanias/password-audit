import io
import json
import re
import sys
import threading
import xml.etree.ElementTree as ET
from unittest.mock import DEFAULT, MagicMock, call, patch

import pytest
from rich.console import Console
from rich.progress import BarColumn, SpinnerColumn, TaskProgressColumn, TextColumn

from analysis.hibp import HibpDataError, check_hibp
import analysis.hibp as hibp_analysis
from analysis.technical_commentary import commentary_hibp
import auditing.workflow as audit_workflow
import analysis.results as analysis_results
import analysis.workflow as analysis_workflow
from cli import audit, main


def test_hibp_commentary_includes_up_to_five_account_examples():
    accounts = [
        "DOMAIN\\ali|ce", "DOMAIN\\bob", "DOMAIN\\carol",
        "DOMAIN\\dave", "DOMAIN\\eve", "DOMAIN\\frank",
    ]
    masked_hash = "ab" + "*" * 28 + "11"
    examples = [{"username": name, "masked_hash": masked_hash} for name in accounts[:5]]
    text = commentary_hibp({
        "hibp": {"checked": 10, "count": 6, "accounts": accounts, "examples": examples}
    })

    assert (
        "Have I Been Pwned (HIBP) maintains Pwned Passwords, a dataset of "
        "passwords exposed in known data breaches."
    ) in text
    assert "against a locally downloaded copy of the dataset." in text
    assert "A total of six accounts had matching password hashes." in text
    assert (
        "However, it should be noted that a matching hash does not mean "
        "the account itself appeared in a breach."
    ) in text
    assert "Matching passwords may not have been recovered" not in text
    assert "A non-match does not establish" not in text
    assert f"| Username | NTLM Hash |\n| ---------- | ---------- |\n| ali\\|ce | {masked_hash} |" in text
    assert f"| eve | {masked_hash} |" in text
    assert "frank" not in text

    zero = commentary_hibp({"hibp": {"checked": 1, "count": 0, "accounts": [], "examples": []}})
    assert "| Username |" not in zero
    assert "A matching hash would not mean the account itself appeared in a breach." in zero
    assert commentary_hibp({}) == ""


def test_audit_shows_company_word_notice_during_organisation(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    with patch.multiple(
        audit_workflow,
        validate_audit_inputs=DEFAULT, organise_dataset=DEFAULT,
        load_campaign=DEFAULT, has_enabled_phases=DEFAULT,
        analyse_passwords=DEFAULT, load_domain_policy=DEFAULT,
    ) as mocks:
        mocks["organise_dataset"].side_effect = [
            {"filtered_users": [], "enabled_users": [], "ntlm_hashes": [],
             "lm_hashes": [], "domain_admins": [],
             "privileged_users": {
                 "status": "incomplete", "accounts": [],
                 "warnings": ["Some group members were not resolved."],
             }},
            {"mapped_ntlm_passwords": []},
        ]
        mocks["load_campaign"].return_value = {"ntlm": {"parameters": {}, "phases": []}}
        mocks["load_domain_policy"].return_value = {"Minimum Password Length": "12"}
        mocks["has_enabled_phases"].return_value = False
        monkeypatch.setattr(audit_workflow, "console", Console(
            file=sys.stdout, force_terminal=False, width=120
        ))
        mocks["analyse_passwords"].side_effect = lambda **kwargs: print(
            "Loading and analyzing datasets"
        )
        audit_workflow.run_audit("ntds", "zip", "config", "run")

    output = re.sub(r"\x1b\[[0-9;]*m", "", capsys.readouterr().out)
    notice = "No curated company wordlist supplied; using generated terms only."
    group_counts = "Privileged group counts: matched enabled NTDS accounts."
    assert output.split(group_counts, 1)[0].endswith("\n\n")
    assert group_counts + "\n\n[!] Privileged group coverage is incomplete:" in output
    assert "Some group members were not resolved.\n\n[!] " + notice in output
    assert output.index("Stage 1/5 - Organising Data") < output.index(notice)
    assert output.index(notice) < output.index("Stage 2/5 - Recovering NTLM Passwords")
    assert output.split("--company-words PATH.", 1)[1].startswith("\n\n")
    assert output.index("Stage 5/5 - Analysing Passwords") < output.index(
        "Loading and analyzing datasets"
    )


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
        "examples": [
            {"username": "alice", "masked_hash": "ab" + "*" * 28 + "11"},
            {"username": "bob", "masked_hash": "ab" + "*" * 28 + "11"},
            {"username": "dave", "masked_hash": "12" + "*" * 28 + "33"},
        ],
    }


def test_parallel_ranges_report_completed_work_and_preserve_match_order(tmp_path):
    (tmp_path / "12345").write_text("1" * 27 + ":1\n", encoding="ascii")
    (tmp_path / "ABCDE").write_text("2" * 27 + ":1\n", encoding="ascii")
    accounts = [
        {"username": "Alice", "ntlm": "12345" + "1" * 27},
        {"username": "aLiCe", "ntlm": "ABCDE" + "2" * 27},
    ]
    first_started = threading.Event()
    release_first = threading.Event()
    main_thread = threading.get_ident()
    progress = []
    original_check = hibp_analysis._check_range

    def controlled_check(directory, prefix, suffixes):
        if prefix == "12345":
            first_started.set()
            if not release_first.wait(5):
                raise TimeoutError("Second range did not complete concurrently")
        else:
            if not first_started.wait(5):
                raise TimeoutError("First range did not start concurrently")
        return original_check(directory, prefix, suffixes)

    def on_progress(completed, total):
        progress.append((completed, total, threading.get_ident()))
        if completed == 1:
            release_first.set()

    with patch.object(hibp_analysis, "_check_range", side_effect=controlled_check):
        result = check_hibp(accounts, tmp_path, progress_callback=on_progress)

    assert result["accounts"] == ["Alice", "aLiCe"]
    assert [item["username"] for item in result["examples"]] == ["Alice", "aLiCe"]
    assert progress == [(0, 2, main_thread), (1, 2, main_thread), (2, 2, main_thread)]


def test_analysis_progress_advances_during_checks_and_each_breach_range(tmp_path):
    mapped = tmp_path / "mapped.txt"
    mapped.write_text("alice:Secret123!\nbob:Another123!\n", encoding="utf-8")
    enabled = tmp_path / "enabled.txt"
    enabled.write_text("alice\nbob\n", encoding="utf-8")
    policy = tmp_path / "policy.txt"
    policy.write_text("Domain: example.test\nMinimum Password Length: 8\n", encoding="utf-8")
    users = tmp_path / "ntds-users.txt"
    users.write_text(
        "alice:1000:" + "a" * 32 + ":ABCDE" + "1" * 27 + ":::\n"
        "bob:1001:" + "a" * 32 + ":12345" + "2" * 27 + ":::\n",
        encoding="utf-8",
    )
    ranges = tmp_path / "ranges"
    ranges.mkdir()
    (ranges / "ABCDE").write_text("1" * 27 + ":1\n", encoding="ascii")
    (ranges / "12345").write_text("2" * 27 + ":1\n", encoding="ascii")

    progress = MagicMock()
    progress.__enter__.return_value = progress
    progress.add_task.side_effect = [1, 2]
    original_company_check = analysis_results.company_name_passwords

    def company_check(*args):
        assert progress.advance.call_count >= 3
        assert progress.update.call_args == call(
            2, description="Checking company-specific terms", refresh=True,
        )
        return original_company_check(*args)

    with (
        patch.object(analysis_workflow, "SpacedProgress", return_value=progress) as progress_class,
        patch.object(analysis_workflow, "_print_console_summary"),
        patch.object(analysis_results, "company_name_passwords", side_effect=company_check),
    ):
        results = analysis_workflow.analyse_passwords(
            mapped_ntlm_passwords=mapped, domain_admins=None, company_words=None,
            pass_policy=policy, enabled_users=enabled, ntds_users=users, hibp=ranges,
            output_file=tmp_path / "report.html", findings_file=tmp_path / "findings.json",
        )

    assert results["hibp"]["count"] == 2
    assert progress_class.call_args.kwargs["transient"] is True
    assert progress.add_task.call_args_list == [
        call("Loading datasets", total=None),
        call("Validating account data", total=None),
    ]
    assert call(1, description="Analysing password data", total=12, completed=1) in progress.update.call_args_list
    assert progress.advance.call_args_list == [call(1)] * 11
    for completed in (0, 1, 2):
        assert call(2, description="Checking breach data", total=2, completed=completed) in progress.update.call_args_list
    for description in (
        "Checking password length compliance", "Checking recovered password reuse",
        "Checking company-specific terms", "Checking keyboard walks",
        "Checking username-based passwords", "Checking common passwords",
        "Checking date patterns", "Checking password complexity",
        "Checking LM hashes", "Checking NTLM hash reuse",
    ):
        assert call(2, description=description, refresh=True) in progress.update.call_args_list
    assert call(2, visible=False) in progress.update.call_args_list


def test_analysis_progress_renders_one_blank_line_between_visible_rows():
    output = io.StringIO()
    console = Console(file=output, force_terminal=False, width=100)
    progress = analysis_workflow.SpacedProgress(
        SpinnerColumn(), TextColumn("{task.description}"), BarColumn(),
        TaskProgressColumn(), console=console,
    )
    progress.add_task("Analysing password data", total=12, completed=10)
    check = progress.add_task("Checking breach data", total=2, completed=0)
    progress.add_task("Hidden check", visible=False)
    console.print(progress.get_renderable())
    lines = output.getvalue().splitlines()
    assert len(lines) == 3
    assert "Analysing password data" in lines[0]
    assert not lines[1].strip()
    assert "Checking breach data" in lines[2]
    assert "0%" in lines[2]

    progress.update(check, visible=False)
    output.seek(0)
    output.truncate()
    console.print(progress.get_renderable())
    assert len(output.getvalue().splitlines()) == 1


def test_breach_progress_only_advances_for_validated_ranges(tmp_path):
    accounts = [{"username": "alice", "ntlm": "ABCDE" + "1" * 27}]
    (tmp_path / "ABCDE").write_text("invalid\n", encoding="ascii")
    progress = MagicMock()
    with pytest.raises(HibpDataError):
        check_hibp(accounts, tmp_path, progress_callback=progress)
    assert progress.call_args_list == [call(0, 1)]


def test_invalid_range_among_parallel_checks_stops_without_complete_progress(tmp_path):
    (tmp_path / "ABCDE").write_text("1" * 27 + ":1\n", encoding="ascii")
    (tmp_path / "12345").write_text("2" * 27 + ":1\nbroken\n", encoding="ascii")
    accounts = [
        {"username": "alice", "ntlm": "ABCDE" + "1" * 27},
        {"username": "bob", "ntlm": "12345" + "2" * 27},
    ]
    progress = MagicMock()
    with pytest.raises(HibpDataError, match="Invalid HIBP NTLM range"):
        check_hibp(accounts, tmp_path, progress_callback=progress)
    assert call(2, 2) not in progress.call_args_list


def test_range_matching_limits_examples_without_limiting_affected_accounts(tmp_path):
    (tmp_path / "ABCDE").write_text("1" * 27 + ":2\n")
    accounts = [
        {"username": f"user{index}", "ntlm": "ABCDE" + "1" * 27}
        for index in reversed(range(6))
    ]
    result = check_hibp(accounts, tmp_path)
    assert result["count"] == 6
    assert result["accounts"] == [f"user{index}" for index in range(6)]
    assert [item["username"] for item in result["examples"]] == result["accounts"][:5]
    assert all(item["masked_hash"] == "ab" + "*" * 28 + "11" for item in result["examples"])


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
    assert "| alice | ab" + "*" * 28 + "11 |" in report
    assert (
        "However, it should be noted that a matching hash does not mean "
        "the account itself appeared in a breach."
    ) in report
    assert "did not identify any significant" not in report
    assert "ABCDE" + "1" * 27 not in report
    assert ("ABCDE" + "1" * 27).lower() not in report
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
