from unittest.mock import MagicMock, call, patch

from cracking.loopback import generate_loopback_wordlist
from ntds.lm import build_lm_candidates
from ntds.parsers import load_lm_results, load_potfile


def test_loopback_generation_shows_rich_progress_and_writes_unique_passwords(tmp_path):
    potfile = tmp_path / "hashcat.potfile"
    potfile.write_text(
        "hash-a:password-one\nhash-b:password-two\nhash-c:password-one\n",
        encoding="utf-8",
    )
    progress = MagicMock()
    progress.__enter__.return_value = progress
    progress.add_task.return_value = 1

    with patch("cracking.loopback.Progress", return_value=progress):
        output = generate_loopback_wordlist(potfile, tmp_path / "hashes.txt")

    assert output == str(tmp_path / "loopback.txt")
    assert (tmp_path / "loopback.txt").read_text(encoding="utf-8") == (
        "password-one\npassword-two\n"
    )
    assert progress.add_task.call_args.args == (
        "Generating loopback dictionary",
    )
    assert progress.add_task.call_args.kwargs["total"] == 2
    assert progress.advance.call_args_list == [call(1), call(1)]


def test_password_whitespace_survives_potfile_lm_and_loopback(tmp_path):
    potfile = tmp_path / "hashcat.potfile"
    potfile.write_text("hash-a: Ab \t\n", encoding="utf-8")
    assert load_potfile(potfile) == {"hash-a": " Ab \t"}
    assert load_lm_results(potfile) == {"hash-a": " Ab \t"}
    assert set(build_lm_candidates([{"password": " Ab \t"}])) == {
        " ab \t", " aB \t", " Ab \t", " AB \t",
    }
    generate_loopback_wordlist(potfile, tmp_path / "hashes.txt")
    assert (tmp_path / "loopback.txt").read_text(encoding="utf-8") == " Ab \t\n"


def test_potfile_and_loopback_reject_invalid_utf8(tmp_path):
    potfile = tmp_path / "hashcat.potfile"
    potfile.write_bytes(b"hash:\xff\n")
    import pytest
    with pytest.raises(UnicodeError):
        load_potfile(potfile)
    with pytest.raises(UnicodeError):
        generate_loopback_wordlist(potfile, tmp_path / "hashes.txt")
