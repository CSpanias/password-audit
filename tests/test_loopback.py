from unittest.mock import MagicMock, call, patch

from cracking.loopback import generate_loopback_wordlist


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
