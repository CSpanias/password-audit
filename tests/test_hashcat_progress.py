import unittest
from unittest.mock import MagicMock, Mock, call, patch

from cracking.hashcat import live_status_flags, run_phase


class HashcatProgressTests(unittest.TestCase):
    def test_status_flags_use_a_five_second_update_interval(self):
        self.assertEqual(
            live_status_flags([
                "-O",
                "--status",
                "--status-timer",
                "300",
            ]),
            ["-O", "--status", "--status-timer=5"],
        )

    def test_run_phase_updates_progress_with_hashcat_status(self):
        progress = MagicMock()
        progress.__enter__.return_value = progress
        progress.add_task.return_value = 1
        process = Mock()
        process.stdout = [
            "Status...........: Running\n",
            "Recovered........: 3/10 (30.00%), 2/10 (20.00%)\n",
            "Progress.........: 50/100 (50.00%)\n",
            "Speed.#1.........: 1.0 kH/s (1.00ms)\n",
            "Time.Estimated...: 10 secs\n",
            "Status...........: Exhausted\n",
            "Recovered........: 4/10 (40.00%), 1/10 (10.00%)\n",
            "Progress.........: 100/100 (100.00%)\n",
            "Speed.#1.........: 1.2 kH/s (1.00ms)\n",
            "Time.Estimated...: 0 secs\n",
        ]
        process.returncode = 1

        with (
            patch("cracking.hashcat.Progress", return_value=progress),
            patch("cracking.hashcat.windows_path", side_effect=str),
            patch("cracking.hashcat.subprocess.Popen", return_value=process) as popen,
            patch("cracking.hashcat.time.time", side_effect=[10, 20]),
            patch("builtins.print") as print_mock,
        ):
            result = run_phase(
                phase_id=1,
                total_phases=2,
                hashcat_binary="hashcat.exe",
                hash_file="hashes.txt",
                hash_mode=1000,
                hashcat_potfile="potfile.txt",
                wordlist="words.txt",
                rule="rules.rule",
                session_name="campaign-first",
                flags=["-O", "--status", "--status-timer", "300"],
            )

        command = popen.call_args.args[0]
        self.assertEqual(command.count("--status"), 1)
        self.assertIn("--status-timer=5", command)
        self.assertNotIn("300", command)
        self.assertIsNone(progress.add_task.call_args.kwargs["total"])
        last_update = progress.update.call_args.kwargs
        self.assertEqual(last_update["completed"], 100)
        self.assertEqual(last_update["total"], 100)
        self.assertEqual(
            last_update["recovered"],
            "4/10 (40.00%)",
        )
        self.assertEqual(last_update["speed"], "1.2 kH/s")
        self.assertEqual(last_update["eta"], "0 secs")
        self.assertEqual(result["newRecovered"], 1)
        self.assertEqual(result["totalRecovered"], 4)
        printed = print_mock.call_args_list
        rule_line = printed.index(call("    Rule     : rules.rule"))
        self.assertEqual(printed[rule_line + 1], call())


if __name__ == "__main__":
    unittest.main()
