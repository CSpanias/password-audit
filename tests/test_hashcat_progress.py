import os
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

    def test_run_phase_uses_paths_for_the_selected_hashcat_binary(self):
        cases = [
            ("linux", "tools/hashcat", False),
            ("linux", "tools/HASHCAT.EXE", True),
            ("win32", "tools/hashcat.exe", False),
        ]
        for platform, binary, convert in cases:
            with self.subTest(platform=platform, binary=binary):
                process = Mock(stdout=[], returncode=0)
                progress = MagicMock()
                progress.__enter__.return_value = progress
                with (
                    patch("cracking.hashcat.sys.platform", platform),
                    patch("cracking.hashcat.windows_path", side_effect=lambda path: f"WIN:{path}") as convert_path,
                    patch("cracking.hashcat.Progress", return_value=progress),
                    patch("cracking.hashcat.subprocess.Popen", return_value=process) as popen,
                ):
                    run_phase(
                        phase_id=1, total_phases=1, hashcat_binary=binary,
                        hash_file="data/hashes", hash_mode=1000,
                        hashcat_potfile="data/potfile", wordlist="data/words",
                        rule="data/rules", session_name="test", flags=[],
                    )
                command = popen.call_args.args[0]
                expected_paths = [
                    f"WIN:{path}" if convert else os.path.abspath(path)
                    for path in ("data/hashes", "data/words", "data/potfile", "data/rules")
                ]
                self.assertEqual(command[0], os.path.abspath(binary))
                self.assertEqual([command[3], command[4], command[6], command[8]], expected_paths)
                self.assertEqual(convert_path.call_count, 4 if convert else 0)
                self.assertEqual(str(popen.call_args.kwargs["cwd"]), os.path.dirname(os.path.abspath(binary)))


if __name__ == "__main__":
    unittest.main()
