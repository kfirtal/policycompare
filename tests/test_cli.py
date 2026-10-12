"""Exercise real script entry points, with no live mode or server access."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


class CLITests(unittest.TestCase):
    def run_script(self, script, *args):
        root = Path(__file__).resolve().parents[1]
        environment = dict(os.environ, PYTHONIOENCODING='cp1252')
        # Install the HTTP guard in the child too; the explicit script entry
        # point still runs through runpy, including its console configuration.
        code = ("import runpy,sys; from unittest.mock import patch; "
                "sys.argv=sys.argv[1:]; "
                "guard=patch('requests.Session.request', side_effect=AssertionError('Real HTTP forbidden')); "
                "guard.start(); runpy.run_path(sys.argv[0], run_name='__main__')")
        return subprocess.run([sys.executable, '-c', code, script, *args], cwd=root,
                              env=environment, capture_output=True, timeout=20)

    def test_preflight_prints_hebrew_even_with_limited_windows_encoding(self):
        result = self.run_script('lab.py', '--csm-url', 'https://example.invalid/nbi',
                                 '--fmc-url', 'https://example.invalid', '--csm-policy', 'example-policy',
                                 '--fmc-policy', 'example-policy', '--fmc-version', '7.6.5',
                                 '--output-dir', 'reports/cli-preflight-no-write')
        self.assertEqual(result.returncode, 0, result.stderr.decode('utf-8'))
        self.assertIn('לא בוצעו חיבורים', result.stdout.decode('utf-8'))
        self.assertFalse((Path(__file__).resolve().parents[1] / 'reports/cli-preflight-no-write').exists())

    def test_offline_cli_returns_known_drift_and_no_traceback(self):
        result = self.run_script('compare.py', 'examples/csm.json', 'examples/fmc-network-drift.json')
        self.assertEqual(result.returncode, 1, result.stderr.decode('utf-8'))
        report = json.loads(result.stdout.decode('utf-8'))
        self.assertEqual(report['rules_report']['status'], 'PASS')
        self.assertEqual(report['objects_report']['status'], 'FAIL')
        self.assertFalse(result.stderr)


if __name__ == '__main__':
    unittest.main()
