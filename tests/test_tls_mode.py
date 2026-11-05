"""Offline TLS-option regression tests; never contact any server."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import lab
from errors import ValidationError
from rule import Rule
from transport import Transport


class TLSModeTests(unittest.TestCase):
    def setUp(self):
        reports = Path(lab.__file__).resolve().parent / 'reports'
        reports.mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=reports)
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.argv = [
            '--csm-url', 'https://example.invalid/nbi', '--fmc-url', 'https://example.invalid',
            '--csm-policy', 'example-policy', '--fmc-policy', 'example-policy',
            '--fmc-version', '7.6.5', '--output-dir', str(self.folder / 'run'),
        ]
        guard = patch('requests.Session.request', side_effect=AssertionError('Real HTTP forbidden'))
        guard.start()
        self.addCleanup(guard.stop)

    def run_mocked(self, extra):
        source, target = Mock(), Mock()
        rules = [Rule('1', ['@any'], ['@any'], [('any', 0, 65535)], referenced_objects=[])]
        source.policy_rules.return_value = rules
        target.policy_rules.return_value = rules
        target.policy_uuid_by_name.return_value = 'synthetic-policy'
        args = lab.parser().parse_args(self.argv + ['--connect'] + extra)
        with patch('lab.CSMClient', return_value=source) as csm, patch('lab.FMCClient', return_value=target) as fmc:
            with patch('lab.login_interactively'):
                result = lab.run_lab(args)
        return result, csm.call_args.kwargs['verify'], fmc.call_args.kwargs['verify']

    def test_default_keeps_both_certificates_verified(self):
        result, csm_verify, fmc_verify = self.run_mocked([])
        self.assertIs(csm_verify, True)
        self.assertIs(fmc_verify, True)
        self.assertEqual(result['run']['tls_verification'], {'csm': True, 'fmc': True})

    def test_insecure_reaches_both_clients_and_saved_manifest(self):
        result, csm_verify, fmc_verify = self.run_mocked(['--insecure'])
        self.assertEqual(result['status'], 'PASS')
        self.assertIs(csm_verify, False)
        self.assertIs(fmc_verify, False)
        manifest = json.loads((self.folder / 'run/run.json').read_text(encoding='utf-8'))
        self.assertEqual(manifest['tls_verification'], {'csm': False, 'fmc': False})

    def test_custom_ca_remains_supported(self):
        ca = self.folder / 'synthetic-ca.pem'
        ca.write_text('synthetic-test-file', encoding='utf-8')
        result, csm_verify, fmc_verify = self.run_mocked(['--csm-ca', str(ca)])
        self.assertEqual(csm_verify, str(ca))
        self.assertIs(fmc_verify, True)
        self.assertEqual(result['run']['tls_verification'], {'csm': True, 'fmc': True})

    def test_insecure_and_ca_options_cannot_conflict(self):
        for option in ('--csm-ca', '--fmc-ca'):
            args = lab.parser().parse_args(self.argv + ['--insecure', option, 'unused.pem'])
            with self.subTest(option=option), self.assertRaises(ValidationError):
                lab.validate_settings(args)

    def test_insecure_does_not_enable_network_in_preflight(self):
        with patch('lab.CSMClient') as csm, patch('lab.FMCClient') as fmc, patch('builtins.input') as prompt:
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(lab.main(self.argv + ['--insecure']), 0)
        csm.assert_not_called()
        fmc.assert_not_called()
        prompt.assert_not_called()
        self.assertFalse((self.folder / 'run').exists())
        self.assertIn('TLS', output.getvalue())

    def test_insecure_still_requires_https(self):
        args = lab.parser().parse_args(self.argv + ['--insecure', '--csm-url', 'http://example.invalid/nbi'])
        with self.assertRaises(ValidationError):
            lab.validate_settings(args)

    def test_transport_passes_requested_verification_without_redirects(self):
        for verify in (True, False):
            session = Mock()
            session.request.return_value = Mock(status_code=200)
            client = Transport('https://example.invalid', verify=verify, session=session)
            client.request('GET', '/synthetic')
            with self.subTest(verify=verify):
                self.assertIs(session.request.call_args.kwargs['verify'], verify)
                self.assertIs(session.request.call_args.kwargs['allow_redirects'], False)


if __name__ == '__main__':
    unittest.main()
