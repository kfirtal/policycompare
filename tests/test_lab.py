"""Lab lifecycle tests. All credentials and endpoints here are synthetic."""
from contextlib import redirect_stdout
import getpass
import io
import json
from pathlib import Path
import tempfile
import unittest
import warnings
from unittest.mock import Mock, patch

import requests

import lab
from compare import compare_all
from csm import CSMClient
from errors import APIError, ValidationError
from fmc import FMCClient
from rule import Rule
from snapshots import load_snapshot


class LabTests(unittest.TestCase):
    def setUp(self):
        # Use ignored output directories, even for tests, and delete on cleanup.
        reports = Path(lab.__file__).resolve().parent / 'reports'
        reports.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=reports)
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / 'run'
        guard = patch('requests.Session.request', side_effect=AssertionError('Real HTTP forbidden'))
        guard.start()
        self.addCleanup(guard.stop)
        self.user = patch('builtins.input', return_value='synthetic-user').start()
        self.password = patch('getpass.getpass', return_value='synthetic-password').start()
        self.addCleanup(patch.stopall)

    def argv(self, *extra):
        return ['--csm-url', 'https://example.invalid/nbi', '--fmc-url', 'https://example.invalid',
                '--csm-policy', 'example-policy', '--fmc-policy', 'example-policy',
                '--fmc-version', '7.6.5', '--output-dir', str(self.output), *extra]

    def args(self, *extra):
        return lab.parser().parse_args(self.argv('--connect', *extra))

    def clients(self):
        source, target = Mock(), Mock()
        rule = Rule('1', ['@any'], ['@any'], [('6', 443, 443)], referenced_objects=[])
        source.policy_rules.return_value = [rule]
        target.policy_uuid_by_name.return_value = 'synthetic-policy'
        target.policy_rules.return_value = [rule]
        a = patch('lab.CSMClient', return_value=source)
        b = patch('lab.FMCClient', return_value=target)
        a.start()
        b.start()
        return source, target

    def test_default_preflight_never_constructs_clients_or_prompts_or_writes(self):
        with patch('lab.CSMClient') as csm, patch('lab.FMCClient') as fmc, redirect_stdout(io.StringIO()):
            self.assertEqual(lab.main(self.argv()), 0)
        csm.assert_not_called()
        fmc.assert_not_called()
        self.user.assert_not_called()
        self.password.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_run_function_also_requires_explicit_connection(self):
        args = lab.parser().parse_args(self.argv())
        with self.assertRaises(ValidationError):
            lab.run_lab(args)
        self.user.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_preflight_rejects_bad_urls_timeout_ca_domain_or_output(self):
        for extra in (
            ['--csm-url', 'http://example.invalid/nbi'],
            ['--fmc-url', 'https://user:secret@example.invalid'],
            ['--fmc-url', 'https://example.invalid/api'],
            ['--fmc-url', 'https://example.invalid:bad'],
            ['--csm-url', 'https://example.invalid/nbi?query=yes'],
            ['--timeout', '0'], ['--timeout', '-1'], ['--timeout', 'nan'], ['--timeout', 'inf'],
            ['--fmc-domain', ' '], ['--csm-policy', ' '], ['--fmc-version', ''],
            ['--csm-ca', str(Path(self.temp.name) / 'missing.pem')],
            ['--output-dir', str(Path(self.temp.name).parents[1].parent / 'outside-reports')],
        ):
            with self.subTest(extra=extra), self.assertRaises((ValidationError, ValueError)):
                lab.validate_settings(self.args(*extra))
        self.user.assert_not_called()

    def test_completed_run_saves_replayable_inputs_and_both_reports(self):
        source, target = self.clients()
        result = lab.run_lab(self.args())
        self.assertEqual(result['status'], 'PASS')
        source.login.assert_called_once_with('synthetic-user', 'synthetic-password')
        source.close.assert_called_once()
        target.close.assert_called_once()
        replay = compare_all(load_snapshot(self.output / 'csm.snapshot.json'),
                             load_snapshot(self.output / 'fmc.snapshot.json'))
        self.assertEqual(replay['status'], 'PASS')
        self.assertEqual(len(list(self.output.iterdir())), 7)
        manifest = json.loads((self.output / 'run.json').read_text(encoding='utf-8'))
        self.assertEqual(manifest['completed_snapshots'], ['csm', 'fmc'])
        self.assertEqual(manifest['declared_versions']['fmc'], '7.6.5')
        contents = ''.join(path.read_text(encoding='utf-8') for path in self.output.iterdir())
        for secret in ('synthetic-user', 'synthetic-password', 'example.invalid'):
            self.assertNotIn(secret, contents)

    def test_auth_read_and_lookup_failures_are_indeterminate_and_cleanup(self):
        for stage in ('csm_login', 'csm_policy_read', 'fmc_login', 'fmc_policy_lookup', 'fmc_policy_read'):
            with self.subTest(stage=stage):
                self.output = Path(self.temp.name) / stage
                source, target = self.clients()
                methods = {'csm_login': source.login, 'csm_policy_read': source.policy_rules,
                           'fmc_login': target.login, 'fmc_policy_lookup': target.policy_uuid_by_name,
                           'fmc_policy_read': target.policy_rules}
                methods[stage].side_effect = APIError('PRIVATE-RESPONSE-BODY')
                result = lab.run_lab(self.args())
                self.assertEqual(result['status'], 'INDETERMINATE')
                self.assertEqual(result['run']['error_details'], [{'stage': stage, 'category': 'api_error'}])
                self.assertNotIn('PRIVATE-RESPONSE', json.dumps(result))
                source.close.assert_called_once()
                target.close.assert_called_once()
                if stage.startswith('csm'):
                    target.login.assert_not_called()
                else:
                    self.assertEqual(result['run']['completed_snapshots'], ['csm'])

    def test_snapshot_write_failure_closes_clients_and_stops_collection(self):
        source, target = self.clients()
        with patch('lab.save_snapshot', side_effect=OSError('PRIVATE-PATH')):
            result = lab.run_lab(self.args())
        self.assertEqual(result['run']['error_details'][0],
                         {'stage': 'csm_snapshot_write', 'category': 'output_error'})
        target.login.assert_not_called()
        source.close.assert_called_once()
        target.close.assert_called_once()
        self.assertNotIn('PRIVATE-PATH', json.dumps(result))

    def test_interrupt_and_password_echo_fallback_do_not_expose_credentials(self):
        for error in (KeyboardInterrupt(), EOFError(), getpass.GetPassWarning('echo unavailable')):
            with self.subTest(error=type(error).__name__):
                self.output = Path(self.temp.name) / type(error).__name__
                source, target = self.clients()
                self.password.side_effect = error
                result = lab.run_lab(self.args())
                self.assertEqual(result['status'], 'INDETERMINATE')
                source.login.assert_not_called()
                source.close.assert_called_once()
                target.close.assert_called_once()

    def test_cleanup_failure_preserves_comparison_but_fails_overall_run(self):
        source, target = self.clients()
        source.close.side_effect = APIError('PRIVATE-LOGOUT')
        result = lab.run_lab(self.args())
        self.assertEqual(result['status'], 'INDETERMINATE')
        self.assertEqual(result['rules_report']['status'], 'PASS')
        self.assertEqual(result['run']['cleanup_errors'], ['csm_cleanup'])
        self.assertNotIn('PRIVATE-LOGOUT', json.dumps(result))
        target.close.assert_called_once()

    def test_getpass_warning_aborts_before_echo_fallback(self):
        source, _ = self.clients()
        fallback = Mock()
        def unsafe_getpass(prompt):
            warnings.warn('echo unavailable', getpass.GetPassWarning)
            return fallback()
        self.password.side_effect = unsafe_getpass
        result = lab.run_lab(self.args())
        self.assertEqual(result['status'], 'INDETERMINATE')
        fallback.assert_not_called()
        source.login.assert_not_called()

    def test_client_setup_failure_closes_client_already_constructed(self):
        source, _ = self.clients()
        lab.FMCClient.side_effect = ValueError('PRIVATE-SETTINGS')
        result = lab.run_lab(self.args())
        source.close.assert_called_once()
        self.user.assert_not_called()
        self.assertEqual(result['run']['error_details'][0]['stage'], 'client_setup')
        self.assertNotIn('PRIVATE-SETTINGS', json.dumps(result))

    def test_empty_policy_requires_explicit_option(self):
        source, target = self.clients()
        source.policy_rules.return_value = []
        target.policy_rules.return_value = []
        result = lab.run_lab(self.args())
        self.assertEqual(result['status'], 'INDETERMINATE')
        self.output = Path(self.temp.name) / 'explicit-empty'
        result = lab.run_lab(self.args('--allow-empty'))
        self.assertEqual(result['status'], 'PASS')

    def test_existing_output_stops_before_network_or_prompt(self):
        self.output.mkdir()
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(lab.main(self.argv('--connect')), 2)
        self.user.assert_not_called()
        self.assertNotIn('example.invalid', output.getvalue())

    def test_main_exit_codes_and_declared_ca_timeout(self):
        source, target = self.clients()
        target.policy_rules.return_value[0] = Rule('2', ['@any'], ['@any'], [('17', 443, 443)], referenced_objects=[])
        # Source and target initially shared the same Rule; replace only target.
        source.policy_rules.return_value = [Rule('1', ['@any'], ['@any'], [('6', 443, 443)], referenced_objects=[])]
        ca = Path(self.temp.name) / 'example-ca.pem'
        ca.write_text('synthetic-test-file', encoding='utf-8')
        with redirect_stdout(io.StringIO()):
            self.assertEqual(lab.main(self.argv('--connect', '--csm-ca', str(ca), '--timeout', '9')), 1)
        lab.CSMClient.assert_called_once_with('https://example.invalid/nbi', verify=str(ca), timeout=9)
        lab.FMCClient.assert_called_once_with('https://example.invalid', domain=None, verify=True, timeout=9)

    def test_real_clients_complete_mocked_http_lifecycle_without_configuration_writes(self):
        def response(text='', data=None, headers=None, cookie=None):
            value = Mock(status_code=200, text=text, headers=headers or {})
            value.json.return_value = data
            value.cookies.get.return_value = cookie
            return value
        csm_session, fmc_session = Mock(), Mock()
        csm_session.request.side_effect = [
            response('<loginResponse/>', cookie='synthetic-cookie'),
            response('<policyConfigDeviceResponse><policy><deviceAccessRuleFirewallPolicy><orderId>1</orderId><sources/><destinations/><services/></deviceAccessRuleFirewallPolicy></policy></policyConfigDeviceResponse>'),
            response('<logoutResponse/>'),
        ]
        fmc_session.request.side_effect = [
            response(headers={'X-auth-access-token': 'synthetic-token', 'DOMAINS': '[{"uuid":"synthetic-domain"}]'}),
            response(data={'items': [{'id': 'p', 'name': 'example-policy'}], 'paging': {'count': 1}}),
            response(data={'items': [{'id': 'r'}], 'paging': {'count': 1}}),
        ]
        csm = CSMClient('https://example.invalid/nbi', session=csm_session)
        fmc = FMCClient('https://example.invalid', session=fmc_session)
        with patch('lab.CSMClient', return_value=csm), patch('lab.FMCClient', return_value=fmc):
            self.assertEqual(lab.run_lab(self.args())['status'], 'PASS')
        self.assertEqual([call.args[1].split('/nbi')[-1] for call in csm_session.request.call_args_list],
                         ['/login', '/configservice/getPolicyConfigByName', '/logout'])
        self.assertEqual([call.args[0] for call in fmc_session.request.call_args_list], ['POST', 'GET', 'GET'])
        self.assertIsNone(csm.cookie)
        self.assertIsNone(fmc.token)
        csm_session.close.assert_called_once()
        fmc_session.close.assert_called_once()

    def test_csm_failed_logout_still_clears_all_local_session_state(self):
        session = Mock()
        client = CSMClient('https://example.invalid/nbi', session=session)
        client.cookie, client.cache = 'synthetic-cookie', {'synthetic': 'cached'}
        client.call = Mock(side_effect=APIError('failure'))
        with self.assertRaises(APIError):
            client.close()
        self.assertIsNone(client.cookie)
        self.assertFalse(client.cache)
        session.cookies.clear.assert_called_once()
        session.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
