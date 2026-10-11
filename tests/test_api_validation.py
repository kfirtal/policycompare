"""Malformed synthetic API responses must never masquerade as Any/empty."""
import json
import unittest
from unittest.mock import Mock

from csm import CSMClient, parse_xml, required
from fmc import FMCClient
from compare import compare_policies, compare_rules
from errors import APIError, ValidationError
from rule import Rule


class APIValidationTests(unittest.TestCase):
    def fmc(self, payload):
        client = FMCClient('https://example.invalid', domain='domain', session=Mock())
        client.token = 'synthetic-token'
        client.get = Mock(return_value=payload)
        return client

    def test_invalid_collection_identifiers(self):
        for ident in (None, [], {}, 1, True, '', ' padded '):
            client = self.fmc({'items': [{'id': ident}], 'paging': {'count': 1}})
            with self.subTest(ident=ident), self.assertRaises(ValidationError):
                client.collection('/policy/accesspolicies')

    def test_wrong_page_offset(self):
        for offset in (1, '0', False):
            client = self.fmc({'items': [{'id': 'r'}], 'paging': {'count': 1, 'offset': offset}})
            with self.subTest(offset=offset), self.assertRaises(ValidationError):
                client.collection('/policy/accesspolicies')

    def test_malformed_rule_arrays(self):
        for field in ('objects', 'literals'):
            for value in (None, {}, 'text', [None], [1]):
                raw = {'id': 'r', 'enabled': True, 'action': 'ALLOW',
                       'sourceNetworks': {field: value}}
                client = self.fmc({})
                client.collection = Mock(return_value=[raw])
                with self.subTest(field=field, value=value), self.assertRaises(ValidationError):
                    client.policy_rules('p')

    def test_malformed_group_arrays(self):
        for field in ('objects', 'literals', 'literal'):
            client = self.fmc({'id': 'g', 'type': 'NetworkGroup', field: None})
            with self.subTest(field=field), self.assertRaises(ValidationError):
                client.resolve({'id': 'g', 'type': 'NetworkGroup'}, 'network')

    def test_group_cannot_hide_second_literal_array(self):
        client = self.fmc({'id': 'g', 'type': 'NetworkGroup', 'literal': [], 'literals': []})
        with self.assertRaises(ValidationError):
            client.resolve({'id': 'g', 'type': 'NetworkGroup'}, 'network')

    def test_object_kind_mismatch_stops_before_request(self):
        client = self.fmc({})
        with self.assertRaises(ValidationError):
            client.resolve({'id': 'g', 'type': 'PortObjectGroup'}, 'network')
        client.get.assert_not_called()

    def test_failed_fmc_login_clears_old_token(self):
        for domains in (None, {}, [None], [{'uuid': []}]):
            client = self.fmc({})
            client.request = Mock(return_value=Mock(headers={
                'X-auth-access-token': 'new-synthetic-token', 'DOMAINS': json.dumps(domains),
            }))
            with self.subTest(domains=domains), self.assertRaises(APIError):
                client.login('synthetic-user', 'synthetic-password')
            self.assertIsNone(client.token)

    def test_failed_csm_login_clears_old_cookie(self):
        client = CSMClient('https://example.invalid/nbi', session=Mock())
        client.cookie = 'old-synthetic-cookie'
        client.call = Mock(side_effect=APIError('synthetic failure'))
        with self.assertRaises(APIError):
            client.login('synthetic-user', 'synthetic-password')
        self.assertIsNone(client.cookie)

    def test_csm_error_root(self):
        with self.assertRaises(APIError):
            parse_xml('<error><code>7</code></error>')

    def test_csm_duplicate_scalar(self):
        root = parse_xml('<rule><permit>true</permit><permit>false</permit></rule>')
        with self.assertRaises(ValidationError):
            required(root, 'permit')

    def test_csm_reference_list_shape(self):
        for xml in ('<networkObjectGIDs>text</networkObjectGIDs>',
                    '<serviceObjectGIDs><unexpected>value</unexpected></serviceObjectGIDs>'):
            with self.subTest(xml=xml), self.assertRaises(ValidationError):
                parse_xml(xml)

    def test_csm_ambiguous_ports(self):
        client = CSMClient('https://example.invalid/nbi', session=Mock())
        for content in ('<port>80</port><port>443</port>',
                        '<port>80</port><portRefGID>synthetic</portRefGID>',
                        '<unknown>80</unknown>', '<port/>', '<portRefGID/>'):
            param = parse_xml('<serviceParameters><protocol>tcp</protocol><destinationPort>'
                              + content + '</destinationPort></serviceParameters>')
            with self.subTest(content=content), self.assertRaises(ValidationError):
                client.parameter(param)

    def test_explicit_empty_fmc_port_is_not_any(self):
        for value in (None, '', ' '):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                FMCClient.literal({'type': 'PortLiteral', 'protocol': '6', 'port': value}, 'service')

    def test_csm_duplicate_policy_container(self):
        client = CSMClient('https://example.invalid/nbi', session=Mock())
        with self.assertRaises(ValidationError):
            client.PolicyRules('<policyConfigDeviceResponse><policy/><policy/></policyConfigDeviceResponse>')

    def test_failure_report_stage_and_redaction(self):
        for stage in ('csm_policy_read', 'fmc_policy_lookup', 'fmc_policy_read'):
            source, target = Mock(), Mock()
            source.policy_rules.return_value = []
            target.policy_uuid_by_name.return_value = 'synthetic-policy'
            target.policy_rules.return_value = []
            failing = {'csm_policy_read': source.policy_rules,
                       'fmc_policy_lookup': target.policy_uuid_by_name,
                       'fmc_policy_read': target.policy_rules}[stage]
            failing.side_effect = APIError('DO-NOT-EXPOSE-RESPONSE-BODY')
            report = compare_policies(source, 'source', target, 'target')
            self.assertEqual(report['status'], 'INDETERMINATE')
            self.assertEqual(report['error_details'], [{'stage': stage, 'category': 'api_error'}])
            self.assertNotIn('DO-NOT-EXPOSE', json.dumps(report))

    def test_report_explains_legacy_limits(self):
        rule = Rule('1', ['source'], ['destination'], ['443'])
        report = compare_rules([rule], [rule])
        self.assertEqual(report['summary'], {'source_rules': 1, 'target_rules': 1})
        self.assertTrue(any('names only' in warning for warning in report['warnings']))
        self.assertTrue(any('no protocol' in warning for warning in report['warnings']))

    def test_missing_rule_includes_resolved_values(self):
        source = Rule('1', ['source'], ['destination'], [('6', 443, 443)],
                      object_values={'source': ['192.0.2.1'], 'destination': ['198.51.100.0/24']})
        target = Rule('2', ['source'], ['destination'], [('17', 443, 443)],
                      object_values=source.object_values)
        report = compare_rules([source], [target])
        self.assertEqual(report['missing'][0]['resolved_sources'], ['192.0.2.1/32'])
        self.assertEqual(report['extra'][0]['resolved_destinations'], ['198.51.100.0/24'])
