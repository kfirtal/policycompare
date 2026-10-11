"""End-to-end synthetic CSM/FMC policies, including nested cached references."""
import copy
import unittest
from unittest.mock import Mock, patch

from csm import CSMClient, parse_xml
from fmc import FMCClient
from compare import compare_all
from errors import APIError


class PolicyInventoryTests(unittest.TestCase):
    def setUp(self):
        guard = patch('requests.Session.request', side_effect=AssertionError('Real HTTP forbidden'))
        guard.start()
        self.addCleanup(guard.stop)

    def csm_rules(self, host='192.0.2.1', port='443', extra_fields='', count=1):
        client = CSMClient('https://example.invalid/nbi', session=Mock())
        client.cache = {
            'ng': parse_xml('<networkPolicyObject><name>example-networks</name><refGIDs><gid>h</gid></refGIDs></networkPolicyObject>'),
            'h': parse_xml('<networkPolicyObject><name>example-host</name><ipv4Data>' + host + '</ipv4Data></networkPolicyObject>'),
            'sg': parse_xml('<servicePolicyObject><name>example-services</name><refGIDs><gid>s</gid></refGIDs></servicePolicyObject>'),
            's': parse_xml('<servicePolicyObject><name>example-https</name><serviceParameters><protocol>tcp</protocol><destinationPort><port>' + port + '</port></destinationPort><sourcePort><port>1024-65535</port></sourcePort></serviceParameters></servicePolicyObject>'),
            'unused': parse_xml('<networkPolicyObject><name>unused-example</name><ipv4Data>203.0.113.1</ipv4Data></networkPolicyObject>'),
        }
        rule = '<deviceAccessRuleFirewallPolicy><orderId>{}</orderId><sources><networkObjectGIDs><gid>ng</gid></networkObjectGIDs></sources><destinations/><services><serviceObjectGIDs><gid>sg</gid></serviceObjectGIDs></services>' + extra_fields + '</deviceAccessRuleFirewallPolicy>'
        xml = '<policyConfigDeviceResponse><policy>' + ''.join(rule.format(i) for i in range(count)) + '</policy></policyConfigDeviceResponse>'
        return client.PolicyRules(xml)

    def fmc_rules(self, host='192.0.2.1/32', port='443', extra_fields=None, count=1):
        client = FMCClient('https://example.invalid', domain='synthetic', session=Mock())
        raw = {
            'sourceNetworks': {'objects': [{'id': 'ng', 'type': 'NetworkGroup', 'name': 'example-networks'}]},
            'destinationPorts': {'objects': [{'id': 'sg', 'type': 'PortObjectGroup', 'name': 'example-services'}]},
            **(extra_fields or {}),
        }
        objects = {
            'ng': {'id': 'ng', 'type': 'NetworkGroup', 'name': 'example-networks', 'objects': [{'id': 'h', 'type': 'Host', 'name': 'example-host'}]},
            'h': {'id': 'h', 'type': 'Host', 'name': 'example-host', 'value': host},
            'sg': {'id': 'sg', 'type': 'PortObjectGroup', 'name': 'example-services', 'objects': [{'id': 's', 'type': 'ProtocolPortObject', 'name': 'example-https'}]},
            's': {'id': 's', 'type': 'ProtocolPortObject', 'name': 'example-https', 'protocol': '6', 'port': port},
        }
        client.collection = Mock(return_value=[{**copy.deepcopy(raw), 'id': str(i)} for i in range(count)])
        client.get = Mock(side_effect=lambda path: copy.deepcopy(objects[path.rsplit('/', 1)[1]]))
        return client.policy_rules('policy'), client

    def test_both_reports_pass_for_named_nested_groups(self):
        source = self.csm_rules()
        target, _ = self.fmc_rules()
        result = compare_all(source, target)
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['objects_report']['summary'], {'source_objects': 4, 'target_objects': 4})
        self.assertNotIn('unused-example', [item['name'] for item in source[0].referenced_objects])

    def test_network_drift_leaves_rules_matching(self):
        source = self.csm_rules()
        target, _ = self.fmc_rules(host='192.0.2.2')
        result = compare_all(source, target)
        self.assertEqual(result['rules_report']['status'], 'PASS')
        self.assertEqual(result['objects_report']['status'], 'FAIL')
        self.assertEqual({item['name'] for item in result['objects_report']['changed']},
                         {'example-networks', 'example-host'})

    def test_service_drift_changes_both_reports(self):
        target, _ = self.fmc_rules(port='8443')
        result = compare_all(self.csm_rules(), target)
        self.assertEqual(result['rules_report']['status'], 'FAIL')
        self.assertEqual({item['name'] for item in result['objects_report']['changed']},
                         {'example-services', 'example-https'})

    def test_cached_nested_objects_keep_every_affected_rule(self):
        target, client = self.fmc_rules(host='192.0.2.2', count=2)
        result = compare_all(self.csm_rules(count=2), target)
        self.assertEqual(client.get.call_count, 4)
        host = next(item for item in result['objects_report']['changed'] if item['name'] == 'example-host')
        self.assertEqual(host['source_rules'], ['0', '1'])
        self.assertEqual(host['target_rules'], ['0', '1'])

    def test_fields_outside_scope_do_not_change_either_report(self):
        source = self.csm_rules(extra_fields='<permit>false</permit><isEnabled>false</isEnabled><users><name>synthetic</name></users><iosOptions>Established</iosOptions><interfaceRoleObjectGIDs><gid>unresolved-interface</gid></interfaceRoleObjectGIDs>')
        target, _ = self.fmc_rules(extra_fields={'action': 'MONITOR', 'enabled': 'ignored',
                                                'sourceZones': {'objects': [{'id': 'unresolved-zone'}]},
                                                'users': {'objects': [{'id': 'unresolved-user'}]}})
        self.assertEqual(compare_all(source, target)['status'], 'PASS')

    def test_network_resolution_failure_does_not_erase_rule_names(self):
        client = FMCClient('https://example.invalid', domain='synthetic', session=Mock())
        client.collection = Mock(return_value=[{'id': 'r', 'sourceNetworks': {'objects': [
            {'id': 'h', 'type': 'Host', 'name': 'example-host'}]}}])
        client.get = Mock(side_effect=APIError('DO-NOT-EXPOSE'))
        rules = client.policy_rules('policy')
        result = compare_all(rules, rules)
        self.assertEqual(result['rules_report']['status'], 'PASS')
        self.assertEqual(result['objects_report']['status'], 'INDETERMINATE')
        self.assertNotIn('DO-NOT-EXPOSE', str(result))

    def test_service_resolution_failure_invalidates_both_reports(self):
        client = FMCClient('https://example.invalid', domain='synthetic', session=Mock())
        client.collection = Mock(return_value=[{'id': 'r', 'destinationPorts': {'objects': [
            {'id': 's', 'type': 'ProtocolPortObject', 'name': 'example-service'}]}}])
        client.get = Mock(side_effect=APIError('DO-NOT-EXPOSE'))
        rules = client.policy_rules('policy')
        result = compare_all(rules, rules)
        self.assertEqual(result['rules_report']['status'], 'INDETERMINATE')
        self.assertEqual(result['objects_report']['status'], 'INDETERMINATE')

    def test_literal_networks_compare_by_value_not_position(self):
        source = CSMClient('https://example.invalid/nbi', session=Mock()).PolicyRules(
            '<policyConfigDeviceResponse><policy><deviceAccessRuleFirewallPolicy><orderId>1</orderId><sources><ipv4Data>192.0.2.1</ipv4Data></sources><destinations/><services/></deviceAccessRuleFirewallPolicy></policy></policyConfigDeviceResponse>')
        target = FMCClient('https://example.invalid', domain='synthetic', session=Mock())
        target.collection = Mock(return_value=[{'id': 'r', 'sourceNetworks': {'literals': [{'type': 'Host', 'value': '192.0.2.1/32'}]}}])
        result = compare_all(source, target.policy_rules('policy'))
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['objects_report']['summary']['source_objects'], 0)
