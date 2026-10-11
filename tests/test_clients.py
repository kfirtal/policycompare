import importlib
import unittest
from unittest.mock import Mock, patch
import requests
from csm import CSMClient, parse_xml
from fmc import FMCClient
from errors import APIError, ValidationError


def response(data=None, text='', status=200, headers=None, cookie=None):
    result = Mock(status_code=status, text=text, headers=headers or {})
    result.json.return_value = data
    result.cookies.get.return_value = cookie
    return result


def fmc(*responses):
    session = Mock()
    session.request.side_effect = responses
    client = FMCClient('https://example.invalid', domain='domain', session=session, sleep=Mock())
    client.token = 'test-token'
    return client, session


def csm(*responses):
    session = Mock()
    session.request.side_effect = responses
    client = CSMClient('https://example.invalid/nbi', session=session)
    client.cookie = 'test-cookie'
    return client, session


def xml_rule(ident='1'):
    return f'<deviceAccessRuleFirewallPolicy><orderId>{ident}</orderId><permit>true</permit><isEnabled>true</isEnabled><sources/><destinations/><services><serviceParameters><protocol>tcp</protocol><destinationPort><port>80</port></destinationPort></serviceParameters></services></deviceAccessRuleFirewallPolicy>'


class ClientTests(unittest.TestCase):
    def setUp(self):
        guard = patch('requests.Session.request', side_effect=AssertionError('Real HTTP forbidden in offline tests'))
        guard.start()
        self.addCleanup(guard.stop)

    def test_imports_offline(self):
        with patch('requests.Session.request', side_effect=AssertionError('network')), patch('builtins.input', side_effect=AssertionError('prompt')):
            for name in ('csm', 'fmc', 'compare'):
                importlib.reload(importlib.import_module(name))

    def test_fmc_pagination(self):
        client, session = fmc(response({'items': [{'id': 'a'}], 'paging': {'count': 2}}), response({'items': [{'id': 'b'}], 'paging': {'count': 2}}))
        self.assertEqual(len(client.collection('/policy/accesspolicies')), 2)
        self.assertEqual(session.request.call_args.kwargs['params']['offset'], 1)
        self.assertTrue(session.request.call_args.kwargs['verify'])
        self.assertEqual(session.request.call_args.kwargs['timeout'], 30)
        self.assertFalse(session.request.call_args.kwargs['allow_redirects'])

    def test_fmc_incomplete_repeated_count(self):
        for second in ({'items': [], 'paging': {'count': 2}}, {'items': [{'id': 'a'}], 'paging': {'count': 2}}, {'items': [{'id': 'b'}], 'paging': {'count': 3}}):
            client, _ = fmc(response({'items': [{'id': 'a'}], 'paging': {'count': 2}}), response(second))
            with self.subTest(second=second), self.assertRaises(ValidationError):
                client.collection('/policy/accesspolicies')

    def test_transport_failures(self):
        for item in (response(status=500), response(status=302), requests.Timeout('secret')):
            client, _ = fmc(item)
            with self.subTest(item=item), self.assertRaises(APIError) as ctx:
                client.get('/object/hosts/a')
            self.assertNotIn('secret', str(ctx.exception))

    def test_rate_limit(self):
        client, _ = fmc(response(status=429, headers={'Retry-After': '1'}), response({'ok': True}))
        self.assertTrue(client.get('/object/hosts/a')['ok'])
        client.sleep.assert_called_once_with(1)

    def test_fmc_auth(self):
        client, _ = fmc(response(status=204, headers={'X-auth-access-token': 'new', 'DOMAINS': '[{"uuid":"domain"}]'}))
        client.login('user', 'secret')
        self.assertEqual(client.token, 'new')
        client, _ = fmc(response(status=204, headers={}))
        with self.assertRaises(APIError):
            client.login('user', 'secret')

    def test_fmc_group_cache_cycle(self):
        group = {'id': 'g', 'type': 'NetworkGroup', 'objects': [{'id': 'h', 'type': 'Host'}], 'literals': [{'type': 'Network', 'value': '198.51.100.0/24'}]}
        host = {'id': 'h', 'type': 'Host', 'value': '192.0.2.1'}
        client, session = fmc(response(group), response(host))
        ref = {'id': 'g', 'type': 'NetworkGroup'}
        self.assertEqual(len(client.resolve(ref, 'network')), 2)
        client.resolve(ref, 'network')
        self.assertEqual(session.request.call_count, 2)
        group['objects'] = [ref]
        client, _ = fmc(response(group))
        with self.assertRaises(ValidationError):
            client.resolve(ref, 'network')

    def test_fmc_rule_literals(self):
        raw = {'id': 'r', 'action': 'ALLOW', 'enabled': True, 'sourceNetworks': {'literals': [{'type': 'Host', 'value': '192.0.2.1'}]}, 'destinationPorts': {'literals': [{'type': 'PortLiteral', 'protocol': '6', 'port': '80'}]}}
        client, _ = fmc(response({'items': [raw], 'paging': {'count': 1}}))
        rules = client.policy_rules('policy')
        self.assertEqual(rules[0].destination_services, [('6', 80, 80)])
        # The network inventory must never contain protocol/port service tuples.
        self.assertTrue(all(isinstance(value, str)
                            for values in rules[0].object_values.values()
                            for value in values))

    def test_csm_pagination(self):
        client, session = csm(response(text='<policyConfigDeviceResponse><policy>' + xml_rule() + '</policy><endIndex>1</endIndex><totalCount>2</totalCount></policyConfigDeviceResponse>'), response(text='<policyConfigDeviceResponse><policy>' + xml_rule('2') + '</policy></policyConfigDeviceResponse>'))
        rules = client.policy_rules('a&b')
        self.assertEqual(len(rules), 2)
        self.assertIn(b'<startIndex>1</startIndex>', session.request.call_args.kwargs['data'])
        self.assertIn(b'a&amp;b', session.request.call_args.kwargs['data'])

    def test_csm_incomplete(self):
        client, _ = csm(response(text='<policyConfigDeviceResponse><policy>' + xml_rule() + '</policy><endIndex>1</endIndex><totalCount>3</totalCount></policyConfigDeviceResponse>'), response(text='<policyConfigDeviceResponse><policy/></policyConfigDeviceResponse>'))
        with self.assertRaises(ValidationError):
            client.policy_rules('p')

    def test_xml_errors(self):
        for text in ('<broken', '<!DOCTYPE a><a/>', '<response><error><code>7</code></error></response>'):
            with self.subTest(text=text), self.assertRaises((ValidationError, APIError)):
                parse_xml(text)

    def test_csm_nested_objects(self):
        client, _ = csm()
        client.cache = {'g': parse_xml('<networkPolicyObject><name>group</name><refGIDs><gid>h</gid></refGIDs><ipv4Data>198.51.100.0/24</ipv4Data></networkPolicyObject>'), 'h': parse_xml('<networkPolicyObject><name>host</name><ipv4Data>192.0.2.1</ipv4Data></networkPolicyObject>')}
        self.assertEqual(len(client.resolve('g', 'network')), 2)
        client.cache['h'] = parse_xml('<networkPolicyObject><refGIDs><gid>g</gid></refGIDs></networkPolicyObject>')
        with self.assertRaises(ValidationError):
            client.resolve('g', 'network')

    def test_csm_login_logout(self):
        client, session = csm(response(text='<loginResponse/>', cookie='cookie'), response(text='<logoutResponse/>'))
        client.login('a&b', '<secret>')
        self.assertIn(b'&lt;secret&gt;', session.request.call_args.kwargs['data'])
        client.logout()
        self.assertIsNone(client.cookie)

    def test_service_groups(self):
        group = {'id': 'g', 'type': 'PortObjectGroup', 'objects': [{'id': 's', 'type': 'ProtocolPortObject'}], 'literals': [{'type': 'PortLiteral', 'protocol': '17', 'port': '53'}]}
        client, _ = fmc(response(group), response({'id': 's', 'type': 'ProtocolPortObject', 'protocol': '6', 'port': '80-81'}))
        self.assertEqual(client.resolve({'id': 'g', 'type': 'PortObjectGroup'}, 'service'), frozenset({('6', 80, 81), ('17', 53, 53)}))

    def test_csm_port_list(self):
        client, _ = csm()
        client.cache['ports'] = parse_xml('<portListPolicyObject><startPort><portNum>80</portNum></startPort><endPort><portNum>82</portNum></endPort></portListPolicyObject>')
        param = parse_xml('<serviceParameters><protocol>6</protocol><destinationPort><portRefGID>ports</portRefGID></destinationPort></serviceParameters>')
        self.assertEqual(client.parameter(param), {('6', 80, 82)})

    def test_policy_missing_or_ambiguous(self):
        for items in ([], [{'id': 'a', 'name': 'p'}, {'id': 'b', 'name': 'p'}]):
            client, _ = fmc(response({'items': items, 'paging': {'count': len(items)}}))
            with self.assertRaises(ValidationError):
                client.policy_uuid_by_name('p')

    def test_constraints_indeterminate(self):
        from compare import compare_rules
        raw = {'id': 'r', 'action': 'ALLOW', 'enabled': True, 'applications': {'objects': [{'id': 'app'}]}}
        client, _ = fmc(response({'items': [raw], 'paging': {'count': 1}}))
        rules = client.policy_rules('p')
        self.assertEqual(compare_rules(rules, rules)['status'], 'INDETERMINATE')

    def test_api_failure_indeterminate(self):
        from compare import compare_policies
        source, target = Mock(), Mock()
        source.policy_rules.side_effect = APIError('failure')
        self.assertEqual(compare_policies(source, 'p', target, 'p')['status'], 'INDETERMINATE')
        target.policy_rules.assert_not_called()

    def test_fmc_unknown_container(self):
        raw = {'id': 'r', 'action': 'ALLOW', 'enabled': True, 'sourceNetworks': {'unknown': True}}
        client, _ = fmc(response({'items': [raw], 'paging': {'count': 1}}))
        with self.assertRaises(ValidationError):
            client.policy_rules('p')

    def test_csm_direct_page_rejected(self):
        client, _ = csm()
        with self.assertRaises(ValidationError):
            client.PolicyRules('<policyConfigDeviceResponse><endIndex>1</endIndex></policyConfigDeviceResponse>')

    def test_xml_namespaces(self):
        client, _ = csm()
        text = '<policyConfigDeviceResponse xmlns="csm"><policy>' + xml_rule() + '</policy></policyConfigDeviceResponse>'
        self.assertEqual(len(client.PolicyRules(text)), 1)

    def test_unauthenticated(self):
        client, session = fmc()
        client.token = None
        with self.assertRaises(APIError):
            client.get('/policy/accesspolicies')
        session.request.assert_not_called()

    def test_retries_exhausted(self):
        client, session = fmc(*(response(status=429) for _ in range(5)))
        with self.assertRaises(APIError):
            client.get('/policy/accesspolicies')
        self.assertEqual(session.request.call_count, 5)

    def test_cross_vendor_value_equivalence(self):
        from compare import compare_rules
        source, _ = csm()
        source.cache['host'] = parse_xml('<networkPolicyObject><name>CSM-name</name><ipv4Data>192.0.2.1</ipv4Data></networkPolicyObject>')
        raw_xml = xml_rule().replace('<sources/>', '<sources><networkObjectGIDs><gid>host</gid></networkObjectGIDs></sources>')
        source_rules = source.PolicyRules('<policyConfigDeviceResponse><policy>' + raw_xml + '</policy></policyConfigDeviceResponse>')
        raw = {'id': 'r', 'action': 'ALLOW', 'enabled': True, 'sourceNetworks': {'objects': [{'id': 'host', 'name': 'FMC-name', 'type': 'Host'}]}, 'destinationPorts': {'literals': [{'type': 'PortLiteral', 'protocol': '6', 'port': '80'}]}}
        target, _ = fmc(response({'items': [raw], 'paging': {'count': 1}}), response({'id': 'host', 'type': 'Host', 'value': '192.0.2.1/32'}))
        self.assertEqual(compare_rules(source_rules, target.policy_rules('p'))['status'], 'PASS')
