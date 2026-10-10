import unittest
from rule import Rule
from compare import find_gaps, compare_rules
from normalization import networks, service, services
from errors import ValidationError


class ComparisonTests(unittest.TestCase):
    def rule(self, port='80', **kwargs):
        return Rule(1, ['src'], ['dst'], [port], **kwargs)

    def test_legacy_identical(self):
        self.assertEqual(find_gaps([self.rule()], [self.rule()]), [])

    def test_legacy_changed(self):
        self.assertEqual(len(find_gaps([self.rule()], [self.rule('443')])), 1)

    def test_bidirectional(self):
        report = compare_rules([self.rule()], [self.rule(), self.rule('443')])
        self.assertEqual(report['status'], 'FAIL')
        self.assertEqual(len(report['extra']), 1)

    def test_empty(self):
        self.assertEqual(compare_rules([], [])['status'], 'INDETERMINATE')
        self.assertEqual(compare_rules([], [], True)['status'], 'PASS')

    def test_unsupported(self):
        self.assertEqual(compare_rules([self.rule(issues=['zone'])], [self.rule()])['status'], 'INDETERMINATE')

    def test_protocol(self):
        a, b = self.rule(), self.rule()
        a.destination_services = list(service('TCP', '80'))
        b.destination_services = list(service('17', '80'))
        self.assertEqual(compare_rules([a], [b])['status'], 'FAIL')

    def test_ranges(self):
        self.assertEqual(services([('tcp', 80, 82)]), services([('6', 80, 80), ('6', 81, 82)]))
        for value in ('-1', '65536', '90-80', 'http', '1-2-3'):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                service('tcp', value)

    def test_network_equivalence(self):
        self.assertEqual(networks(['192.0.2.0/25', '192.0.2.128/25']), networks(['192.0.2.0/24']))
        self.assertEqual(networks(['192.0.2.1']), networks(['192.0.2.1/32']))
        self.assertEqual(networks(['192.0.2.0-192.0.2.255']), networks(['192.0.2.0/24']))

    def test_drift_and_affected_rules(self):
        a = self.rule(object_values={'src': ['192.0.2.1'], 'dst': ['0.0.0.0/0']})
        b = self.rule(object_values={'src': ['192.0.2.2'], 'dst': ['0.0.0.0/0']})
        report = compare_rules([a], [b])
        self.assertEqual(report['status'], 'FAIL')
        self.assertEqual(report['changed_objects'][0]['source_rules'], [1])

    def test_action_enabled_order(self):
        self.assertEqual(compare_rules([self.rule()], [self.rule(action='DROP')])['status'], 'FAIL')
        self.assertEqual(compare_rules([self.rule()], [self.rule(enabled=False)])['status'], 'FAIL')
        self.assertEqual(compare_rules([self.rule(), self.rule('443')], [self.rule('443'), self.rule()])['status'], 'PASS')
