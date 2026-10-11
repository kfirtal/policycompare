import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from compare import compare_all, compare_objects, compare_rules, find_gaps, main, save_reports
from errors import ValidationError
from normalization import networks, service, services
from rule import Rule
from snapshots import load_snapshot, save_snapshot


def sample_rule(port=80, source_value='192.0.2.1', destination_value='198.51.100.0/24', **kwargs):
    inventory = [
        dict(name='source', kind='network', values=[source_value]),
        dict(name='destination', kind='network', values=[destination_value]),
        dict(name='web', kind='service', values=[('6', port, port)]),
    ]
    return Rule('1', ['source'], ['destination'], [('6', port, port)],
                referenced_objects=inventory, service_objects=['web'], **kwargs)


class ComparisonTests(unittest.TestCase):
    def test_original_gap_api_returns_rules(self):
        a, b = sample_rule(), sample_rule(443)
        self.assertEqual(find_gaps([a], [a]), [])
        self.assertEqual(find_gaps([a], [b]), [a])

    def test_bidirectional(self):
        report = compare_rules([sample_rule()], [sample_rule(), sample_rule(443)])
        self.assertEqual(report['status'], 'FAIL')
        self.assertEqual(len(report['extra']), 1)

    def test_empty(self):
        self.assertEqual(compare_all([], [])['status'], 'INDETERMINATE')
        self.assertEqual(compare_all([], [], True)['status'], 'PASS')

    def test_incomplete_rule_fields(self):
        a = sample_rule(issues=['Unresolved destination service'])
        self.assertEqual(compare_rules([a], [a])['status'], 'INDETERMINATE')

    def test_protocol_identity(self):
        a, b = sample_rule(), sample_rule()
        b.destination_services = [('17', 80, 80)]
        self.assertEqual(compare_rules([a], [b])['status'], 'FAIL')

    def test_ranges(self):
        self.assertEqual(services([('tcp', 80, 82)]), services([('6', 80, 80), ('6', 81, 82)]))
        for value in ('-1', '65536', '90-80', 'http', '1-2-3'):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                service('tcp', value)

    def test_invalid_service_tuples_cannot_pass(self):
        for value in (('any', 80, 80), ('ip', 1, 65535), ('6', -1, 80),
                      ('6', 80, 65536), ('6', 90, 80), ('6', True, 80), ('6', '80', '80'), ('6', 80)):
            rule = sample_rule()
            rule.destination_services = [value]
            with self.subTest(value=value):
                self.assertEqual(compare_rules([rule], [rule])['status'], 'INDETERMINATE')

    def test_port_only_services_do_not_claim_protocol_validation(self):
        rule = Rule('1', ['source'], ['destination'], ['80'])
        self.assertEqual(compare_rules([rule], [rule])['status'], 'INDETERMINATE')

    def test_any_aliases_are_equivalent(self):
        self.assertEqual(services([('ip', 0, 65535)]), services([('any', 0, 65535)]))

    def test_network_equivalence(self):
        self.assertEqual(networks(['192.0.2.0/25', '192.0.2.128/25']), networks(['192.0.2.0/24']))
        self.assertEqual(networks(['192.0.2.1']), networks(['192.0.2.1/32']))
        self.assertEqual(networks(['192.0.2.0-192.0.2.255']), networks(['192.0.2.0/24']))

    def test_value_drift_only_fails_object_report(self):
        a, b = sample_rule(), sample_rule(source_value='192.0.2.2')
        result = compare_all([a], [b])
        self.assertEqual(result['rules_report']['status'], 'PASS')
        self.assertEqual(result['objects_report']['status'], 'FAIL')
        self.assertEqual(result['objects_report']['changed'][0]['source_rules'], ['1'])

    def test_different_names_same_values_fail_rules_and_objects(self):
        a, b = sample_rule(), sample_rule()
        b.source_objects = ['renamed-source']
        b.referenced_objects[0]['name'] = 'renamed-source'
        result = compare_all([a], [b])
        self.assertEqual(result['rules_report']['status'], 'FAIL')
        self.assertEqual(result['objects_report']['status'], 'FAIL')

    def test_actions_enabled_and_order_ignored(self):
        a = sample_rule(action='ALLOW', enabled=True)
        b = sample_rule(action='DROP', enabled=False)
        self.assertEqual(compare_all([a], [b])['status'], 'PASS')
        self.assertEqual(compare_rules([a, sample_rule(443)], [sample_rule(443), b])['status'], 'PASS')

    def test_service_names_only_matter_in_object_report(self):
        a, b = sample_rule(), sample_rule()
        b.service_objects = ['renamed-web']
        b.referenced_objects[2]['name'] = 'renamed-web'
        result = compare_all([a], [b])
        self.assertEqual(result['rules_report']['status'], 'PASS')
        self.assertEqual(result['objects_report']['status'], 'FAIL')

    def test_missing_inventory_does_not_invalidate_rule_report(self):
        rule = Rule('1', ['source'], ['destination'], [('6', 80, 80)])
        result = compare_all([rule], [rule])
        self.assertEqual(result['rules_report']['status'], 'PASS')
        self.assertEqual(result['objects_report']['status'], 'INDETERMINATE')

    def test_resolution_issue_cannot_pass_object_report(self):
        rule = sample_rule(object_issues=['Unresolved child'])
        self.assertEqual(compare_all([rule], [rule])['objects_report']['status'], 'INDETERMINATE')

    def test_invalid_object_values_cannot_pass(self):
        for value in (None, '', '192.0.2.1', [], [None], ['invalid']):
            rule = sample_rule()
            rule.referenced_objects[0]['values'] = value
            with self.subTest(value=value):
                self.assertEqual(compare_objects([rule], [rule])['status'], 'INDETERMINATE')
                self.assertEqual(compare_rules([rule], [rule])['status'], 'PASS')

    def test_conflicting_named_objects_cannot_pass(self):
        a, b = sample_rule(), sample_rule(source_value='192.0.2.2')
        self.assertEqual(compare_objects([a, b], [a])['status'], 'INDETERMINATE')

    def test_nested_member_changes_are_visible_even_if_group_union_equal(self):
        a, b = sample_rule(), sample_rule()
        for rule in (a, b):
            rule.referenced_objects.append(dict(name='group', kind='network', values=['192.0.2.0/24']))
            rule.referenced_objects.append(dict(name='child', kind='network', values=['192.0.2.10']))
        b.referenced_objects[-1]['values'] = ['192.0.2.11']
        report = compare_objects([a], [b])
        self.assertEqual([item['name'] for item in report['changed']], ['child'])

    def test_network_and_service_same_name_are_distinct(self):
        a, b = sample_rule(), sample_rule()
        for rule in (a, b):
            rule.service_objects = ['source']
            rule.referenced_objects[2]['name'] = 'source'
        self.assertEqual(compare_all([a], [b])['status'], 'PASS')

    def test_port_list_ranges_compare_semantically(self):
        a, b = sample_rule(), sample_rule()
        a.referenced_objects.append(dict(name='ports', kind='port_list', values=['80-82']))
        b.referenced_objects.append(dict(name='ports', kind='port_list', values=['80', '81-82']))
        self.assertEqual(compare_objects([a], [b])['status'], 'PASS')

    def test_cli_separate_reports_and_exit_codes(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as folder:
            root = Path(folder)
            a, b = root / 'a.json', root / 'b.json'
            save_snapshot([sample_rule()], a)
            save_snapshot([sample_rule()], b)
            for target, expected in (([sample_rule()], 0), ([sample_rule(443)], 1),
                                     ([Rule('1', ['source'], ['destination'], [('6', 80, 80)])], 2)):
                if b.exists():
                    b.unlink()
                save_snapshot(target, b)
                output = io.StringIO()
                with patch('sys.argv', ['compare.py', str(a), str(b)]), contextlib.redirect_stdout(output):
                    self.assertEqual(main(), expected)
                result = json.loads(output.getvalue())
                self.assertIn('rules_report', result)
                self.assertIn('objects_report', result)
            result = compare_all(load_snapshot(a), load_snapshot(a))
            save_reports(result, root / 'reports')
            self.assertEqual(len(list((root / 'reports').iterdir())), 4)
            for name in ('rules_report', 'objects_report'):
                self.assertEqual(json.loads((root / 'reports' / (name + '.json')).read_text(encoding='utf-8'))['status'], 'PASS')
                self.assertIn('תוצאה: PASS', (root / 'reports' / (name + '.txt')).read_text(encoding='utf-8'))
            with self.assertRaises(ValidationError):
                save_reports(result, root / 'reports')

    def test_checked_in_examples_prove_separate_results(self):
        examples = Path(__file__).resolve().parents[1] / 'examples'
        source = load_snapshot(examples / 'csm.json')
        network = compare_all(source, load_snapshot(examples / 'fmc-network-drift.json'))
        service = compare_all(source, load_snapshot(examples / 'fmc-service-drift.json'))
        self.assertEqual(network['rules_report']['status'], 'PASS')
        self.assertEqual(network['objects_report']['status'], 'FAIL')
        self.assertEqual(service['rules_report']['status'], 'FAIL')
        self.assertEqual(service['objects_report']['status'], 'FAIL')
