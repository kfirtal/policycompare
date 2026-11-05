import json
import unittest
from unittest.mock import mock_open, patch

from errors import ValidationError
from snapshots import load_snapshot


class SnapshotTests(unittest.TestCase):
    def record(self):
        return {
            'rule_number': '1', 'source_objects': ['source'],
            'destination_objects': ['destination'],
            'destination_services': [['6', 443, 443]],
        }

    def load(self, data):
        with patch('builtins.open', mock_open(read_data=json.dumps(data))):
            return load_snapshot('synthetic.snapshot.json')

    def test_converts_service_arrays(self):
        rule = self.load([self.record()])[0]
        self.assertEqual(rule.destination_services, [('6', 443, 443)])

    def test_rejects_non_array_root(self):
        for value in ({}, None, 'text', 5):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                self.load(value)

    def test_rejects_malformed_record(self):
        for value in (None, [], 'text', {}):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                self.load([value])

    def test_rejects_wrong_field_types(self):
        for field, value in (
            ('source_objects', 'source'), ('destination_objects', None),
            ('destination_services', {}), ('object_values', []),
            ('object_values', None), ('issues', 'error'), ('issues', [None]),
        ):
            with self.subTest(field=field, value=value), self.assertRaises(ValidationError):
                self.load([{**self.record(), field: value}])

    def test_unknown_fields_rejected(self):
        with self.assertRaises(ValidationError):
            self.load([{**self.record(), 'unsupported_constraint': True}])

    def test_duplicate_json_keys_cannot_hide_fields(self):
        text = '[{"rule_number":"1","source_objects":["PRIVATE-FIRST-VALUE"],"source_objects":["source"],"destination_objects":["destination"],"destination_services":[["6",443,443]]}]'
        with patch('builtins.open', mock_open(read_data=text)), self.assertRaises(ValidationError) as caught:
            load_snapshot('synthetic.snapshot.json')
        self.assertNotIn('PRIVATE-FIRST-VALUE', str(caught.exception))

    def test_duplicate_rule_identifiers_rejected(self):
        with self.assertRaises(ValidationError):
            self.load([self.record(), {**self.record(), 'rule_number': 1}])

    def test_identifiers_reference_names_and_issues_are_validated(self):
        for field, value in (
            ('rule_number', []), ('rule_number', None), ('rule_number', True), ('rule_number', ''),
            ('service_objects', [None]), ('service_objects', ['']),
            ('object_issues', [None]), ('object_issues', ['']),
        ):
            with self.subTest(field=field, value=value), self.assertRaises(ValidationError):
                self.load([{**self.record(), field: value}])

    def test_bad_json_has_sanitized_error(self):
        with patch('builtins.open', mock_open(read_data='private-content-not-json')):
            with self.assertRaises(ValidationError) as caught:
                load_snapshot('synthetic.snapshot.json')
        self.assertNotIn('private-content', str(caught.exception))
