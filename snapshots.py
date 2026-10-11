"""Load normalized offline rules. Raw Cisco responses belong to API adapters."""
import json

from errors import ValidationError
from rule import Rule


REQUIRED_FIELDS = {
    'rule_number', 'source_objects', 'destination_objects', 'destination_services',
}
OPTIONAL_FIELDS = {'action', 'enabled', 'object_values', 'issues'}


def load_snapshot(path):
    """Read a JSON array and reject malformed records without exposing content.

    JSON has arrays but no tuples. Convert service arrays to tuples so the
    normalizer can distinguish protocol-aware services from legacy port strings.
    This validates the container shape; signature() validates rule semantics.
    """
    try:
        with open(path, encoding='utf-8-sig') as stream:
            records = json.load(stream)
    except (OSError, ValueError):
        raise ValidationError('Invalid or unreadable snapshot') from None

    if not isinstance(records, list):
        raise ValidationError('Snapshot must be a JSON array of rules')

    rules = []
    for index, record in enumerate(records, start=1):
        error = f'Invalid snapshot record {index}'
        if not isinstance(record, dict):
            raise ValidationError(error)
        if not REQUIRED_FIELDS <= record.keys():
            raise ValidationError(error + ': missing required fields')
        if record.keys() - (REQUIRED_FIELDS | OPTIONAL_FIELDS):
            raise ValidationError(error + ': unrecognized fields')
        for field in ('source_objects', 'destination_objects', 'destination_services'):
            if not isinstance(record[field], list):
                raise ValidationError(error + ': rule fields must be arrays')
        if 'object_values' in record and not isinstance(record['object_values'], dict):
            raise ValidationError(error + ': object_values must be an object')
        if 'issues' in record and (
            not isinstance(record['issues'], list)
            or any(not isinstance(issue, str) for issue in record['issues'])
        ):
            raise ValidationError(error + ': issues must be an array of strings')

        fields = dict(record)
        fields['destination_services'] = [
            tuple(service) if isinstance(service, list) else service
            for service in record['destination_services']
        ]
        rules.append(Rule(**fields))
    return rules
