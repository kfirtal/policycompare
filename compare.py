"""Two independent comparisons: rule fields, then referenced object values."""
import argparse
import json
import sys
from pathlib import Path

from errors import APIError, ValidationError
from normalization import networks, services, ports
from snapshots import load_snapshot


def validate_network_names(names):
    """Require explicit network fields and recognize only our internal markers."""
    if not isinstance(names, (list, tuple, set, frozenset)):
        raise ValidationError('Network object names must be a collection')
    if not names:
        raise ValidationError('Network fields must explicitly describe Any or object names')
    if any(not isinstance(name, str) or not name.strip() for name in names):
        raise ValidationError('Invalid network object name')
    for name in names:
        if name.startswith('@literal:'):
            networks(name[len('@literal:'):].split(','))
        elif name.startswith('@') and name != '@any':
            raise ValidationError('Invalid internal network marker')


def signature(rule):
    """Only source names, destination names and destination protocol/ports."""
    if rule.issues:
        raise ValidationError('; '.join(rule.issues))
    validate_network_names(rule.source_objects)
    validate_network_names(rule.destination_objects)
    if not isinstance(rule.destination_services, (list, tuple, set, frozenset)):
        raise ValidationError('Destination services must be a collection')
    if not rule.destination_services:
        raise ValidationError('Destination services must explicitly describe Any or protocol/ports')
    if any(not isinstance(value, tuple) for value in rule.destination_services):
        raise ValidationError('Destination services require protocol and port ranges')
    return (frozenset(rule.source_objects), frozenset(rule.destination_objects),
            services(rule.destination_services))


def find_gaps(csm_list, fmc_list):
    """Keep the original API: return CSM Rule instances absent from FMC."""
    target = {signature(rule) for rule in fmc_list}
    return [rule for rule in csm_list if signature(rule) not in target]


def rule_detail(rule):
    return dict(rule_number=rule.rule_number, sources=sorted(set(rule.source_objects)),
                destinations=sorted(set(rule.destination_objects)),
                services=sorted(services(rule.destination_services)))


def compare_rules(source, target, allow_empty=False):
    """Stage one intentionally never reads object values, action or enabled."""
    source, target = list(source), list(target)
    report = dict(status='INDETERMINATE', errors=[], missing=[], extra=[],
                  summary={'source_rules': len(source), 'target_rules': len(target)},
                  scope='Source object names, destination object names, destination protocol/ports. Order, action and enabled state are ignored.')
    if not allow_empty and (not source or not target):
        report['errors'].append('Empty policy requires explicit allow_empty')
    for side, rules in (('source', source), ('target', target)):
        for rule in rules:
            try:
                signature(rule)
            except (ValidationError, TypeError, ValueError):
                report['errors'].append(f'{side} rule {rule.rule_number}: incomplete or invalid comparison fields')
    if report['errors']:
        return report
    report['missing'] = [rule_detail(rule) for rule in find_gaps(source, target)]
    report['extra'] = [rule_detail(rule) for rule in find_gaps(target, source)]
    report['status'] = 'FAIL' if report['missing'] or report['extra'] else 'PASS'
    return report


def normalized_object(record):
    """Groups compare their expanded values; every named child is also audited."""
    if not isinstance(record, dict):
        raise ValidationError('Invalid referenced object record')
    name, kind, values = record.get('name'), record.get('kind'), record.get('values')
    if not isinstance(name, str) or not name.strip() or name.startswith('@'):
        raise ValidationError('Invalid object name')
    if not isinstance(values, (list, tuple, set, frozenset)) or not values:
        raise ValidationError('Empty or malformed object values')
    if kind == 'network':
        if any(not isinstance(value, str) for value in values):
            raise ValidationError('Invalid network values')
        value = networks(values)
    elif kind == 'service':
        tuples = [tuple(item) if isinstance(item, list) else item for item in values]
        if any(not isinstance(item, tuple) for item in tuples):
            raise ValidationError('Service object requires protocol/ports')
        value = services(tuples)
    elif kind == 'port_list':
        # CSM port-list objects have no protocol of their own.
        if any(type(item) not in (str, int) or not str(item).strip() for item in values):
            raise ValidationError('Invalid port-list value')
        spans = [('6', lo, hi) for item in values for lo, hi in ports(item)]
        value = frozenset((lo, hi) for _, lo, hi in services(spans))
    else:
        raise ValidationError('Unsupported referenced object kind')
    return (kind, name), value


def object_inventory(rules, side):
    inventory, affected, errors = {}, {}, []
    for rule in rules:
        try:
            validate_network_names(rule.source_objects)
            validate_network_names(rule.destination_objects)
            if (not isinstance(rule.service_objects, (list, tuple, set, frozenset))
                    or any(not isinstance(name, str) or not name.strip() for name in rule.service_objects)):
                raise ValidationError('Invalid service object names')
        except ValidationError:
            errors.append(f'{side} rule {rule.rule_number}: invalid named references')
            continue
        if rule.object_issues:
            errors.append(f'{side} rule {rule.rule_number}: referenced object resolution incomplete')
        if rule.referenced_objects is None:
            errors.append(f'{side} rule {rule.rule_number}: complete referenced-object inventory unavailable')
            continue
        if not isinstance(rule.referenced_objects, list):
            errors.append(f'{side} rule {rule.rule_number}: invalid referenced-object inventory')
            continue
        keys = set()
        for record in rule.referenced_objects:
            try:
                key, values = normalized_object(record)
                keys.add(key)
                if key in inventory and inventory[key] != values:
                    raise ValidationError('Conflicting values for the same object name')
                inventory[key] = values
                affected.setdefault(key, [])
                if rule.rule_number not in affected[key]:
                    affected[key].append(rule.rule_number)
            except (ValidationError, TypeError, ValueError):
                errors.append(f'{side} rule {rule.rule_number}: invalid or conflicting object values')
        # Check coverage of direct named references. Literals and omitted Any
        # have reserved @ markers and are not real objects to match by name.
        for name in list(rule.source_objects) + list(rule.destination_objects):
            if not name.startswith('@') and ('network', name) not in keys:
                errors.append(f'{side} rule {rule.rule_number}: network object missing from inventory')
        for name in rule.service_objects:
            if ('service', name) not in keys:
                errors.append(f'{side} rule {rule.rule_number}: service object missing from inventory')
    return inventory, affected, errors


def compare_objects(source, target, allow_empty=False):
    """Stage two matches names and kinds, independently of rule signatures."""
    source, target = list(source), list(target)
    a, source_rules, errors_a = object_inventory(source, 'source')
    b, target_rules, errors_b = object_inventory(target, 'target')
    errors = errors_a + errors_b
    if not allow_empty and (not source or not target):
        errors.append('Empty policy requires explicit allow_empty')
    def detail(key):
        kind, name = key
        return dict(kind=kind, name=name,
                    source_values=sorted(a[key]) if key in a else None,
                    target_values=sorted(b[key]) if key in b else None,
                    source_rules=source_rules.get(key, []), target_rules=target_rules.get(key, []))
    missing = [detail(key) for key in sorted(a.keys() - b.keys())]
    extra = [detail(key) for key in sorted(b.keys() - a.keys())]
    changed = [detail(key) for key in sorted(a.keys() & b.keys()) if a[key] != b[key]]
    status = 'INDETERMINATE' if errors else 'FAIL' if missing or extra or changed else 'PASS'
    return dict(status=status, errors=errors, missing=missing, extra=extra, changed=changed,
                summary={'source_objects': len(a), 'target_objects': len(b)},
                scope='Referenced network/service objects and groups matched by kind and exact name; includes nested members. Group values are expanded.')


def compare_all(source, target, allow_empty=False):
    """Return two distinct reports and a conservative overall status."""
    source, target = list(source), list(target)
    rules = compare_rules(source, target, allow_empty)
    objects = compare_objects(source, target, allow_empty)
    statuses = (rules['status'], objects['status'])
    status = 'INDETERMINATE' if 'INDETERMINATE' in statuses else 'FAIL' if 'FAIL' in statuses else 'PASS'
    return dict(status=status, rules_report=rules, objects_report=objects)


def incomplete_result(stage, category):
    """Describe a failed run without copying URLs, credentials or exceptions."""
    detail = dict(stage=stage, category=category)
    failure = dict(status='INDETERMINATE', errors=['Policy collection or comparison did not complete'],
                   error_details=[detail], missing=[], extra=[])
    return dict(status='INDETERMINATE', error_details=[detail],
                rules_report=dict(failure), objects_report={**failure, 'changed': []})


def compare_policies(csm_client, csm_name, fmc_client, fmc_name):
    """Requires explicit authorization and already authenticated clients."""
    stage = 'csm_policy_read'
    try:
        source = csm_client.policy_rules(csm_name)
        stage = 'fmc_policy_lookup'
        policy_id = fmc_client.policy_uuid_by_name(fmc_name)
        stage = 'fmc_policy_read'
        target = fmc_client.policy_rules(policy_id)
        stage = 'comparison'
        return compare_all(source, target)
    except (APIError, ValidationError, KeyError, TypeError, ValueError) as exc:
        return incomplete_result(stage, 'api_error' if isinstance(exc, APIError) else 'invalid_response')


def save_reports(result, directory):
    """Write separate JSON/text reports. Refuse to overwrite an earlier run."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    paths = [directory / (name + suffix) for name in ('rules_report', 'objects_report') for suffix in ('.json', '.txt')]
    if any(path.exists() for path in paths):
        raise ValidationError('Report files already exist; choose a new output directory')
    for name in ('rules_report', 'objects_report'):
        report = result[name]
        with (directory / (name + '.json')).open('x', encoding='utf-8') as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
        with (directory / (name + '.txt')).open('x', encoding='utf-8') as stream:
            stream.write(format_report(name, report))


def format_report(name, report):
    """Human-readable companion to the machine-readable JSON report."""
    title = 'דוח השוואת חוקים' if name == 'rules_report' else 'דוח השוואת אובייקטים'
    lines = [title, 'תוצאה: ' + report['status'], report.get('scope', '')]
    for key, value in report.get('summary', {}).items():
        lines.append(f'{key}: {value}')
    lines.extend('שגיאה: ' + error for error in report['errors'])
    for detail in report.get('error_details', []):
        lines.append('שלב: ' + detail['stage'] + '; קטגוריה: ' + detail['category'])
    for category, heading in (('missing', 'קיימים ב-CSM וחסרים ב-FMC'),
                              ('extra', 'קיימים ב-FMC וחסרים ב-CSM'),
                              ('changed', 'אובייקטים בעלי ערכים שונים')):
        if category not in report:
            continue
        entries = report[category]
        lines.extend(['', f'{heading}: {len(entries)}'])
        for entry in entries:
            if name == 'rules_report':
                lines.extend([f"  חוק: {entry['rule_number']}",
                              '  Source Objects: ' + ', '.join(entry['sources']),
                              '  Destination Objects: ' + ', '.join(entry['destinations']),
                              '  Destination Services: ' + json.dumps(entry['services'])])
            else:
                lines.extend([f"  {entry['name']} ({entry['kind']})",
                              '  CSM values: ' + json.dumps(entry['source_values'], ensure_ascii=False),
                              '  FMC values: ' + json.dumps(entry['target_values'], ensure_ascii=False),
                              '  CSM rules: ' + json.dumps(entry['source_rules'], ensure_ascii=False),
                              '  FMC rules: ' + json.dumps(entry['target_rules'], ensure_ascii=False)])
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description='Compare offline policies: separate rule and object reports')
    parser.add_argument('source')
    parser.add_argument('target')
    parser.add_argument('--allow-empty', action='store_true')
    parser.add_argument('--output-dir', help='New report directory; reports contain internal infrastructure data')
    args = parser.parse_args()
    try:
        result = compare_all(load_snapshot(args.source), load_snapshot(args.target), args.allow_empty)
        if args.output_dir:
            save_reports(result, args.output_dir)
    except (OSError, ValueError, TypeError, KeyError):
        failure = dict(status='INDETERMINATE', errors=['Invalid snapshot or report output failure'], missing=[], extra=[])
        result = dict(status='INDETERMINATE', rules_report=dict(failure), objects_report={**failure, 'changed': []})
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return {'PASS': 0, 'FAIL': 1, 'INDETERMINATE': 2}[result['status']]


if __name__ == '__main__':
    # Windows redirected output may default to an encoding without Hebrew.
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
    raise SystemExit(main())
