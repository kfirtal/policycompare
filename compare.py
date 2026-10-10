"""Offline comparison; imports never connect to Cisco."""
import argparse
import json
from rule import Rule
from normalization import services, networks
from errors import ValidationError


def signature(rule):
    if rule.issues:
        raise ValidationError('; '.join(rule.issues))
    if rule.action not in ('ALLOW', 'DROP') or not isinstance(rule.enabled, bool):
        raise ValidationError('Invalid action or enabled state')
    def net(values):
        if rule.object_values:
            try:
                return networks(v for name in values for v in rule.object_values[name])
            except KeyError:
                raise ValidationError('Unresolved network reference') from None
        return frozenset(values)
    return (rule.action, rule.enabled, net(rule.source_objects),
            net(rule.destination_objects), services(rule.destination_services))


def find_gaps(csm_list, fmc_list):
    signatures = {signature(r) for r in fmc_list}
    return [r for r in csm_list if signature(r) not in signatures]


def compare_rules(source, target, allow_empty=False):
    source, target = list(source), list(target)
    errors = []
    if not allow_empty and (not source or not target):
        errors.append('Empty policy requires explicit allow_empty')
    for side, rules in [('source', source), ('target', target)]:
        for r in rules:
            try:
                signature(r)
            except ValidationError as exc:
                errors.append(f'{side} rule {r.rule_number}: {exc}')
    if errors:
        return dict(status='INDETERMINATE', errors=errors, missing=[], extra=[], changed_objects=[])
    missing, extra = find_gaps(source, target), find_gaps(target, source)
    changed = []
    def inventory(rules):
        result = {}
        for r in rules:
            for name in set(r.source_objects) | set(r.destination_objects):
                if name in r.object_values:
                    result.setdefault(name, []).append((r.rule_number, networks(r.object_values[name])))
        return result
    a, b = inventory(source), inventory(target)
    for name in sorted(a.keys() & b.keys()):
        if {v for _, v in a[name]} != {v for _, v in b[name]}:
            changed.append(dict(name=name, source_values=sorted(set().union(*(v for _, v in a[name]))),
                                target_values=sorted(set().union(*(v for _, v in b[name]))),
                                source_rules=[i for i, _ in a[name]], target_rules=[i for i, _ in b[name]]))
    def detail(r):
        return dict(rule_number=r.rule_number, action=r.action, enabled=r.enabled,
                    sources=list(r.source_objects), destinations=list(r.destination_objects),
                    services=sorted(services(r.destination_services)))
    return dict(status='FAIL' if missing or extra else 'PASS', errors=[],
                missing=[detail(r) for r in missing], extra=[detail(r) for r in extra], changed_objects=changed)


def main():
    parser = argparse.ArgumentParser(description='Compare offline normalized policy JSON files')
    parser.add_argument('source')
    parser.add_argument('target')
    parser.add_argument('--allow-empty', action='store_true')
    args = parser.parse_args()
    try:
        def read(path):
            with open(path, encoding='utf-8') as f:
                data = json.load(f)
            for item in data:
                item['destination_services'] = [tuple(s) if isinstance(s, list) else s for s in item['destination_services']]
            return [Rule(**item) for item in data]
        report = compare_rules(read(args.source), read(args.target), args.allow_empty)
    except (OSError, ValueError, TypeError, KeyError):
        report = dict(status='INDETERMINATE', errors=['Invalid or unreadable snapshot'])
    print(json.dumps(report, indent=2))
    return {'PASS': 0, 'FAIL': 1, 'INDETERMINATE': 2}[report['status']]


if __name__ == '__main__':
    raise SystemExit(main())
