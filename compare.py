"""Offline comparison; imports never connect to Cisco."""
import argparse
import json
from snapshots import load_snapshot
from normalization import services, networks
from errors import ValidationError, APIError


def signature(rule):
    """Return an order-independent key, only after validating the rule."""
    if rule.issues:
        raise ValidationError('; '.join(rule.issues))
    if rule.action not in ('ALLOW', 'DROP') or not isinstance(rule.enabled, bool):
        raise ValidationError('Invalid action or enabled state')
    for values in (rule.source_objects, rule.destination_objects, rule.destination_services):
        if not isinstance(values, (list, tuple, set, frozenset)) or any(v is None for v in values):
            raise ValidationError('Invalid rule field')
    if not isinstance(rule.object_values, dict):
        raise ValidationError('Resolved objects must be a mapping')
    for name, values in rule.object_values.items():
        if not isinstance(name, str) or not name:
            raise ValidationError('Invalid resolved object name')
        if not isinstance(values, (list, tuple, set, frozenset)) or not values:
            raise ValidationError('Resolved object must contain a collection of network values')
        if any(not isinstance(value, str) or not value.strip() for value in values):
            raise ValidationError('Invalid resolved network value')
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


def report_context(source, target):
    """Expose counts and comparison limits without claiming full equivalence."""
    warnings = ['Comparison covers supported access-rule fields; rule order is ignored.']
    if any(not rule.object_values for rule in source + target):
        warnings.append('Some rules compare network names only; object values are not verified for those rules.')
    if any(isinstance(value, str) for rule in source + target for value in
           (rule.destination_services if isinstance(rule.destination_services, (list, tuple, set, frozenset)) else [])):
        warnings.append('Some services have no protocol; TCP/UDP identity is not verified for those services.')
    return dict(summary={'source_rules': len(source), 'target_rules': len(target)}, warnings=warnings)


def compare_rules(source, target, allow_empty=False):
    """Report both directions; invalid input always prevents a PASS."""
    source, target = list(source), list(target)
    errors = []
    if not allow_empty and (not source or not target):
        errors.append('Empty policy requires explicit allow_empty')
    for side, rules in [('source', source), ('target', target)]:
        for r in rules:
            try:
                signature(r)
            except (ValidationError, TypeError, ValueError) as exc:
                errors.append(f'{side} rule {r.rule_number}: {exc}')
    if errors:
        return dict(status='INDETERMINATE', errors=errors, missing=[], extra=[], changed_objects=[],
                    **report_context(source, target))
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
                    services=sorted(services(r.destination_services)),
                    resolved_sources=sorted(signature(r)[2]) if r.object_values else None,
                    resolved_destinations=sorted(signature(r)[3]) if r.object_values else None)
    return dict(status='FAIL' if missing or extra else 'PASS', errors=[],
                missing=[detail(r) for r in missing], extra=[detail(r) for r in extra], changed_objects=changed,
                **report_context(source, target))


def compare_policies(csm_client, csm_name, fmc_client, fmc_name):
    """Use only with explicitly authorized, already authenticated clients."""
    stage = 'csm_policy_read'
    try:
        source = csm_client.policy_rules(csm_name)
        stage = 'fmc_policy_lookup'
        policy_id = fmc_client.policy_uuid_by_name(fmc_name)
        stage = 'fmc_policy_read'
        target = fmc_client.policy_rules(policy_id)
        stage = 'comparison'
        return compare_rules(source, target)
    except (APIError, ValidationError, KeyError, TypeError, ValueError) as exc:
        # Do not copy exception text: an adapter or HTTP library may include
        # response bodies, URLs or credentials. Stage/category are safe context.
        category = 'api_error' if isinstance(exc, APIError) else 'invalid_response'
        return dict(status='INDETERMINATE', errors=['Policy retrieval or parsing failed'],
                    error_details=[dict(stage=stage, category=category)],
                    missing=[], extra=[], changed_objects=[])


def main():
    parser = argparse.ArgumentParser(description='Compare offline normalized policy JSON files')
    parser.add_argument('source')
    parser.add_argument('target')
    parser.add_argument('--allow-empty', action='store_true')
    args = parser.parse_args()
    try:
        source = load_snapshot(args.source)
        target = load_snapshot(args.target)
        report = compare_rules(source, target, args.allow_empty)
    except (OSError, ValueError, TypeError, KeyError):
        report = dict(status='INDETERMINATE', errors=['Invalid or unreadable snapshot'])
    print(json.dumps(report, indent=2))
    return {'PASS': 0, 'FAIL': 1, 'INDETERMINATE': 2}[report['status']]


if __name__ == '__main__':
    raise SystemExit(main())
