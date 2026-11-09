"""Start here: collect two policies, compare their rules, and write a report."""
from datetime import datetime
from getpass import getpass
from pathlib import Path
import csm
import fmc

# CONFIGURATION: replace example addresses only in your private copy.
CSM_URL = 'https://csm.example.invalid/nbi'
FMC_URL = 'https://fmc.example.invalid'
FMC_DOMAIN = None  # Set a domain UUID if the account has multiple domains.
CSM_VERIFY = True  # Or a path to your trusted CA certificate bundle.
FMC_VERIFY = True
HTTP_TIMEOUT = 30
REPORT_FOLDER = Path('reports')


def find_gaps(source, target):
    """Return source rules with no matching signature in target."""
    target_signatures = {rule.signature() for rule in target}
    return [rule for rule in source if rule.signature() not in target_signatures]


def build_report(source, target):
    """CSM is authoritative. Report drift, never apply or guess rule edits."""
    if not source or not target:
        raise ValueError('Empty policies require manual review')
    source_objects, source_usage = object_inventory(source)
    target_objects, target_usage = object_inventory(target)
    missing = find_gaps(source, target)
    extra = find_gaps(target, source)
    changed = [key for key in source_objects.keys() & target_objects.keys()
               if source_objects[key] != target_objects[key]]
    missing_objects = source_objects.keys() - target_objects.keys()
    extra_objects = target_objects.keys() - source_objects.keys()
    differences = bool(missing or extra or changed or missing_objects or extra_objects)
    lines = ['CSM -> FMC synchronization review (read-only)',
             'CSM is the source of truth; FMC is the comparison target.',
             'Result: ' + ('DRIFT FOUND' if differences else 'MATCH WITHIN COMPARED SCOPE'),
             f'CSM rules: {len(source)}', f'FMC rules: {len(target)}',
             'Compared: src_objects, dst_objects, dst_services and referenced object values.',
             'Not compared: rule order, action, enabled state, source ports, zones or users.',
             '', f'1. CSM rule signatures missing in FMC: {len(missing)}',
             'Review these CSM rules for addition or correction in FMC.']
    lines.extend(str(rule) for rule in missing)
    lines.extend(['', f'2. FMC rule signatures not present in CSM: {len(extra)}',
                  'Review for stale/modified rules. Do not delete automatically.'])
    lines.extend(str(rule) for rule in extra)
    lines.extend(['', f'3. Same-name objects with different values: {len(changed)}'])
    for key in sorted(changed):
        lines.extend([f'{key[0]} object: {key[1]}',
                      f'  Expected (CSM): {source_objects[key]}',
                      f'  Current  (FMC): {target_objects[key]}',
                      f'  CSM affected rules: {sorted(source_usage[key])}',
                      f'  FMC affected rules: {sorted(target_usage[key])}'])
    for title, keys, values, usage in [
            ('4. Referenced only by CSM policy', missing_objects, source_objects, source_usage),
            ('5. Referenced only by FMC policy', extra_objects, target_objects, target_usage)]:
        lines.extend(['', f'{title}: {len(keys)}'])
        for key in sorted(keys):
            lines.append(f'  {key}: values={values[key]}; rules={sorted(usage[key])}')
    lines.extend(['', 'Object inventories cover selected-policy references, not all objects on the server.',
                  'A modified service can appear as one missing and one extra signature; rule IDs differ across systems.',
                  'Duplicate signatures are compared by presence, not count. No rule pairing is guessed.',
                  'No changes were applied. A match does not prove effective traffic equivalence.'])
    return '\n'.join(lines), differences


def object_inventory(rules):
    """Combine per-rule values and retain affected rule IDs for every object."""
    values, usage = {}, {}
    for rule in rules:
        if rule.referenced_objects is None:
            raise ValueError('Object values were not collected; cannot report a match')
        for name in rule.source_objects + rule.destination_objects:
            if not name.startswith('@') and ('network', name) not in rule.referenced_objects:
                raise ValueError('Referenced network object values are missing')
        for key, value in rule.referenced_objects.items():
            if not value:
                raise ValueError('Referenced object values are empty')
            if key in values and values[key] != value:
                raise ValueError('An object name has conflicting values within the policy')
            values[key] = value
            usage.setdefault(key, set()).add(str(rule.rule_number))
    return values, usage


def main():
    csm_client = fmc_client = None
    try:
        csm_policy = input('CSM policy name: ').strip()
        fmc_policy = input('FMC policy name: ').strip()
        if not csm_policy or not fmc_policy:
            raise ValueError('Both policy names are required')
        csm_user = input('CSM username: ').strip()
        csm_client = csm.connect(CSM_URL, csm_user, getpass('CSM password: '), CSM_VERIFY, HTTP_TIMEOUT)
        fmc_user = input('FMC username: ').strip()
        fmc_client = fmc.connect(FMC_URL, fmc_user, getpass('FMC password: '), FMC_DOMAIN, FMC_VERIFY, HTTP_TIMEOUT)
        print('Reading CSM policy...')
        source = csm.policy_rules(csm_client, csm_policy)
        print('Reading FMC policy...')
        target = fmc.policy_rules(fmc_client, fmc_policy)
        report, differences = build_report(source, target)
        REPORT_FOLDER.mkdir(parents=True, exist_ok=True)
        path = REPORT_FOLDER / ('comparison-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f') + '.txt')
        with path.open('x', encoding='utf-8') as output:
            output.write(report + '\n')
        print(report)
        print(f'\nReport saved to: {path}')
        return 1 if differences else 0
    except Exception as error:
        # Do not print raw responses, credentials, or third-party exception text.
        print(f'Comparison stopped ({type(error).__name__}). No successful comparison was reported.')
        if isinstance(error, (ValueError, RuntimeError)) and type(error) in (ValueError, RuntimeError):
            print(error)
        return 2
    finally:
        for name, module, client in [('CSM', csm, csm_client), ('FMC', fmc, fmc_client)]:
            if client is not None:
                try:
                    module.close(client)
                except Exception:
                    print(f'{name}: connection cleanup failed; check server session state.')


if __name__ == '__main__':
    raise SystemExit(main())
