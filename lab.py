"""Explicit lab entry point. Default mode validates settings without any HTTP."""
import argparse
from datetime import datetime, timezone
import getpass
import json
import math
import sys
from pathlib import Path
from urllib.parse import urlsplit
import warnings

from compare import compare_all, incomplete_result, save_reports
from csm import CSMClient
from errors import APIError, ValidationError
from fmc import FMCClient
from snapshots import save_snapshot


def parser():
    result = argparse.ArgumentParser(description='Prepare or explicitly run a read-only CSM/FMC lab comparison')
    result.add_argument('--csm-url', required=True, help='HTTPS URL ending in /nbi')
    result.add_argument('--fmc-url', required=True, help='HTTPS server origin, without an API path')
    result.add_argument('--csm-policy', required=True, help='Exact shared policy name')
    result.add_argument('--fmc-policy', required=True, help='Exact access policy name')
    result.add_argument('--fmc-version', required=True, help='Declared lab version; not detected automatically')
    result.add_argument('--fmc-domain', help='Explicit domain UUID when the account has multiple domains')
    result.add_argument('--csm-ca', help='PEM CA bundle; system trust is used if omitted')
    result.add_argument('--fmc-ca', help='PEM CA bundle; system trust is used if omitted')
    result.add_argument('--timeout', type=float, default=30, help='Positive timeout per HTTP request, seconds')
    result.add_argument('--output-dir', required=True, type=Path, help='New directory under reports/')
    result.add_argument('--allow-empty', action='store_true')
    result.add_argument('--connect', action='store_true', help='Explicitly authorize this invocation to contact lab servers')
    return result


def validate_settings(args):
    """No network, client construction, prompts or file writes in this step."""
    for url, expected_path in ((args.csm_url, '/nbi'), (args.fmc_url, '')):
        parts = urlsplit(url)
        if (parts.scheme != 'https' or not parts.hostname or parts.username is not None
                or parts.password is not None or parts.query or parts.fragment
                or parts.path.rstrip('/') != expected_path):
            raise ValidationError('Expected HTTPS CSM /nbi and FMC server origin, without embedded credentials')
        try:
            parts.port
        except ValueError:
            raise ValidationError('Invalid server port') from None
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        raise ValidationError('Timeout must be finite and positive')
    for value in (args.csm_policy, args.fmc_policy, args.fmc_version):
        if not value.strip() or value != value.strip():
            raise ValidationError('Policy names and version must be nonempty without surrounding whitespace')
    if args.fmc_domain is not None and (not args.fmc_domain.strip() or args.fmc_domain != args.fmc_domain.strip()):
        raise ValidationError('Invalid domain identifier')
    for bundle in (args.csm_ca, args.fmc_ca):
        if bundle is not None and not Path(bundle).is_file():
            raise ValidationError('CA bundle must be an existing file')
    # Keep real policy snapshots and reports under the Git-ignored data tree.
    root = (Path(__file__).resolve().parent / 'reports').resolve()
    output = args.output_dir.resolve()
    if output == root or not output.is_relative_to(root):
        raise ValidationError('Choose a new run directory inside this project reports/ directory')
    if output.exists():
        raise ValidationError('Output directory already exists; choose a new run directory')
    args.output_dir = output


def login_interactively(client, label):
    """Refuse getpass fallback that would echo a password to the terminal."""
    username = input(label + ' username: ').strip()
    if not username:
        raise ValidationError('A username is required')
    with warnings.catch_warnings():
        warnings.simplefilter('error', getpass.GetPassWarning)
        password = getpass.getpass(label + ' password: ')
    if not password:
        raise ValidationError('A password is required')
    try:
        client.login(username, password)
    finally:
        # Drop local references. Python does not guarantee memory zeroization.
        password = None


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def error_category(error):
    if isinstance(error, APIError):
        return 'api_error'
    if isinstance(error, getpass.GetPassWarning):
        return 'credentials_unavailable'
    if isinstance(error, (ValidationError, ValueError, TypeError, KeyError)):
        return 'invalid_data'
    if isinstance(error, OSError):
        return 'output_error'
    return 'internal_error'


def run_lab(args):
    """Collect once, persist normalized inputs, compare and always clean up."""
    validate_settings(args)
    if not args.connect:
        raise ValidationError('Live collection requires explicit --connect')
    args.output_dir.mkdir(parents=True, exist_ok=False)
    clients, completed, cleanup_errors = [], [], []
    started, stage = utc_now(), 'client_setup'
    try:
        csm = CSMClient(args.csm_url, verify=args.csm_ca or True, timeout=args.timeout)
        clients.append(('csm_cleanup', csm))
        fmc = FMCClient(args.fmc_url, domain=args.fmc_domain,
                        verify=args.fmc_ca or True, timeout=args.timeout)
        clients.append(('fmc_cleanup', fmc))
        stage = 'csm_login'
        login_interactively(csm, 'CSM')
        stage = 'csm_policy_read'
        source = csm.policy_rules(args.csm_policy)
        stage = 'csm_snapshot_write'
        save_snapshot(source, args.output_dir / 'csm.snapshot.json')
        completed.append('csm')
        stage = 'fmc_login'
        login_interactively(fmc, 'FMC')
        stage = 'fmc_policy_lookup'
        policy_id = fmc.policy_uuid_by_name(args.fmc_policy)
        stage = 'fmc_policy_read'
        target = fmc.policy_rules(policy_id)
        stage = 'fmc_snapshot_write'
        save_snapshot(target, args.output_dir / 'fmc.snapshot.json')
        completed.append('fmc')
        stage = 'comparison'
        result = compare_all(source, target, args.allow_empty)
    except (KeyboardInterrupt, EOFError):
        result = incomplete_result(stage, 'interrupted')
    except Exception as error:
        # CLI boundary: never print raw HTTP/parser/OS exceptions with internal data.
        result = incomplete_result(stage, error_category(error))
    finally:
        for label, client in reversed(clients):
            try:
                client.close()
            except (Exception, KeyboardInterrupt):
                cleanup_errors.append(label)
    # Keep completed comparisons intact even if a logout failed. The overall
    # run remains indeterminate; cleanup failures are recorded separately.
    if cleanup_errors:
        result['status'] = 'INDETERMINATE'
    manifest = dict(status=result['status'], started_utc=started, finished_utc=utc_now(),
                    declared_versions={'csm': '4.25', 'fmc': args.fmc_version},
                    completed_snapshots=completed, cleanup_errors=cleanup_errors,
                    rules_status=result['rules_report']['status'],
                    objects_status=result['objects_report']['status'],
                    error_details=result.get('error_details', []))
    save_reports(result, args.output_dir)
    with (args.output_dir / 'run.json').open('x', encoding='utf-8') as stream:
        json.dump(manifest, stream, ensure_ascii=False, indent=2)
    result['run'] = manifest
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        validate_settings(args)
        if not args.connect:
            print('בדיקת הגדרות מקומית הושלמה. לא בוצעו חיבורים או בדיקת זמינות שרתים.')
            return 0
        result = run_lab(args)
    except (Exception, KeyboardInterrupt):
        print('INDETERMINATE: בדוק הגדרות, תעודות והרשאות כתיבה. ההרצה לא הושלמה.')
        return 2
    print('Run: ' + result['status'] + '; rules: ' + result['rules_report']['status']
          + '; objects: ' + result['objects_report']['status'])
    return {'PASS': 0, 'FAIL': 1, 'INDETERMINATE': 2}[result['status']]


if __name__ == '__main__':
    # Keep Hebrew output readable in both the terminal and redirected files.
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
    raise SystemExit(main())
