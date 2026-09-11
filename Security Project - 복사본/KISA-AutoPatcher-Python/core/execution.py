"""Checked Windows execution and pure policy comparisons."""
import os
import subprocess
import tempfile
from pathlib import Path


def matches(actual, desired, comparison='eq'):
    if comparison == 'file_exists':
        return isinstance(actual, str) and os.path.isfile(os.path.expandvars(actual))
    if comparison == 'nonempty':
        return bool(str(actual).strip()) if actual is not None else False
    if comparison == 'eq':
        return str(actual) == str(desired)
    value, target = int(actual), int(desired)
    if comparison == 'ge':
        return value >= target
    if comparison == 'positive_le':
        return 0 < value <= target
    if comparison == 'rdp_encryption':
        return value in (2, 3, 4)
    if comparison == 'ntlmv2':
        return value in (3, 4, 5)
    raise ValueError(f'Unknown comparison: {comparison}')


def registry_settings(item):
    settings = [dict(s) for s in item.get('RegistryValues', [])]
    if not settings or len({s['RegistryName'] for s in settings}) != len(settings):
        raise ValueError('Registry setting group is empty or contains duplicate names')
    for setting in settings:
        if setting.get('ExpandEnvironment'):
            setting['SecureValue'] = os.path.expandvars(setting['SecureValue'])
    return settings


def run_checked(args, timeout=60):
    result = subprocess.run(args, capture_output=True, timeout=timeout,
                            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if result.returncode:
        detail = (result.stderr or result.stdout or b'')
        if isinstance(detail, bytes):
            detail = detail.decode('utf-8', errors='replace')
        raise RuntimeError(f'{args[0]} failed ({result.returncode}): {detail[:1500]}')
    return result


def run_ps(command):
    if not command or not command.strip():
        raise ValueError('Empty PowerShell command')
    import base64
    script = "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); " + command
    encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
    result = run_checked(['powershell.exe', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded])
    return result.stdout.decode('utf-8-sig', errors='strict').strip()


def export_security_policy():
    with tempfile.TemporaryDirectory(prefix='kisa_scan_') as folder:
        path = Path(folder)/'security.inf'
        run_checked(['secedit', '/export', '/cfg', str(path), '/areas', 'SECURITYPOLICY', '/quiet'])
        text = path.read_text(encoding='utf-16')
        values = {}
        section = ''
        for line in text.splitlines():
            line = line.strip()
            if line.startswith('['):
                section = line
            elif section == '[System Access]' and '=' in line:
                key, value = line.split('=', 1)
                values[key.strip()] = value.strip()
        if not values:
            raise RuntimeError('Security export contains no System Access values')
        return values


def apply_security_policy(values):
    # Only the requested settings are imported. Never replay a whole security export.
    allowed = {'LockoutBadCount', 'LockoutDuration', 'ResetLockoutCount', 'ClearTextPassword',
               'PasswordComplexity', 'MinimumPasswordLength', 'MaximumPasswordAge',
               'MinimumPasswordAge', 'PasswordHistorySize', 'EnableGuestAccount',
               'LSAAnonymousNameLookup'}
    if not values or not set(values) <= allowed:
        raise ValueError('Unsupported security policy keys')
    for key in ('EnableGuestAccount', 'LSAAnonymousNameLookup'):
        if key in values and int(values[key]) not in (0, 1):
            raise ValueError('Boolean security policy requires 0 or 1')
    lines = ['[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"',
             'Revision=1', '[System Access]']
    lines.extend(f'{k} = {int(v)}' for k, v in values.items())
    with tempfile.TemporaryDirectory(prefix='kisa_apply_') as folder:
        path = Path(folder)/'apply.inf'
        path.write_text('\r\n'.join(lines)+'\r\n', encoding='utf-16')
        run_checked(['secedit', '/configure', '/db', str(Path(folder)/'apply.sdb'),
                     '/cfg', str(path), '/overwrite', '/areas', 'SECURITYPOLICY', '/quiet'])
