"""Backed-up, verified remediation. Unsupported mutations require manual work."""
import base64
import ctypes
import json
import os
import re
import threading
import uuid
import winreg
from pathlib import Path
from .detector import _parse_reg_path, get_vulnerability_status
from .execution import run_ps, export_security_policy, apply_security_policy, matches

_LOCK = threading.Lock()
_TYPES = {'DWord': winreg.REG_DWORD, 'String': winreg.REG_SZ}


def _snapshot(path, name):
    hive, subkey = _parse_reg_path(path)
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            value, typ = winreg.QueryValueEx(key, name)
        return {'exists': True, 'value': value, 'type': typ}
    except FileNotFoundError:
        return {'exists': False}


def reg_read(path, name):
    return _snapshot(path, name).get('value')


def reg_write(path, name, value, reg_type='DWord'):
    typ = _TYPES[reg_type] if isinstance(reg_type, str) else reg_type
    if typ in (winreg.REG_DWORD, winreg.REG_QWORD):
        value = int(value)
    hive, subkey = _parse_reg_path(path)
    with winreg.CreateKeyEx(hive, subkey, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as key:
        winreg.SetValueEx(key, name, 0, typ, value)


def _restore_registry(path, name, old):
    if old['exists']:
        reg_write(path, name, old['value'], old['type'])
    else:
        hive, subkey = _parse_reg_path(path)
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as key:
                winreg.DeleteValue(key, name)
        except FileNotFoundError:
            pass
    if _snapshot(path, name) != old:
        raise RuntimeError('Registry rollback verification failed')


def _encode(value):
    if isinstance(value, bytes):
        return {'__bytes__': base64.b64encode(value).decode('ascii')}
    raise TypeError(type(value).__name__)


def _decode(value):
    if set(value) == {'__bytes__'}:
        return base64.b64decode(value['__bytes__'])
    return value


def restore_backup(filename):
    """Explicit administrator recovery of one saved setting; never auto-load arbitrary files."""
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise PermissionError('Administrator required')
    data = json.loads(Path(filename).read_text(encoding='utf-8'), object_hook=_decode)
    if data['kind'] == 'registry':
        _restore_registry(data['path'], data['name'], data['before'])
    elif data['kind'] == 'secedit':
        apply_security_policy(data['before'])
        current = export_security_policy()
        if any(str(current.get(k)) != str(v) for k, v in data['before'].items()):
            raise RuntimeError('Security policy rollback verification failed')
    else:
        raise ValueError('Unknown backup kind')


def invoke_remediation(vulnerability_results, backup_dir, evidence_dir='', log_callback=None,
                       approved_items=None):
    approved = set(approved_items or [])
    def log(msg, level='info'):
        if log_callback:
            log_callback(msg, level)
    if not _LOCK.acquire(blocking=False):
        for result in vulnerability_results:
            result['FixStatus'] = '실패'
            result['Note'] = '다른 조치가 실행 중입니다'
        return vulnerability_results
    try:
        for result in vulnerability_results:
            item = result.get('ConfigItem', {})
            iid = result.get('ItemId', '')
            kind = item.get('TechType')
            result['FixStatus'] = '건너뜀'
            if result.get('Status') != '취약':
                continue
            if kind not in ('Type_Registry', 'Type_Secedit'):
                result.update(FixStatus='수동 조치 필요', Note='안전한 백업·복원 구현이 없는 조치는 자동 실행하지 않습니다')
                log(f'[{iid}] {result["Note"]}', 'warn')
                continue
            if item.get('RequiresConfirmation') and iid not in approved:
                result.update(FixStatus='승인 필요', Note=item.get('Impact', '운영 영향 검토 필요'))
                continue
            backup = None
            attempted = False
            try:
                if not re.fullmatch(r'W-\d{2}(?:_[A-Za-z]+)?', iid):
                    raise ValueError('Invalid item id')
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    raise PermissionError('관리자 권한이 필요합니다')
                # Local writes cannot demonstrate domain resultant policy compliance.
                role = json.loads(run_ps('Get-CimInstance Win32_ComputerSystem | Select-Object PartOfDomain,DomainRole | ConvertTo-Json -Compress'))
                if role.get('PartOfDomain') is not False or int(role['DomainRole']) >= 4:
                    result.update(FixStatus='수동 조치 필요', Note='도메인/GPO 관리 장비는 중앙 정책과 유효 정책 확인 후 적용하세요')
                    continue
                Path(backup_dir).mkdir(parents=True, exist_ok=True)
                backup = Path(backup_dir)/f'{iid}_{uuid.uuid4().hex}.json'
                if kind == 'Type_Registry':
                    path, name = item['RegistryPath'], item['RegistryName']
                    old = _snapshot(path, name)
                    data = {'kind': 'registry', 'path': path, 'name': name, 'before': old}
                else:
                    wanted = item.get('SeceditValues', {item.get('SeceditKey'): item.get('SecureValue')})
                    current = export_security_policy()
                    if any(k not in current for k in wanted):
                        raise RuntimeError('변경 전 정책 값을 확인할 수 없어 조치를 중단합니다')
                    old = {k: current[k] for k in wanted}
                    # Preserve stronger existing settings in a compound policy.
                    wanted = {k: (current[k] if matches(current[k], v, item.get('Comparisons', {}).get(k, 'eq')) else v)
                              for k, v in wanted.items()}
                    if 'LockoutDuration' in wanted:
                        wanted['LockoutDuration'] = max(int(wanted['LockoutDuration']), int(wanted['ResetLockoutCount']))
                    data = {'kind': 'secedit', 'before': old}
                with backup.open('x', encoding='utf-8') as stream:
                    json.dump(data, stream, ensure_ascii=False, default=_encode)
                    stream.flush()
                    os.fsync(stream.fileno())
                result['BackupFile'] = str(backup)
                attempted = True
                if kind == 'Type_Registry':
                    reg_write(path, name, item['SecureValue'], item.get('RegistryType', 'DWord'))
                    after = _snapshot(path, name)
                    if not after['exists'] or not matches(after['value'], item['SecureValue'], item.get('Comparison', 'eq')):
                        raise RuntimeError('조치 후 레지스트리 검증 실패')
                else:
                    apply_security_policy(wanted)
                    after = export_security_policy()
                    if any(str(after.get(k)) != str(v) for k, v in wanted.items()):
                        raise RuntimeError('조치 후 보안 정책 검증 실패')
                result.update(FixStatus='완료', AfterValue=after, Note='변경값 재조회 검증 완료. 업무 기능 검증은 별도 필요')
                log(f'[{iid}] 설정 검증 완료 / 백업: {backup}', 'good')
            except Exception as exc:
                result.update(FixStatus='실패', Note=str(exc))
                log(f'[{iid}] 조치 실패: {exc}', 'error')
                if attempted and backup:
                    try:
                        restore_backup(backup)
                        result['RollbackStatus'] = '성공'
                    except Exception as rollback_error:
                        result['RollbackStatus'] = '실패'
                        result['Note'] += f'; 복원 실패: {rollback_error}'
                        log(result['Note'], 'error')
    finally:
        _LOCK.release()
    return vulnerability_results
