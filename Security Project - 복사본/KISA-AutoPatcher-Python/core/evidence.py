"""Fresh readback and per-run evidence, independent of UI capture success."""
import hashlib
import json
import os
import socket
import getpass
import uuid
from datetime import datetime, timezone
from pathlib import Path


def create_run(root):
    folder = Path(root) / (datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    folder.mkdir(parents=True, exist_ok=False)
    return folder


def save_record(folder, initial, final, screenshot=None, error=None):
    policy = initial['ConfigItem']
    data = {
        'ItemId': initial['ItemId'], 'Host': socket.gethostname(),
        'ExecutionUser': getpass.getuser(), 'Scope': policy.get('ScopeNote', '항목 정책에 정의된 범위'),
        'CollectedAt': datetime.now(timezone.utc).isoformat(),
        'PolicySHA256': hashlib.sha256(json.dumps(policy, sort_keys=True, ensure_ascii=False).encode()).hexdigest(),
        'Policy': policy, 'BeforeStatus': initial['Status'],
        'BeforeValue': initial.get('CurrentValue'), 'AfterStatus': final['Status'],
        'AfterValue': final.get('CurrentValue'), 'FixStatus': initial.get('FixStatus'),
        'BackupFile': initial.get('BackupFile'), 'RollbackStatus': initial.get('RollbackStatus'),
        'Note': initial.get('Note'),
        'ExecutionStages': initial.get('ExecutionStages', []),
        'ScreenshotIsComplianceProof': False,
    }
    data['ScreenshotStatus'] = '실패' if error else '미수집'
    if error and not screenshot:
        candidate = Path(folder) / (initial['ItemId'] + '.png')
        if candidate.is_file():
            screenshot = candidate  # Capture may have succeeded before cleanup failed.
    if screenshot:
        path = Path(screenshot).resolve()
        if path.parent != Path(folder).resolve():
            raise ValueError('Screenshot must belong to current run')
        data.update(Screenshot=path.name, ScreenshotStatus='실패(이미지 저장됨)' if error else '저장됨(내용 검토 필요)',
                    ScreenshotSHA256=hashlib.sha256(path.read_bytes()).hexdigest())
    if error:
        data['CaptureError'] = str(error)
    # Keep component images, including partial evidence when a later capture failed.
    data['ScreenshotFiles'] = []
    for path in sorted(Path(folder).glob(initial['ItemId'] + '_part*.png')):
        data['ScreenshotFiles'].append({'File': path.name, 'SHA256': hashlib.sha256(path.read_bytes()).hexdigest()})
    dest = Path(folder) / (initial['ItemId'] + '.json')
    with dest.open('x', encoding='utf-8') as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2, default=str)
        stream.flush()
        os.fsync(stream.fileno())
    return dest
