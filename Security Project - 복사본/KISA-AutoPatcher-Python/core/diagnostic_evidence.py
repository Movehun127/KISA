"""Read-only diagnostics shown in a dedicated, paginated evidence window."""
import base64
import ctypes
import json
import re
import socket
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from .execution import run_ps, run_checked

def command(args, timeout=20):
    started = datetime.now(timezone.utc).isoformat()
    try:
        r = subprocess.run(args, capture_output=True, timeout=timeout,
                           creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        encoding = 'cp' + str(ctypes.windll.kernel32.GetOEMCP())
        return {'Command': subprocess.list2cmdline(args), 'At': started,
                'ExitCode': r.returncode, 'Output': r.stdout.decode(encoding, errors='replace'),
                'Error': r.stderr.decode(encoding, errors='replace')}
    except subprocess.TimeoutExpired:
        return {'Command': subprocess.list2cmdline(args), 'At': started,
                'ExitCode': None, 'Output': '', 'Error': '명령 실행 시간 초과'}

def collect_ntp():
    queries = {key: command(['w32tm.exe', '/query', flag])
               for key, flag in [('source','/source'),('status','/status'),('peers','/peers'),('configuration','/configuration')]}
    source = queries['source']['Output'].strip()
    result = {'Queries':queries, 'SyncCompliance':'미판정: 최근 성공 시각과 동기화 상태를 원문으로 확인',
              'KerberosTolerance':'별도 기준: NTP 응답만으로 Kerberos 허용 오차 적합 판정 불가'}
    # Probe only the actual time source; never substitute a public server.
    if queries['source']['ExitCode'] == 0 and re.fullmatch(r'[A-Za-z0-9_.:%-]+', source):
        probe = command(['w32tm.exe','/stripchart', '/computer:'+source, '/dataonly','/samples:3','/period:1'], 15)
        offsets = re.findall(r'([+-]\d+[.,]\d+)s\b', probe['Output'])
        result.update(Probe=probe, OffsetSeconds=[float(v.replace(',','.')) for v in offsets],
                      NtpResponseObserved=probe['ExitCode']==0 and bool(offsets))
    else:
        result.update(NtpResponseObserved=False, ProbeNote='네트워크 NTP 원본 미확인: 로컬 시계·가상화 공급자·조회 실패 여부 확인')
    return result

def collect(kind):
    if kind == 'ntp':
        data = collect_ntp()
    elif kind == 'audit':
        from . import audit_policy
        from .detector import reg_read
        rows = audit_policy.read()
        data = {'EffectiveAuditPolicies': [
            dict(Subcategory=key, Category=audit_policy.CATEGORIES[row['category']][0],
                 Success=bool(row['flags'] & 1), Failure=bool(row['flags'] & 2))
            for key,row in rows.items()],
            'AdvancedOverride':reg_read(audit_policy.OVERRIDE_PATH,audit_policy.OVERRIDE_NAME),
            'CommandOutput':command(['auditpol.exe','/get','/category:*','/r'])}
    elif kind == 'remote_shutdown':
        with tempfile.TemporaryDirectory(prefix='kisa_rights_') as folder:
            path = Path(folder)/'rights.inf'
            run_checked(['secedit','/export','/cfg',str(path),'/areas','USER_RIGHTS','/quiet'])
            raw = path.read_text(encoding='utf-16')
        lines = [line for line in raw.splitlines() if line.strip().startswith('SeRemoteShutdownPrivilege ')]
        if len(lines) != 1:
            raise RuntimeError('SeRemoteShutdownPrivilege 값을 확인하지 못했습니다.')
        value = lines[0].split('=',1)[1].strip()
        data = {'Policy':'원격 시스템에서 강제로 시스템 종료',
                'ExportCommand':'secedit /export /areas USER_RIGHTS',
                'RawValue':value, 'Expected':'*S-1-5-32-544 (Administrators)',
                'AdministratorsOnly':value == '*S-1-5-32-544'}
    else:
        raise ValueError('Unknown diagnostic collector')
    return {'Host':socket.gethostname(), 'CollectedAt':datetime.now(timezone.utc).isoformat(),
            'EvidenceType':'실제 조회 결과 표시 (Windows 설정 대화상자가 아님)', 'Data':data}

def pages(data, limit=24, width=80):
    import textwrap
    def lines_of(value, prefix=''):
        if isinstance(value, dict):
            for key, child in value.items():
                if isinstance(child, (dict,list)):
                    yield prefix + str(key) + ':'
                    yield from lines_of(child, prefix+'  ')
                else:
                    yield prefix + str(key) + ': ' + str(child)
        elif isinstance(value,list):
            for child in value:
                if isinstance(child,dict) and all(not isinstance(v,(dict,list)) for v in child.values()):
                    yield prefix + '; '.join(str(k)+'='+str(v) for k,v in child.items())
                else:
                    yield from lines_of(child,prefix)
        else:
            yield prefix + str(value)
    lines = []
    for block in lines_of(data):
        for line in block.splitlines():
            lines.extend(textwrap.wrap(line, width=width, replace_whitespace=False, drop_whitespace=False) or [''])
    return ['\r\n'.join(lines[i:i+limit]) for i in range(0,len(lines),limit)]

def launch_viewer(title, path):
    def b64(text):
        return base64.b64encode(text.encode('utf-8')).decode('ascii')
    # Only encoded literals enter the script; no source text is interpreted as PowerShell.
    script = """
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
function Decode($s) { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)) }
$f = New-Object Windows.Forms.Form
$f.Text = Decode('TITLE')
$f.Width=900; $f.Height=1000
$t = New-Object Windows.Forms.TextBox
$t.Name='EvidenceText'; $t.Multiline=$true; $t.ReadOnly=$true
$t.Dock='Fill'; $t.ScrollBars='Both'; $t.WordWrap=$false
$t.Font=New-Object Drawing.Font('Consolas',10)
$f.Controls.Add($t)
$p=Decode('PATH')
$timer=New-Object Windows.Forms.Timer
$timer.Interval=150
$timer.Add_Tick({ try { $v=[IO.File]::ReadAllText($p,[Text.Encoding]::UTF8); if($v -ne $t.Text){$t.Text=$v} } catch {} })
$timer.Start()
[Windows.Forms.Application]::Run($f)
$timer.Dispose()
"""
    script = script.replace('TITLE',b64(title)).replace('PATH',b64(str(path)))
    return subprocess.Popen(['powershell.exe','-NoProfile','-STA','-EncodedCommand',
                             base64.b64encode(script.encode('utf-16-le')).decode('ascii')],
                            creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))

def capture(item, folder, log, wait, stop, action, stage):
    from . import capturer as cap
    from .window_session import WindowSession, prepare_window
    iid = item['ItemId']
    folder = Path(folder)
    title = 'KISA Evidence ' + iid + ' ' + str(time.time_ns())
    display = folder/(iid+'_display.txt')
    display.write_text('증빙 조회 준비 중', encoding='utf-8')
    session = WindowSession(cap.auto,cap.user32,log)
    proc = None
    try:
        stage('창 열기')
        proc = launch_viewer(title,display)
        root = cap._wait_app(session,'kisa-evidence',{'ViewerTitle':title},proc,stop)
        prepare_window(root,cap.user32,cap.pyautogui.size())
        stage('오른쪽 정렬 확인')
        cap._check_stop(stop)
        if action:
            stage('조치 및 설정 재조회')
            action()
        cap._check_stop(stop)
        data = collect(item['EvidenceCollector'])
        (folder/(iid+'_diagnostic.json')).write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
        content = pages(data)
        for number, page in enumerate(content,1):
            cap._check_stop(stop)
            text = f'{iid} 실제 조회 결과 / {number}/{len(content)}\r\n'+page
            display.write_text(text,encoding='utf-8')
            deadline = time.monotonic()+5
            while True:
                edit = root.EditControl(searchDepth=3)
                if edit.Exists(0.1) and edit.GetValuePattern().Value.replace('\r','') == text.replace('\r',''):
                    break
                if time.monotonic()>deadline:
                    raise RuntimeError('증빙 조회 결과의 화면 표시를 확인하지 못했습니다.')
                cap._check_stop(stop)
                time.sleep(.15)
            if wait and not wait():
                raise cap.CaptureCancelled('User Cancelled Execution')
            cap._take_screenshot(str(folder/f'{iid}_part{number}.png'),root)
        import shutil
        shutil.copy2(folder/f'{iid}_part1.png',folder/f'{iid}.png')
        stage('캡처 저장')
        return str(folder/f'{iid}.png')
    finally:
        # This process is exclusively our read-only viewer.
        if proc:
            try:
                session.close()
            finally:
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    proc.wait(timeout=3)
        display.unlink(missing_ok=True)
        stage('창 닫힘 확인')
