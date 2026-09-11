"""Scoped UI evidence: validate window, foreground, bounds, then close owned windows."""
import ctypes
import os
import re
import subprocess
import time
from pathlib import Path, PureWindowsPath
from datetime import datetime, timezone
from ctypes import wintypes
from .window_session import WindowSession, prepare_window, target_matches, CaptureCancelled, WindowCleanupError
try:
    import uiautomation as auto
except ImportError:
    auto = None
try:
    import pyautogui
except (ImportError, KeyError, OSError):
    pyautogui = None

user32 = ctypes.windll.user32 if os.name == 'nt' else None
if user32:
    user32.GetForegroundWindow.restype = wintypes.HWND
    user32.SetForegroundWindow.argtypes = [wintypes.HWND]
    user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    user32.SetWindowPos.argtypes = [wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.UINT]
    user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    user32.IsWindow.argtypes = [wintypes.HWND]
    user32.GetWindow.argtypes = [wintypes.HWND, wintypes.UINT]
    user32.GetWindow.restype = wintypes.HWND

APP_TITLES = {
    'ncpa.cpl': ['네트워크 연결', 'Network Connections'],
    'timedate.cpl': ['날짜 및 시간', 'Date and Time'],
    'firewall.cpl': ['Windows Defender 방화벽', 'Windows 방화벽', 'Windows Defender Firewall', 'Windows Firewall'],
    'winver': ['Windows 정보', 'About Windows'],
    'taskmgr': ['작업 관리자', 'Task Manager'],
    'odbcad32.exe': ['ODBC 데이터 원본 관리자', 'ODBC Data Source Administrator'],
    'control desk.cpl,screensaver,@screensaver': ['화면 보호기 설정', 'Screen Saver Settings'],
}

def _check_stop(stop):
    if stop and stop():
        raise CaptureCancelled('User Cancelled Execution')

def _spawn_app(app):
    if app.endswith('.msc'):
        return subprocess.Popen(['mmc.exe', app])
    if app.startswith('control '):
        return subprocess.Popen(['control.exe', app.split(' ', 1)[1]])
    if app.endswith('.cpl'):
        return subprocess.Popen(['control.exe', app])
    if app.startswith(('ms-settings:', 'windowsdefender:')):
        os.startfile(app)
        return None
    if not app:
        raise ValueError('증빙 앱이 지정되지 않았습니다.')
    return subprocess.Popen([app])

def _app_matches(window, app, item, pid=None):
    title, cls = window.Name or '', window.ClassName or ''
    if app.endswith('.msc'):
        return cls == 'MMCMainFrame' and pid is not None and window.ProcessId == pid
    if app == 'regedit':
        return cls == 'RegEdit_RegEdit'
    if app == 'explorer.exe' and item.get('targetItem'):
        return cls == '#32770' and target_matches(title, PureWindowsPath(item['targetItem'][0]).name)
    if app.startswith('ms-settings:'):
        return title in ('설정', 'Settings')
    if app.startswith('windowsdefender:'):
        return title in ('Windows 보안', 'Windows Security')
    return any(target_matches(title, a) or title.startswith(a + ' (') for a in APP_TITLES.get(app, []))

def _wait_app(session, app, item, proc, stop):
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        _check_stop(stop)
        candidates = [w for h, w in session.snapshot().items()
                      if h not in session.before and _app_matches(w, app, item, getattr(proc, 'pid', None))]
        if len(candidates) == 1:
            session.track(candidates[0])
            return candidates[0]
        if len(candidates) > 1:
            if proc and app.endswith('.msc'):
                for w in candidates:
                    session.track(w)
            raise RuntimeError('대상 창이 여러 개여서 선택할 수 없습니다.')
        time.sleep(0.15)
    raise WindowCleanupError('새 대상 창을 찾지 못해 진행을 중단합니다. 기존 창 재사용 또는 실행 실패 여부를 확인하세요.')

def _require_foreground(window):
    if user32.GetForegroundWindow() != window.NativeWindowHandle:
        raise RuntimeError('다른 창으로 포커스가 이동했습니다.')

def _named(parent, method, aliases):
    for name in aliases:
        control = getattr(parent, method)(searchDepth=12, Name=name)
        if control.Exists(0.1):
            return control
    return None

def _walk(parent):
    stack = [(parent, 0)]
    seen = 0
    while stack and seen < 2500:
        node, depth = stack.pop()
        seen += 1
        yield node
        if depth < 12:
            stack.extend((c, depth + 1) for c in reversed(node.GetChildren()))

def _navigate_msc_tree(item, root, stop):
    tree_path, targets = item.get('treePath', []), item.get('targetItem', [])
    if tree_path:
        tree = root.TreeControl(searchDepth=8)
        if not tree.Exists(2):
            raise RuntimeError('관리 콘솔의 트리를 찾지 못했습니다.')
        parent = tree
        for aliases in tree_path:
            _check_stop(stop)
            _require_foreground(root)
            node = _named(parent, 'TreeItemControl', aliases)
            if node is None:
                raise RuntimeError('정책 경로를 찾지 못했습니다: ' + ' / '.join(aliases))
            node.Click()
            try:
                node.GetExpandCollapsePattern().Expand()
            except Exception:
                _require_foreground(root)
                node.SendKeys('{RIGHT}')
            parent = node
            time.sleep(0.15)
    if not targets:
        return
    listing = root.ListControl(searchDepth=12)
    if not listing.Exists(0.2):
        listing = root.TableControl(searchDepth=12)
    if not listing.Exists(1):
        raise RuntimeError('정책 목록을 찾지 못했습니다.')
    match = None
    for node in _walk(listing):
        _check_stop(stop)
        if any(target_matches(node.Name or '', alias) for alias in targets):
            match = node
            break
    if match is None:
        _require_foreground(root)
        listing.SetFocus()
        listing.SendKeys('{HOME}')
        last = None
        for _ in range(300):
            _check_stop(stop)
            _require_foreground(root)
            focused = auto.GetFocusedControl()
            if focused.ProcessId != root.ProcessId:
                raise RuntimeError('다른 프로세스의 목록이 선택되었습니다.')
            title = focused.Name or ''
            if any(target_matches(title, alias) for alias in targets):
                match = focused
                break
            if title == last:
                break
            last = title
            listing.SendKeys('{DOWN}')
            time.sleep(0.08)
    if match is None:
        raise RuntimeError('대상 정책을 찾지 못했습니다: ' + ' / '.join(targets))
    _require_foreground(root)
    match.Click()
    _require_foreground(root)
    match.SendKeys('{ALT}{ENTER}' if item.get('actionType') == 'Properties' else '{ENTER}')

def _wait_dialog(session, root, aliases, stop):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        _check_stop(stop)
        candidates = [w for h, w in session.snapshot().items()
                      if h not in session.before and w.ProcessId == root.ProcessId
                      and w.ClassName == '#32770' and session._owner_depth(h)
                      and any(target_matches(w.Name or '', a) for a in aliases)]
        if len(candidates) == 1:
            session.track(candidates[0])
            return candidates[0]
        if len(candidates) > 1:
            raise RuntimeError('동일한 정책 대화상자가 여러 개 열렸습니다.')
        time.sleep(0.1)
    raise RuntimeError('정확한 정책 속성 창을 찾지 못했습니다.')

def _navigate_registry(root, item):
    path = item.get('RegistryPath')
    if not path:
        raise RuntimeError('검증된 레지스트리 증빙 경로가 없습니다.')
    _require_foreground(root)
    address = root.EditControl(searchDepth=5)
    if not address.Exists(1):
        raise RuntimeError('레지스트리 주소 표시줄을 찾지 못했습니다.')
    address.GetValuePattern().SetValue(path.replace('HKLM:', 'HKEY_LOCAL_MACHINE').replace('HKCU:', 'HKEY_CURRENT_USER'))
    address.SetFocus()
    address.SendKeys('{ENTER}')
    time.sleep(0.5)
    if item.get('RegistryName'):
        selected = next((n for n in _walk(root) if target_matches(n.Name or '', item['RegistryName'])), None)
        if selected is None:
            raise RuntimeError('증빙 레지스트리 값을 찾지 못했습니다.')
        _require_foreground(root)
        selected.Click()

def _take_screenshot(path, target):
    if pyautogui is None:
        raise RuntimeError('pyautogui가 없어 캡처할 수 없습니다.')
    region = prepare_window(target, user32, pyautogui.size())
    time.sleep(0.25)
    _require_foreground(target)
    picture = pyautogui.screenshot(region=region)
    _require_foreground(target)
    from PIL.PngImagePlugin import PngInfo
    info = PngInfo()
    for key, value in {'WindowTitle': target.Name or '', 'WindowHandle': target.NativeWindowHandle,
                       'ProcessId': target.ProcessId, 'Region': region,
                       'CapturedAt': datetime.now(timezone.utc).isoformat()}.items():
        info.add_text(key, str(value))
    picture.save(path, pnginfo=info)

def _show_file_properties(file_path: str):
    """
    ctypes ShellExecuteExW API를 사용하여 지정된 파일 또는 폴더의 속성 대화상자를 안정적으로 기동시킵니다.
    """
    import ctypes
    from ctypes import wintypes

    class SHELLEXECUTEINFO(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD),
            ("fMask", ctypes.c_ulong),
            ("hwnd", wintypes.HWND),
            ("lpVerb", ctypes.c_wchar_p),
            ("lpFile", ctypes.c_wchar_p),
            ("lpParameters", ctypes.c_wchar_p),
            ("lpDirectory", ctypes.c_wchar_p),
            ("nShow", ctypes.c_int),
            ("hInstApp", wintypes.HINSTANCE),
            ("lpIDList", ctypes.c_void_p),
            ("lpClass", ctypes.c_wchar_p),
            ("hkeyClass", wintypes.HANDLE),
            ("dwHotKey", wintypes.DWORD),
            ("hIconOrMonitor", wintypes.HANDLE),
            ("hProcess", wintypes.HANDLE)
        ]

    SEE_MASK_INVOKEIDLIST = 0x0000000c
    SW_SHOW = 5

    sei = SHELLEXECUTEINFO()
    sei.cbSize = ctypes.sizeof(SHELLEXECUTEINFO)
    sei.fMask = SEE_MASK_INVOKEIDLIST
    sei.lpVerb = "properties"
    sei.lpFile = file_path
    sei.nShow = SW_SHOW

    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei)):
        raise RuntimeError('파일 속성 창을 열지 못했습니다.')



def capture_evidence(item, evidence_dir, log_callback=None, wait_before_capture=0.5,
                     wait_callback=None, stop_callback=None):
    """Failures propagate; owned windows always close before the next item."""
    def log(message, level='info'):
        if log_callback:
            log_callback(message, level)
    iid = item['ItemId']
    if not re.fullmatch(r'W-\d{2}(?:_[A-Za-z0-9]+)*', iid):
        raise ValueError('Invalid evidence item id')
    Path(evidence_dir).mkdir(parents=True, exist_ok=True)
    _check_stop(stop_callback)
    plans = item.get('captureTargets', [])
    if item.get('multiCapture'):
        from .execution import run_ps
        import json
        plans = []
        for service in item.get('targetServices', []):
            name = service['name']
            if not re.fullmatch(r'[A-Za-z0-9_-]+', name):
                raise ValueError('Invalid service name')
            raw = run_ps(f"Get-Service -Name '{name}' -ErrorAction Stop | Select-Object DisplayName | ConvertTo-Json -Compress")
            plans.append([json.loads(raw)['DisplayName']])
    if plans:
        paths = []
        for number, aliases in enumerate(plans, 1):
            sub = dict(item, ItemId=f'{iid}_part{number}', targetItem=aliases, actionType='Properties')
            sub.pop('captureTargets', None)
            sub.pop('multiCapture', None)
            paths.append(capture_evidence(sub, evidence_dir, log_callback, wait_before_capture,
                                          wait_callback, stop_callback))
        import shutil
        main = str(Path(evidence_dir) / f'{iid}.png')
        shutil.copy2(paths[0], main)
        return main
    if not auto or user32 is None or pyautogui is None:
        raise RuntimeError('Windows UI Automation과 pyautogui가 필요합니다.')
    ctypes.oledll.ole32.CoInitialize(None)
    session = None
    try:
        session = WindowSession(auto, user32, log)
        app = item.get('appTarget', '')
        if app == 'explorer.exe' and item.get('targetItem'):
            _show_file_properties(item['targetItem'][0])
            proc = None
        else:
            proc = _spawn_app(app)
        root = _wait_app(session, app, item, proc, stop_callback)
        log(f'  대상 창 확인: {root.Name} / HWND={root.NativeWindowHandle} / PID={root.ProcessId}')
        prepare_window(root, user32, pyautogui.size())
        target = root
        if app.endswith('.msc'):
            _navigate_msc_tree(item, root, stop_callback)
            if item.get('targetItem'):
                target = _wait_dialog(session, root, item['targetItem'], stop_callback)
        elif app == 'regedit':
            _navigate_registry(root, item)
        elif app == 'explorer.exe' and item.get('actionType') == 'FileProperties':
            tab = _named(root, 'TabItemControl', ['보안', 'Security'])
            if tab is None:
                raise RuntimeError('파일 권한 증빙의 보안 탭을 찾지 못했습니다.')
            _require_foreground(root)
            tab.Click()
        elif item.get('actionType') == 'NetworkWins':
            log('  NIC 전체 설정은 JSON으로 수집하며 이미지는 연결 목록입니다.', 'warn')
        if wait_callback and not wait_callback():
            raise CaptureCancelled('User Cancelled Execution')
        _check_stop(stop_callback)
        time.sleep(wait_before_capture)
        path = str(Path(evidence_dir) / f'{iid}.png')
        _take_screenshot(path, target)
        log(f'  증빙 이미지 저장: {path}', 'good')
        return path
    finally:
        try:
            if session is not None:
                session.close()
        finally:
            ctypes.oledll.ole32.CoUninitialize()
