"""Close newly opened evidence windows without terminating shared processes."""
import time
import ctypes
from ctypes import wintypes
from types import SimpleNamespace


def target_matches(label, expected):
    def normalize(value):
        value = ' '.join(str(value).casefold().split())
        for suffix in (' 속성', ' properties'):
            if value.endswith(suffix):
                value = value[:-len(suffix)]
        return value
    return normalize(label) == normalize(expected)


class WindowCleanupError(RuntimeError):
    pass


class CaptureCancelled(RuntimeError):
    pass


def prepare_window(window, api, screen_size, timeout=3):
    """Position the native top-level window; verify physical bounds and foreground."""
    handle = window.NativeWindowHandle
    sw, sh = screen_size
    left, top, right, bottom = 0, 0, sw, sh - 48
    # Use the primary monitor's work area, excluding taskbars on any edge.
    work = wintypes.RECT()
    if hasattr(api, 'SystemParametersInfoW') and api.SystemParametersInfoW(0x0030, 0, ctypes.byref(work), 0):
        if work.right > work.left and work.bottom > work.top:
            left, top, right, bottom = work.left, work.top, work.right, work.bottom
    if not handle or not api.IsWindow(handle):
        raise RuntimeError('대상 창이 닫혔거나 핸들이 유효하지 않습니다.')
    rect = wintypes.RECT()
    if not api.GetWindowRect(handle, ctypes.byref(rect)):
        raise RuntimeError('대상 창 좌표 조회 실패')
    width = min(max(rect.right - rect.left, (right-left)//2), right-left)
    height = min(max(rect.bottom - rect.top, 500), bottom-top)
    api.ShowWindow(handle, 9)
    if not api.SetWindowPos(handle, 0, right-width, top, width, height, 0x0040):
        raise RuntimeError('증빙 창 오른쪽 배치 실패')
    # Fixed-size dialogs can ignore the requested size. Align their actual width.
    if not api.GetWindowRect(handle, ctypes.byref(rect)):
        raise RuntimeError('배치 후 창 좌표 조회 실패')
    if not api.SetWindowPos(handle, 0, right-(rect.right-rect.left), top, 0, 0, 0x0041):
        raise RuntimeError('증빙 창 오른쪽 정렬 실패')
    deadline = time.monotonic() + timeout
    while True:
        try:
            window.SetActive()
            window.SetFocus()
        except Exception:
            pass
        api.SetForegroundWindow(handle)
        if api.GetForegroundWindow() == handle:
            if not api.GetWindowRect(handle, ctypes.byref(rect)):
                raise RuntimeError('배치 후 창 좌표 조회 실패')
            if not (left <= rect.left < rect.right <= right and top <= rect.top < rect.bottom <= bottom):
                raise RuntimeError('창이 화면 밖으로 잘려 있습니다.')
            if abs(rect.right-right) > 2:
                raise RuntimeError('대상 창의 오른쪽 정렬을 확인하지 못했습니다.')
            return rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top
        if time.monotonic() >= deadline:
            raise RuntimeError('다른 창이 전경에 있어 증빙 캡처를 중단했습니다.')
        time.sleep(0.1)


class WindowSession:
    def __init__(self, auto, user32, log=None):
        self.auto, self.user32, self.log = auto, user32, log
        self.before = self.snapshot()
        self.targets = {}
        self.launched_pids = set()

    def register_process(self, proc, app):
        # Only MMC is guaranteed to be a dedicated process we just launched.
        if proc is not None and app.endswith('.msc'):
            self.launched_pids.add(proc.pid)

    def snapshot(self):
        if self.auto is None:
            raise WindowCleanupError('UI Automation을 사용할 수 없어 창 추적을 시작할 수 없습니다.')
        if isinstance(self.user32, ctypes.CDLL):
            # UIA can omit owned dialogs. Enumerate native HWNDs for lifecycle tracking.
            windows = {}
            callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
            def collect(handle, _):
                pid = wintypes.DWORD()
                self.user32.GetWindowThreadProcessId(handle, ctypes.byref(pid))
                title, cls = ctypes.create_unicode_buffer(2048), ctypes.create_unicode_buffer(256)
                self.user32.GetWindowTextW(handle, title, len(title))
                self.user32.GetClassNameW(handle, cls, len(cls))
                windows[handle] = SimpleNamespace(NativeWindowHandle=handle, ProcessId=pid.value,
                                                  Name=title.value, ClassName=cls.value,
                                                  Visible=bool(self.user32.IsWindowVisible(handle)))
                return True
            if not self.user32.EnumWindows(callback_type(collect), 0):
                raise WindowCleanupError('Windows 창 목록 조회 실패')
            # EnumWindows is documented for desktop apps; retain UIA-discovered
            # top-level handles as well for Settings/Windows Security hosts.
            try:
                for control in self.auto.GetRootControl().GetChildren():
                    handle = control.NativeWindowHandle
                    if handle and handle not in windows and self.user32.IsWindow(handle):
                        collect(handle, 0)
                        if not windows[handle].Name:
                            windows[handle].Name = control.Name or ''
            except Exception:
                pass  # Native enumeration remains available when UIA is stalled.
            return windows
        return {w.NativeWindowHandle: w for w in self.auto.GetRootControl().GetChildren() if w.NativeWindowHandle}

    def control(self, window):
        if isinstance(self.user32, ctypes.CDLL):
            return self.auto.ControlFromHandle(window.NativeWindowHandle)
        return window

    def track(self, window):
        if window is not None:
            handle = window.NativeWindowHandle
            if handle and handle not in self.before:
                self.targets[handle] = (window.ProcessId, window.ClassName)

    def _owner_depth(self, handle):
        seen = set()
        depth = 0
        owned = False
        while handle and handle not in seen:
            seen.add(handle)
            handle = self.user32.GetWindow(handle, 4)  # GW_OWNER
            if not handle:
                break
            depth += 1
            if handle in self.targets:
                owned = True
        return depth if owned else 0

    def close(self):
        try:
            self._close_owned()
        except WindowCleanupError:
            raise
        except Exception as exc:
            raise WindowCleanupError(f'창 종료 확인 실패: {exc}') from exc

    def _close_owned(self):
        # MMC property sheets can be modeless, with no GW_OWNER link to the frame.
        # Re-enumerate after EVERY close; never close the frame while a sheet remains.
        for _ in range(64):
            current = self.snapshot()
            pids = {pid for pid, _ in self.targets.values()}
            for handle, window in current.items():
                if handle in self.before or not self.user32.IsWindow(handle):
                    continue
                dedicated = (window.ProcessId in self.launched_pids
                             and getattr(window, 'Visible', True)
                             and window.ClassName in ('#32770', 'MMCMainFrame'))
                owned = window.ProcessId in pids and self._owner_depth(handle)
                if dedicated or owned:
                    self.track(window)
            pending = [(h, identity) for h, identity in self.targets.items()
                       if h in current and self.user32.IsWindow(h)
                       and (current[h].ProcessId, current[h].ClassName) == identity]
            if not pending:
                if self.log and self.targets:
                    self.log('  증빙 창 닫기 완료 → 다음 항목 진행', 'info')
                return
            pending.sort(key=lambda pair: (pair[1][1] != 'MMCMainFrame',
                                            self._owner_depth(pair[0])), reverse=True)
            handle, identity = pending[0]
            if isinstance(self.user32, ctypes.CDLL):
                pid, cls = wintypes.DWORD(), ctypes.create_unicode_buffer(256)
                self.user32.GetWindowThreadProcessId(handle, ctypes.byref(pid))
                self.user32.GetClassNameW(handle, cls, len(cls))
                if (pid.value, cls.value) != identity:
                    continue
            if not self.user32.PostMessageW(handle, 0x0010, 0, 0):
                raise WindowCleanupError(f'HWND={handle}: 창 닫기 요청 거부. 본창 종료를 시도하지 않습니다.')
            deadline = time.monotonic() + 3
            while self.user32.IsWindow(handle):
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.1)
            if self.user32.IsWindow(handle) and identity[1] == '#32770':
                # Modeless property sheets may require their Cancel command.
                # Never press OK/Apply: cleanup must not commit an unsaved edit.
                button = self.user32.GetDlgItem(handle, 2)  # IDCANCEL
                if isinstance(button, int) and button and self.user32.IsWindowEnabled(button):
                    if self.user32.PostMessageW(handle, 0x0111, 2, button):  # WM_COMMAND / BN_CLICKED
                        deadline = time.monotonic() + 3
                        while self.user32.IsWindow(handle) and time.monotonic() < deadline:
                            time.sleep(0.1)
            if self.user32.IsWindow(handle):
                raise WindowCleanupError(f'HWND={handle}: 속성/관리 창 종료 시간 초과. 본창 종료와 다음 항목을 중단합니다.')
        raise WindowCleanupError('새 대화상자가 반복 생성되어 창 정리를 중단합니다.')
