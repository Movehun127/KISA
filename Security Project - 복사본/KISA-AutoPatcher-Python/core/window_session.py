"""Close newly opened evidence windows without terminating shared processes."""
import time
import ctypes
from ctypes import wintypes


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
    if not handle or not api.IsWindow(handle):
        raise RuntimeError('대상 창이 닫혔거나 핸들이 유효하지 않습니다.')
    rect = wintypes.RECT()
    if not api.GetWindowRect(handle, ctypes.byref(rect)):
        raise RuntimeError('대상 창 좌표 조회 실패')
    width = min(max(rect.right - rect.left, 700), sw)
    height = min(max(rect.bottom - rect.top, 500), sh - 48)
    api.ShowWindow(handle, 9)
    if not api.SetWindowPos(handle, 0, 0, 0, width, height, 0x0040):
        raise RuntimeError('증빙 창 좌측 배치 실패')
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
            if not (0 <= rect.left < rect.right <= sw and 0 <= rect.top < rect.bottom <= sh):
                raise RuntimeError('창이 화면 밖으로 잘려 있습니다.')
            return rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top
        if time.monotonic() >= deadline:
            raise RuntimeError('다른 창이 전경에 있어 증빙 캡처를 중단했습니다.')
        time.sleep(0.1)


class WindowSession:
    def __init__(self, auto, user32, log=None):
        self.auto, self.user32, self.log = auto, user32, log
        self.before = self.snapshot()
        self.targets = {}

    def snapshot(self):
        if self.auto is None:
            raise WindowCleanupError('UI Automation을 사용할 수 없어 창 추적을 시작할 수 없습니다.')
        return {w.NativeWindowHandle: w for w in self.auto.GetRootControl().GetChildren()
                if w.NativeWindowHandle}

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
        current = self.snapshot()
        pids = {pid for pid, _ in self.targets.values()}
        # Shared Explorer processes can host unrelated dialogs: require an owner chain.
        dialogs = {h: (w.ProcessId, w.ClassName) for h, w in current.items()
                   if h not in self.before and w.ProcessId in pids and self._owner_depth(h)}
        targets = {**self.targets, **dialogs}
        targets = sorted(targets.items(), key=lambda pair: self._owner_depth(pair[0]), reverse=True)
        for handle, identity in targets:
            if not self.user32.IsWindow(handle):
                continue
            # HWNDs may be reused; check identity before sending WM_CLOSE.
            live = current.get(handle)
            if live is None or (live.ProcessId, live.ClassName) != identity:
                continue
            if not self.user32.PostMessageW(handle, 0x0010, 0, 0):
                raise WindowCleanupError('증빙 창 닫기 요청이 거부되었습니다.')
            deadline = time.monotonic() + 3
            while self.user32.IsWindow(handle):
                if time.monotonic() >= deadline:
                    raise WindowCleanupError('증빙 창을 닫지 못해 다음 항목 진행을 중단합니다.')
                time.sleep(0.1)
        if self.log and targets:
            self.log('  증빙 창 닫기 완료 → 다음 항목 진행', 'info')
