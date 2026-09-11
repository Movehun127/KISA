import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.window_session import WindowSession, WindowCleanupError, prepare_window
import ctypes
from ctypes import wintypes


def window(handle, pid, cls='MMCMainFrame'):
    return SimpleNamespace(NativeWindowHandle=handle, ProcessId=pid, ClassName=cls)


class WindowSessionTests(unittest.TestCase):
    def test_closes_dialog_before_parent_preserves_existing_and_unrelated(self):
        old, parent, dialog, unrelated = (window(1, 10), window(2, 20),
                                        window(3, 20, '#32770'), window(4, 30))
        auto, api = Mock(), Mock()
        auto.GetRootControl.return_value.GetChildren.side_effect = [[old], [old, parent, dialog, unrelated]]
        alive = {1, 2, 3, 4}
        api.IsWindow.side_effect = lambda h: h in alive
        api.PostMessageW.side_effect = lambda h, *args: (alive.remove(h), True)[1]
        api.GetWindow.side_effect = lambda h, _: 2 if h == 3 else 0
        session = WindowSession(auto, api)
        session.track(old)
        session.track(parent)
        session.close()
        self.assertEqual([c.args[0] for c in api.PostMessageW.call_args_list], [3, 2])
        self.assertEqual(alive, {1, 4})

    def test_refusal_to_close_stops_progress(self):
        parent = window(2, 20)
        auto, api = Mock(), Mock()
        auto.GetRootControl.return_value.GetChildren.side_effect = [[], [parent]]
        api.IsWindow.return_value = True
        api.GetWindow.return_value = 0
        session = WindowSession(auto, api)
        session.track(parent)
        with patch('core.window_session.time.monotonic', side_effect=[0, 4]):
            with self.assertRaises(WindowCleanupError):
                session.close()

    def test_missing_automation_fails_before_opening_windows(self):
        with self.assertRaises(WindowCleanupError):
            WindowSession(None, Mock())

    def test_nested_owned_dialogs_close_deepest_first(self):
        root, child, nested, unrelated = window(10, 20), window(11, 20, '#32770'), window(12, 20, '#32770'), window(13, 20, '#32770')
        auto, api = Mock(), Mock()
        auto.GetRootControl.return_value.GetChildren.side_effect = [[], [root, child, nested, unrelated]]
        alive = {10, 11, 12, 13}
        api.GetWindow.side_effect = lambda h, _: {11:10, 12:11}.get(h, 0)
        api.IsWindow.side_effect = lambda h: h in alive
        api.PostMessageW.side_effect = lambda h, *args: (alive.remove(h), True)[1]
        session = WindowSession(auto, api)
        for w in (root, child, nested):
            session.track(w)
        session.close()
        self.assertEqual([c.args[0] for c in api.PostMessageW.call_args_list], [12, 11, 10])
        self.assertEqual(alive, {13})

    def test_reused_handle_is_not_closed(self):
        root = window(10, 20)
        auto, api = Mock(), Mock()
        auto.GetRootControl.return_value.GetChildren.side_effect = [[], [window(10, 999)]]
        api.GetWindow.return_value = 0
        session = WindowSession(auto, api)
        session.track(root)
        session.close()
        api.PostMessageW.assert_not_called()

    def test_prepare_recovers_offscreen_window(self):
        api, ctrl = Mock(), Mock()
        ctrl.NativeWindowHandle = 10
        coords = [-900, -30, -100, 570]
        def get_rect(handle, ptr):
            rect = ctypes.cast(ptr, ctypes.POINTER(wintypes.RECT)).contents
            rect.left, rect.top, rect.right, rect.bottom = coords
            return True
        def set_pos(h, z, x, y, w, height, flags):
            coords[:] = [x, y, x+w, y+height]
            return True
        api.GetWindowRect.side_effect = get_rect
        api.SetWindowPos.side_effect = set_pos
        api.GetForegroundWindow.return_value = 10
        self.assertEqual(prepare_window(ctrl, api, (1920, 1080)), (0, 0, 800, 600))

    def test_prepare_rejects_foreground_failure(self):
        api, ctrl = Mock(), Mock()
        ctrl.NativeWindowHandle = 10
        api.GetForegroundWindow.return_value = 999
        with patch('core.window_session.time.monotonic', side_effect=[0, 4]):
            with self.assertRaisesRegex(RuntimeError, '전경'):
                prepare_window(ctrl, api, (1920, 1080))
