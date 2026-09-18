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


def snapshots(auto, before, current):
    first = [True]
    def read():
        if first.pop() if first else False:
            return before
        return current
    auto.GetRootControl.return_value.GetChildren.side_effect = read


class WindowSessionTests(unittest.TestCase):
    def test_modeless_mmc_sheet_without_owner_closes_before_frame(self):
        frame, sheet, helper = window(2,20), window(3,20,'#32770'), window(4,20,'HiddenHelper')
        helper.Visible = False
        auto, api = Mock(), Mock()
        snapshots(auto, [], [frame,sheet,helper])  # Native order puts the frame first.
        alive = {2,3,4}
        api.IsWindow.side_effect = lambda h: h in alive
        api.GetWindow.return_value = 0  # Modeless sheet has NO owner link.
        api.PostMessageW.side_effect = lambda h,*a: (alive.remove(h),True)[1]
        session = WindowSession(auto,api)
        session.register_process(SimpleNamespace(pid=20),'secpol.msc')
        session.track(frame)
        session.close()
        self.assertEqual([c.args[0] for c in api.PostMessageW.call_args_list],[3,2])
        self.assertEqual(alive,{4})

    def test_custom_policy_editor_closes_before_console(self):
        frame, sheet = window(2,20), window(3,20,'PolicyEditor')
        auto, api = Mock(), Mock()
        snapshots(auto, [], [frame,sheet])
        alive = {2,3}
        api.IsWindow.side_effect = lambda h: h in alive
        api.GetWindow.return_value = 0
        api.PostMessageW.side_effect = lambda h,*a: (alive.remove(h),True)[1]
        session = WindowSession(auto,api)
        session.register_process(SimpleNamespace(pid=20),'gpedit.msc')
        session.close()
        self.assertEqual([c.args[0] for c in api.PostMessageW.call_args_list],[3,2])

    def test_new_dialog_is_discovered_before_frame_close(self):
        frame, sheet, notice = window(2,20), window(3,20,'#32770'), window(4,20,'#32770')
        auto, api = Mock(), Mock()
        alive = {2,3}
        snapshots(auto, [], [frame,sheet,notice])
        api.IsWindow.side_effect = lambda h: h in alive
        api.GetWindow.return_value = 0
        def close(h,*args):
            alive.remove(h)
            if h == 3:
                alive.add(4)
            return True
        api.PostMessageW.side_effect = close
        session = WindowSession(auto,api)
        session.register_process(SimpleNamespace(pid=20),'secpol.msc')
        session.close()
        self.assertEqual([c.args[0] for c in api.PostMessageW.call_args_list],[3,4,2])

    def test_modeless_cancel_fallback_finishes_before_frame_close(self):
        frame, sheet = window(2,20), window(3,20,'#32770')
        auto, api = Mock(), Mock()
        alive = {2,3}
        snapshots(auto, [], [frame,sheet])
        api.IsWindow.side_effect = lambda h: h in alive
        api.GetWindow.return_value = 0
        api.GetDlgItem.return_value = 33
        api.IsWindowEnabled.return_value = True
        def message(h,msg,w,l):
            if h == 2 or msg == 0x0111:
                alive.remove(h)
            return True
        api.PostMessageW.side_effect = message
        session = WindowSession(auto,api)
        session.register_process(SimpleNamespace(pid=20),'secpol.msc')
        with patch('core.window_session.time.monotonic',side_effect=[0,4,5,6]):
            session.close()
        self.assertEqual([c.args for c in api.PostMessageW.call_args_list],
                         [(3,0x0010,0,0),(3,0x0111,2,33),(2,0x0010,0,0)])

    def test_failed_mmc_discovery_still_closes_launched_process_windows(self):
        ours, other = window(2,20,'#32770'), window(3,30,'#32770')
        auto, api = Mock(), Mock()
        snapshots(auto, [], [ours,other])
        alive = {2,3}
        api.IsWindow.side_effect = lambda h: h in alive
        api.GetWindow.return_value = 0
        api.PostMessageW.side_effect = lambda h,*a: (alive.remove(h),True)[1]
        session = WindowSession(auto,api)
        session.register_process(SimpleNamespace(pid=20),'secpol.msc')
        session.close()
        self.assertEqual(alive,{3})

    def test_closes_dialog_before_parent_preserves_existing_and_unrelated(self):
        old, parent, dialog, unrelated = (window(1, 10), window(2, 20),
                                        window(3, 20, '#32770'), window(4, 30))
        auto, api = Mock(), Mock()
        snapshots(auto, [old], [old, parent, dialog, unrelated])
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
        snapshots(auto, [], [parent])
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
        snapshots(auto, [], [root, child, nested, unrelated])
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
        snapshots(auto, [], [window(10, 999)])
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
            if flags & 1:
                w, height = coords[2]-coords[0], coords[3]-coords[1]
            coords[:] = [x, y, x+w, y+height]
            return True
        api.GetWindowRect.side_effect = get_rect
        api.SetWindowPos.side_effect = set_pos
        api.GetForegroundWindow.return_value = 10
        self.assertEqual(prepare_window(ctrl, api, (1920, 1080)), (960, 0, 960, 1032))

    def test_fixed_size_dialog_aligns_actual_width_to_work_area(self):
        api, ctrl = Mock(), Mock()
        ctrl.NativeWindowHandle = 10
        coords = [0, 0, 450, 350]
        def get_rect(h, ptr):
            rect = ctypes.cast(ptr, ctypes.POINTER(wintypes.RECT)).contents
            rect.left, rect.top, rect.right, rect.bottom = coords
            return True
        def work_area(action, size, ptr, flags):
            rect = ctypes.cast(ptr, ctypes.POINTER(wintypes.RECT)).contents
            rect.left, rect.top, rect.right, rect.bottom = 40, 0, 1920, 1040
            return True
        def set_pos(h, z, x, y, w, height, flags):
            coords[:] = [x, y, x+450, y+350]  # fixed-size window ignores resize
            return True
        api.GetWindowRect.side_effect = get_rect
        api.SystemParametersInfoW.side_effect = work_area
        api.SetWindowPos.side_effect = set_pos
        api.GetForegroundWindow.return_value = 10
        self.assertEqual(prepare_window(ctrl, api, (1920,1080)), (1470,0,450,350))

    def test_parent_is_never_closed_when_dialog_refuses_close(self):
        parent, dialog = window(2,20), window(3,20,'#32770')
        auto, api = Mock(), Mock()
        snapshots(auto, [], [parent,dialog])
        alive = {2,3}
        api.IsWindow.side_effect = lambda h: h in alive
        api.GetWindow.side_effect = lambda h, _: 2 if h == 3 else 0
        def close(h, *args):
            if h == 3:
                return False
            alive.clear()
            return True
        api.PostMessageW.side_effect = close
        session = WindowSession(auto, api)
        session.track(parent)
        with self.assertRaises(WindowCleanupError):
            session.close()
        self.assertEqual([c.args[0] for c in api.PostMessageW.call_args_list], [3])
        self.assertEqual(alive, {2,3})

    def test_prepare_rejects_foreground_failure(self):
        api, ctrl = Mock(), Mock()
        ctrl.NativeWindowHandle = 10
        api.GetForegroundWindow.return_value = 999
        with patch('core.window_session.time.monotonic', side_effect=[0, 4]):
            with self.assertRaisesRegex(RuntimeError, '전경'):
                prepare_window(ctrl, api, (1920, 1080))
