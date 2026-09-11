import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from types import SimpleNamespace
from core import capturer as cap


class CaptureFlowTests(unittest.TestCase):
    def test_firewall_cannot_match_old_security_dialog(self):
        wrong = SimpleNamespace(Name='도메인 구성원: 보안 채널 데이터 디지털 서명(가능한 경우) 속성', ClassName='#32770')
        self.assertFalse(cap._app_matches(wrong, 'firewall.cpl', {}))

    def test_mmc_requires_launched_process(self):
        win = SimpleNamespace(Name='로컬 보안 정책', ClassName='MMCMainFrame', ProcessId=55)
        self.assertTrue(cap._app_matches(win, 'secpol.msc', {}, 55))
        self.assertFalse(cap._app_matches(win, 'secpol.msc', {}, 99))

    def test_foreground_switch_during_capture_does_not_save_image(self):
        ctrl, api, pag = Mock(), Mock(), Mock()
        ctrl.NativeWindowHandle = 10
        api.GetForegroundWindow.side_effect = [10, 99]
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(cap, 'user32', api), patch.object(cap, 'pyautogui', pag), \
             patch.object(cap, 'prepare_window', return_value=(0,0,700,500)), \
             patch.object(cap.time, 'sleep'):
            path = Path(folder) / 'W-64.png'
            with self.assertRaisesRegex(RuntimeError, '포커스'):
                cap._take_screenshot(path, ctrl)
            pag.screenshot.return_value.save.assert_not_called()
            self.assertFalse(path.exists())

    def test_capture_cleanup_next_item_order_even_after_capture_failure(self):
        events = []
        ctrl = SimpleNamespace(Name='로컬 보안 정책', NativeWindowHandle=10, ProcessId=20)
        session = Mock()
        session.close.side_effect = lambda: events.append('close')
        def capture(path, target):
            events.append('capture')
            if len(events) == 2:
                raise RuntimeError('capture failed')
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(cap, 'auto', Mock()), patch.object(cap, 'user32', Mock()), \
             patch.object(cap, 'pyautogui', Mock()), \
             patch.object(cap.ctypes, 'oledll', Mock(), create=True), \
             patch.object(cap, 'WindowSession', return_value=session), \
             patch.object(cap, '_spawn_app', side_effect=lambda app: events.append('spawn')), \
             patch.object(cap, '_wait_app', return_value=ctrl), \
             patch.object(cap, 'prepare_window'), patch.object(cap, '_navigate_msc_tree'), \
             patch.object(cap, '_take_screenshot', side_effect=capture), patch.object(cap.time, 'sleep'):
            with self.assertRaises(RuntimeError):
                cap.capture_evidence({'ItemId':'W-03','appTarget':'lusrmgr.msc'}, folder)
            cap.capture_evidence({'ItemId':'W-16','appTarget':'fsmgmt.msc'}, folder)
        self.assertEqual(events, ['spawn','capture','close','spawn','capture','close'])

    def test_cancel_before_start_never_opens_window(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(cap, '_spawn_app') as spawn:
            with self.assertRaises(cap.CaptureCancelled):
                cap.capture_evidence({'ItemId':'W-03'}, folder, stop_callback=lambda: True)
            spawn.assert_not_called()
