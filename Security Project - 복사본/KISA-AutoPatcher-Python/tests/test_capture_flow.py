import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import Mock, patch
from types import SimpleNamespace
from core import capturer as cap


class CaptureFlowTests(unittest.TestCase):
    def test_modeless_policy_dialog_matches_by_dedicated_pid_and_exact_title(self):
        sheet = SimpleNamespace(Name='계정: Administrator 계정 이름 바꾸기 속성',
                                ClassName='#32770', ProcessId=20, NativeWindowHandle=3)
        session = Mock(before={}, launched_pids={20})
        session.snapshot.return_value = {3:sheet}
        session._owner_depth.return_value = 0
        session.control.side_effect = lambda w:w
        found = cap._wait_dialog(session,SimpleNamespace(ProcessId=20, NativeWindowHandle=2),
                                 ['계정: Administrator 계정 이름 바꾸기'],None)
        self.assertIs(found,sheet)
        session.track.assert_called_once_with(sheet)

    def test_policy_editor_custom_class_matches_exact_title(self):
        sheet = SimpleNamespace(Name='Set client connection encryption level',
                                ClassName='PolicyEditor', ProcessId=20, NativeWindowHandle=3)
        session = Mock(before={}, launched_pids={20})
        session.snapshot.return_value = {3:sheet}
        session.control.side_effect = lambda w:w
        root = SimpleNamespace(ProcessId=20, NativeWindowHandle=2)
        self.assertIs(cap._wait_dialog(session, root, [sheet.Name], None), sheet)

    def test_reveal_scrolls_before_click_and_rejects_still_hidden_item(self):
        control = Mock(IsOffscreen=True)
        with self.assertRaisesRegex(RuntimeError, '스크롤'):
            cap._reveal(control)
        control.GetScrollItemPattern.return_value.ScrollIntoView.assert_called_once()
        control.Click.assert_not_called()

    def run_flow(self, folder, events, action, **kwargs):
        ctrl = Mock(Name='정책', NativeWindowHandle=10, ProcessId=20)
        session = Mock()
        session.before = {}
        session.close.side_effect = lambda: events.append('close')
        def screenshot(path, target):
            events.append('capture')
            from PIL import Image
            Image.new('RGB',(12,10),'white').save(path)
        with ExitStack() as stack:
            for name, value in [('auto',Mock()), ('user32',Mock()), ('pyautogui',Mock())]:
                stack.enter_context(patch.object(cap,name,value))
            stack.enter_context(patch.object(cap.ctypes,'oledll',Mock(),create=True))
            stack.enter_context(patch.object(cap,'WindowSession',return_value=session))
            stack.enter_context(patch.object(cap,'_spawn_app',side_effect=lambda a: events.append('open')))
            stack.enter_context(patch.object(cap,'_wait_app',return_value=ctrl))
            stack.enter_context(patch.object(cap,'_wait_dialog',return_value=ctrl))
            stack.enter_context(patch.object(cap,'prepare_window',side_effect=kwargs.pop('position',lambda *a: events.append('right'))))
            stack.enter_context(patch.object(cap,'_require_foreground'))
            stack.enter_context(patch.object(cap,'_navigate_msc_tree',side_effect=lambda *a: events.append('navigate')))
            stack.enter_context(patch.object(cap,'_take_screenshot',side_effect=screenshot))
            stack.enter_context(patch.object(cap.time,'sleep'))
            return cap.capture_evidence(dict(ItemId='W-08',appTarget=kwargs.pop('app','secpol.msc'),**kwargs),folder,
                                        action_callback=action)

    def test_position_before_action_then_capture_and_close(self):
        events = []
        with tempfile.TemporaryDirectory() as folder:
            self.run_flow(folder, events, lambda: events.append('apply'))
        self.assertEqual(events,['open','right','apply','right','navigate','capture','close'])

    def test_position_failure_closes_window_without_mutating(self):
        events, action = [], Mock()
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(RuntimeError,'alignment'):
                self.run_flow(folder,events,action,position=Mock(side_effect=RuntimeError('alignment')))
        action.assert_not_called()
        self.assertEqual(events,['open','close'])

    def test_action_failure_still_closes_window_without_capture(self):
        events = []
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(RuntimeError,'mutation'):
                self.run_flow(folder,events,Mock(side_effect=RuntimeError('mutation')))
        self.assertEqual(events,['open','right','close'])

    def test_multi_capture_applies_once_and_closes_between_parts(self):
        events = []
        action = Mock(side_effect=lambda: events.append('apply'))
        with tempfile.TemporaryDirectory() as folder:
            self.run_flow(folder,events,action,captureTargets=[['duration'],['reset']])
            self.assertTrue((Path(folder)/'W-08.png').exists())
            from PIL import Image
            with Image.open(Path(folder)/'W-08.png') as overview:
                self.assertEqual(overview.size,(12,20))
        action.assert_called_once()
        self.assertEqual(events.count('capture'),2)
        first_close = events.index('close')
        self.assertEqual(events[first_close+1],'open')

    def test_cached_control_panel_is_reopened_after_mutation(self):
        events = []
        def apply():
            events.append('apply')
            return True
        with tempfile.TemporaryDirectory() as folder:
            self.run_flow(folder,events,apply,app='firewall.cpl')
        self.assertEqual(events,['open','right','apply','right','close','open','right','capture','close'])

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
