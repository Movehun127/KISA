import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from core import capturer as cap, diagnostic_evidence as diag
from core.window_session import target_matches
from core.evidence import save_record

ROOT=Path(__file__).resolve().parents[1]
def policy(i):
    return json.loads((ROOT/'config/policies'/f'{i}.json').read_text())

class RunRegressionTests(unittest.TestCase):
    def test_service_local_computer_suffix_preserves_exact_match(self):
        for name in ['Remote Registry 속성(로컬 컴퓨터)','Remote Registry Properties (Local Computer)']:
            self.assertTrue(target_matches(name,'Remote Registry'))
        self.assertFalse(target_matches('Other Remote Registry Properties (Local Computer)','Remote Registry'))

    def test_hidden_status_bar_uses_selected_tree_full_path(self):
        tree=Mock()
        parent=SimpleNamespace(ControlTypeName='TreeControl')
        for name in ['컴퓨터','HKEY_LOCAL_MACHINE','Software','Target']:
            previous=parent
            parent=SimpleNamespace(ControlTypeName='TreeItemControl',Name=name,GetParentControl=lambda p=previous:p)
        tree.GetSelectionPattern.return_value.GetSelection.return_value=[parent]
        root=Mock()
        root.TreeControl.return_value=tree
        root.StatusBarControl.return_value.Exists.return_value=False
        self.assertTrue(cap._registry_location_matches(root,r'hkey_local_machine\software\target'))
        self.assertFalse(cap._registry_location_matches(root,r'hkey_local_machine\software\other'))

    def test_password_evidence_contains_all_five_actual_values(self):
        from core import execution
        p=policy('W-09')
        current={k:str(v) for k,v in p['SeceditValues'].items()}
        with patch.object(execution,'export_security_policy',return_value=current):
            data=diag.collect('password_policy',p)
        self.assertEqual({r['Setting'] for r in data['Data']['Sections']},set(p['SeceditValues']))
        self.assertTrue(all(r['Compliant'] for r in data['Data']['Sections']))
        current.pop('MinimumPasswordLength')
        with patch.object(execution,'export_security_policy',return_value=current):
            with self.assertRaisesRegex(RuntimeError,'누락'):
                diag.collect('password_policy',p)

    def test_smb_both_settings_and_units_collected(self):
        from core import native_actions
        values={'EnableForcedLogoff':True,'AutoDisconnectTimeoutInMinutesV1':15,'AutoDisconnectTimeoutInSecondsV2':900}
        with patch.object(native_actions,'read_smb',return_value=values):
            d=diag.collect('smb')
        self.assertEqual(len(d['Data']['Sections']),2)
        self.assertEqual(d['Data']['Sections'][1]['Values']['AutoDisconnectTimeoutInSecondsV2'],900)

    def test_raw_data_without_completed_capture_is_not_success(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'W-56_diagnostic.json'
            p.write_text(json.dumps({'CaptureComplete':False,'Data':{'Sections':[{},{}]}}))
            initial={'ItemId':'W-56','ConfigItem':policy('W-56'),'Status':'양호'}
            d=json.loads(save_record(folder,initial,initial).read_text())
            self.assertIn('실패',d['ScreenshotStatus'])

    def test_task_scheduler_local_name_spacing(self):
        self.assertIn('작업 스케줄러 (로컬)',policy('W-37')['treePath'][0])

    def test_startup_inventory_does_not_use_task_manager_or_run_entries(self):
        from core import startup_inventory
        self.assertEqual(policy('W-62')['EvidenceCollector'],'startup')
        self.assertIn('StartupApproved',startup_inventory.SCRIPT)
        self.assertIn('Registry32',startup_inventory.SCRIPT)
        self.assertNotIn('Start-Process',startup_inventory.SCRIPT)
        with patch.object(startup_inventory,'run_ps',return_value='{"Registry":[],"StartupFolders":[]}'):
            self.assertEqual(startup_inventory.collect()['Registry'],[])

    def test_ntp_local_clock_observation_is_explicit(self):
        with patch.object(diag,'command',return_value={'ExitCode':0,'Output':'Local CMOS Clock','Error':''}):
            data=diag.collect_ntp()
        self.assertFalse(data['NtpResponseObserved'])
        self.assertIn('연동 미확인',data['Summary'])
        self.assertIn('Local CMOS Clock',data['Summary'])

    def test_netbios_evidence_has_actual_adapter_options(self):
        with patch.object(diag,'run_ps',return_value='[{"Index":7,"TcpipNetbiosOptions":2}]'):
            d=diag.collect('netbios')
        self.assertEqual(d['Data']['Adapters'][0]['TcpipNetbiosOptions'],2)

class DiagnosticCaptureTests(unittest.TestCase):
    def run_capture(self,folder,fail_second=False):
        from PIL import Image
        root,session,proc=Mock(),Mock(),Mock()
        events=[]
        edit=root.EditControl.return_value
        edit.GetValuePattern.return_value=SimpleNamespace()
        class Value:
            @property
            def Value(self):
                return (Path(folder)/'W-56_display.txt').read_text()
        edit.GetValuePattern.return_value=Value()
        def screenshot(path,window):
            events.append('capture')
            if fail_second and events.count('capture')==2:
                raise RuntimeError('lost foreground')
            Image.new('RGB',(20,10),'white').save(path)
        values={'Host':'test','CollectedAt':'now','Data':{'Source':'read','Sections':[{'one':1},{'two':2}]}}
        from core import window_session
        with patch.object(window_session,'WindowSession',return_value=session), \
             patch.object(window_session,'prepare_window',side_effect=lambda *a:events.append('position')), \
             patch.object(diag,'launch_viewer',return_value=proc), \
             patch.object(diag,'collect',return_value=values), \
             patch.object(cap,'_wait_app',return_value=root), \
             patch.object(cap,'pyautogui',Mock()), patch.object(cap,'_take_screenshot',side_effect=screenshot):
            result=diag.capture(policy('W-56'),folder,Mock(),None,None,
                                lambda:events.append('apply'),lambda stage:None)
        return result,events,session

    def test_sections_apply_once_and_capture_both_then_close(self):
        from PIL import Image
        with tempfile.TemporaryDirectory() as folder:
            path,events,session=self.run_capture(folder)
            self.assertEqual(events,['position','apply','capture','capture'])
            with Image.open(path) as im:
                self.assertEqual(im.size,(20,20))
            data=json.loads((Path(folder)/'W-56_diagnostic.json').read_text())
            self.assertTrue(data['CaptureComplete'])
            self.assertEqual(data['SectionCount'],2)
            session.close.assert_called_once()

    def test_partial_capture_cannot_claim_complete(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(RuntimeError,'lost foreground'):
                self.run_capture(folder,True)
            data=json.loads((Path(folder)/'W-56_diagnostic.json').read_text())
            self.assertFalse(data['CaptureComplete'])
            self.assertFalse((Path(folder)/'W-56.png').exists())
