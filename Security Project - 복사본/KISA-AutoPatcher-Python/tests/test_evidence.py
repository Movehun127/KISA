import json
import tempfile
import unittest
import sys
import runpy
from unittest.mock import patch
from pathlib import Path
from core.evidence import create_run, save_record
from core.window_session import target_matches


class EvidenceTests(unittest.TestCase):
    def test_cleanup_failure_keeps_image_hash_and_failed_status(self):
        with tempfile.TemporaryDirectory() as root:
            run = create_run(root)
            (run/'W-08.png').write_bytes(b'captured-before-close-error')
            initial = {'ItemId':'W-08','Status':'취약','ConfigItem':{},
                       'ExecutionStages':['스캔 완료','오른쪽 정렬 확인','캡처 저장']}
            record = save_record(run,initial,{'Status':'양호'},error='창 종료 시간 초과')
            data = json.loads(record.read_text())
            self.assertTrue(data['ScreenshotStatus'].startswith('실패'))
            self.assertEqual(data['Screenshot'],'W-08.png')
            self.assertEqual(len(data['ScreenshotSHA256']),64)
            self.assertEqual(data['ExecutionStages'],initial['ExecutionStages'])

    def test_frozen_build_uses_bundled_policies_not_old_dist_config(self):
        source = Path(__file__).resolve().parents[1] / 'core' / 'paths.py'
        with patch.object(sys, 'frozen', True, create=True), \
             patch.object(sys, '_MEIPASS', '/bundle', create=True), \
             patch.object(sys, 'executable', '/old-dist/app.exe'):
            values = runpy.run_path(str(source))
        self.assertEqual(values['POLICY_DIR'], Path('/bundle/config/policies'))
        self.assertEqual(values['OUTPUT_DIR'], Path('/old-dist'))

    def test_admin_group_match_is_exact(self):
        self.assertFalse(target_matches('Hyper-V Administrators 속성', 'Administrators'))
        self.assertTrue(target_matches('Administrators 속성', 'Administrators'))

    def test_capture_success_does_not_mean_compliance(self):
        with tempfile.TemporaryDirectory() as root:
            run = create_run(root)
            png = run / 'W-08.png'
            png.write_bytes(b'fake-screenshot')
            initial = {'ItemId': 'W-08', 'Status': '취약', 'CurrentValue': 30,
                       'ConfigItem': {'SecureValue': 60}, 'FixStatus': '실패'}
            path = save_record(run, initial, {'Status': '취약', 'CurrentValue': 30}, png)
            data = json.loads(path.read_text())
            self.assertEqual(data['AfterStatus'], '취약')
            self.assertFalse(data['ScreenshotIsComplianceProof'])
            self.assertEqual(len(data['ScreenshotSHA256']), 64)

    def test_reject_previous_run_image(self):
        with tempfile.TemporaryDirectory() as root:
            run, other = create_run(root), create_run(root)
            png = other / 'W-02.png'
            png.write_bytes(b'old')
            initial = {'ItemId': 'W-02', 'Status': '양호', 'ConfigItem': {}}
            with self.assertRaises(ValueError):
                save_record(run, initial, {'Status': '양호'}, png)

    def test_subitems_have_distinct_evidence(self):
        with tempfile.TemporaryDirectory() as root:
            run = create_run(root)
            for iid in ['W-57_Caption', 'W-57_Text']:
                initial = {'ItemId': iid, 'Status': '취약', 'ConfigItem': {}}
                save_record(run, initial, {'Status': '오류'}, error='capture failed')
            self.assertEqual(len(list(run.glob('*.json'))), 2)
