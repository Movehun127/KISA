import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from test_safety import rem, det, policy, result
from core import native_actions as native


class NativeActionTests(unittest.TestCase):
    def test_smb_requires_both_conditions_and_preserves_stronger_timeout(self):
        self.assertFalse(native.smb_compliant({'EnableForcedLogoff':False, 'AutoDisconnectTimeout':5}))
        self.assertFalse(native.smb_compliant({'EnableForcedLogoff':True, 'AutoDisconnectTimeout':16}))
        self.assertEqual(native.smb_target({'EnableForcedLogoff':False, 'AutoDisconnectTimeout':0}),
                         {'EnableForcedLogoff':True, 'AutoDisconnectTimeout':0})
        self.assertTrue(native.smb_compliant({'EnableForcedLogoff':True, 'AutoDisconnectTimeout':0}))

    def test_smb_rejects_missing_timeout_and_unknown_mutations(self):
        with patch.object(native, 'run_ps', return_value='{"EnableForcedLogoff":true}'):
            with self.assertRaises(ValueError):
                native.read_smb()
        with self.assertRaises(ValueError):
            native.write_smb({'EnableForcedLogoff':True, 'EnableSMB1Protocol':True})

    def test_firewall_profile_query_cannot_pass_missing_profile(self):
        with patch.object(native, 'run_ps', return_value='[{"Name":"Domain","Enabled":"True"}]'):
            with self.assertRaises(ValueError):
                native.read_firewall()

    def test_native_settings_require_approval_before_any_query_or_write(self):
        for iid in ('W-47', 'W-56', 'W-64'):
            r = result(policy(iid))
            with patch.object(rem, 'run_ps') as query:
                rem.invoke_remediation([r], 'unused')
                query.assert_not_called()
            self.assertEqual(r['FixStatus'], '승인 필요')

    def test_firewall_effective_policy_failure_restores_original_profiles(self):
        before = {'Domain':'True', 'Private':'False', 'Public':'NotConfigured'}
        state = dict(before)
        writes = []
        def write(values, **kwargs):
            writes.append(dict(values)); state.update(values)
        def read(store='PersistentStore'):
            return dict(before if store == 'ActiveStore' else state)
        r = result(policy('W-64'))
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(rem.ctypes, 'windll', create=True), \
             patch.object(rem, 'run_ps', return_value='{"PartOfDomain":false,"DomainRole":0}'), \
             patch.object(native, 'read_firewall', side_effect=read), \
             patch.object(native, 'write_firewall', side_effect=write):
            rem.invoke_remediation([r], folder, approved_items=['W-64'])
            self.assertEqual(r['FixStatus'], '실패')
            self.assertEqual(r['RollbackStatus'], '성공')
            self.assertEqual(state, before)
            self.assertEqual(writes[-1], before)
            self.assertEqual(json.loads(Path(r['BackupFile']).read_text())['before'], before)

    def test_smb_success_backup_and_readback(self):
        old = {'EnableForcedLogoff':False, 'AutoDisconnectTimeout':30}
        new = {'EnableForcedLogoff':True, 'AutoDisconnectTimeout':15}
        r = result(policy('W-56'))
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(rem.ctypes, 'windll', create=True), \
             patch.object(rem, 'run_ps', return_value='{"PartOfDomain":false,"DomainRole":0}'), \
             patch.object(native, 'read_smb', side_effect=[old, new]), \
             patch.object(native, 'write_smb') as write:
            rem.invoke_remediation([r], folder, approved_items=['W-56'])
            self.assertEqual(r['FixStatus'], '완료')
            write.assert_called_once_with(new)
            self.assertEqual(json.loads(Path(r['BackupFile']).read_text())['before'], old)

    def test_firewall_restore_attempts_remaining_profiles_after_error(self):
        values = {'Domain':'True', 'Private':'False', 'Public':'False'}
        with patch.object(native, 'run_ps', side_effect=[RuntimeError('one profile failed'), '', '']) as run:
            with self.assertRaises(RuntimeError):
                native.write_firewall(values, best_effort=True)
            self.assertEqual(run.call_count, 3)

    def test_partial_registry_group_write_restores_every_original_value(self):
        r = result(policy('W-47'))
        state = {}
        writes = []
        def snapshot(path, name):
            return state.get(name, {'exists':False}).copy()
        def write(path, name, value, kind):
            writes.append(name)
            if len(writes) == 2:
                raise OSError('access denied')
            state[name] = {'exists':True, 'value':value, 'type':1}
        def restore(path, name, old):
            if old['exists']:
                state[name] = old
            else:
                state.pop(name, None)
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(rem.ctypes, 'windll', create=True), \
             patch.object(rem, 'run_ps', return_value='{"PartOfDomain":false,"DomainRole":0}'), \
             patch.object(rem, '_snapshot', side_effect=snapshot), \
             patch.object(rem, 'reg_write', side_effect=write), \
             patch.object(rem, '_restore_registry', side_effect=restore), \
             patch.object(rem.os.path, 'isfile', return_value=True):
            rem.invoke_remediation([r], folder, approved_items=['W-47'])
            self.assertEqual(r['FixStatus'], '실패')
            self.assertEqual(r['RollbackStatus'], '성공')
            self.assertEqual(state, {})

    def test_ntfs_query_mixed_disk_not_reported_good(self):
        p = str(Path(__file__).resolve().parents[1] / 'config/policies/W-61.json')
        with patch.object(det, '_run_ps', return_value='[{"DeviceID":"C:","FileSystem":"NTFS"},{"DeviceID":"D:","FileSystem":"FAT32"}]'):
            self.assertEqual(det.get_vulnerability_status(p)[0]['Status'], '취약')
