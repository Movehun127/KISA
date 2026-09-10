import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
if sys.platform != 'win32':
    fake = types.ModuleType('winreg')
    for i, name in enumerate(('HKEY_LOCAL_MACHINE','HKEY_CURRENT_USER','HKEY_CLASSES_ROOT','HKEY_USERS','HKEY_CURRENT_CONFIG','REG_DWORD','REG_QWORD','REG_SZ','KEY_READ','KEY_WOW64_64KEY','KEY_SET_VALUE')):
        setattr(fake, name, i+1)
    sys.modules['winreg'] = fake
from core import execution as ex, detector as det, remediator as rem


def policy(i):
    return json.loads((ROOT/'config/policies'/f'{i}.json').read_text(encoding='utf-8'))


def result(item):
    return {'ItemId':item['ItemId'], 'Status':'취약', 'ConfigItem':item, 'TechType':item['TechType']}


class SafetyTests(unittest.TestCase):
    def test_all_64_ids_present(self):
        ids={json.loads(p.read_text())['ItemId'].split('_')[0] for p in (ROOT/'config/policies').glob('*.json')}
        self.assertEqual(ids,{f'W-{i:02}' for i in range(1,65)})

    def test_threshold_bounds(self):
        for v, expected in [(0,False),(-1,False),(1,True),(5,True),(6,False)]:
            self.assertEqual(ex.matches(v,5,'positive_le'),expected)

    def test_stronger_auth_not_downgraded(self):
        for v in (3,4,5):self.assertTrue(ex.matches(v,3,'ntlmv2'))
        self.assertFalse(ex.matches(2,3,'ntlmv2'))

    def test_w08_both_60(self):
        self.assertEqual(policy('W-08')['SeceditValues'],{'LockoutDuration':60,'ResetLockoutCount':60})

    def test_caption_text_different(self):
        self.assertEqual(policy('W-57_Text')['RegistryName'],'LegalNoticeText')
        self.assertNotEqual(policy('W-57_Text')['RegistryName'],policy('W-57_Caption')['RegistryName'])

    def test_wrong_proxy_checks_manual(self):
        for i in ('W-06','W-12','W-19','W-46','W-54','W-56','W-60','W-63'):
            self.assertEqual(policy(i)['TechType'],'Type_Skip')
            self.assertNotIn('RemediationCommand',policy(i))

    def test_command_nonzero_raises(self):
        with patch.object(ex.subprocess,'run',return_value=types.SimpleNamespace(returncode=1,stderr=b'bad',stdout=b'')):
            with self.assertRaises(RuntimeError):ex.run_checked(['secedit'])

    def test_ps_timeout_raises(self):
        with patch.object(ex,'run_checked',side_effect=TimeoutError('timed out')):
            with self.assertRaises(TimeoutError):ex.run_ps('Get-Service')

    def test_single_json_accepted(self):
        with patch.object(det,'reg_read',return_value=1):
            rows=det.get_vulnerability_status(str(ROOT/'config/policies/W-10.json'))
        self.assertEqual(rows[0]['Status'],'양호')

    def test_access_denied_is_error(self):
        with patch.object(det,'reg_read',side_effect=PermissionError('denied')):
            rows=det.get_vulnerability_status(str(ROOT/'config/policies/W-10.json'))
        self.assertEqual(rows[0]['Status'],'오류')

    def test_missing_secedit_is_error(self):
        with patch.object(det,'_load_secedit',return_value={}):
            rows=det.get_vulnerability_status(str(ROOT/'config/policies/W-08.json'))
        self.assertEqual(rows[0]['Status'],'오류')

    def test_unknown_type_is_error(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'test.json';p.write_text(json.dumps({'ItemId':'W-99','TechType':'invalid'}))
            self.assertEqual(det.get_vulnerability_status(str(p))[0]['Status'],'오류')

    def test_no_success_on_empty_powershell(self):
        with patch.object(det,'_run_ps',return_value=''):
            rows=det.get_vulnerability_status(str(ROOT/'config/policies/W-64.json'))
        self.assertEqual(rows[0]['Status'],'오류')

    def test_error_never_remediated(self):
        row=result(policy('W-10'));row['Status']='오류'
        with patch.object(rem,'reg_write') as write:
            rem.invoke_remediation([row],'unused')
            write.assert_not_called()
        self.assertEqual(row['FixStatus'],'건너뜀')

    def test_risky_requires_approval(self):
        row=result(policy('W-59'))
        with patch.object(rem,'reg_write') as write:
            rem.invoke_remediation([row],'unused');write.assert_not_called()
        self.assertEqual(row['FixStatus'],'승인 필요')

    def test_unbacked_commands_blocked(self):
        row=result(policy('W-64'))
        with patch.object(rem,'run_ps') as run:
            rem.invoke_remediation([row],'unused');run.assert_not_called()
        self.assertEqual(row['FixStatus'],'수동 조치 필요')

    def test_domain_mutation_blocked(self):
        row=result(policy('W-10'))
        with patch.object(rem.ctypes,'windll',create=True) as dll, patch.object(rem,'run_ps',return_value='{"PartOfDomain":true,"DomainRole":3}'), patch.object(rem,'reg_write') as write:
            dll.shell32.IsUserAnAdmin.return_value=1
            rem.invoke_remediation([row],'unused');write.assert_not_called()
        self.assertEqual(row['FixStatus'],'수동 조치 필요')

    def test_failed_verification_rolls_back(self):
        row=result(policy('W-10'))
        with tempfile.TemporaryDirectory() as d, patch.object(rem.ctypes,'windll',create=True) as dll, patch.object(rem,'run_ps',return_value='{"PartOfDomain":false,"DomainRole":2}'), patch.object(rem,'_snapshot',return_value={'exists':True,'value':0,'type':4}), patch.object(rem,'reg_write'), patch.object(rem,'restore_backup') as restore:
            dll.shell32.IsUserAnAdmin.return_value=1
            rem.invoke_remediation([row],d)
            self.assertEqual(row['FixStatus'],'실패');restore.assert_called_once()
            self.assertTrue(Path(row['BackupFile']).exists())

    def test_success_requires_readback(self):
        row=result(policy('W-10'))
        with tempfile.TemporaryDirectory() as d, patch.object(rem.ctypes,'windll',create=True) as dll, patch.object(rem,'run_ps',return_value='{"PartOfDomain":false,"DomainRole":2}'), patch.object(rem,'_snapshot',side_effect=[{'exists':False},{'exists':True,'value':1,'type':4}]), patch.object(rem,'reg_write'):
            dll.shell32.IsUserAnAdmin.return_value=1
            rem.invoke_remediation([row],d)
            self.assertEqual(row['FixStatus'],'완료')

    def test_backup_failure_prevents_write(self):
        row=result(policy('W-10'))
        with tempfile.TemporaryDirectory() as d, patch.object(rem.ctypes,'windll',create=True) as dll, patch.object(rem,'run_ps',return_value='{"PartOfDomain":false,"DomainRole":2}'), patch.object(rem,'_snapshot',return_value={'exists':False}), patch.object(rem.json,'dump',side_effect=OSError('disk full')), patch.object(rem,'reg_write') as write:
            dll.shell32.IsUserAnAdmin.return_value=1
            rem.invoke_remediation([row],d);write.assert_not_called()
            self.assertEqual(row['FixStatus'],'실패')

    def test_security_template_is_scoped(self):
        commands=[]
        def check(args):
            commands.append(args)
            data=Path(args[args.index('/cfg')+1]).read_text(encoding='utf-16')
            self.assertIn('ClearTextPassword = 0',data)
            self.assertNotIn('Privilege Rights',data)
        with patch.object(ex,'run_checked',side_effect=check):ex.apply_security_policy({'ClearTextPassword':0})
        self.assertIn('SECURITYPOLICY',commands[0])

    def test_capture_does_not_change_netbios(self):
        source=(ROOT/'core/capturer.py').read_text()
        self.assertNotIn('disable_radio.Select()',source)
        self.assertNotIn('yes_btn.Click()',source)

    def test_restore_absent_value_deletes_it(self):
        old={'exists':False}
        fakekey=MagicMock()
        with patch.object(rem.winreg,'OpenKey',create=True,return_value=fakekey), patch.object(rem.winreg,'DeleteValue',create=True) as delete, patch.object(rem,'_snapshot',return_value=old):
            rem._restore_registry('HKLM:\\Software\\Test','value',old)
            delete.assert_called_once()

    def test_no_global_taskkill(self):
        self.assertNotIn('taskkill',(ROOT/'core/capturer.py').read_text())

if __name__=='__main__':unittest.main()
