import ast
import ctypes
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from core import capturer as cap, audit_policy as audit, diagnostic_evidence as diag
from core.evidence import save_record

ROOT = Path(__file__).resolve().parents[1]
def policy(i):
    return json.loads((ROOT/'config/policies'/f'{i}.json').read_text())

class FeedbackTests(unittest.TestCase):
    def test_audit_guid_and_struct_layout(self):
        guid = next(iter(audit.CATEGORIES))
        self.assertEqual(audit.GUID.parse(guid).text(), guid)
        self.assertEqual(ctypes.sizeof(audit.GUID),16)
        self.assertEqual(ctypes.sizeof(audit.POLICY),36)

    def test_audit_preserves_existing_success_and_requires_all_categories(self):
        values = {str(i):{'category':k, 'flags':1} for i,k in enumerate(audit.CATEGORIES)}
        desired = audit.target(values)
        self.assertTrue(all(row['flags']==3 for row in desired.values()))
        self.assertTrue(audit.compliant(desired))
        self.assertFalse(audit.compliant(values))
        with self.assertRaises(ValueError):
            audit.target({})

    def test_w26_skip_predicate_includes_iis(self):
        tree = ast.parse((ROOT/'main.py').read_text())
        conditions = [n for n in ast.walk(tree) if isinstance(n,ast.If)
                      and "services_config.get('iis')" in ast.unparse(n.test)]
        self.assertTrue(conditions)
        check = ast.Expression(conditions[0].test)
        self.assertTrue(eval(compile(check,'<test>','eval'),{}, {'services_config':{'iis':'skip'},'item_id':'W-26'}))
        self.assertFalse(eval(compile(check,'<test>','eval'),{}, {'services_config':{'iis':'proceed'},'item_id':'W-26'}))

    def test_exact_warning_and_registry_sources(self):
        for iid,value in [('W-57_Caption','Warning!'),('W-57_Text','관리자외 접근을 허용하지 않습니다.')]:
            p=policy(iid)
            self.assertEqual(p['SecureValue'],value)
            self.assertEqual(p['Comparison'],'eq')
        for iid in ['W-28','W-36']:
            self.assertEqual(policy(iid)['appTarget'],'regedit')
            self.assertTrue(policy(iid)['RegistryName'])

    def test_odbc_title_variants(self):
        for title in ['ODBC 데이터 원본 관리자(64비트)','ODBC Data Source Administrator (64-bit)']:
            self.assertTrue(cap._app_matches(SimpleNamespace(Name=title,ClassName='#32770'),'odbcad32.exe',{}))
        self.assertFalse(cap._app_matches(SimpleNamespace(Name='Windows 정보',ClassName='#32770'),'odbcad32.exe',{}))

    def test_registry_typed_address_is_not_navigation_proof(self):
        root = Mock(NativeWindowHandle=5)
        root.StatusBarControl.return_value.Exists.return_value=False
        with patch.object(cap,'_require_foreground'), patch.object(cap.time,'monotonic',side_effect=[0,6]):
            with self.assertRaisesRegex(RuntimeError,'실제 선택 경로'):
                cap._navigate_registry(root,{'RegistryPath':r'HKLM:\Software\Target'})
        root.ListControl.assert_not_called()

    def test_registry_actual_path_then_value_selected(self):
        root, row = Mock(NativeWindowHandle=5),Mock(Name='TargetValue',IsOffscreen=False)
        bar = root.StatusBarControl.return_value
        with patch.object(cap,'_require_foreground'), patch.object(cap,'_walk',
             side_effect=lambda node: iter([SimpleNamespace(Name=r'컴퓨터\HKEY_LOCAL_MACHINE\Software\Target')]) if node is bar else iter([row])):
            cap._navigate_registry(root,{'RegistryPath':r'HKLM:\Software\Target','RegistryName':'TargetValue'})
        row.Click.assert_called_once()

    def test_ntp_unreachable_not_reported_connected(self):
        def run(args,timeout=20):
            return {'ExitCode':0,'Output':'ntp.internal' if '/source' in args else 'error 0x800705B4','Error':''}
        with patch.object(diag,'command',side_effect=run):
            r=diag.collect_ntp()
        self.assertFalse(r['NtpResponseObserved'])
        self.assertEqual(r['OffsetSeconds'],[])

    def test_ntp_samples_are_not_claimed_as_sync_compliance(self):
        def run(args,timeout=20):
            return {'ExitCode':0,'Output':'ntp.internal' if '/source' in args else '12:00:00, +00.0012345s','Error':''}
        with patch.object(diag,'command',side_effect=run) as run_mock:
            r=diag.collect_ntp()
        self.assertTrue(r['NtpResponseObserved'])
        self.assertIn('미판정',r['SyncCompliance'])
        self.assertIn('/computer:ntp.internal',run_mock.call_args.args[0])

    def test_local_clock_does_not_probe_public_ntp(self):
        with patch.object(diag,'command',return_value={'ExitCode':0,'Output':'Local CMOS Clock','Error':''}) as run:
            r=diag.collect_ntp()
        self.assertFalse(r['NtpResponseObserved'])
        self.assertEqual(run.call_count,4)

    def test_incomplete_w56_record_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder)/'W-56_part1.png').write_bytes(b'one')
            initial={'ItemId':'W-56','Status':'양호','ConfigItem':policy('W-56')}
            data=json.loads(save_record(folder,initial,initial).read_text())
            self.assertEqual(data['ExpectedComponentCount'],2)
            self.assertIn('실패',data['ScreenshotStatus'])

    def test_processes_page_never_used_for_startup(self):
        root = Mock()
        with patch.object(cap,'_require_foreground'), patch.object(cap,'_named',return_value=None):
            with self.assertRaisesRegex(RuntimeError,'시작프로그램'):
                cap._navigate_startup(root)

    def test_paginated_diagnostics_do_not_drop_text(self):
        data={'Output':'\n'.join('line'+str(i) for i in range(200))}
        pages=diag.pages(data)
        self.assertGreater(len(pages),1)
        self.assertIn('line199','\n'.join(pages))

if __name__=='__main__':
    unittest.main()

class AuditTransactionTests(unittest.TestCase):
    def test_partial_audit_failure_restores_policy_and_override(self):
        from core import remediator as rem
        before={str(i):{'category':k,'flags':0} for i,k in enumerate(audit.CATEGORIES)}
        state={k:dict(v) for k,v in before.items()}
        writes=[]
        def write(values):
            writes.append(values)
            state.update({k:dict(v) for k,v in values.items()})
            if len(writes)==1:
                raise RuntimeError('partial API failure')
        row={'ItemId':'W-40','Status':'취약','ConfigItem':policy('W-40')}
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(rem.ctypes,'windll',Mock(),create=True), \
             patch.object(rem,'run_ps',return_value='{"PartOfDomain":false,"DomainRole":0}'), \
             patch.object(audit,'read',side_effect=lambda: {k:dict(v) for k,v in state.items()}), \
             patch.object(audit,'write',side_effect=write), \
             patch.object(rem,'_snapshot',return_value={'exists':False}), \
             patch.object(rem,'reg_write'), patch.object(rem,'_restore_registry') as restore:
            rem.invoke_remediation([row],folder,approved_items=['W-40'])
            self.assertEqual(row['FixStatus'],'실패')
            self.assertEqual(row['RollbackStatus'],'성공')
            self.assertEqual(state,before)
            restore.assert_called_once_with(audit.OVERRIDE_PATH,audit.OVERRIDE_NAME,{'exists':False})

    def test_audit_backup_failure_never_changes_settings(self):
        from core import remediator as rem
        before={str(i):{'category':k,'flags':0} for i,k in enumerate(audit.CATEGORIES)}
        row={'ItemId':'W-40','Status':'취약','ConfigItem':policy('W-40')}
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(rem.ctypes,'windll',Mock(),create=True), \
             patch.object(rem,'run_ps',return_value='{"PartOfDomain":false,"DomainRole":0}'), \
             patch.object(audit,'read',return_value=before), \
             patch.object(audit,'write') as write, \
             patch.object(rem,'_snapshot',return_value={'exists':False}), \
             patch.object(rem,'reg_write') as reg_write, \
             patch.object(Path,'open',side_effect=OSError('disk full')):
            rem.invoke_remediation([row],folder,approved_items=['W-40'])
            self.assertEqual(row['FixStatus'],'실패')
            write.assert_not_called()
            reg_write.assert_not_called()

    def test_audit_success_requires_effective_readback(self):
        from core import remediator as rem
        before={str(i):{'category':k,'flags':0} for i,k in enumerate(audit.CATEGORIES)}
        after=audit.target(before)
        row={'ItemId':'W-40','Status':'취약','ConfigItem':policy('W-40')}
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(rem.ctypes,'windll',Mock(),create=True), \
             patch.object(rem,'run_ps',return_value='{"PartOfDomain":false,"DomainRole":0}'), \
             patch.object(audit,'read',side_effect=[before,after]), \
             patch.object(audit,'write') as write, \
             patch.object(rem,'_snapshot',return_value={'exists':False}), \
             patch.object(rem,'reg_read',return_value=1), patch.object(rem,'reg_write'):
            rem.invoke_remediation([row],folder,approved_items=['W-40'])
            self.assertEqual(row['FixStatus'],'완료')
            write.assert_called_once_with(after)
            self.assertEqual(json.loads(Path(row['BackupFile']).read_text())['before'],before)

class NativeAuditFlagsTests(unittest.TestCase):
    def test_restore_zero_flags_sends_none_not_unchanged(self):
        import uuid
        values={str(uuid.UUID(int=i+1)):{'category':k,'flags':0} for i,k in enumerate(audit.CATEGORIES)}
        dll=Mock()
        with patch.object(audit,'api',return_value=dll):
            audit.write.__wrapped__(values)
        entries,count=dll.AuditSetSystemPolicy.call_args.args
        self.assertEqual(count,6)
        self.assertTrue(all(entry.flags==4 for entry in entries))

    def test_missing_audit_category_cannot_be_marked_good(self):
        with self.assertRaises(ValueError):
            audit.compliant({'one':{'category':next(iter(audit.CATEGORIES)),'flags':3}})
