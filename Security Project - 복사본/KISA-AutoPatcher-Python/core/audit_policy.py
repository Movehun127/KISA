"""W-40 effective audit policy, using locale-independent Windows audit GUIDs."""
import ctypes as C
import uuid
from contextlib import contextmanager

class GUID(C.Structure):
    _fields_ = [('Data1', C.c_uint32), ('Data2', C.c_uint16), ('Data3', C.c_uint16),
                ('Data4', C.c_ubyte * 8)]
    @classmethod
    def parse(cls, value):
        return cls.from_buffer_copy(uuid.UUID(value).bytes_le)
    def text(self):
        return str(uuid.UUID(bytes_le=bytes(self)))

class POLICY(C.Structure):
    _fields_ = [('subcategory', GUID), ('flags', C.c_uint32), ('category', GUID)]

# Model.pdf p.236: account management / DS access failure; other four success+failure.
CATEGORIES = {
    '69979849-797a-11d9-bed3-505054503030': ('로그온 이벤트', 3),
    '6997984b-797a-11d9-bed3-505054503030': ('권한 사용', 3),
    '6997984d-797a-11d9-bed3-505054503030': ('정책 변경', 3),
    '6997984e-797a-11d9-bed3-505054503030': ('계정 관리', 2),
    '6997984f-797a-11d9-bed3-505054503030': ('디렉터리 서비스 액세스', 2),
    '69979850-797a-11d9-bed3-505054503030': ('계정 로그온 이벤트', 3),
}
OVERRIDE_PATH = r'HKLM:\System\CurrentControlSet\Control\Lsa'
OVERRIDE_NAME = 'SCENoApplyLegacyAuditPolicy'

def api():
    dll = C.WinDLL('advapi32', use_last_error=True)
    dll.AuditEnumerateSubCategories.argtypes = [C.POINTER(GUID), C.c_ubyte, C.POINTER(C.POINTER(GUID)), C.POINTER(C.c_uint32)]
    dll.AuditEnumerateSubCategories.restype = C.c_ubyte
    dll.AuditQuerySystemPolicy.argtypes = [C.POINTER(GUID), C.c_uint32, C.POINTER(C.POINTER(POLICY))]
    dll.AuditQuerySystemPolicy.restype = C.c_ubyte
    dll.AuditSetSystemPolicy.argtypes = [C.POINTER(POLICY), C.c_uint32]
    dll.AuditSetSystemPolicy.restype = C.c_ubyte
    dll.AuditFree.argtypes = [C.c_void_p]
    return dll

class LUID(C.Structure):
    _fields_ = [('low',C.c_uint32),('high',C.c_int32)]
class TOKEN_PRIVILEGES(C.Structure):
    _fields_ = [('count',C.c_uint32),('luid',LUID),('attributes',C.c_uint32)]

@contextmanager
def security_privilege():
    dll = C.WinDLL('advapi32',use_last_error=True)
    kernel = C.WinDLL('kernel32',use_last_error=True)
    dll.OpenProcessToken.argtypes=[C.c_void_p,C.c_uint32,C.POINTER(C.c_void_p)]
    dll.LookupPrivilegeValueW.argtypes=[C.c_wchar_p,C.c_wchar_p,C.POINTER(LUID)]
    dll.AdjustTokenPrivileges.argtypes=[C.c_void_p,C.c_int,C.POINTER(TOKEN_PRIVILEGES),
                                       C.c_uint32,C.POINTER(TOKEN_PRIVILEGES),C.POINTER(C.c_uint32)]
    kernel.CloseHandle.argtypes=[C.c_void_p]
    token=C.c_void_p()
    if not dll.OpenProcessToken(C.c_void_p(-1),0x28,C.byref(token)):
        raise C.WinError(C.get_last_error())
    old=TOKEN_PRIVILEGES()
    adjusted=False
    try:
        new=TOKEN_PRIVILEGES(count=1,attributes=2)
        if not dll.LookupPrivilegeValueW(None,'SeSecurityPrivilege',C.byref(new.luid)):
            raise C.WinError(C.get_last_error())
        size=C.c_uint32()
        C.set_last_error(0)
        ok=dll.AdjustTokenPrivileges(token,False,C.byref(new),C.sizeof(old),C.byref(old),C.byref(size))
        if not ok or C.get_last_error():
            raise C.WinError(C.get_last_error())
        adjusted=True
        yield
    finally:
        try:
            if adjusted:
                if not dll.AdjustTokenPrivileges(token,False,C.byref(old),0,None,None):
                    raise C.WinError(C.get_last_error())
        finally:
            kernel.CloseHandle(token)

@security_privilege()
def read():
    dll = api()
    result = {}
    for category, (label, required) in CATEGORIES.items():
        ids, count = C.POINTER(GUID)(), C.c_uint32()
        if not dll.AuditEnumerateSubCategories(C.byref(GUID.parse(category)), False, C.byref(ids), C.byref(count)):
            raise C.WinError(C.get_last_error())
        policies = C.POINTER(POLICY)()
        try:
            if not count.value or not dll.AuditQuerySystemPolicy(ids, count.value, C.byref(policies)):
                raise RuntimeError('감사 하위 범주 조회 실패: ' + label)
            for i in range(count.value):
                entry = policies[i]
                result[entry.subcategory.text()] = {'category': category, 'flags': int(entry.flags) & 3}
        finally:
            if policies:
                dll.AuditFree(policies)
            dll.AuditFree(ids)
    return result

def target(before):
    if not before or {r['category'] for r in before.values()} != set(CATEGORIES):
        raise ValueError('감사 6개 범주의 백업이 완전하지 않습니다.')
    return {key: dict(row, flags=(row['flags'] | CATEGORIES[row['category']][1]))
            for key, row in before.items()}

def compliant(values):
    return bool(values) and target(values) == values

@security_privilege()
def write(values):
    target(values)  # validate scope; restore never touches unrelated categories
    entries = (POLICY * len(values))()
    for entry, (key, row) in zip(entries, values.items()):
        if row['flags'] not in (0, 1, 2, 3):
            raise ValueError('Invalid audit flags')
        entry.subcategory = GUID.parse(key)
        entry.category = GUID.parse(row['category'])
        entry.flags = row['flags'] or 4  # zero means UNCHANGED to AuditSetSystemPolicy
    dll = api()
    if not dll.AuditSetSystemPolicy(entries, len(entries)):
        raise C.WinError(C.get_last_error())
