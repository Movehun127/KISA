# -*- coding: utf-8 -*-
"""
detector.py  –  취약점 진단 엔진 (PowerShell Detector.psm1 대체)
레지스트리, Secedit, Powershell 명령어를 Python으로 직접 실행
"""

import os
import re
import json
import glob
import winreg
import subprocess
import tempfile
import shutil
from datetime import datetime, timezone


# ── 레지스트리 경로 변환 ──────────────────────────────────────────────
_REG_ROOTS = {
    "HKLM":  winreg.HKEY_LOCAL_MACHINE,
    "HKCU":  winreg.HKEY_CURRENT_USER,
    "HKCR":  winreg.HKEY_CLASSES_ROOT,
    "HKU":   winreg.HKEY_USERS,
    "HKCC":  winreg.HKEY_CURRENT_CONFIG,
    "HKEY_LOCAL_MACHINE":  winreg.HKEY_LOCAL_MACHINE,
    "HKEY_CURRENT_USER":   winreg.HKEY_CURRENT_USER,
    "HKEY_CLASSES_ROOT":   winreg.HKEY_CLASSES_ROOT,
    "HKEY_USERS":          winreg.HKEY_USERS,
    "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG,
}

def _parse_reg_path(path: str):
    """'HKLM:\\\\Software\\\\...' 형식의 경로를 (hive, subkey)로 분리"""
    path = path.replace("/", "\\")
    parts = path.split("\\", 1)
    hive_str = parts[0].upper().rstrip(":")
    subkey   = parts[1] if len(parts) > 1 else ""
    hive     = _REG_ROOTS.get(hive_str)
    if hive is None:
        raise ValueError(f"알 수 없는 레지스트리 루트: {hive_str}")
    return hive, subkey


def reg_read(path: str, name: str):
    """레지스트리 값 읽기, 없으면 None 반환"""
    try:
        hive, subkey = _parse_reg_path(path)
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            val, _ = winreg.QueryValueEx(key, name)
            return val
    except FileNotFoundError:
        return None


def _run_ps(command: str) -> str:
    from .execution import run_ps
    return run_ps(command)


# ── Secedit 캐시 ──────────────────────────────────────────────────────
_secedit_cache: dict[str, str] = {}
_secedit_loaded = False

def _load_secedit() -> dict[str, str]:
    global _secedit_cache, _secedit_loaded
    if _secedit_loaded:
        return _secedit_cache
    from .execution import export_security_policy
    _secedit_cache = export_security_policy()
    _secedit_loaded = True
    return _secedit_cache


def _reset_secedit_cache():
    global _secedit_cache, _secedit_loaded
    _secedit_cache = {}
    _secedit_loaded = False


# ── 메인 진단 함수 ────────────────────────────────────────────────────
def get_vulnerability_status(config_path: str) -> list[dict]:
    """
    config_path: Config/Policies 폴더 경로 (또는 단일 JSON 파일 경로)
    반환값: 각 항목의 진단 결과 dict 리스트
    """
    _reset_secedit_cache()

    criteria_list = []
    if os.path.isdir(config_path):
        files = sorted(glob.glob(os.path.join(config_path, "*.json")))
        for f in files:
            with open(f, encoding="utf-8-sig") as fp:
                criteria_list.append(json.load(fp))
    else:
        with open(config_path, encoding="utf-8-sig") as fp:
            loaded = json.load(fp)
            criteria_list = loaded if isinstance(loaded, list) else [loaded]

    results = []

    for item in criteria_list:
        item_id    = item.get("ItemId", "")
        title      = item.get("Title", "")
        level      = item.get("Level", "")
        tech_type  = item.get("TechType", "")
        secure_val = str(item.get("SecureValue", "")) if item.get("SecureValue") is not None else ""

        status        = "오류"
        current_value = None

        try:
            status = "양호"
            if tech_type == "Type_Skip":
                status = f"수동 조치({item.get('Description', '')})"
                check_cmd = item.get("CheckCommand")
                current_value = _run_ps(check_cmd) if check_cmd else "N/A"

            elif tech_type == "Type_Powershell":
                check_cmd = item.get("CheckCommand", "")
                if not check_cmd:
                    raise ValueError("점검 명령 없음")
                current_value = _run_ps(check_cmd)
                if not current_value:
                    raise ValueError("점검 결과가 비어 있습니다")
                if current_value != secure_val:
                    status = "취약"

            elif tech_type == "Type_NtfsVolumes":
                current_value = json.loads(_run_ps("@(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Select-Object DeviceID,FileSystem) | ConvertTo-Json -Compress"))
                if isinstance(current_value, dict):
                    current_value = [current_value]
                if not current_value or any(not r.get('FileSystem') for r in current_value):
                    raise ValueError('고정 디스크 파일 시스템을 조회하지 못했습니다.')
                formats = {r['FileSystem'].upper() for r in current_value}
                status = ('취약' if formats & {'FAT', 'FAT32', 'EXFAT'} else
                          '양호' if formats == {'NTFS'} else '수동 조치(기타 파일 시스템 적용 범위 확인)')

            elif tech_type == "Type_SmbSession":
                from .native_actions import read_smb, smb_compliant
                current_value = read_smb()
                status = '양호' if smb_compliant(current_value) else '취약'

            elif tech_type == "Type_Firewall":
                from .native_actions import read_firewall
                current_value = read_firewall('ActiveStore')
                status = '양호' if all(v == 'True' for v in current_value.values()) else '취약'

            elif tech_type == "Type_RegistryGroup":
                from .execution import registry_settings, matches
                current_value = {}
                for setting in registry_settings(item):
                    name = setting['RegistryName']
                    value = reg_read(item['RegistryPath'], name)
                    if value is None and item.get('FallbackRegistryPath'):
                        value = reg_read(item['FallbackRegistryPath'], name)
                    current_value[name] = value
                    if value is None or not matches(value, setting['SecureValue'], setting.get('Comparison', 'eq')):
                        status = '취약'

            elif tech_type == "Type_Registry":
                reg_path = item.get("RegistryPath", "")
                reg_name = item.get("RegistryName", "")
                current_value = reg_read(reg_path, reg_name)
                if current_value is None:
                    if secure_val:
                        status = "취약"
                    current_value = "Not Found"
                else:
                    from .execution import matches
                    if not matches(current_value, item.get("SecureValue"), item.get("Comparison", "eq")):
                        status = "취약"

            elif tech_type == "Type_Secedit":
                sec = _load_secedit()
                key = item.get("SeceditKey", "")
                current_value = sec.get(key, "Not Found")
                from .execution import matches
                values = item.get("SeceditValues", {key: item.get("SecureValue")})
                current_value = {k: sec.get(k) for k in values}
                if any(v is None for v in current_value.values()):
                    raise ValueError("보안 정책 값을 읽지 못했습니다")
                if not all(matches(current_value[k], target, item.get("Comparisons", {}).get(k, "eq"))
                           for k, target in values.items()):
                    status = "취약"

            elif tech_type == "Type_Defender":
                try:
                    ps_out = _run_ps(
                        "(Get-MpComputerStatus -ErrorAction SilentlyContinue)"
                        ".AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd')"
                    )
                    if ps_out:
                        last_update = datetime.strptime(ps_out, "%Y-%m-%d")
                        days = (datetime.now() - last_update).days
                        if days > 7:
                            status = "취약"
                            current_value = f"Outdated ({days} days)"
                        else:
                            current_value = "UpToDate"
                    else:
                        status = "취약"
                        current_value = "Defender Not Found"
                except Exception as e:
                    status = "취약"
                    current_value = f"Error: {e}"

            elif tech_type == "Type_Python_ServiceCheck":
                target_services_raw = item.get("targetItem") or item.get("targetServices") or []
                target_services = []
                for s in target_services_raw:
                    if isinstance(s, dict):
                        target_services.append(s.get("name"))
                    else:
                        target_services.append(s)
                
                if not target_services:
                    status = "오류"
                    current_value = "대상 서비스 없음"
                else:
                    running_count = 0
                    for svc in target_services:
                        # 서비스가 실행 중이거나 시작 유형이 Disabled가 아니면 취약
                        ps_out = _run_ps(
                            f"$s = Get-Service -Name '{svc}' -ErrorAction SilentlyContinue; "
                            "if ($null -ne $s) { "
                            "  if ($s.Status -eq 'Running' -or $s.StartType -ne 'Disabled') { 'Vulnerable' } "
                            "}"
                        )
                        if ps_out.strip() == "Vulnerable":
                            running_count += 1
                    
                    if running_count > 0:
                        status = "취약"
                        current_value = f"{running_count}개 미흡"
                    else:
                        status = "양호"
                        current_value = "모두 중지 및 사용안함"

            else:
                raise ValueError(f"지원하지 않는 진단 유형: {tech_type}")

        except Exception as e:
            status = "오류"
            current_value = f"Error: {e}"

        results.append({
            "ItemId":       item_id,
            "Title":        title,
            "Level":        level,
            "TechType":     tech_type,
            "Status":       status,
            "CurrentValue": current_value,
            "SecureValue":  secure_val,
            "ConfigItem":   item,
        })

    return results
