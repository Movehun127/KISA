# -*- coding: utf-8 -*-
"""
remediator.py  –  보안 조치 엔진 (PowerShell Remediation.psm1 대체)
레지스트리 쓰기, Secedit 적용, Powershell 명령 실행
"""

import os
import json
import winreg
import subprocess
import tempfile
import shutil
from datetime import datetime


# ── 레지스트리 경로 변환 ─────────────────────────────────────────────
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
_REG_TYPES = {
    "DWord":      winreg.REG_DWORD,
    "DWORD":      winreg.REG_DWORD,
    "QWord":      winreg.REG_QWORD,
    "QWORD":      winreg.REG_QWORD,
    "String":     winreg.REG_SZ,
    "REG_SZ":     winreg.REG_SZ,
    "ExpandString": winreg.REG_EXPAND_SZ,
    "Binary":     winreg.REG_BINARY,
    "MultiString": winreg.REG_MULTI_SZ,
}

def _parse_reg_path(path: str):
    path = path.replace("/", "\\")
    parts = path.split("\\", 1)
    hive_str = parts[0].upper().rstrip(":")
    subkey   = parts[1] if len(parts) > 1 else ""
    hive     = _REG_ROOTS.get(hive_str)
    if hive is None:
        raise ValueError(f"알 수 없는 레지스트리 루트: {hive_str}")
    return hive, subkey


def _run_ps(command: str) -> str:
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive",
         "-ExecutionPolicy", "Bypass", "-Command", command],
        capture_output=True, text=True, timeout=60,
        creationflags=subprocess.CREATE_NO_WINDOW
    )
    return result.stdout.strip()


def reg_read(path: str, name: str):
    try:
        hive, subkey = _parse_reg_path(path)
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            val, _ = winreg.QueryValueEx(key, name)
            return val
    except Exception:
        return None


def reg_write(path: str, name: str, value, reg_type: str = "DWord"):
    hive, subkey = _parse_reg_path(path)
    wtype = _REG_TYPES.get(reg_type, winreg.REG_DWORD)
    # DWord 값은 정수 변환
    if wtype in (winreg.REG_DWORD, winreg.REG_QWORD):
        value = int(value)
    with winreg.CreateKeyEx(hive, subkey, 0, winreg.KEY_WRITE) as key:
        winreg.SetValueEx(key, name, 0, wtype, value)


# ── 메인 조치 함수 ────────────────────────────────────────────────────
def invoke_remediation(
    vulnerability_results: list[dict],
    backup_dir: str,
    evidence_dir: str = "",
    log_callback=None
) -> None:
    """
    취약 항목에 대해 자동 보안 조치를 수행합니다.
    log_callback(msg, level): GUI 로그 출력용 콜백 (optional)
    level: 'info' | 'good' | 'warn' | 'error'
    """
    os.makedirs(backup_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def log(msg, level="info"):
        if log_callback:
            log_callback(msg, level)

    for result in vulnerability_results:
        status    = result.get("Status", "")
        item      = result.get("ConfigItem", {})
        item_id   = result.get("ItemId", "")
        tech_type = result.get("TechType", "")

        # 양호 / 수동조치 항목은 건너뜀
        if "양호" in status or "수동 조치" in status:
            log(f"[{item_id}] 상태 양호 – 조치 건너뜀", "good")
            continue

        log(f"[{item_id}] 취약 → 자동 보안 조치 적용 중... ({tech_type})", "warn")
        backup_file = os.path.join(backup_dir, f"{item_id}_{timestamp}.bak")
        rollback = None

        try:
            if tech_type == "Type_Powershell":
                prev = result.get("CurrentValue", "")
                with open(backup_file, "w", encoding="utf-8") as bf:
                    bf.write(f"PreviousState={prev}")
                cmd = item.get("RemediationCommand", "")
                if cmd:
                    _run_ps(cmd)

            elif tech_type == "Type_Registry":
                reg_path = item.get("RegistryPath", "")
                reg_name = item.get("RegistryName", "")
                reg_type = item.get("RegistryType", "DWord")
                prev_val = reg_read(reg_path, reg_name)
                with open(backup_file, "w", encoding="utf-8") as bf:
                    json.dump({reg_name: prev_val}, bf, ensure_ascii=False)

                def _rollback_reg(rp=reg_path, rn=reg_name, rt=reg_type, pv=prev_val):
                    if pv is not None:
                        reg_write(rp, rn, pv, rt)

                rollback = _rollback_reg
                reg_write(reg_path, reg_name, item.get("SecureValue"), reg_type)

            elif tech_type == "Type_Secedit":
                key      = item.get("SeceditKey", "")
                sec_val  = item.get("SecureValue", "")
                sec_temp = os.path.join(tempfile.gettempdir(), "sec_backup.inf")
                subprocess.run(
                    ["secedit", "/export", "/cfg", sec_temp, "/quiet"],
                    capture_output=True, timeout=30,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                shutil.copy2(sec_temp, backup_file)

                def _rollback_sec(bf=backup_file):
                    sdb = os.path.join(tempfile.gettempdir(), "sec_rollback.sdb")
                    subprocess.run(
                        ["secedit", "/configure", "/db", sdb, "/cfg", bf, "/quiet"],
                        capture_output=True, timeout=60,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )

                rollback = _rollback_sec

                with open(sec_temp, encoding="utf-16-le", errors="replace") as f:
                    content = f.read()
                import re
                content = re.sub(
                    rf"^{re.escape(key)}\s*=.*",
                    f"{key} = {sec_val}",
                    content, flags=re.MULTILINE
                )
                with open(sec_temp, "w", encoding="utf-16-le") as f:
                    f.write(content)
                sdb = os.path.join(tempfile.gettempdir(), "sec_apply.sdb")
                subprocess.run(
                    ["secedit", "/configure", "/db", sdb, "/cfg", sec_temp, "/quiet"],
                    capture_output=True, timeout=60,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                if os.path.exists(sec_temp):
                    os.remove(sec_temp)

            elif tech_type == "Type_Defender":
                with open(backup_file, "w", encoding="utf-8") as bf:
                    bf.write("Signature Update Triggered")
                log(f"  → Defender 서명 업데이트를 백그라운드로 시작합니다.", "info")
                _run_ps("Update-MpSignature")

            elif tech_type == "Type_Python_ServiceCheck":
                target_services_raw = item.get("targetItem") or item.get("targetServices") or []
                target_services = []
                for s in target_services_raw:
                    if isinstance(s, dict):
                        target_services.append(s.get("name"))
                    else:
                        target_services.append(s)
                
                failed_services = []
                with open(backup_file, "w", encoding="utf-8") as bf:
                    bf.write("Service remediation triggered for: " + ", ".join(target_services))
                
                for svc in target_services:
                    # 서비스 중지 및 비활성화 (오류 무시)
                    stop_cmd = f"Stop-Service -Name '{svc}' -Force -ErrorAction SilentlyContinue; Set-Service -Name '{svc}' -StartupType Disabled -ErrorAction SilentlyContinue"
                    _run_ps(stop_cmd)
                    
                    # 조치 후 상태 확인
                    ps_out = _run_ps(f"(Get-Service -Name '{svc}' -ErrorAction SilentlyContinue).Status").strip()
                    if ps_out == "Running":
                        failed_services.append(svc)
                
                if failed_services:
                    fail_note = f"~~서비스 종료 X ({', '.join(failed_services[:3])})"
                    result["Note"] = fail_note
                    log(f"  → 일부 서비스 종료 실패: {fail_note}", "warn")

            log(f"  → 조치 완료 / 백업: {backup_file}", "good")

        except Exception as e:
            log(f"  → [오류] 자동 조치 실패: {e}", "error")
            if rollback:
                try:
                    rollback()
                    log(f"  → 롤백 성공", "info")
                except Exception as re_err:
                    log(f"  → 롤백 실패: {re_err}", "error")
