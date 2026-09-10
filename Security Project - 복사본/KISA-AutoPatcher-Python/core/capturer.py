# -*- coding: utf-8 -*-
"""
capturer.py  –  화면 자동 캡처 엔진 (C# UIAutomation → Python uiautomation)
Windows 설정 창을 자동으로 탐색하고 증빙 스크린샷을 캡처합니다.
"""

import os
import time
import subprocess
import threading
import ctypes
from datetime import datetime
try:
    import uiautomation as auto
except ImportError:
    auto = None

try:
    import pyautogui
except ImportError:
    pyautogui = None

import ctypes
user32 = ctypes.windll.user32

def _init_com():
    """백그라운드 스레드에서 COM(UI Automation)이 동작할 수 있도록 초기화"""
    try:
        ctypes.oledll.ole32.CoInitialize(None)
    except Exception:
        pass


# ── 복수의 서브아이템 정규화 처리 ───────────────────────────────────
def _normalize_item_id(item_id: str) -> str:
    """W-01_Complexity → W-01 처럼 숫자 부분만"""
    return item_id.split("_")[0]


def _take_screenshot(save_path: str, target_ctrl=None):
    """지정된 컨트롤 영역 또는 전체 화면 스크린샷 저장"""
    try:
        rect = None
        if target_ctrl:
            try:
                # 대상 윈도우 컨트롤의 영역(Bounding Rectangle) 가져오기
                rect = target_ctrl.BoundingRectangle
            except Exception:
                pass

        if rect and pyautogui:
            # 타겟 설정창 영역만 크롭하여 캡처 (Left, Top, Width, Height)
            w = rect.right - rect.left
            # DPI 스케일 감안하여 비정상적인 값 방어
            h = rect.bottom - rect.top
            if w > 100 and h > 100:
                img = pyautogui.screenshot(region=(rect.left, rect.top, w, h))
                img.save(save_path)
                return
        
        # 폴백: pyautogui를 통한 전체화면 캡처
        if pyautogui:
            img = pyautogui.screenshot()
            img.save(save_path)
        else:
            # fallback: PowerShell을 통한 스크린샷
            subprocess.run([
                "powershell", "-Command",
                f"Add-Type -AssemblyName System.Windows.Forms; "
                f"$b=[System.Drawing.Bitmap]::new([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width,"
                f"[System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height);"
                f"$g=[System.Drawing.Graphics]::FromImage($b);"
                f"$g.CopyFromScreen(0,0,0,0,$b.Size);"
                f"$b.Save('{save_path}');"
                f"$g.Dispose();$b.Dispose()"
            ], capture_output=True, timeout=15)
    except Exception:
        pass


def _spawn_app(app_name: str, item_id: str = "") -> subprocess.Popen | None:
    """지정된 앱 실행 (cmd 번쩍임 제거를 위해 shell=True 미사용)"""
    try:
        # 윈도우 콘솔창 생성 플래그 차단 (CLI 툴용)
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0 # SW_HIDE

        # 1. 특수 제어판 단축어 (control userpasswords2 등 인자가 있는 경우)
        if app_name.startswith("control "):
            parts = app_name.split(" ", 1)
            try:
                os.startfile("control.exe", operation="open", arguments=parts[1])
            except Exception:
                subprocess.Popen(["control.exe", parts[1]])
            return None

        # 2. UWP 설정, 제어판 스냅인(.cpl), MMC 콘솔(.msc), 레지스트리/시스템 기본 GUI 실행파일들
        gui_apps = ["regedit", "winver", "odbcad32.exe"]
        is_gui = (
            app_name.startswith("ms-settings:") or 
            app_name.startswith("windowsdefender:") or 
            app_name.endswith(".cpl") or 
            app_name.endswith(".msc") or 
            any(x in app_name for x in gui_apps)
        )
        
        if is_gui:
            os.startfile(app_name)
            return None
            
        # 3. 기타 백그라운드 CLI 프로그램용 폴백 (숨김 기동 필요)
        p = subprocess.Popen([app_name], startupinfo=startupinfo)
        return p
    except Exception:
        return None


def _set_clipboard_text(text: str) -> bool:
    """Windows API를 사용하여 클립보드에 텍스트를 복사합니다 (외부 의존성 없음)"""
    try:
        import ctypes
        from ctypes import wintypes
        
        # Open clipboard
        if not ctypes.windll.user32.OpenClipboard(None):
            return False
        try:
            # Empty clipboard
            ctypes.windll.user32.EmptyClipboard()
            
            # UTF-16-LE 인코딩 및 널 문자 종료 처리
            data = text.encode('utf-16-le') + b'\x00\x00'
            
            # GMEM_MOVEABLE = 0x0002
            h_global = ctypes.windll.kernel32.GlobalAlloc(0x0002, len(data))
            if not h_global:
                return False
            
            p_global = ctypes.windll.kernel32.GlobalLock(h_global)
            ctypes.memmove(p_global, data, len(data))
            ctypes.windll.kernel32.GlobalUnlock(h_global)
            
            # CF_UNICODETEXT = 13
            if not ctypes.windll.user32.SetClipboardData(13, h_global):
                ctypes.windll.kernel32.GlobalFree(h_global)
                return False
        finally:
            ctypes.windll.user32.CloseClipboard()
        return True
    except Exception:
        return False


def _set_regedit_lastkey(reg_path: str):
    """
    regedit.exe 실행 전에 LastKey 값을 원하는 경로로 강제 설정하여
    기동 시 자동으로 해당 레지스트리 경로로 바로 진입하도록 함.
    """
    if not reg_path:
        return
    
    # 윈도우 한글/영문 에디션에 따른 "컴퓨터" 또는 "Computer" 루트 노드 표준 규격 보정
    normalized_path = reg_path
    if not normalized_path.startswith("컴퓨터\\") and not normalized_path.startswith("Computer\\"):
        normalized_path = "컴퓨터\\" + normalized_path
        
    try:
        import winreg
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Applets\Regedit"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "LastKey", 0, winreg.REG_SZ, normalized_path)
    except Exception:
        pass


def _show_file_properties(file_path: str):
    """
    ctypes ShellExecuteExW API를 사용하여 지정된 파일 또는 폴더의 속성 대화상자를 안정적으로 기동시킵니다.
    """
    import ctypes
    from ctypes import wintypes

    class SHELLEXECUTEINFO(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD),
            ("fMask", ctypes.c_ulong),
            ("hwnd", wintypes.HWND),
            ("lpVerb", ctypes.c_wchar_p),
            ("lpFile", ctypes.c_wchar_p),
            ("lpParameters", ctypes.c_wchar_p),
            ("lpDirectory", ctypes.c_wchar_p),
            ("nShow", ctypes.c_int),
            ("hInstApp", wintypes.HINSTANCE),
            ("lpIDList", ctypes.c_void_p),
            ("lpClass", ctypes.c_wchar_p),
            ("hkeyClass", wintypes.HANDLE),
            ("dwHotKey", wintypes.DWORD),
            ("hIconOrMonitor", wintypes.HANDLE),
            ("hProcess", wintypes.HANDLE)
        ]

    SEE_MASK_INVOKEIDLIST = 0x0000000c
    SW_SHOW = 5

    sei = SHELLEXECUTEINFO()
    sei.cbSize = ctypes.sizeof(SHELLEXECUTEINFO)
    sei.fMask = SEE_MASK_INVOKEIDLIST
    sei.lpVerb = "properties"
    sei.lpFile = file_path
    sei.nShow = SW_SHOW

    try:
        ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei))
    except Exception:
        pass


def _navigate_to_reg_path(reg_path: str):
    """
    레지스트리 편집기에서 특정 경로로 이동
    (한글/백슬래시 이슈 방지 및 윈도우 주소창 단축키 Alt+D 결합)
    """
    if not auto:
        return
    try:
        time.sleep(1.5)
        regedit_win = auto.WindowControl(searchDepth=1, ClassName="RegEdit_RegEdit")
        if not regedit_win.Exists(3):
            return
        
        # 주소창 포커스
        regedit_win.SetActive()
        regedit_win.SetFocus()

        # ── regedit 창을 오른쪽 절반에 맞추기 ──
        import pyautogui
        screen_w, screen_h = pyautogui.size()
        half_w = screen_w // 2
        
        # 최대화 창 강제 해제 (SW_RESTORE = 9)
        hwnd = regedit_win.Handle
        ctypes.windll.user32.ShowWindow(hwnd, 9)
        time.sleep(0.1)
        
        ctypes.windll.user32.SetWindowPos(hwnd, 0, half_w, 0, half_w, screen_h - 40, 0x0040)
        time.sleep(0.3)

        # 클립보드에 경로 복사
        _set_clipboard_text(reg_path)
        time.sleep(0.1)

        import pyautogui as pag
        
        # 1순위: UIA 주소창 EditControl 직접 탐색 후 클릭/포커스
        address_bar = None
        try:
            address_bar = regedit_win.EditControl(searchDepth=4)
        except Exception:
            pass

        if address_bar and address_bar.Exists(0.5):
            address_bar.Click()
            address_bar.SetFocus()
            pag.hotkey("ctrl", "a")
            time.sleep(0.1)
            pag.hotkey("ctrl", "v")
        else:
            # 2순위 폴백: 레지스트리 편집기 전용 주소창 진입 단축키 Alt + D 송신 (Ctrl + L은 브라우저용 단축키임)
            pag.hotkey("alt", "d")
            time.sleep(0.3)
            pag.hotkey("ctrl", "a")
            time.sleep(0.1)
            pag.hotkey("ctrl", "v")
            
        time.sleep(0.2)
        # 이동 (Enter)
        pag.press("enter")
        time.sleep(1.5)
    except Exception:
        pass


def _navigate_wins_properties(log_callback=None):
    """
    네트워크 연결 창에서 이더넷/로컬 영역 연결 선택 -> 속성 -> IPv4 속성 -> 고급 -> WINS 탭 이동
    """
    def log(msg, level="info"):
        if log_callback:
            log_callback(msg, level)

    if not auto:
        return

    # 1. 네트워크 연결 창 획득
    net_win = None
    for attempt in range(30):
        wins = auto.GetRootControl().GetChildren()
        for w in wins:
            w_name = w.Name or ""
            if "네트워크 연결" in w_name or "Network Connections" in w_name:
                net_win = w
                break
        if net_win:
            break
            
        # 10번째 시도(약 2초 대기)까지 창이 감지되지 않으면 explorer.exe를 통한 폴백 기동 시도
        if attempt == 10:
            try:
                sys_root = os.environ.get("SystemRoot", "C:\\Windows")
                explorer_path = os.path.join(sys_root, "explorer.exe")
                subprocess.Popen([explorer_path, "shell:::{7007ACC7-3202-11D1-AAD2-00805FC1270E}"])
            except Exception:
                pass
                
        time.sleep(0.2)

    if not net_win:
        log("  [경고] 네트워크 연결 창을 발견할 수 없습니다.", "warn")
        return

    log("    -> 네트워크 연결 창 감지 성공. 활성 연결 탐색...", "info")
    net_win.SetActive()
    net_win.SetFocus()

    # 창 절반 크기 조절
    try:
        import pyautogui
        sw, sh = pyautogui.size()
        hw = sw // 2
        ctypes.windll.user32.ShowWindow(net_win.NativeWindowHandle, 9)
        time.sleep(0.1)
        ctypes.windll.user32.SetWindowPos(net_win.NativeWindowHandle, 0, hw, 0, hw, sh - 40, 0x0040)
    except Exception:
        pass

    # ── [사전 확인] 속성 대화상자가 이미 열려있는지 검사 ──
    prop_dlg = None
    # 1순위: '이더넷 속성', 'Wi-Fi 속성', '로컬 영역 연결 속성', 'Ethernet Properties' 등 구체적인 창 탐색 (WindowControl로 직접 찾기)
    for title in ["이더넷 속성", "Wi-Fi 속성", "로컬 영역 연결 속성", "Ethernet Properties"]:
        temp_dlg = auto.WindowControl(searchDepth=1, ClassName="#32770", Name=title)
        if temp_dlg.Exists(0.2):
            prop_dlg = temp_dlg
            log(f"    => 속성 대화상자('{title}')가 이미 열려있음을 감지했습니다. 바로 다음 단계로 진입합니다.", "good")
            break

    # 2순위: 구체적인 이름을 못 찾은 경우 임의의 #32770 창 중 이름에 '속성'이 들어가는지 대조
    if not prop_dlg:
        try:
            # Desktop Root 레벨 검색
            wins = auto.GetRootControl().GetChildren()
            for w in wins:
                w_name = w.Name or ""
                if w.ClassName == "#32770" and ("속성" in w_name or "Properties" in w_name):
                    prop_dlg = w
                    log(f"    => 활성 속성 대화상자('{w_name}')를 감지했습니다. 바로 다음 단계로 진입합니다.", "good")
                    break
                    
            # 별도 프로세스로 노출되지 않고 net_win 자식으로 팝업된 경우 검색
            if not prop_dlg and net_win:
                for w in net_win.GetChildren():
                    w_name = w.Name or ""
                    if w.ClassName == "#32770" and ("속성" in w_name or "Properties" in w_name):
                        prop_dlg = w
                        log(f"    => 네트워크 연결 자식 속성 대화상자('{w_name}')를 감지했습니다. 바로 다음 단계로 진입합니다.", "good")
                        break
        except Exception:
            pass

    # ── 속성 대화상자가 열려있지 않은 경우에만 어댑터 선택 및 기동 조작 수행 ──
    if not prop_dlg:
        # 2. 이더넷 또는 로컬 영역 연결 등의 어댑터 찾기 (Wi-Fi 제외, 오직 이더넷만 대상)
        adapter_names = ["이더넷", "Ethernet", "로컬 영역 연결", "Local Area Connection"]
        target_adapter = None
        
        # 1순위: ListControl (UIItemsView) 탐색 후 하위 아이템 순회 (가장 빠르고 정확함)
        list_ctrl = net_win.ListControl(searchDepth=9, ClassName="UIItemsView")
        if list_ctrl.Exists(1.0):
            for child in list_ctrl.GetChildren():
                s_name = child.Name or ""
                if any(name.lower() in s_name.lower() for name in adapter_names):
                    target_adapter = child
                    log(f"      => 연결 어댑터 발견 (ListControl 순회): '{s_name}'", "info")
                    break
                    
        # 2순위: 직접 쿼리 (searchDepth 9로 상향)
        if not target_adapter or not target_adapter.Exists(0.1):
            for name in adapter_names:
                try:
                    target_adapter = net_win.ListItemControl(searchDepth=9, Name=name)
                    if target_adapter.Exists(0.1):
                        log(f"      => 연결 어댑터 발견 (직접 쿼리): '{name}'", "info")
                        break
                except Exception:
                    pass

        if not target_adapter or not target_adapter.Exists(0.5):
            log("  [오류] 네트워크 어댑터 리스트를 획득할 수 없습니다.", "warn")
            return

        # 3. 어댑터 속성창 열기 (마우스 우클릭 후 속성 메뉴 진입 또는 Alt+Enter)
        target_adapter.Click()
        time.sleep(0.2)
        target_adapter.SendKeys("{ALT}{ENTER}") # 속성 단축키
        time.sleep(1.0)

        # UIPI 등으로 인해 Alt+Enter가 차단된 경우 우클릭 + 'r' 단축키 폴백 시도
        prop_opened = False
        wins = auto.GetRootControl().GetChildren()
        for w in wins:
            if w.ClassName == "#32770" and ("속성" in (w.Name or "") or "Properties" in (w.Name or "")):
                prop_opened = True
                break
        if not prop_opened and net_win:
            try:
                for w in net_win.GetChildren():
                    if w.ClassName == "#32770" and ("속성" in (w.Name or "") or "Properties" in (w.Name or "")):
                        prop_opened = True
                        break
            except Exception:
                pass
                
        if not prop_opened:
            log("      => Alt+Enter 작동 실패. 우클릭 및 컨텍스트 메뉴 클릭 폴백 시도...", "info")
            target_adapter.RightClick()
            time.sleep(0.6)
            try:
                # 윈도우 기본 팝업 컨텍스트 메뉴 클래스인 #32768 창 획득
                menu_win = auto.WindowControl(searchDepth=1, ClassName="#32768")
                if menu_win.Exists(1.0):
                    prop_item = None
                    # 다국어(속성(R), 속성, Properties) 매핑 대응
                    for menu_name in ["속성(R)", "속성", "Properties"]:
                        prop_item = menu_win.MenuItemControl(searchDepth=2, Name=menu_name)
                        if prop_item.Exists(0.1):
                            break
                    
                    if prop_item and prop_item.Exists(0.2):
                        prop_item.Click()
                        log("      => 컨텍스트 메뉴에서 '속성' 항목 클릭 성공.", "info")
                    else:
                        auto.SendKeys("r")
                else:
                    auto.SendKeys("r")
            except Exception as ex:
                log(f"      => 컨텍스트 메뉴 제어 오류: {ex}", "warn")
                auto.SendKeys("r")
            time.sleep(1.5)

    # 4. 속성 대화상자(#32770) 대기 (열려있지 않던 경우 대기 진행)
    if not prop_dlg:
        for _ in range(50):
            wins = auto.GetRootControl().GetChildren()
            for w in wins:
                if w.ClassName == "#32770" and ("속성" in (w.Name or "") or "Properties" in (w.Name or "")):
                    prop_dlg = w
                    break
            if prop_dlg:
                break
                
            # net_win 자식 중에서도 속성창 탐색 (별도 독립 윈도우 프로세스로 표시되지 않는 구조 대비)
            if net_win:
                try:
                    for w in net_win.GetChildren():
                        if w.ClassName == "#32770" and ("속성" in (w.Name or "") or "Properties" in (w.Name or "")):
                            prop_dlg = w
                            break
                except Exception:
                    pass
            if prop_dlg:
                break
            time.sleep(0.2)

    if not prop_dlg:
        log("  [오류] 네트워크 속성 대화상자를 열지 못했습니다.", "warn")
        try:
            log("    [디버그] 현재 감지된 모든 탑레벨 윈도우 목록:", "info")
            for w in auto.GetRootControl().GetChildren():
                log(f"      - 이름: '{w.Name}', 클래스: '{w.ClassName}'", "info")
        except Exception:
            pass
        return

    log("    -> 네트워크 속성창 진입 성공. TCP/IPv4 프로토콜 탐색...", "info")
    prop_dlg.SetActive()
    prop_dlg.SetFocus()

    # 5. 인터넷 프로토콜 버전 4(TCP/IPv4) 찾기 및 더블클릭
    ipv4_item = None
    ipv4_names = ["인터넷 프로토콜 버전 4(TCP/IPv4)", "Internet Protocol Version 4 (TCP/IPv4)"]
    
    # 리스트 포커스 후 Home 키로 맨 위 이동 후 Down 탐색 가속
    list_box = prop_dlg.ListControl(searchDepth=3)
    if list_box.Exists(0.5):
        # 마우스 클릭 대신 포커스만 주어 체크박스가 오작동으로 토글되는 현상 원천 차단
        list_box.SetFocus()
        list_box.SendKeys("{HOME}")
        time.sleep(0.2)
        
        last_item_name = None
        for _ in range(25):
            curr_focused = auto.GetFocusedControl()
            if curr_focused:
                curr_n = curr_focused.Name or ""
                if last_item_name and curr_n == last_item_name:
                    break
                last_item_name = curr_n
                
                if any(x in curr_n for x in ipv4_names):
                    ipv4_item = curr_focused
                    log(f"      => 프로토콜 선택됨: '{curr_n}'", "info")
                    break
            list_box.SendKeys("{DOWN}")
            time.sleep(0.05)

    if not ipv4_item:
        log("  [오류] TCP/IPv4 프로토콜 항목을 찾지 못했습니다.", "warn")
        return

    # TCP/IPv4의 속성 진입 수행 (Enter키는 대화상자 확인/종료를 트리거하므로 속성 버튼 클릭 또는 더블클릭 사용)
    prop_btn = None
    for btn_name in ["속성(R)", "속성", "Properties"]:
        temp_btn = prop_dlg.ButtonControl(searchDepth=3, Name=btn_name)
        if temp_btn.Exists(0.2):
            prop_btn = temp_btn
            break
            
    if prop_btn and prop_btn.Exists(0.2):
        prop_btn.Click()
        log("      => '속성(R)' 버튼 클릭 성공.", "info")
    else:
        # 폴백: 항목 더블클릭 수행
        ipv4_item.DoubleClick()
        log("      => 프로토콜 더블클릭 수행.", "info")
    time.sleep(1.0)

    # 6. IPv4 속성 대화상자 대기 (진입 로드 고려하여 10초로 대기시간 연장)
    ip_dlg = None
    for _ in range(50):
        # Capture must never accept a network configuration change dialog.
        # 1순위: Desktop Root 레벨 검색
        wins = auto.GetRootControl().GetChildren()
        for w in wins:
            w_name = w.Name or ""
            if w.ClassName == "#32770" and ("TCP/IP" in w_name or "Protocol" in w_name or "프로토콜" in w_name or "IPv4" in w_name):
                ip_dlg = w
                break
        if ip_dlg:
            break
            
        # 2순위: 부모 창인 prop_dlg의 자식에서 검색 (다이얼로그가 중첩 구조로 종속 활성화된 경우)
        if prop_dlg:
            try:
                for w in prop_dlg.GetChildren():
                    w_name = w.Name or ""
                    if w.ClassName == "#32770" and ("TCP/IP" in w_name or "Protocol" in w_name or "프로토콜" in w_name or "IPv4" in w_name):
                        ip_dlg = w
                        break
            except Exception:
                pass
        if ip_dlg:
            break
            
        # 3순위: net_win 자식에서 검색
        if net_win:
            try:
                for w in net_win.GetChildren():
                    w_name = w.Name or ""
                    if w.ClassName == "#32770" and ("TCP/IP" in w_name or "Protocol" in w_name or "프로토콜" in w_name or "IPv4" in w_name):
                        ip_dlg = w
                        break
            except Exception:
                pass
        if ip_dlg:
            break

        time.sleep(0.2)

    if not ip_dlg:
        log("  [오류] TCP/IPv4 속성 창 진입에 실패했습니다.", "warn")
        try:
            log("    [디버그] 현재 감지된 모든 탑레벨 윈도우 목록:", "info")
            for w in auto.GetRootControl().GetChildren():
                log(f"      - 이름: '{w.Name}', 클래스: '{w.ClassName}'", "info")
            if prop_dlg:
                log("    [디버그] prop_dlg 자식 윈도우 목록:", "info")
                for w in prop_dlg.GetChildren():
                    log(f"      - 이름: '{w.Name}', 클래스: '{w.ClassName}'", "info")
        except Exception:
            pass
        return

    log("    -> TCP/IPv4 속성창 진입 성공. '고급' 설정 진입...", "info")
    ip_dlg.SetActive()
    ip_dlg.SetFocus()

    # 7. 고급(V) 버튼 클릭
    advanced_btn = None
    btn_names = ["고급(V)...", "고급(V)", "Advanced..."]
    for btn_n in btn_names:
        advanced_btn = ip_dlg.ButtonControl(searchDepth=3, Name=btn_n)
        if advanced_btn.Exists(0.2):
            break

    if not advanced_btn or not advanced_btn.Exists(0.5):
        # Fallback: Alt+V 전송으로 고급 버튼 단축키 입력
        ip_dlg.SendKeys("%v")
    else:
        advanced_btn.Click()
    time.sleep(1.0)

    # 8. 고급 TCP/IP 설정 대화상자 대기 (진입 부하 고려하여 10초 대기)
    adv_dlg = None
    for _ in range(50):
        # 1순위: Desktop Root 레벨 검색
        wins = auto.GetRootControl().GetChildren()
        for w in wins:
            w_name = w.Name or ""
            if w.ClassName == "#32770" and ("고급 TCP/IP" in w_name or "Advanced TCP/IP" in w_name):
                adv_dlg = w
                break
        if adv_dlg:
            break
            
        # 2순위: 부모 창인 ip_dlg의 자식에서 검색
        if ip_dlg:
            try:
                for w in ip_dlg.GetChildren():
                    w_name = w.Name or ""
                    if w.ClassName == "#32770" and ("고급 TCP/IP" in w_name or "Advanced TCP/IP" in w_name):
                        adv_dlg = w
                        break
            except Exception:
                pass
        if adv_dlg:
            break
            
        # 3순위: 상위 창인 prop_dlg의 자식에서 검색
        if prop_dlg:
            try:
                for w in prop_dlg.GetChildren():
                    w_name = w.Name or ""
                    if w.ClassName == "#32770" and ("고급 TCP/IP" in w_name or "Advanced TCP/IP" in w_name):
                        adv_dlg = w
                        break
            except Exception:
                pass
        if adv_dlg:
            break
            
        # 4순위: net_win 자식에서 검색
        if net_win:
            try:
                for w in net_win.GetChildren():
                    w_name = w.Name or ""
                    if w.ClassName == "#32770" and ("고급 TCP/IP" in w_name or "Advanced TCP/IP" in w_name):
                        adv_dlg = w
                        break
            except Exception:
                pass
        if adv_dlg:
            break

        time.sleep(0.2)

    if not adv_dlg:
        log("  [오류] 고급 TCP/IP 설정창 진입에 실패했습니다.", "warn")
        try:
            log("    [디버그] 현재 감지된 모든 탑레벨 윈도우 목록:", "info")
            for w in auto.GetRootControl().GetChildren():
                log(f"      - 이름: '{w.Name}', 클래스: '{w.ClassName}'", "info")
            if ip_dlg:
                log("    [디버그] ip_dlg 자식 윈도우 목록:", "info")
                for w in ip_dlg.GetChildren():
                    log(f"      - 이름: '{w.Name}', 클래스: '{w.ClassName}'", "info")
        except Exception:
            pass
        return

    log("    -> 고급 TCP/IP 설정 진입 성공. 'WINS' 탭 획득...", "info")
    adv_dlg.SetActive()
    adv_dlg.SetFocus()

    # 9. WINS 탭 선택 (TabItemControl)
    wins_tab = None
    for _ in range(10):
        wins_tab = adv_dlg.TabItemControl(searchDepth=3, Name="WINS")
        if wins_tab.Exists(0.2):
            wins_tab.Click()
            log("    => 최종 WINS 속성 화면 활성화 성공.", "good")
            time.sleep(0.5)
            break
        time.sleep(0.2)

    if not wins_tab or not wins_tab.Exists(0.5):
        log("  [경고] 'WINS' 탭을 UIA 클릭할 수 없어 단축키(Ctrl+Tab)로 이동 시도.", "info")
        # 고급 설정창에서 Ctrl+Tab 2회로 WINS 이동 시도 (IP 설정 -> DNS -> WINS)
        adv_dlg.SendKeys("^{TAB}")
        time.sleep(0.2)
        adv_dlg.SendKeys("^{TAB}")
        time.sleep(0.5)

    # Read-only evidence: leave the current NetBIOS radio selection unchanged.


def _navigate_msc_tree(item: dict, log_callback=None):
    """
    MSC(secpol/gpedit) 창에서 treePath 따라 트리 탐색 후 targetItem 선택
    uiautomation 기반
    """
    def log(msg, level="info"):
        if log_callback:
            log_callback(msg, level)

    if not auto:
        log("  [오류] uiautomation 모듈이 로드되지 않았습니다.", "warn")
        return
    tree_path  = item.get("treePath") or []
    target_items = item.get("targetItem") or []

    log(f"  [진행] MSC 트리 탐색 개시. 경로 깊이: {len(tree_path)}, 타겟 아이템: {target_items}", "info")

    # 창 탐색 – ClassNameList로 mmc 창 찾기 (대기 시간 상향)
    mmc_win = None
    for attempt in range(25):
        try:
            sec_warn = auto.WindowControl(searchDepth=1, Name="보안 템플릿")
            if sec_warn.Exists(0.2):
                log("  [알림] '보안 템플릿' 경고창 감지됨. 강제 ESC 차단 처리.", "info")
                sec_warn.SendKey(auto.Keys.VK_ESCAPE) 
        except Exception:
            pass

        wins = auto.GetRootControl().GetChildren()
        for w in wins:
            try:
                w_class = (w.ClassName or "").lower()
                w_name = (w.Name or "").lower()
                if "mmc" in w_class or "mainframe" in w_class or "보안 정책" in w_name or "그룹 정책" in w_name or "console" in w_name:
                    mmc_win = w
                    break
            except Exception:
                pass
        if mmc_win:
            break
        time.sleep(0.3)

    if not mmc_win:
        log("  [오류] MMC (로컬 보안 정책 등) 설정 창을 화면에서 감지하지 못했습니다.", "warn")
        return

    log(f"  [확인] MMC 창 발견 (Name: {mmc_win.Name}, Class: {mmc_win.ClassName})", "info")

    # treePath가 정의되지 않았거나 빈 리스트인 경우, 단순 대기 후 종료
    if not tree_path:
        log("  [알림] treePath가 비어 있으므로 좌측 트리 탐색을 건너뛰고 창 전체 화면을 캡처합니다.", "good")
        time.sleep(1.0)
        return

    # 트리뷰에서 경로 탐색
    try:
        tree = None
        for _ in range(15):
            tree = mmc_win.TreeControl(searchDepth=5)
            if tree.Exists(0.5):
                break
            time.sleep(0.3)

        if not tree or not tree.Exists(1):
            log("  [오류] MMC 내부의 좌측 트리뷰(TreeControl) 영역을 찾을 수 없습니다.", "warn")
            return

        log("  [진행] 트리뷰 탐색 진행 중...", "info")
        # 루트 노드부터 시작하여 Name 검색 기반으로 다이렉트 매칭 (속도 향상)
        current_parent = tree
        for step, node_names in enumerate(tree_path):
            found = False
            log(f"    - 트리 {step+1}단계 진입 타겟 후보: {node_names}", "info")
            
            # node_names 목록에 있는 이름 중 하나를 직접 탐색
            for name_to_find in node_names:
                try:
                    # 바로 아래의 자식 TreeItem에서 고속으로 찾음 (searchDepth=1)
                    target_node = current_parent.TreeItemControl(searchDepth=1, Name=name_to_find)
                    if target_node.Exists(0.1):
                        log(f"      => 1단계 깊이에서 노드 '{name_to_find}' 매칭 성공.", "info")
                        try:
                            target_node.ScrollIntoView()
                        except Exception:
                            pass
                        try:
                            target_node.Select()
                        except Exception:
                            target_node.Click()
                        target_node.SendKeys("{RIGHT}")
                        current_parent = target_node
                        found = True
                        break
                except Exception:
                    pass
            
            if not found:
                # 1단계 자식에서 실패 시 2~3단계 수준으로 넓혀 빠르게 직접 쿼리
                for name_to_find in node_names:
                    try:
                        target_node = current_parent.TreeItemControl(searchDepth=3, Name=name_to_find)
                        if target_node.Exists(0.2):
                            log(f"      => 3단계 깊이에서 노드 '{name_to_find}' 매칭 성공.", "info")
                            try:
                                target_node.ScrollIntoView()
                            except Exception:
                                pass
                            try:
                                target_node.Select()
                            except Exception:
                                target_node.Click()
                            target_node.SendKeys("{RIGHT}")
                            current_parent = target_node
                            found = True
                            break
                    except Exception:
                        pass

            if not found:
                # 최악의 경우 부분 이름 일치 하위 컨트롤 고속 매칭
                for name_to_find in node_names:
                    log(f"      => 부분 일치 탐색 개시 ('{name_to_find}')", "info")
                    for child in current_parent.GetChildren():
                        c_name = child.Name or ""
                        if name_to_find.lower() in c_name.lower():
                            log(f"        -> '{c_name}' 부분 매칭 성공.", "info")
                            try:
                                child.ScrollIntoView()
                            except Exception:
                                pass
                            try:
                                child.Select()
                            except Exception:
                                child.Click()
                            child.SendKeys("{RIGHT}")
                            current_parent = child
                            found = True
                            break
                    if found:
                        break
                        
            if not found:
                log(f"  [오류] 트리 {step+1}단계 ({node_names}) 경로 진입에 실패했습니다.", "warn")
                return

            # [핵심 추가] 노드 확장 및 렌더링을 기다리기 위해 자식 노드 존재가 보장될 때까지 대기
            if found:
                for _ in range(8):
                    if len(current_parent.GetChildren()) > 0:
                        break
                    time.sleep(0.1)

        # 우측 패널에서 targetItem 클릭/더블클릭
        time.sleep(0.5)
        if target_items:
            log("  [진행] 우측 목록 패널에서 순차 방향키 탐색 개시...", "info")
            
            # 리스트뷰(List/DataGrid) 자체의 포커스 획득
            list_ctrl = mmc_win.ListControl(searchDepth=6)
            if not list_ctrl.Exists(0.2):
                list_ctrl = mmc_win.TableControl(searchDepth=6)
                
            if list_ctrl.Exists(0.5):
                try:
                    list_ctrl.SetFocus()
                    list_ctrl.Click()
                except Exception:
                    pass
                # 첫 번째 자식 아이템을 직접 구해서 포커스 및 클릭 시도
                try:
                    children = list_ctrl.GetChildren()
                    if children:
                        children[0].SetFocus()
                        children[0].Click()
                except Exception:
                    pass
                list_ctrl.SendKeys("{HOME}")  # 맨 처음에 최상단으로 커서 이동
                time.sleep(0.2)
                
                # 아래 방향키를 내리며 이름 매칭 진행 (최대 150회)
                matched_item = None
                last_name = None
                
                for step_down in range(150):
                    # 현재 윈도우에서 포커스를 가진 활성 아이템 조회
                    focused_item = auto.GetFocusedControl()
                        
                    if focused_item:
                        curr_name = focused_item.Name or ""
                        
                        # 무한루프(바닥 도달) 방어
                        if last_name and curr_name == last_name:
                            log("    -> 리스트 바닥 도달. 탐색 종료.", "info")
                            break
                        last_name = curr_name
                        
                        # 대상 명칭과 대조 매칭
                        match_found = False
                        for target_name in target_items:
                            if target_name.lower() in curr_name.lower():
                                matched_item = focused_item
                                log(f"    => 매칭 타겟 발견! 단계 {step_down+1}: '{curr_name}' (검색명: '{target_name}')", "good")
                                match_found = True
                                break
                                
                        if match_found:
                            break
                            
                    # 매칭 실패 시 아래 방향키 전송 (Win32 로우레벨 하드웨어 키 이벤트를 통한 가속)
                    try:
                        # 0x28: VK_DOWN (아래 방향키)
                        ctypes.windll.user32.keybd_event(0x28, 0, 0, 0) # Key Down
                        time.sleep(0.001)
                        ctypes.windll.user32.keybd_event(0x28, 0, 2, 0) # Key Up
                    except Exception:
                        list_ctrl.SendKeys("{DOWN}")
                    # UI 윈도우 스레드가 포커스 상태를 갱신할 수 있는 시간만큼 대기 (이 값이 너무 작으면 포커스 변경 전에 동일 항목으로 인식해 검색 조기 중단됨)
                    time.sleep(0.1)
                
                if matched_item:
                    # 마우스로 확실하게 항목을 한번 클릭해 주어 포커스를 강제 동기화
                    try:
                        matched_item.Click()
                        time.sleep(0.2)
                    except Exception:
                        pass
                    # 이미 포커스되어 활성화된 아이템이므로 속성창(Properties) 액션 시 Alt+Enter 사용
                    if item.get("actionType") == "Properties":
                        matched_item.SendKeys("{ALT}{ENTER}")
                    else:
                        matched_item.SendKeys("{ENTER}")
                    time.sleep(0.8)
                    
                    # ── 추가: 새로 열린 속성 대화상자(#32770)가 뜰 때까지 대기 및 포커스 ──
                    dlg_found = False
                    for _ in range(30):
                        # 1순위: 전체 루트 상에서 최신 활성화된 속성창 다이렉트 감지
                        dlg = auto.WindowControl(searchDepth=1, ClassName="#32770")
                        
                        # 2순위: MMC 윈도우 하위 자식 중에서 감지
                        if (not dlg.Exists(0.05)) and mmc_win:
                            try:
                                dlg = mmc_win.WindowControl(searchDepth=2, ClassName="#32770")
                            except Exception:
                                pass
                                
                        if dlg.Exists(0.1):
                            log(f"    -> 세부 속성 대화상자(팝업) 감지 성공 (Name: {dlg.Name}). 포커스 획득.", "good")
                            dlg.SetActive()
                            dlg.SetFocus()
                            time.sleep(0.3)
                            dlg_found = True
                            break
                        time.sleep(0.2)
                    if not dlg_found:
                        log("    [경고] 엔터 키를 보냈으나 세부 속성 대화상자(#32770)가 활성화되지 않았습니다.", "warn")
                else:
                    log("  [오류] 키보드 순차 탐색 결과 대조 대상을 발견하지 못했습니다.", "warn")
            else:
                log("  [오류] 우측 리스트뷰 영역(ListControl) 포커스 획득에 실패했습니다.", "warn")
    except Exception as e:
        log(f"  [예외] 트리 탐색 중 예외 발생: {e}", "warn")


def capture_evidence(
    item: dict,
    evidence_dir: str,
    log_callback=None,
    wait_before_capture: float = 1.5,
    wait_callback=None
) -> str | None:
    """
    항목에 맞는 Windows 설정 화면을 띄우고 스크린샷을 캡처합니다.
    반환값: 저장된 PNG 파일 경로 (실패 시 None)
    """
    _init_com()
    item_id  = item.get("ItemId", "")
    norm_id  = _normalize_item_id(item_id)

    if item.get("multiCapture", False):
        target_services = item.get("targetServices", [])
        log_cb = log_callback
        def log(msg, level="info"):
            if log_cb:
                log_cb(msg, level)

        log(f"  [{item_id}] 멀티 서비스 개별 캡처를 순차 진행합니다.", "info")
        import shutil
        for svc_info in target_services:
            svc = svc_info.get("name", "")
            disp_name = svc_info.get("displayName", svc)
            sub_save_name = f"{norm_id}_{svc}.png"
            sub_save_path = os.path.join(evidence_dir, sub_save_name)
            log(f"  [{item_id}] 서비스 '{disp_name}' 캡처 개시...", "info")
            
            sub_item = item.copy()
            sub_item["targetItem"] = [disp_name]
            sub_item["actionType"] = "Properties"  # 상세 속성 창 팝업 캡처 유도
            
            sub_proc = None
            sub_mmc_win = None
            try:
                sub_proc = _spawn_app(app_name or "services.msc", item_id)
                time.sleep(1.2)
                
                # mmc 감지 및 우측 절반 정렬
                try:
                    for _ in range(25):
                        wins = auto.GetRootControl().GetChildren()
                        for w in wins:
                            w_class = (w.ClassName or "").lower()
                            w_name = (w.Name or "").lower()
                            if "mmc" in w_class or "mainframe" in w_class or "보안 정책" in w_name or "그룹 정책" in w_name or "console" in w_name or "서비스" in w_name:
                                sub_mmc_win = w
                                break
                        if sub_mmc_win and sub_mmc_win.Exists(0.2):
                            sub_mmc_win.SetActive()
                            sub_mmc_win.SetFocus()
                            import pyautogui
                            sw, sh = pyautogui.size()
                            hw = sw // 2
                            ctypes.windll.user32.ShowWindow(sub_mmc_win.NativeWindowHandle, 9)
                            time.sleep(0.1)
                            ctypes.windll.user32.SetWindowPos(sub_mmc_win.NativeWindowHandle, 0, hw, 0, hw, sh - 40, 0x0040)
                            break
                        time.sleep(0.2)
                except Exception as ex:
                    log(f"    [경고] 서비스 MMC 윈도우 정렬 실패: {ex}", "warn")
                
                _navigate_msc_tree(sub_item, log_callback=log_callback)
                time.sleep(wait_before_capture)
                
                sub_capture_target = None
                try:
                    global_dlg = auto.WindowControl(searchDepth=1, ClassName="#32770")
                    if global_dlg.Exists(0.2):
                        sub_capture_target = global_dlg
                        log(f"  [캡처] 활성화된 속성 다이얼로그({global_dlg.Name}) 영역 캡처 진행.", "info")
                except Exception:
                    pass
                
                if not sub_capture_target:
                    if sub_mmc_win and sub_mmc_win.Exists(0.2):
                        try:
                            child_dlg = sub_mmc_win.WindowControl(searchDepth=2, ClassName="#32770")
                            if child_dlg.Exists(0.2):
                                sub_capture_target = child_dlg
                                log("  [캡처] 자식 속성 다이얼로그 영역 캡처 진행.", "info")
                            else:
                                sub_capture_target = sub_mmc_win
                                log("  [캡처] 메인 설정 윈도우 영역 캡처 진행.", "info")
                        except Exception:
                            sub_capture_target = sub_mmc_win
                
                _take_screenshot(sub_save_path, target_ctrl=sub_capture_target)
                log(f"  📷 '{disp_name}' 증빙 캡처 완료: {sub_save_path}", "good")
                
            except Exception as ex:
                log(f"  ⚠️ '{disp_name}' 캡처 중 오류: {ex}", "warn")
            finally:
                if sub_proc:
                    try:
                        sub_proc.terminate()
                    except Exception:
                        pass
                _cleanup_windows(item_id, log_callback=log)
        
        main_save_path = os.path.join(evidence_dir, f"{norm_id}.png")
        if target_services:
            first_svc = target_services[0].get("name", "")
            first_img = os.path.join(evidence_dir, f"{norm_id}_{first_svc}.png")
            if os.path.exists(first_img):
                shutil.copy2(first_img, main_save_path)
        return main_save_path

    app_name = item.get("appTarget")
    is_fullscreen = (item.get("actionType") == "Fullscreen")

    os.makedirs(evidence_dir, exist_ok=True)
    # 캡처를 호출하는 흐름에서 item 객체 내에 담긴 상태값을 추가로 파악
    is_status_safe = "양호" in str(item.get("Status", ""))
    
    # 이미 양호(Safe)로 진단되어 스킵되는 경우 파일명 옆에 (Skip)을 표시
    is_skip_item = (item.get("captureOnly") == True)
    if is_skip_item and wait_callback is not None and not is_status_safe:
        is_skip_item = False
        
    # 캡처 증빙 자료 수집의 경우 매칭 신뢰도를 위해 (Skip) 접미사 없이 일관되게 {norm_id}.png 형식으로 저장
    save_name = f"{norm_id}.png"
        
    save_path = os.path.join(evidence_dir, save_name)

    def log(msg, level="info"):
        if log_callback:
            log_callback(msg, level)

    proc = None
    mmc_win = None
    try:
        # ── 앱 실행 ──────────────────────────────────────────────────
        if app_name and not is_fullscreen:
            log(f"  [실행] {app_name} 프로그램 로드 시도 중...", "info")
            if app_name == "regedit":
                reg_path = item.get("RegistryPath", "")
                
                # Existing administrator windows belong to the user; do not kill them.
                # 2. LastKey 설정하여 기동 시 자동 경로 진입 보장
                if reg_path:
                    _set_regedit_lastkey(reg_path)
                
                proc = _spawn_app("regedit", item_id)
                time.sleep(1.0)
                
                # regedit 윈도우 즉시 찾기 및 정렬
                try:
                    for _ in range(15):
                        mmc_win = auto.WindowControl(searchDepth=1, ClassName="RegEdit_RegEdit")
                        if mmc_win.Exists(0.2):
                            log("    -> 레지스트리 편집기 윈도우 감지 성공. 우측 정렬 수행.", "info")
                            mmc_win.SetActive()
                            mmc_win.SetFocus()
                            import pyautogui
                            sw, sh = pyautogui.size()
                            hw = sw // 2
                            ctypes.windll.user32.ShowWindow(mmc_win.NativeWindowHandle, 9) # SW_RESTORE
                            time.sleep(0.1)
                            ctypes.windll.user32.SetWindowPos(mmc_win.NativeWindowHandle, 0, hw, 0, hw, sh - 40, 0x0040)
                            break
                        time.sleep(0.2)
                except Exception as ex:
                    log(f"    [경고] 레지스트리 정렬 실패: {ex}", "warn")

                # 3. 이중 안전 장치: 폴백으로 UIA/단축키를 이용한 탐색도 병행 시도
                if reg_path:
                    _navigate_to_reg_path(reg_path)
                    
            elif app_name.endswith(".msc"):
                proc = _spawn_app(app_name, item_id)
                time.sleep(1.2)
                
                # mmc 윈도우 즉시 찾기 및 우측 절반 정렬 (한글 환경 호환성 극대화)
                try:
                    for _ in range(20):
                        wins = auto.GetRootControl().GetChildren()
                        for w in wins:
                            w_class = (w.ClassName or "").lower()
                            w_name = (w.Name or "").lower()
                            # MMC 기본 클래스인 MMCMainFrame 또는 타이틀에 정책/콘솔/mmc가 들어가는 경우
                            if "mmc" in w_class or "mainframe" in w_class or "보안 정책" in w_name or "그룹 정책" in w_name or "console" in w_name:
                                mmc_win = w
                                break
                        if mmc_win and mmc_win.Exists(0.2):
                            log(f"    -> MMC 윈도우 감지 성공 (Name: {mmc_win.Name}). 우측 정렬 수행.", "info")
                            mmc_win.SetActive()
                            mmc_win.SetFocus()
                            import pyautogui
                            sw, sh = pyautogui.size()
                            hw = sw // 2
                            ctypes.windll.user32.ShowWindow(mmc_win.NativeWindowHandle, 9) # SW_RESTORE
                            time.sleep(0.1)
                            ctypes.windll.user32.SetWindowPos(mmc_win.NativeWindowHandle, 0, hw, 0, hw, sh - 40, 0x0040)
                            break
                        time.sleep(0.2)
                except Exception as ex:
                    log(f"    [경고] MMC 윈도우 정렬 실패: {ex}", "warn")

                _navigate_msc_tree(item, log_callback=log_callback)
            elif app_name.endswith(".cpl") or "control" in app_name:
                proc = _spawn_app(app_name, item_id)
                time.sleep(1.5)
                
                # CPL 제어판 창 즉시 찾기 및 우측 절반 정렬
                try:
                    for _ in range(20):
                        wins = auto.GetRootControl().GetChildren()
                        for w in wins:
                            w_class = (w.ClassName or "").lower()
                            w_name = (w.Name or "").lower()
                            # timedate.cpl, desk.cpl 등은 보통 #32770 클래스이거나 창 이름에 특정 키워드가 포함됨
                            if w.ClassName == "#32770" or "날짜" in w_name or "시간" in w_name or "화면" in w_name or "네트워크" in w_name or "속성" in w_name or "보호기" in w_name:
                                mmc_win = w
                                break
                        if mmc_win and mmc_win.Exists(0.2):
                            log(f"    -> 제어판/다이얼로그 창 감지 성공 (Name: {mmc_win.Name}). 우측 정렬 수행.", "info")
                            mmc_win.SetActive()
                            mmc_win.SetFocus()
                            import pyautogui
                            sw, sh = pyautogui.size()
                            hw = sw // 2
                            ctypes.windll.user32.ShowWindow(mmc_win.NativeWindowHandle, 9) # SW_RESTORE
                            time.sleep(0.1)
                            ctypes.windll.user32.SetWindowPos(mmc_win.NativeWindowHandle, 0, hw, 0, hw, sh - 40, 0x0040)
                            break
                        time.sleep(0.2)
                except Exception as ex:
                    log(f"    [경고] 제어판 윈도우 정렬 실패: {ex}", "warn")

                # JSON에 설정된 actionType에 따라 고급 WINS 탭 진입
                if item.get("actionType") == "NetworkWins":
                    log("  [진행] TCP/IPv4 WINS 탭 네이티브 탐색 개시...", "info")
                    _navigate_wins_properties(log_callback=log_callback)
            elif app_name == "explorer.exe":
                # explorer.exe의 경우 속성창 띄우기 수행
                targets = item.get("targetItem", [])
                if targets:
                    target_path = targets[0]
                    log(f"  [실행] {target_path} 속성 창 로드 시도 중...", "info")
                    _show_file_properties(target_path)
                else:
                    proc = _spawn_app(app_name, item_id)
                time.sleep(1.5)
                
                # 파일/폴더 속성 대화상자 (#32770) 감지 및 우측 절반 정렬
                try:
                    for _ in range(25):
                        wins = auto.GetRootControl().GetChildren()
                        for w in wins:
                            w_class = w.ClassName or ""
                            w_name = w.Name or ""
                            w_class_lower = w_class.lower()
                            w_name_lower = w_name.lower()
                            if w_class == "#32770" and ("속성" in w_name_lower or "properties" in w_name_lower or "sam" in w_name_lower or "logs" in w_name_lower):
                                mmc_win = w
                                break
                        if mmc_win and mmc_win.Exists(0.2):
                            log(f"    -> 속성 대화상자 감지 성공 (Name: {mmc_win.Name}). 우측 정렬 수행.", "info")
                            mmc_win.SetActive()
                            mmc_win.SetFocus()
                            import pyautogui
                            sw, sh = pyautogui.size()
                            hw = sw // 2
                            ctypes.windll.user32.ShowWindow(mmc_win.NativeWindowHandle, 9) # SW_RESTORE
                            time.sleep(0.1)
                            ctypes.windll.user32.SetWindowPos(mmc_win.NativeWindowHandle, 0, hw, 0, hw, sh - 40, 0x0040)
                            break
                        time.sleep(0.2)
                except Exception as ex:
                    log(f"    [경고] 속성 창 정렬 실패: {ex}", "warn")
            else:
                proc = _spawn_app(app_name, item_id)
                time.sleep(1.2)
                
                # UWP 설정 앱 또는 기타 GUI 창 즉시 찾기 및 우측 절반 정렬
                try:
                    for _ in range(25):
                        wins = auto.GetRootControl().GetChildren()
                        target_win = None
                        for w in wins:
                            w_class = w.ClassName or ""
                            w_name = w.Name or ""
                            w_class_lower = w_class.lower()
                            w_name_lower = w_name.lower()
                            
                            # 1. UWP 설정창 감지
                            if w_class_lower == "applicationframewindow" and ("설정" in w_name_lower or "settings" in w_name_lower):
                                target_win = w
                                break
                            # 2. Windows 보안 앱 (Windows Defender) 감지
                            elif (w_class_lower == "applicationframewindow" or w_class == "CabinetWClass") and ("보안" in w_name_lower or "security" in w_name_lower):
                                target_win = w
                                break
                            # 3. 파일/폴더 속성 대화상자 (#32770) 감지 (SAM 속성, Logs 속성 등)
                            elif w_class == "#32770" and ("속성" in w_name_lower or "properties" in w_name_lower or "sam" in w_name_lower or "logs" in w_name_lower):
                                target_win = w
                                break
                            # 4. 작업 관리자 (taskmgr) 감지
                            elif w_class == "TaskManagerWindow" or ("작업" in w_name_lower and "관리자" in w_name_lower) or "task manager" in w_name_lower:
                                target_win = w
                                break
                            # 5. winver (Windows 정보) 감지
                            elif w_class == "#32770" and ("정보" in w_name_lower or "about" in w_name_lower or "windows" in w_name_lower):
                                target_win = w
                                break
                            # 6. odbcad32.exe 등 기타 다이얼로그 감지
                            elif w_class == "#32770" and "odbc" in w_name_lower:
                                target_win = w
                                break
                                
                        if target_win and target_win.Exists(0.2):
                            log(f"    -> GUI 설정/정보 창 감지 성공 (Name: {target_win.Name}). 우측 정렬 수행.", "info")
                            target_win.SetActive()
                            target_win.SetFocus()
                            import pyautogui
                            sw, sh = pyautogui.size()
                            hw = sw // 2
                            ctypes.windll.user32.ShowWindow(target_win.NativeWindowHandle, 9) # SW_RESTORE
                            time.sleep(0.1)
                            ctypes.windll.user32.SetWindowPos(target_win.NativeWindowHandle, 0, hw, 0, hw, sh - 40, 0x0040)
                            mmc_win = target_win
                            break
                        time.sleep(0.2)
                except Exception as ex:
                    log(f"    [경고] GUI 창 정렬 실패: {ex}", "warn")

        time.sleep(wait_before_capture)
        
        # ── [추가] 캡처를 실행하기 전 사용자의 준비 완료 입력 홀딩 ──
        if wait_callback:
            log("  ⏳ 설정 대화상자 조작 대기 (사용자 캡처 확인 대기 중)...", "warn")
            if not wait_callback():
                log("  ⏹ 사용자에 의해 캡처 및 진행이 취소되었습니다.", "warn")
                raise Exception("User Cancelled Execution")
        
        # ── [크롭 캡처 타겟 찾기] ──
        capture_target = None
        
        # 1순위: 글로벌로 떠 있는 활성 속성 대화상자(#32770) 우선 체크
        try:
            global_dlg = auto.WindowControl(searchDepth=1, ClassName="#32770")
            if global_dlg.Exists(0.2):
                capture_target = global_dlg
                log(f"  [캡처] 활성화된 속성 다이얼로그({global_dlg.Name}) 영역 캡처 진행.", "info")
        except Exception:
            pass
            
        # 2순위: 팝업 대화상자가 없으면 MMC 메인 윈도우 정렬 영역 캡처
        if not capture_target:
            if mmc_win and mmc_win.Exists(0.2):
                try:
                    child_dlg = mmc_win.WindowControl(searchDepth=2, ClassName="#32770")
                    if child_dlg.Exists(0.2):
                        capture_target = child_dlg
                        log("  [캡처] 자식 속성 다이얼로그 영역 캡처 진행.", "info")
                    else:
                        capture_target = mmc_win
                        log("  [캡처] 메인 설정 윈도우 영역 캡처 진행.", "info")
                except Exception:
                    capture_target = mmc_win
        
        _take_screenshot(save_path, target_ctrl=capture_target)
        log(f"  📷 증빙 캡처 완료: {save_path}", "good")
        return save_path

    except Exception as e:
        log(f"  ⚠️ 캡처 오류 [{item_id}]: {e}", "warn")
        return None

    finally:
        # 1. 잔여 모달 팝업 및 자식/부모 창 순차 정리부터 수행 (락 해제)
        _cleanup_windows(item_id, log_callback=log)
        
        # 2. 열었던 메인 부모 프로세스 최종 종료
        if proc:
            try:
                proc.terminate()
            except Exception:
                pass


def _cleanup_network_windows(log=None):
    """Leave unowned desktop windows open; title matching cannot prove ownership."""
    return


def _cleanup_windows(item_id: str, log_callback=None):
    """Never close unrelated administrative tools or arbitrary dialogs."""
    if log_callback:
        log_callback("증빙 확인 후 열린 관리 창을 직접 닫아주세요.", "info")
