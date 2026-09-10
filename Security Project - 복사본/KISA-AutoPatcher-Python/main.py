# -*- coding: utf-8 -*-
"""
main.py  –  KISA 보안 패치 에이전트 GUI 메인 (CustomTkinter 기반 프리미엄 다크 디자인)
"""

import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk
from datetime import datetime

# customtkinter 테마 설정
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ── 경로 설정 (PyInstaller 번들 환경 대응) ───────────────────────────
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

POLICY_DIR   = os.path.join(BASE_DIR, "config", "policies")
EVIDENCE_DIR = os.path.join(BASE_DIR, "evidence")
REPORTS_DIR  = os.path.join(BASE_DIR, "reports")
BACKUPS_DIR  = os.path.join(BASE_DIR, "backups")
LOGS_DIR     = os.path.join(BASE_DIR, "logs")
MODEL_GUIDES_PATH = os.path.join(BASE_DIR, "config", "model_guides.json")

os.makedirs(LOGS_DIR, exist_ok=True)

# ── 코어 모듈 임포트 (패키지 방식 – PyInstaller 호환) ────────────────
_core_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "core")
if _core_path not in sys.path:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.detector   import get_vulnerability_status
from core.remediator import invoke_remediation
from core.reporter   import invoke_reporting
from core.capturer   import capture_evidence

# ── 디자인 시스템 핵심 컬러 스키마 (gui_design_guide.md 준수) ───────
BG_DARK   = "#141622"  # 전체 윈도우 배경
BG_CARD   = "#1E2130"  # 카드/섹션 배경
BG_INNER  = "#252840"  # 카드 내부 중첩 영역 및 입력 요소 배경
BG_GROUP  = "#1A1D2E"  # 컴포넌트 내부 소그룹 배경 / 트리뷰 배경 A
BG_ROW_B  = "#202336"  # 트리뷰 배경 B
ACCENT    = "#4F8EF7"  # 메인 강조색 (포인트 블루)
ACCENT2   = "#6C63FF"  # 호버 상태 강조색 (인디고 퍼플)
TEXT_MAIN = "#E2E8F0"  # 주 텍스트 색상
TEXT_DIM  = "#8892A4"  # 부 텍스트 색상
SUCCESS   = "#2DD4BF"  # 성공 상태 (소프트 민트)
WARNING   = "#F59E0B"  # 경고 상태 (소프트 오렌지)
ERROR_C   = "#FF5C5C"  # 에러 상태 (소프트 레드)

STATUS_COLORS = {
    "양호":    SUCCESS,
    "수동 조치": WARNING,
    "취약":    ERROR_C,
    "오류":    TEXT_DIM,
    "대기":    TEXT_DIM,
}

COL_WIDTHS = [85, 290, 60, 95, 95]
COL_NAMES  = ["항목코드", "항목명", "중요도", "스캔 상태", "조치 상태"]


class KisaPatcherApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("KISA 보안 취약점 자동 조치 시스템")
        self.configure(fg_color=BG_DARK)
        self.resizable(True, True)
        self.minsize(980, 720)

        # ── 앱 첫 실행 시 모니터의 좌측 절반에 맞추어 기동 ──
        try:
            import pyautogui
            sw, sh = pyautogui.size()
            half_w = max(520, sw // 2)
            self.geometry(f"{half_w}x{sh - 80}+0+0")
        except Exception:
            self.geometry("980x820+0+0")

        self.policies        = []
        self.vuln_results    = []
        self.model_guides    = {}
        self.is_running      = False
        self.stop_requested  = False
        self.last_exec_mode = "manual_pause"
        self.last_services_config = {"iis": "proceed", "dns": "proceed", "snmp": "proceed", "telnet": "proceed"}

        # 캡처 버튼 이벤트를 위한 동기화 객체 선언
        import threading
        self.next_clicked    = threading.Event()

        self._setup_styles()
        self._build_ui()
        self._load_policies()

    # ── 스타일 ──────────────────────────────────────────────────────
    def _setup_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        # Treeview (Segoe UI 폰트와 HSL 다크 테마 색상 튜닝)
        style.configure("Custom.Treeview",
            background=BG_GROUP, foreground=TEXT_MAIN,
            fieldbackground=BG_GROUP, borderwidth=0,
            font=("Segoe UI", 9), rowheight=28)
        style.configure("Custom.Treeview.Heading",
            background=BG_CARD, foreground=ACCENT,
            font=("Segoe UI", 9, "bold"), relief="flat", padding=6)
        style.map("Custom.Treeview",
            background=[("selected", ACCENT)],
            foreground=[("selected", "white")])

        # Scrollbar (Segoe UI 테마와 맞는 HSL 그레이 스타일)
        style.configure("Custom.Vertical.TScrollbar",
            troughcolor=BG_DARK, background=BG_CARD,
            borderwidth=0, arrowsize=10)

    # ── UI 빌드 ──────────────────────────────────────────────────────
    def _build_ui(self):
        # ── 헤더 ─────────────────────────────────────────────────────
        hdr = ctk.CTkFrame(self, fg_color=BG_CARD, height=64, corner_radius=0)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        ctk.CTkLabel(hdr, text="🛡️",
                     font=("Segoe UI Emoji", 22), text_color=ACCENT
                     ).pack(side="left", padx=(18, 6), pady=10)

        title_f = ctk.CTkFrame(hdr, fg_color=BG_CARD)
        title_f.pack(side="left", pady=10)

        ctk.CTkLabel(title_f, text="KISA 보안 취약점 자동 조치 시스템",
                     font=("Segoe UI", 15, "bold"), text_color=TEXT_MAIN
                     ).pack(anchor="w")
        ctk.CTkLabel(title_f, text="주요정보통신기반시설 Windows 보안 점검 · 자동 조치 · 증빙수집",
                     font=("Segoe UI", 9), text_color=TEXT_DIM
                     ).pack(anchor="w")

        # 시계
        self.lbl_clock = ctk.CTkLabel(hdr, text="", font=("Consolas", 11),
                                      text_color=TEXT_DIM)
        self.lbl_clock.pack(side="right", padx=18)
        self._tick_clock()

        # ── 요약 카드 ─────────────────────────────────────────────────
        summary_frame = ctk.CTkFrame(self, fg_color=BG_DARK)
        summary_frame.pack(fill="x", padx=14, pady=(10, 0))

        self.card_total  = self._summary_card(summary_frame, "전체 항목", "–",  ACCENT)
        self.card_vuln   = self._summary_card(summary_frame, "취약",      "–",  ERROR_C)
        self.card_good   = self._summary_card(summary_frame, "양호",      "–",  SUCCESS)
        self.card_manual = self._summary_card(summary_frame, "수동 조치", "–",  WARNING)
        self.card_fixed  = self._summary_card(summary_frame, "조치 완료", "–",  ACCENT2)

        # ── 진행률 ───────────────────────────────────────────────────
        prog_frame = ctk.CTkFrame(self, fg_color=BG_DARK)
        prog_frame.pack(fill="x", padx=14, pady=(8, 0))

        self.progress_bar = ctk.CTkProgressBar(prog_frame, progress_color=ACCENT,
                                            fg_color=BG_CARD, height=10, corner_radius=5)
        self.progress_bar.pack(fill="x")
        self.progress_bar.set(0.0)

        self.lbl_progress = ctk.CTkLabel(prog_frame, text="대기 중...",
                                         font=("Segoe UI", 9), text_color=TEXT_DIM)
        self.lbl_progress.pack(anchor="e", padx=2)

        # ── 메인 분할 ─────────────────────────────────────────────────
        main = ctk.CTkFrame(self, fg_color=BG_DARK)
        main.pack(fill="both", expand=True, padx=14, pady=8)

        # 왼쪽: 트리뷰 + 버튼
        left = ctk.CTkFrame(main, fg_color=BG_DARK)
        left.pack(side="left", fill="both", expand=True)

        # 상단 도구 바
        toolbar = ctk.CTkFrame(left, fg_color=BG_DARK)
        toolbar.pack(fill="x", pady=(0, 6))

        # 선택 제어 버튼
        self._tb_btn(toolbar, "☑ 전체 선택", self._select_all,   ACCENT)
        self._tb_btn(toolbar, "☐ 전체 해제", self._deselect_all, BG_CARD)
        self._tb_btn(toolbar, "↕ 취약만 선택", self._select_vuln, ERROR_C)

        # 실행 모드 변수 선언 (UI에서는 제외하고 모달 팝업으로 관리)
        self.mode_var = tk.StringVar(value="auto")

        # 트리뷰 (항목 목록)
        tree_frame = ctk.CTkFrame(left, fg_color=BG_GROUP, corner_radius=10, border_width=0)
        tree_frame.pack(fill="both", expand=True)

        vsb = ttk.Scrollbar(tree_frame, orient="vertical",
                            style="Custom.Vertical.TScrollbar")
        vsb.pack(side="right", fill="y")

        self.tree = ttk.Treeview(
            tree_frame,
            columns=COL_NAMES,
            show="headings",
            selectmode="extended",
            style="Custom.Treeview",
            yscrollcommand=vsb.set
        )
        vsb.config(command=self.tree.yview)

        for col, w in zip(COL_NAMES, COL_WIDTHS):
            self.tree.heading(col, text=col, anchor="center")
            self.tree.column(col, width=w, minwidth=w, anchor="center")
        self.tree.column("항목명", anchor="w")

        # 항목 우클릭 메뉴
        self.ctx_menu = tk.Menu(self, tearoff=0, bg=BG_CARD, fg=TEXT_MAIN,
                                activebackground=ACCENT,
                                font=("Segoe UI", 9))
        self.ctx_menu.add_command(label="✔ 선택 항목만 조치",
                                  command=self._run_selected)
        self.ctx_menu.add_command(label="📷 선택 항목 캡처",
                                  command=self._capture_selected)
        self.ctx_menu.add_separator()
        self.ctx_menu.add_command(label="📋 세부 정보 보기",
                                  command=self._show_detail)
        self.tree.bind("<Button-3>", self._on_right_click)
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.tree.bind("<Double-1>", lambda e: self._show_detail())

        self.tree.pack(fill="both", expand=True, padx=2, pady=2)

        self.tree.tag_configure("good",   foreground=SUCCESS)
        self.tree.tag_configure("vuln",   foreground=ERROR_C)
        self.tree.tag_configure("manual", foreground=WARNING)
        self.tree.tag_configure("error",  foreground=TEXT_DIM)
        self.tree.tag_configure("fixed",  foreground=SUCCESS)
        self.tree.tag_configure("row_a",  background=BG_GROUP)
        self.tree.tag_configure("row_b",  background=BG_ROW_B)
        self.tree.tag_configure("active", background="#ffeb3b", foreground="#000000")

        # ── 오른쪽: 로그 + 세부 ──────────────────────────────────────
        right = ctk.CTkFrame(main, fg_color=BG_INNER, width=430, corner_radius=10)
        right.pack(side="right", fill="y", padx=(10, 0))
        right.pack_propagate(False)

        # 세부 정보 패널
        detail_lbl = ctk.CTkLabel(right, text="세부 정보",
                                  font=("Segoe UI", 11, "bold"),
                                  text_color=ACCENT)
        detail_lbl.pack(anchor="w", padx=14, pady=(8, 2))

        self.detail_frame = ctk.CTkFrame(right, fg_color=BG_CARD, corner_radius=8)
        self.detail_frame.pack(fill="x", padx=10, pady=(0, 4))

        self.lbl_d_id     = self._detail_row(self.detail_frame, "항목 코드", "–")
        self.lbl_d_title  = self._detail_row(self.detail_frame, "항목명",   "–")
        self.lbl_d_level  = self._detail_row(self.detail_frame, "중요도",   "–")
        self.lbl_d_scan   = self._detail_row(self.detail_frame, "스캔 상태", "–")
        self.lbl_d_sec    = self._detail_row(self.detail_frame, "양호 기준", "–", is_text=True, height=2, text_color=SUCCESS)
        self.lbl_d_manual = self._detail_row(self.detail_frame, "수동 조치 방법", "–", is_text=True, height=4, text_color=WARNING)
        self.lbl_d_cur    = self._detail_row(self.detail_frame, "현재 값",   "–", is_text=True, height=2)
        self.lbl_d_fix    = self._detail_row(self.detail_frame, "조치 상태", "–")

        # 로그 패널
        log_lbl = ctk.CTkLabel(right, text="실행 로그",
                               font=("Segoe UI", 11, "bold"),
                               text_color=ACCENT)
        log_lbl.pack(anchor="w", padx=14, pady=(4, 2))

        # 둥근 모서리 카드형 컨테이너 안에 스크롤텍스트 배치
        log_container = ctk.CTkFrame(right, fg_color="#0d0d15", corner_radius=8, border_width=1, border_color=BG_CARD)
        log_container.pack(fill="both", expand=True, padx=10, pady=(0, 8))

        from tkinter import scrolledtext
        self.log_area = scrolledtext.ScrolledText(
            log_container, bg="#0d0d15", fg=TEXT_MAIN,
            font=("Consolas", 9), state="disabled",
            borderwidth=0, highlightthickness=0, wrap="word",
            insertbackground=TEXT_MAIN
        )
        self.log_area.pack(fill="both", expand=True, padx=6, pady=6)

        for tag, color in {
            "good": SUCCESS, "warn": WARNING,
            "error": ERROR_C, "meta": ACCENT, "info": TEXT_MAIN
        }.items():
            self.log_area.tag_config(tag, foreground=color)

        # ── 하단 버튼 바 ─────────────────────────────────────────────
        btn_bar = ctk.CTkFrame(self, fg_color=BG_DARK, height=56, corner_radius=0)
        btn_bar.pack(fill="x", padx=14, pady=(0, 10))

        self.btn_scan  = self._action_btn(btn_bar, "🔍 전체 스캔",     BG_INNER,  self._on_scan)
        self.btn_auto  = self._action_btn(btn_bar, "⚡ 선택 항목 조치+캡처", ACCENT,    self._on_run)

        self.btn_stop  = self._action_btn(btn_bar, "⏹ 중지",          BG_CARD,  self._on_stop)
        self.btn_stop.configure(state="disabled")

        self.btn_next  = self._action_btn(btn_bar, "⏭ 캡처 및 다음 진행", SUCCESS, self._on_next)
        self.btn_next.configure(state="disabled")

        self.btn_report = self._action_btn(btn_bar, "📄 보고서 생성", SUCCESS, self._on_report,
                                           side="right")

    # ── 위젯 헬퍼 ───────────────────────────────────────────────────
    def _summary_card(self, parent, label, value, color):
        f = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=10)
        f.pack(side="left", padx=5, fill="both", expand=True)
        ctk.CTkLabel(f, text=label, font=("Segoe UI", 9, "bold"),
                     text_color=TEXT_DIM).pack(pady=(8, 2))
        lbl = ctk.CTkLabel(f, text=value, font=("Segoe UI", 16, "bold"),
                           text_color=color)
        lbl.pack(pady=(2, 8))
        return lbl

    def _detail_row(self, parent, label, value, is_text=False, height=4, text_color=None):
        f = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=0)
        f.pack(fill="x", padx=8, pady=1)
        ctk.CTkLabel(f, text=f"{label}:", font=("Segoe UI", 11, "bold"),
                     text_color=TEXT_DIM, width=80, anchor="w").pack(side="left", anchor="n" if is_text else "w")
        if is_text:
            # 둥근 입력 텍스트 영역 컨테이너
            txt_container = ctk.CTkFrame(f, fg_color=BG_INNER, corner_radius=6)
            txt_container.pack(side="left", padx=2, fill="x", expand=True)

            txt = tk.Text(txt_container, font=("Segoe UI", 10), bg=BG_INNER,
                          fg=text_color or TEXT_MAIN,
                          height=height, width=32, wrap="word", bd=0, highlightthickness=0)
            txt.insert("1.0", value)
            txt.config(state="disabled")
            txt.pack(padx=6, pady=4, fill="both", expand=True)
            return txt
        else:
            lbl = ctk.CTkLabel(f, text=value, font=("Segoe UI", 11, "bold"),
                               text_color=text_color or TEXT_MAIN, anchor="w")
            lbl.pack(side="left", padx=2, fill="x", expand=True)
            return lbl

    def _tb_btn(self, parent, text, cmd, color):
        # 툴바 버튼: 보조 기능이므로 다소 정갈하고 둥근 아웃라인/소프트 색상
        b = ctk.CTkButton(parent, text=text, command=cmd,
                          fg_color=color, hover_color=ACCENT2, text_color="white",
                          font=("Segoe UI", 11, "bold"),
                          corner_radius=6, height=28)
        b.pack(side="left", padx=4)

    def _action_btn(self, parent, text, color, cmd, side="left"):
        # 핵심 액션 버튼: 높이를 키우고 둥근 타원 형태로 강조
        b = ctk.CTkButton(parent, text=text, command=cmd,
                          fg_color=color, hover_color=ACCENT2, text_color="white",
                          font=("Segoe UI", 10, "bold"),
                          corner_radius=8, height=36)
        b.pack(side=side, padx=5)
        return b

    @staticmethod
    def _lighten(hex_color):
        """색상을 약간 밝게"""
        try:
            r = int(hex_color[1:3], 16)
            g = int(hex_color[3:5], 16)
            b = int(hex_color[5:7], 16)
            r = min(255, r + 30)
            g = min(255, g + 30)
            b = min(255, b + 30)
            return f"#{r:02x}{g:02x}{b:02x}"
        except Exception:
            return hex_color

    def _tick_clock(self):
        self.lbl_clock.configure(text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.after(1000, self._tick_clock)

    # ── 정책 로드 ────────────────────────────────────────────────────
    def _load_policies(self):
        import glob, json
        files = sorted(glob.glob(os.path.join(POLICY_DIR, "*.json")))
        self.policies = []
        for f in files:
            try:
                with open(f, encoding="utf-8-sig") as fp:
                    data = json.load(fp)
                    # ItemId가 빈값인 경우 파일명에서 안전 복구
                    if not data.get("ItemId"):
                        data["ItemId"] = os.path.splitext(os.path.basename(f))[0]
                    self.policies.append(data)
            except Exception:
                pass

        self.tree.delete(*self.tree.get_children())
        for i, p in enumerate(self.policies):
            tag = "row_a" if i % 2 == 0 else "row_b"
            self.tree.insert("", "end", iid=str(i),
                             values=(p.get("ItemId", ""), p.get("Title", ""), p.get("Level", ""),
                                     "대기", "–"),
                             tags=(tag,))

        n = len(self.policies)
        self.card_total.configure(text=str(n))
        self._log(f"✅ 정책 파일 {n}개 로드 완료 ({POLICY_DIR})", "good")

        # ── KISA Model 가이드 로드 (양호 기준 및 수동 조치 방법) ──
        if os.path.exists(MODEL_GUIDES_PATH):
            try:
                with open(MODEL_GUIDES_PATH, encoding="utf-8") as fp:
                    self.model_guides = json.load(fp)
                self._log(f"📘 KISA 가이드(Model.pdf 기준) {len(self.model_guides)}개 항목 로드 완료", "info")
            except Exception as e:
                self._log(f"⚠️ Model 가이드 로드 실패: {e}", "warn")

    def _log(self, msg, level="info"):
        def _ap():
            self.log_area.configure(state="normal")
            ts = datetime.now().strftime("%H:%M:%S")
            self.log_area.insert("end", f"[{ts}] {msg}\n", level)
            self.log_area.see("end")
            self.log_area.configure(state="disabled")

            if hasattr(self, "current_item_id") and self.current_item_id:
                try:
                    log_file = os.path.join(LOGS_DIR, f"{self.current_item_id}.log")
                    with open(log_file, "a", encoding="utf-8") as lf:
                        lf.write(f"[{ts}] {msg}\n")
                except Exception:
                    pass
        self.after(0, _ap)

    def _set_progress(self, cur, total):
        pct = int(cur / total * 100) if total else 0
        def _up():
            self.progress_bar.set(cur / total if total else 0.0)
            self.lbl_progress.configure(text=f"{cur} / {total}  ({pct}%)")
        self.after(0, _up)

    def _update_tree_status(self, idx: int, scan_status=None, fix_status=None):
        def update():
            iid = str(idx)
            vals = list(self.tree.item(iid, "values"))
            if scan_status is not None:
                vals[3] = scan_status
            if fix_status is not None:
                vals[4] = fix_status

            # 디폴트 번갈아가는 배경색 지정
            tag = "row_a" if idx % 2 == 0 else "row_b"

            # 진행 상태에 따른 하이라이트 분기
            if "중..." in str(scan_status) or "중..." in str(fix_status):
                tag = "active"
            elif scan_status == "취약" or fix_status == "취약 (미해결)":
                tag = "vuln"
            elif "양호" in str(scan_status) or "완료" in str(fix_status):
                tag = "good" if "양호" in str(scan_status) else "fixed"
            elif "수동" in str(scan_status):
                tag = "manual"

            self.tree.item(iid, values=vals, tags=(tag,))
        self.after(0, update)

    def _update_summary(self):
        def _up():
            vuln = sum(1 for r in self.vuln_results if "취약" in r.get("Status","") and "수동" not in r.get("Status",""))
            good = sum(1 for r in self.vuln_results if "양호" in r.get("Status",""))
            manu = sum(1 for r in self.vuln_results if "수동" in r.get("Status",""))
            fixd = sum(1 for r in self.vuln_results if r.get("FixStatus","") == "완료")
            self.card_vuln.configure(text=str(vuln))
            self.card_good.configure(text=str(good))
            self.card_manual.configure(text=str(manu))
            self.card_fixed.configure(text=str(fixd))
        self.after(0, _up)

    # ── 트리뷰 이벤트 ────────────────────────────────────────────────
    def _on_tree_select(self, _e):
        sel = self.tree.selection()
        if not sel:
            return
        idx = int(sel[-1])
        if idx < len(self.vuln_results):
            r = self.vuln_results[idx]
            item = r.get("ConfigItem", {})
            def _set_val(widget, val):
                if isinstance(widget, tk.Text):
                    widget.config(state="normal")
                    widget.delete("1.0", "end")
                    widget.insert("1.0", str(val))
                    widget.config(state="disabled")
                else:
                    widget.configure(text=str(val))

            item_id = r.get("ItemId", "")
            guide_info = self.model_guides.get(item_id, {})
            good_crit = guide_info.get("good_criteria") or r.get("SecureValue", "–")
            manual_text = guide_info.get("manual_guide") or item.get("Description", "–")

            def _up():
                self.lbl_d_id.configure(text=item_id)
                self.lbl_d_title.configure(text=r.get("Title",""))
                self.lbl_d_level.configure(text=r.get("Level",""))
                sc = r.get("Status","대기")
                self.lbl_d_scan.configure(
                    text=sc,
                    text_color=SUCCESS if "양호" in sc else ERROR_C if "취약" in sc else WARNING)
                _set_val(self.lbl_d_sec, good_crit)
                _set_val(self.lbl_d_manual, manual_text)
                _set_val(self.lbl_d_cur, r.get("CurrentValue","–"))
                self.lbl_d_fix.configure(text=r.get("FixStatus","–"))
            self.after(0, _up)
        elif idx < len(self.policies):
            p = self.policies[idx]
            def _set_val(widget, val):
                if isinstance(widget, tk.Text):
                    widget.config(state="normal")
                    widget.delete("1.0", "end")
                    widget.insert("1.0", str(val))
                    widget.config(state="disabled")
                else:
                    widget.configure(text=str(val))

            item_id = p.get("ItemId", "")
            guide_info = self.model_guides.get(item_id, {})
            good_crit = guide_info.get("good_criteria") or p.get("SecureValue", "–")
            manual_text = guide_info.get("manual_guide") or p.get("Description", "–")

            def _up2():
                self.lbl_d_id.configure(text=item_id)
                self.lbl_d_title.configure(text=p.get("Title",""))
                self.lbl_d_level.configure(text=p.get("Level",""))
                self.lbl_d_scan.configure(text="아직 스캔 안됨", text_color=TEXT_DIM)
                _set_val(self.lbl_d_sec, good_crit)
                _set_val(self.lbl_d_manual, manual_text)
                _set_val(self.lbl_d_cur, "–")
                self.lbl_d_fix.configure(text="–")
            self.after(0, _up2)

    def _on_right_click(self, event):
        iid = self.tree.identify_row(event.y)
        if iid:
            if iid not in self.tree.selection():
                self.tree.selection_set(iid)
            self.ctx_menu.post(event.x_root, event.y_root)

    def _show_detail(self):
        sel = self.tree.selection()
        if not sel:
            return
        idx = int(sel[0])
        if idx < len(self.vuln_results):
            r = self.vuln_results[idx]
            item = r.get("ConfigItem", {})
            item_id = r.get("ItemId", "")
            g = self.model_guides.get(item_id, {})
            good_crit = g.get("good_criteria") or r.get("SecureValue", "–")
            manual_text = g.get("manual_guide") or item.get("Description", "–")

            msg = (f"항목 코드:      {item_id}\n"
                   f"항목명:         {r['Title']}\n"
                   f"중요도:         {r['Level']}\n"
                   f"스캔 상태:      {r['Status']}\n"
                   f"양호 판단 기준: {good_crit}\n"
                   f"현재 값:        {r.get('CurrentValue','–')}\n"
                   f"조치 상태:      {r.get('FixStatus','–')}\n\n"
                   f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                   f"📖 수동 조치 방법 (Model.pdf 기준):\n"
                   f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                   f"{manual_text}")
            messagebox.showinfo(f"[{item_id}] 세부 정보 및 수동 조치 가이드", msg)
        elif idx < len(self.policies):
            p = self.policies[idx]
            item_id = p.get("ItemId", "")
            g = self.model_guides.get(item_id, {})
            good_crit = g.get("good_criteria") or p.get("SecureValue", "–")
            manual_text = g.get("manual_guide") or p.get("Description", "–")

            msg = (f"항목 코드:      {item_id}\n"
                   f"항목명:         {p['Title']}\n"
                   f"중요도:         {p['Level']}\n"
                   f"양호 판단 기준: {good_crit}\n\n"
                   f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                   f"📖 수동 조치 방법 (Model.pdf 기준):\n"
                   f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                   f"{manual_text}")
            messagebox.showinfo(f"[{item_id}] 세부 정보 및 수동 조치 가이드", msg)

    # ── 선택 제어 ────────────────────────────────────────────────────
    def _select_all(self):
        self.tree.selection_set(*self.tree.get_children())

    def _deselect_all(self):
        self.tree.selection_remove(*self.tree.get_children())

    def _select_vuln(self):
        self.tree.selection_remove(*self.tree.get_children())
        for i, r in enumerate(self.vuln_results):
            if "취약" in r.get("Status", "") and "수동" not in r.get("Status", ""):
                self.tree.selection_add(str(i))

    def _get_selected_indices(self):
        sel = self.tree.selection()
        if not sel:
            return list(range(len(self.vuln_results) or len(self.policies)))
        return [int(s) for s in sel]

    # ── 버튼 핸들러 ─────────────────────────────────────────────────
    def _on_scan(self):
        if self.is_running:
            return
        self.is_running = True
        self.stop_requested = False
        self._set_buttons_running()

        # 스캔 시작 즉시 왼쪽 절반에 고정
        try:
            import ctypes
            import pyautogui
            sw, sh = pyautogui.size()
            half_w = sw // 2
            hwnd = int(self.wm_frame(), 16) if hasattr(self, 'wm_frame') else int(self.winfo_id())
            ctypes.windll.user32.SetWindowPos(hwnd, 0, 0, 0, half_w, sh - 40, 0x0040)
        except Exception:
            pass

        threading.Thread(target=self._do_scan, daemon=True).start()

    def _do_scan(self):
        self._log("━" * 55, "meta")
        self._log("  🔍 전체 취약점 스캔 시작...", "meta")
        self._log("━" * 55, "meta")
        try:
            self.vuln_results = get_vulnerability_status(POLICY_DIR)
            for i, r in enumerate(self.vuln_results):
                if self.stop_requested:
                    break
                r["FixStatus"] = "–"
                st = r["Status"]
                tag_key = ("good" if "양호" in st else
                           "manual" if "수동" in st else "vuln")
                icon = "✅" if "양호" in st else "⚠️" if "수동" in st else "❌"
                self._update_tree_status(i, scan_status=st)
                self.after(0, lambda idx=i: (self.tree.selection_set(str(idx)), self.tree.see(str(idx))))
                self._log(f"{icon}  [{r['ItemId']}]  {st}", tag_key)
                self._set_progress(i + 1, len(self.vuln_results))
            self._update_summary()
            v = sum(1 for r in self.vuln_results if "취약" in r.get("Status","") and "수동" not in r.get("Status",""))
            self._log(f"\n✅ 스캔 완료 – 취약: {v}개 / 전체: {len(self.vuln_results)}개", "good")
            self.after(0, lambda: (self._select_all(), self.tree.see("0")))
        except Exception as e:
            self._log(f"❌ 스캔 오류: {e}", "error")
        finally:
            self.is_running = False
            self.after(0, self._set_buttons_idle)

    def _detect_service_status(self):
        status_map = {"iis": "미사용", "dns": "미사용", "snmp": "미사용", "telnet": "미사용"}
        # self.vuln_results에서 각 항목 코드를 검색하여 상태 대조
        for r in self.vuln_results:
            item_id = r.get("ItemId")
            st = r.get("Status", "")
            # 스캔 결과 "취약"이거나 "수동 조치"이면 해당 서비스가 구동 중(사용 중)인 것으로 식별
            if item_id == "W-19" and "취약" in st:
                status_map["iis"] = "사용 중"
            elif item_id == "W-25" and "취약" in st:
                status_map["dns"] = "사용 중"
            elif item_id == "W-29" and "취약" in st:
                status_map["snmp"] = "사용 중"
            elif item_id == "W-34" and "취약" in st:
                status_map["telnet"] = "사용 중"
        return status_map

    def _on_run(self):
        if self.is_running:
            return
        if not self.vuln_results:
            messagebox.showinfo("알림", "먼저 전체 스캔을 실행해주세요.")
            return
        idxs = self._get_selected_indices()

        # 현재 스캔된 결과로부터 각 서비스들의 실시간 사용 여부 감지
        srv_status = self._detect_service_status()

        # 실행 옵션 모달 다이얼로그 팝업 호출 (감지된 서비스 상태 목록 전달)
        dialog = RunOptionDialog(self, srv_status)
        self.wait_window(dialog)

        if not dialog.result:
            return # 취약점 조치/캡처 진행 취소

        mode, services_config = dialog.result
        approved = set()
        for idx in idxs:
            result = self.vuln_results[idx]
            item = result.get("ConfigItem", {})
            if result.get("Status") == "취약" and item.get("RequiresConfirmation"):
                if messagebox.askyesno("운영 영향 확인", f"{result['ItemId']} {result['Title']}\n\n{item.get('Impact', '')}\n\n복구 경로와 업무 영향을 확인했으며 이 항목을 적용하시겠습니까?"):
                    approved.add(result['ItemId'])
        self.approved_items = approved
        self.last_exec_mode = mode
        self.last_services_config = services_config
        self.mode_var.set(mode) # UI 라디오버튼 동기화

        self.is_running = True
        self.stop_requested = False
        self._set_buttons_running()

        # ── 추가: Tkinter 메인 윈도우를 모니터 좌측 절반 크기로 리사이징 및 이동 ──
        try:
            import ctypes
            import pyautogui
            sw, sh = pyautogui.size()
            half_w = sw // 2

            # Tkinter의 win32 hwnd 획득 후 API로 직접 배치 (오차 제거)
            hwnd = int(self.wm_frame(), 16) if hasattr(self, 'wm_frame') else int(self.winfo_id())
            ctypes.windll.user32.SetWindowPos(hwnd, 0, 0, 0, half_w, sh - 40, 0x0040)
        except Exception:
            pass

        threading.Thread(target=self._do_run, args=(idxs, mode, services_config), daemon=True).start()

    def _do_run(self, indices: list[int], mode: str, services_config: dict):
        try:
            self._do_run_items(indices, mode, services_config)
        except Exception as exc:
            self._log(f"작업 중 오류: {exc}", "error")
        finally:
            self.is_running = False
            self.after(0, self._set_buttons_idle)

    def _do_run_items(self, indices: list[int], mode: str, services_config: dict):
        self._log("━" * 55, "warn")
        self._log(f"  ⚡ 보안 조치 + 증빙 캡처 시작 ({len(indices)}개 항목)", "warn")
        self._log("━" * 55, "warn")
        total = len(indices)

        for step, idx in enumerate(indices):
            if self.stop_requested:
                self._log("⏹ 사용자에 의해 중지.", "warn")
                break
            if idx >= len(self.vuln_results):
                continue

            result  = self.vuln_results[idx]
            item_id = result["ItemId"]
            status  = result["Status"]

            # 서비스 미사용 상태에 따른 항목 생략 여부 검증
            skip_by_service = False
            if services_config.get("iis") == "skip" and item_id in ["W-19", "W-21", "W-22", "W-24", "W-33"]:
                skip_by_service = True
            elif services_config.get("dns") == "skip" and item_id in ["W-25", "W-32"]:
                skip_by_service = True
            elif services_config.get("snmp") == "skip" and item_id in ["W-29", "W-30", "W-31"]:
                skip_by_service = True
            elif services_config.get("telnet") == "skip" and item_id in ["W-34"]:
                skip_by_service = True

            if skip_by_service:
                self._log(f"\n🔷 [{item_id}]  {result['Title']}", "meta")
                self._log(f"  → 서비스 미사용 설정(IIS/DNS/SNMP/Telnet)에 의해 보안 조치 및 증빙 수집 생략", "good")
                result["FixStatus"] = "생략"
                self._update_tree_status(idx, scan_status=status, fix_status="생략")
                continue

            self.current_item_id = item_id
            try:
                log_file = os.path.join(LOGS_DIR, f"{item_id}.log")
                if os.path.exists(log_file):
                    os.remove(log_file)
            except Exception:
                pass

            self._set_progress(step + 1, total)
            self._log(f"\n🔷 [{item_id}]  {result['Title']}", "meta")

            # ── 트리뷰 자동 스크롤 및 현재 타겟 행 하이라이트 활성화 및 세부정보 표출 ──
            iid = str(idx)
            self.after(0, lambda i=iid: (self.tree.selection_set(i), self.tree.see(i)))

            # ── 1. 보안 조치 ─────────────────────────────────────────
            if "취약" in status and "수동" not in status:
                self._log(f"  🔧 보안 조치 적용 중...", "warn")
                self._update_tree_status(idx, fix_status="조치 중...")

                invoke_remediation(
                    [result], BACKUPS_DIR, EVIDENCE_DIR,
                    log_callback=self._log, approved_items=self.approved_items
                )
                self._update_tree_status(idx, fix_status=result["FixStatus"])
            else:
                self._log(f"  → 조치 불필요 ({status})", "good")
                result["FixStatus"] = status
                self._update_tree_status(idx, fix_status="대기")

            if self.stop_requested:
                break

            # ── 2. 증빙 캡처 및 수동 조치 팝업 ──────────────────────
            self._log(f"  📷 증빙 화면 캡처 대기 중...", "meta")
            self._update_tree_status(idx, fix_status="캡처 대기...")

            try:
                config_item = result["ConfigItem"].copy()
                config_item["Status"] = status

                is_manual_item = "수동" in str(status) or "수동" in result.get("FixStatus", "")

                # 대기 여부 판단:
                # 1) sequential: 모든 항목에서 대기
                # 2) manual_pause: 수동 조치 항목에서만 대기
                # 3) auto: 전혀 대기하지 않음
                should_wait = (mode == "sequential") or (mode == "manual_pause" and is_manual_item)

                wait_fn = None
                if should_wait:
                    guide_data = self.model_guides.get(item_id, {})
                    good_crit = guide_data.get("good_criteria") or result.get("SecureValue", "–")
                    manual_text = guide_data.get("manual_guide") or config_item.get("Description", "–")

                    # 수동 조치 대상이면 화면 중앙에 가이드 팝업 띄우기
                    if is_manual_item:
                        self._log(f"  📢 [{item_id}] 수동 조치 가이드 팝업을 표시합니다.", "warn")

                    def wait_fn():
                        # 이벤트 락 초기화 및 메인 UI 하단 [캡처 및 다음 진행] 버튼 활성화
                        self.next_clicked.clear()
                        self.after(0, lambda: self.btn_next.configure(state="normal"))

                        guide_dlg = None
                        # 수동 조치 항목인 경우 눈에 띄는 전용 모달 팝업 표출
                        if is_manual_item:
                            def _show_guide_dlg():
                                nonlocal guide_dlg
                                guide_dlg = ManualGuideDialog(
                                    parent=self,
                                    item_id=item_id,
                                    title=result["Title"],
                                    good_criteria=good_crit,
                                    manual_guide=manual_text,
                                    on_proceed=self._on_next
                                )
                            self.after(0, _show_guide_dlg)

                        # 사용자 버튼 입력 대기 (메인 버튼 또는 모달 내 조치완료 버튼)
                        while not self.next_clicked.is_set():
                            if self.stop_requested:
                                self.after(0, lambda: self.btn_next.configure(state="disabled"))
                                if guide_dlg and guide_dlg.winfo_exists():
                                    guide_dlg.after(0, guide_dlg.destroy)
                                return False
                            import time
                            time.sleep(0.1)

                        # 대기 해제 후 다이얼로그 닫기 및 버튼 비활성화
                        self.after(0, lambda: self.btn_next.configure(state="disabled"))
                        if guide_dlg and guide_dlg.winfo_exists():
                            guide_dlg.after(0, guide_dlg.destroy)
                        self.next_clicked.clear()
                        return True

                capture_evidence(
                    config_item,
                    EVIDENCE_DIR,
                    log_callback=self._log,
                    wait_callback=wait_fn
                )
            except Exception as e:
                self._log(f"  ⚠️ 캡처 중단 또는 오류: {e}", "warn")
                if should_wait and "User Cancelled" in str(e):
                    self._log("⏹ 사용자가 중단을 선택했습니다.", "warn")
                    break

            # 캡처 완료 후 최종 상태로 원복 갱신
            self._update_tree_status(idx, scan_status=status, fix_status=result["FixStatus"])
            self._update_summary()

        if not self.stop_requested:
            self._log("\n━" * 55, "meta")
            self._log("  📄 최종 보고서 생성 중...", "meta")
            try:
                final = get_vulnerability_status(POLICY_DIR)
                invoke_reporting(
                    self.vuln_results, final,
                    REPORTS_DIR, EVIDENCE_DIR,
                    log_callback=self._log
                )
                self._log("━" * 55, "good")
                self._log("  ✅ 모든 작업 완료!", "good")
                self._log(f"  📁 보고서: {REPORTS_DIR}", "good")
                self.after(0, lambda: messagebox.showinfo(
                    "완료", "보안 조치 및 증빙 수집이 완료되었습니다.\n보고서를 확인해주세요."))
            except Exception as e:
                self._log(f"❌ 보고서 오류: {e}", "error")

        # ── 추가: 프로세스 완료 시 윈도우 중앙 위치 복구 ──
        try:
            import pyautogui
            sw, sh = pyautogui.size()
            x = (sw - 1350) // 2
            y = (sh - 820) // 2
            self.after(0, lambda: self.geometry(f"1350x820+{x}+{y}"))
        except Exception:
            pass

        self.is_running = False
        self.after(0, self._set_buttons_idle)

    def _run_selected(self):
        self._on_run()

    def _capture_selected(self):
        if self.is_running or not self.vuln_results:
            return
        idxs = self._get_selected_indices()
        if not idxs:
            return
        self.is_running = True
        self.stop_requested = False
        self._set_buttons_running()
        threading.Thread(target=self._do_capture_only, args=(idxs,), daemon=True).start()

    def _do_capture_only(self, indices):
        try:
            self._do_capture_items(indices)
        finally:
            self.is_running = False
            self.after(0, self._set_buttons_idle)

    def _do_capture_items(self, indices):
        for idx in indices:
            if self.stop_requested or idx >= len(self.vuln_results):
                break
            r = self.vuln_results[idx]

            self.current_item_id = r["ItemId"]
            try:
                log_file = os.path.join(LOGS_DIR, f"{r['ItemId']}.log")
                if os.path.exists(log_file):
                    os.remove(log_file)
            except Exception:
                pass

            self._log(f"  📷 [{r['ItemId']}] 캡처 중...", "meta")
            try:
                capture_evidence(r["ConfigItem"], EVIDENCE_DIR, log_callback=self._log)
            except Exception as e:
                self._log(f"  ⚠️ [{r['ItemId']}] 캡처 오류: {e}", "warn")

    def _on_stop(self):
        self.stop_requested = True
        self.next_clicked.set() # 대기 상태 락 강제 해제
        self._log("⏹ 중지 요청됨...", "warn")

        # ── 추가: 윈도우 크기 원래대로 복구 및 중앙 배치 ──
        try:
            import pyautogui
            sw, sh = pyautogui.size()
            x = (sw - 1350) // 2
            y = (sh - 820) // 2
            self.after(0, lambda: self.geometry(f"1350x820+{x}+{y}"))
        except Exception:
            pass

    def _on_report(self):
        if self.is_running:
            return
        if not self.vuln_results:
            messagebox.showinfo("알림", "먼저 스캔을 실행해주세요.")
            return
        threading.Thread(target=self._do_report, daemon=True).start()

    def _do_report(self):
        self._log("📄 보고서 생성 중...", "meta")
        try:
            invoke_reporting(
                self.vuln_results, get_vulnerability_status(POLICY_DIR),
                REPORTS_DIR, EVIDENCE_DIR,
                log_callback=self._log
            )
        except Exception as e:
            self._log(f"❌ 보고서 오류: {e}", "error")

    def _on_next(self):
        self.next_clicked.set()

    # ── 버튼 상태 ────────────────────────────────────────────────────
    def _set_buttons_running(self):
        self.btn_scan.configure(state="disabled")
        self.btn_auto.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.btn_report.configure(state="disabled")
        self.btn_next.configure(state="disabled")

    def _set_buttons_idle(self):
        self.btn_scan.configure(state="normal")
        self.btn_auto.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.btn_report.configure(state="normal")
        self.btn_next.configure(state="disabled")

# ── 수동 조치 전용 가이드 팝업 다이얼로그 (화면 중앙 상단 모달) ─────────
class ManualGuideDialog(ctk.CTkToplevel):
    def __init__(self, parent, item_id, title, good_criteria, manual_guide, on_proceed):
        super().__init__(parent)
        self.title(f"[{item_id}] 수동 보안 조치 안내")
        self.geometry("620x520")
        self.resizable(True, True)
        self.minsize(560, 420)
        self.configure(fg_color=BG_DARK)
        self.attributes("-topmost", True)

        self.on_proceed = on_proceed

        # 화면 정중앙 또는 모니터 우측에 적절히 배치
        try:
            sw, sh = parent.winfo_screenwidth(), parent.winfo_screenheight()
            w, h = 620, 520
            # 메인 창이 왼쪽에 배치되어 있으면, 가이드 팝업은 오른쪽 절반 상단에 보기 쉽게 배치
            x = (sw // 2) + 20
            y = 60
            self.geometry(f"{w}x{h}+{x}+{y}")
        except Exception:
            pass

        # 헤더
        hdr = ctk.CTkFrame(self, fg_color=BG_CARD, height=58, corner_radius=0)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        ctk.CTkLabel(hdr, text="💡", font=("Segoe UI Emoji", 20)).pack(side="left", padx=(16, 6))
        title_f = ctk.CTkFrame(hdr, fg_color=BG_CARD)
        title_f.pack(side="left", fill="y", pady=8)
        ctk.CTkLabel(title_f, text=f"[{item_id}] {title}", font=("Segoe UI", 13, "bold"), text_color=TEXT_MAIN).pack(anchor="w")
        ctk.CTkLabel(title_f, text="사용자 직접 조치 필요 (가이드를 확인하고 설정을 완료해주세요)", font=("Segoe UI", 9), text_color=WARNING).pack(anchor="w")

        # 내용 바디 컨테이너
        body = ctk.CTkFrame(self, fg_color=BG_INNER, corner_radius=10)
        body.pack(fill="both", expand=True, padx=14, pady=12)

        # 1. 양호 판단 기준 카드
        crit_lbl = ctk.CTkLabel(body, text="📋 KISA 양호 판단 기준 (Model.pdf)", font=("Segoe UI", 11, "bold"), text_color=SUCCESS)
        crit_lbl.pack(anchor="w", padx=14, pady=(10, 4))

        crit_box = ctk.CTkFrame(body, fg_color=BG_CARD, corner_radius=8)
        crit_box.pack(fill="x", padx=14, pady=(0, 10))

        txt_crit = tk.Text(crit_box, font=("Segoe UI", 10, "bold"), bg=BG_CARD, fg=SUCCESS,
                           height=3, wrap="word", bd=0, highlightthickness=0)
        txt_crit.insert("1.0", good_criteria)
        txt_crit.config(state="disabled")
        txt_crit.pack(fill="both", expand=True, padx=10, pady=8)

        # 2. 수동 조치 방법 카드 (Step-by-Step)
        guide_lbl = ctk.CTkLabel(body, text="🛠️ 수동 조치 상세 가이드 및 단계", font=("Segoe UI", 11, "bold"), text_color=ACCENT)
        guide_lbl.pack(anchor="w", padx=14, pady=(0, 4))

        from tkinter import scrolledtext
        txt_guide = scrolledtext.ScrolledText(
            body, bg=BG_CARD, fg=TEXT_MAIN, font=("Consolas", 10),
            wrap="word", bd=0, highlightthickness=0
        )
        txt_guide.insert("1.0", manual_guide)
        txt_guide.config(state="disabled")
        txt_guide.pack(fill="both", expand=True, padx=14, pady=(0, 10))

        # 하단 조치 완료 버튼바
        btn_bar = ctk.CTkFrame(self, fg_color=BG_DARK, height=54, corner_radius=0)
        btn_bar.pack(fill="x", side="bottom", padx=14, pady=(0, 10))

        btn_ok = ctk.CTkButton(
            btn_bar, text="✔ 조치 완료 (화면 캡처 및 다음으로 진행)",
            font=("Segoe UI", 12, "bold"), fg_color=SUCCESS, text_color="black",
            height=38, corner_radius=8, command=self._on_done
        )
        btn_ok.pack(fill="x", padx=10, pady=6)

    def _on_done(self):
        if self.on_proceed:
            self.on_proceed()
        self.destroy()


# ── 실행 옵션 모달 다이얼로그 ─────────────────────────────────────────
class RunOptionDialog(ctk.CTkToplevel):
    def __init__(self, parent, service_status):
        super().__init__(parent)
        self.title("실행 옵션 설정")
        self.geometry("440x510")
        self.resizable(False, False)
        self.configure(fg_color=BG_INNER)

        # 모달창 동작 선언
        self.transient(parent)
        self.grab_set()

        self.result = None

        # 부모 창 중앙에 정렬 배치
        try:
            x = parent.winfo_x() + (parent.winfo_width() - 440) // 2
            y = parent.winfo_y() + (parent.winfo_height() - 510) // 2
            self.geometry(f"+{max(0, x)}+{max(0, y)}")
        except Exception:
            pass

        # 타이틀
        ctk.CTkLabel(self, text="⚡ 보안 조치 및 증빙 캡처 옵션",
                     font=("Segoe UI", 13, "bold"), text_color=ACCENT).pack(pady=(12, 6))

        # 옵션 영역 카드
        frame = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=10)
        frame.pack(fill="both", expand=True, padx=15, pady=5)

        # 1. 진행 모드 선택 (통합 3가지 모드)
        ctk.CTkLabel(frame, text="1. 진행 모드 선택", font=("Segoe UI", 11, "bold"), text_color=TEXT_MAIN).pack(anchor="w", padx=15, pady=(10, 4))

        current_m = getattr(parent, "last_exec_mode", "manual_pause")
        self.exec_mode_var = tk.StringVar(value=current_m)

        r1 = ctk.CTkRadioButton(frame, text="전체 자동 조치 및 캡처 (대기 없이 원스톱 진행)",
                                variable=self.exec_mode_var, value="auto",
                                text_color=TEXT_MAIN, font=("Segoe UI", 10))
        r1.pack(anchor="w", padx=25, pady=3)

        r2 = ctk.CTkRadioButton(frame, text="수동 조치 항목만 안내 팝업 후 대기 (권장)",
                                variable=self.exec_mode_var, value="manual_pause",
                                text_color=TEXT_MAIN, font=("Segoe UI", 10, "bold"))
        r2.pack(anchor="w", padx=25, pady=3)

        r3 = ctk.CTkRadioButton(frame, text="모든 항목 순차 진행 (항목마다 확인 후 다음으로)",
                                variable=self.exec_mode_var, value="sequential",
                                text_color=TEXT_MAIN, font=("Segoe UI", 10))
        r3.pack(anchor="w", padx=25, pady=3)

        # 구분선
        ctk.CTkFrame(frame, height=2, fg_color=BG_INNER).pack(fill="x", padx=15, pady=10)

        # 2. 서비스 사용 여부 설정
        ctk.CTkLabel(frame, text="2. 서비스별 조치 설정 (스캔 결과 기준)", font=("Segoe UI", 11, "bold"), text_color=TEXT_MAIN).pack(anchor="w", padx=15, pady=(0, 4))

        srv_frame = ctk.CTkFrame(frame, fg_color=BG_CARD)
        srv_frame.pack(fill="x", padx=15, pady=2)

        self.srv_vars = {}
        services_list = [("IIS", "iis"), ("DNS", "dns"), ("SNMP", "snmp"), ("Telnet", "telnet")]

        for label, key in services_list:
            status_text = service_status.get(key, "미사용")

            row_f = ctk.CTkFrame(srv_frame, fg_color=BG_CARD)
            row_f.pack(fill="x", pady=2)

            # 서비스명
            ctk.CTkLabel(row_f, text=f"• {label}", text_color=TEXT_MAIN, font=("Segoe UI", 9, "bold"), width=60, anchor="w").pack(side="left")

            # 스캔된 사용 여부 표시
            status_fg = WARNING if status_text == "미사용" else ERROR_C
            ctk.CTkLabel(row_f, text=f"({status_text})", text_color=status_fg, font=("Segoe UI", 9), width=70, anchor="w").pack(side="left")

            # 기본값 설정: 미사용 상태이면 skip(생략), 사용 중이면 proceed(진행)
            default_val = "skip" if status_text == "미사용" else "proceed"
            prev_val = parent.last_services_config.get(key, default_val)

            var = tk.StringVar(value=prev_val)
            self.srv_vars[key] = var

            r_skip = ctk.CTkRadioButton(row_f, text="생략(Skip)", variable=var, value="skip", text_color=TEXT_MAIN, font=("Segoe UI", 9))
            r_skip.pack(side="left", padx=5)

            r_proc = ctk.CTkRadioButton(row_f, text="진행(Proceed)", variable=var, value="proceed", text_color=TEXT_MAIN, font=("Segoe UI", 9))
            r_proc.pack(side="left", padx=5)

        # 하단 버튼바
        btn_frame = ctk.CTkFrame(self, fg_color=BG_INNER)
        btn_frame.pack(fill="x", side="bottom", pady=12)

        ok_btn = ctk.CTkButton(btn_frame, text="시작", width=110, fg_color=ACCENT, text_color="white", font=("Segoe UI", 11, "bold"),
                               corner_radius=8, command=self.on_ok)
        ok_btn.pack(side="left", padx=(100, 10))

        cancel_btn = ctk.CTkButton(btn_frame, text="취소", width=110, fg_color=BG_CARD, text_color="white", font=("Segoe UI", 11, "bold"),
                                   corner_radius=8, command=self.on_cancel)
        cancel_btn.pack(side="left")

    def on_ok(self):
        self.result = (self.exec_mode_var.get(), {k: v.get() for k, v in self.srv_vars.items()})
        self.destroy()

    def on_cancel(self):
        self.destroy()


# ── 관리자 권한 확인 ─────────────────────────────────────────────────
def _is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _relaunch_as_admin():
    import ctypes
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1
    )


if __name__ == "__main__":
    if not _is_admin():
        root = tk.Tk()
        root.withdraw()
        if messagebox.askyesno("관리자 권한 필요",
                               "이 프로그램은 관리자 권한이 필요합니다.\n관리자 권한으로 재시작하시겠습니까?"):
            _relaunch_as_admin()
        root.destroy()
        sys.exit(0)

    # DPI 인식 활성화 (윈도우 배율이 설정되어 있을 때 화면 배치 왜곡 방지)
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1) # PROCESS_SYSTEM_DPI_AWARE
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass

    app = KisaPatcherApp()
    app.mainloop()
