[assembly: System.Runtime.CompilerServices.RuntimeCompatibility(WrapNonExceptionThrows = true)]
[assembly: System.Runtime.CompilerServices.CompilationRelaxations(8)]
[assembly: System.Reflection.AssemblyVersion("0.0.0.0")]
namespace KisaAutoPatcher
{
	public class MainForm : System.Windows.Forms.Form
	{
		private delegate bool EnumWindowsProc(System.IntPtr hWnd, System.IntPtr lParam);

		public struct RECT
		{
			public int Left;

			public int Top;

			public int Right;

			public int Bottom;
		}

		private const uint WM_CLOSE = 16u;

		private const int SW_SHOWNORMAL = 1;

		private const int SW_RESTORE = 9;

		private const uint SWP_NOZORDER = 4u;

		private const uint SWP_SHOWWINDOW = 64u;

		private System.Windows.Forms.Button btnFullAuto;

		private System.Windows.Forms.Button btnInteractive;

		private System.Windows.Forms.Button btnNext;

		private System.Windows.Forms.Button btnStop;

		private System.Windows.Forms.Label lblItemInfo;

		private System.Windows.Forms.Label lblDescription;

		private System.Windows.Forms.Label lblProgress;   // [3/62] 카운터

		private System.Windows.Forms.ProgressBar progBar;  // 헤더 카드 진행률 바

		private System.Windows.Forms.RichTextBox rtbGuideline;

		private System.Windows.Forms.ListBox lstItems;

		private System.Windows.Forms.Panel pnlSelection;

		private System.Windows.Forms.Panel pnlWork;

		// 사이드바 아이템별 상태 추적 (양호/취약)
		private System.Collections.Generic.Dictionary<int, string> itemStatusMap
			= new System.Collections.Generic.Dictionary<int, string>();

		private string scriptDir;

		private string configPath;

		private string evidenceDir;

		private string reportsDir;

		private dynamic criteriaList;

		private int currentItemIndex = 0;

		private bool isInteractiveMode = false;

		private bool isProgrammaticSelection = false;

		private System.Diagnostics.Process activeUIProcess = null;

		private string currentItemId = "";

		private string currentItemTitle = "";

		private bool stopRequested = false;

		private bool isNavigationActive = false;

		private KisaAutoPatcher.PowerShellController psController;

		private System.Collections.ObjectModel.Collection<System.Management.Automation.PSObject> vulnerabilityResults;

		private System.Windows.Forms.Form navigationLoadingForm = null;

		public MainForm()
		{
			InitializeComponentLayout();
			InitializePaths();
			RepairSecurityDatabase();
		}

		private void InitializePaths()
		{
			scriptDir = System.AppDomain.CurrentDomain.BaseDirectory;
			if (string.IsNullOrEmpty(scriptDir))
			{
				scriptDir = System.IO.Directory.GetCurrentDirectory();
			}
			configPath = System.IO.Path.Combine(scriptDir, "Config", "Policies");
			evidenceDir = System.IO.Path.Combine(scriptDir, "Evidence");
			reportsDir = System.IO.Path.Combine(scriptDir, "Reports");
			if (!System.IO.Directory.Exists(evidenceDir))
			{
				System.IO.Directory.CreateDirectory(evidenceDir);
			}
			if (!System.IO.Directory.Exists(reportsDir))
			{
				System.IO.Directory.CreateDirectory(reportsDir);
			}
			psController = new KisaAutoPatcher.PowerShellController(scriptDir);
		}

		private void RepairSecurityDatabase()
		{
			try
			{
				string systemPath = System.IO.Path.Combine(System.Environment.SystemDirectory, "security\\database\\secedit.sdb");
				if (System.IO.File.Exists(systemPath))
				{
					System.Diagnostics.ProcessStartInfo processStartInfo = new System.Diagnostics.ProcessStartInfo();
					processStartInfo.FileName = "cmd.exe";
					// cryptsvc 중지 -> 소유권 이익 -> 권한 이익 -> 기존 파일 rename(잠금 해제 강제 조치) -> 새 데이터베이스 덮어쓰기 생성 -> cryptsvc 시작
					processStartInfo.Arguments = "/c net stop cryptsvc /y && takeown /f \"" + systemPath + "\" && icacls \"" + systemPath + "\" /grant administrators:F && (if exist \"" + systemPath + "\" ren \"" + systemPath + "\" secedit.sdb.old) && secedit /configure /db \"" + systemPath + "\" /cfg C:\\Windows\\inf\\defltbase.inf /overwrite && net start cryptsvc";
					processStartInfo.CreateNoWindow = true;
					processStartInfo.UseShellExecute = false;
					processStartInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
					
					using (System.Diagnostics.Process process = System.Diagnostics.Process.Start(processStartInfo))
					{
						process.WaitForExit(10000);
					}
				}
			}
			catch
			{
			}
		}

		private void LstItems_DrawItem(object sender, System.Windows.Forms.DrawItemEventArgs e)
		{
			if (e.Index < 0) return;
			e.Graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
			bool selected = (e.State & System.Windows.Forms.DrawItemState.Selected) == System.Windows.Forms.DrawItemState.Selected;

			// 상태별 배경 / 배지 색 결정
			string statusTag = "";
			itemStatusMap.TryGetValue(e.Index, out statusTag);
			bool isVuln = (statusTag == "vuln");
			bool isGood = (statusTag == "good");

			System.Drawing.Color bgColor = selected
				? System.Drawing.Color.FromArgb(52, 42, 36)
				: (e.Index % 2 == 0 ? System.Drawing.Color.FromArgb(28, 25, 23) : System.Drawing.Color.FromArgb(32, 28, 25));
			using (System.Drawing.SolidBrush bgBrush = new System.Drawing.SolidBrush(bgColor))
				e.Graphics.FillRectangle(bgBrush, e.Bounds);

			// 왼쪽 엑센트 바
			System.Drawing.Color barColor = isVuln ? System.Drawing.Color.FromArgb(190, 70, 60)
													: isGood ? System.Drawing.Color.FromArgb(74, 160, 120)
													: (selected ? System.Drawing.Color.FromArgb(204, 120, 92) : System.Drawing.Color.FromArgb(60, 52, 46));
			using (System.Drawing.SolidBrush accentBrush = new System.Drawing.SolidBrush(barColor))
				e.Graphics.FillRectangle(accentBrush, e.Bounds.Left, e.Bounds.Top + 4, 3, e.Bounds.Height - 8);

			// 상태 배지 (✓ / ✗ / ○)
			string badge = isVuln ? "✗" : isGood ? "✓" : "○";
			System.Drawing.Color badgeColor = isVuln ? System.Drawing.Color.FromArgb(190, 70, 60)
													 : isGood ? System.Drawing.Color.FromArgb(74, 160, 120)
													 : System.Drawing.Color.FromArgb(80, 70, 62);
			System.Drawing.Rectangle badgeBounds = new System.Drawing.Rectangle(e.Bounds.Left + 8, e.Bounds.Top + (e.Bounds.Height - 16) / 2, 16, 16);
			System.Windows.Forms.TextRenderer.DrawText(e.Graphics, badge, lstItems.Font, badgeBounds, badgeColor,
				System.Windows.Forms.TextFormatFlags.HorizontalCenter | System.Windows.Forms.TextFormatFlags.VerticalCenter);

			// 아이템 텍스트
			string text = lstItems.Items[e.Index].ToString();
			System.Drawing.Color textColor = selected
				? System.Drawing.Color.FromArgb(232, 213, 183)
				: System.Drawing.Color.FromArgb(178, 168, 155);
			System.Drawing.Rectangle textBounds = new System.Drawing.Rectangle(e.Bounds.Left + 28, e.Bounds.Top, e.Bounds.Width - 32, e.Bounds.Height);
			System.Windows.Forms.TextRenderer.DrawText(e.Graphics, text, lstItems.Font, textBounds, textColor,
				System.Windows.Forms.TextFormatFlags.EndEllipsis | System.Windows.Forms.TextFormatFlags.VerticalCenter);

			// 하단 구분선
			using (System.Drawing.Pen divPen = new System.Drawing.Pen(System.Drawing.Color.FromArgb(45, 40, 36), 1))
				e.Graphics.DrawLine(divPen, e.Bounds.Left, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);
		}

		private void LstItems_SelectedIndexChanged(object sender, System.EventArgs e)
		{
			if (!isProgrammaticSelection && lstItems.Enabled && lstItems.SelectedIndex >= 0 && vulnerabilityResults != null && lstItems.SelectedIndex != currentItemIndex)
			{
				CleanupSpawnedWindows(currentItemId);
				currentItemIndex = lstItems.SelectedIndex;
				ProcessNextItem();
			}
		}

		private void StartPatching(bool interactive)
		{
			isInteractiveMode = interactive;
			stopRequested = false;
			if (btnStop != null)
			{
				btnStop.Enabled = true;
			}
			pnlSelection.Visible = false;
			pnlWork.Visible = true;
			AlignThisWindowToLeft();
			LoadCriteria();
			if (isInteractiveMode)
			{
				currentItemIndex = 0;
				ProcessNextItem();
			}
			else
			{
				RunFullAutoMode();
			}
		}

		private void AlignThisWindowToLeft()
		{
			System.Drawing.Rectangle workingArea = System.Windows.Forms.Screen.PrimaryScreen.WorkingArea;
			int num = workingArea.Width / 2;
			int height = workingArea.Height;
			base.Location = new System.Drawing.Point(0, 0);
			base.Size = new System.Drawing.Size(num, height);
			SetWindowPos(base.Handle, System.IntPtr.Zero, 0, 0, num, height, 68u);
		}

		private void LoadCriteria()
		{
			lstItems.Items.Clear();
			itemStatusMap.Clear();
			lblItemInfo.Text    = "취약점 스캔 진행 중입니다. 잠시만 기다려주세요...";
			lblDescription.Text = "시스템 스캔 진행 중...";
			rtbGuideline.Clear();
			AppendLog("──────────────────────────────────────────────\n", LogLevel.Meta);
			AppendLog("  [KISA SCAN]  보안 취약점 검사를 진행하고 있습니다.\n", LogLevel.Warn);
			AppendLog("──────────────────────────────────────────────\n", LogLevel.Meta);
			System.Windows.Forms.Application.DoEvents();
			try
			{
				vulnerabilityResults = psController.GetVulnerabilityStatus(configPath);
				foreach (System.Management.Automation.PSObject vulnerabilityResult in vulnerabilityResults)
				{
					string arg  = vulnerabilityResult.Properties["ItemId"].Value.ToString();
					string arg2 = vulnerabilityResult.Properties["Title"].Value.ToString();
					lstItems.Items.Add(string.Format("{0}  {1}", arg, arg2));
				}
				if (progBar != null && vulnerabilityResults.Count > 0)
				{
					progBar.Maximum = vulnerabilityResults.Count;
					progBar.Value   = 0;
				}
			}
			catch (System.Exception ex)
			{
				System.Windows.Forms.MessageBox.Show(string.Format("KISA 점검 기준 데이터 및 파워쉘 모듈 로드 실패: {0}", ex.Message), "오류", System.Windows.Forms.MessageBoxButtons.OK, System.Windows.Forms.MessageBoxIcon.Hand);
			}
		}


		// ── 색상 코드된 로그 언팓 헬퍼 ──────────────────────────────────
		private enum LogLevel { Meta, Info, Good, Warn, Error }
		private void AppendLog(string msg, LogLevel level = LogLevel.Info)
		{
			System.Drawing.Color col;
			switch (level)
			{
				case LogLevel.Good:  col = System.Drawing.Color.FromArgb( 74, 160, 120); break;
				case LogLevel.Warn:  col = System.Drawing.Color.FromArgb(204, 120,  92); break;
				case LogLevel.Error: col = System.Drawing.Color.FromArgb(190,  70,  60); break;
				case LogLevel.Meta:  col = System.Drawing.Color.FromArgb( 80,  70,  62); break;
				default:             col = System.Drawing.Color.FromArgb(200, 188, 172); break;
			}
			rtbGuideline.SelectionStart  = rtbGuideline.TextLength;
			rtbGuideline.SelectionLength = 0;
			rtbGuideline.SelectionColor  = col;
			rtbGuideline.AppendText(msg);
			rtbGuideline.SelectionColor  = rtbGuideline.ForeColor;
			rtbGuideline.SelectionStart  = rtbGuideline.TextLength;
			rtbGuideline.ScrollToCaret();
		}

		// ── 진행률 바 업데이트 ──────────────────────────────────────
		private void UpdateProgress(int current, int total)
		{
			if (progBar == null || lblProgress == null) return;
			if (total <= 0) return;
			progBar.Maximum = total;
			progBar.Value   = System.Math.Min(current, total);
			lblProgress.Text = string.Format("{0} / {1}", current, total);
		}

		private void ProcessNextItem()
		{
			if (stopRequested) return;
			if (vulnerabilityResults == null || currentItemIndex >= vulnerabilityResults.Count)
			{
				// 완료 시 인라인 완료 목록 표시 (MessageBox 대체)
				AppendLog("\n\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", LogLevel.Good);
				AppendLog("  ✔  모든 취약점 조치 및 검증 검사가 완료되었습니다!\n", LogLevel.Good);
				AppendLog("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", LogLevel.Good);
				System.Collections.ObjectModel.Collection<System.Management.Automation.PSObject> vulnerabilityStatus = psController.GetVulnerabilityStatus(configPath);
				psController.InvokeReporting(vulnerabilityResults, vulnerabilityStatus, reportsDir, evidenceDir);
				Close();
				return;
			}
			isProgrammaticSelection = true;
			lstItems.SelectedIndex = currentItemIndex;
			isProgrammaticSelection = false;
			System.Management.Automation.PSObject pSObject = vulnerabilityResults[currentItemIndex];
			currentItemId    = pSObject.Properties["ItemId"].Value.ToString();
			currentItemTitle = pSObject.Properties["Title"].Value.ToString();
			string status    = pSObject.Properties["Status"].Value.ToString();
			string curVal    = "N/A";
			if (pSObject.Properties["CurrentValue"] != null && pSObject.Properties["CurrentValue"].Value != null)
				curVal = pSObject.Properties["CurrentValue"].Value.ToString();
			string desc = "상세 설명 없음";
			if (pSObject.Properties["ConfigItem"] != null && pSObject.Properties["ConfigItem"].Value != null)
			{
				dynamic ci = pSObject.Properties["ConfigItem"].Value;
				if ((object)ci != null) try { desc = (ci.Description != null) ? ci.Description.ToString() : "상세 설명 없음"; } catch { }
			}

			// 사이드바 상태 배지 업데이트
			itemStatusMap[currentItemIndex] = status.Contains("취약") ? "vuln" : "good";
			lstItems.Invalidate();

			// 진행률 바 업데이트
			UpdateProgress(currentItemIndex + 1, vulnerabilityResults.Count);

			// 헤더 카드 업데이트
			string statusTag = status.Contains("취약") ? "[⚠ 취약]" : "[✔ 양호]";
			lblItemInfo.Text    = string.Format("{0}  {1}  ·  현재값: {2}", currentItemId, statusTag, curVal);
			lblDescription.Text = currentItemTitle;

			// 로그 초기화 (헤더 섹션)
			rtbGuideline.Clear();
			AppendLog(string.Format("┌── [{0}] {1}\n", currentItemId, currentItemTitle), LogLevel.Warn);
			AppendLog(string.Format("│  설명: {0}\n", desc), LogLevel.Meta);
			AppendLog(string.Format("│  상태: {0}  (측정값: {1})\n", status, curVal),
				status.Contains("취약") ? LogLevel.Error : LogLevel.Good);
			AppendLog("└────────────────────────────────────────────────\n\n", LogLevel.Meta);
			AppendLog("[조치 및 검증 방법 안내]\n", LogLevel.Info);

			if (status.Contains("취약"))
			{
				AppendLog("  → 취약 항목: 파워쉘 자동 보안 조치를 가동합니다...\n", LogLevel.Warn);
				try
				{
					psController.InvokeRemediation(pSObject, ReportsDirFallback("Backups"), evidenceDir);
					rtbGuideline.AppendText(" -> 보안 조치 완료. 시스템 상태가 정책 기준치에 맞게 자동 교정되었습니다.\n\n");
					lblItemInfo.Text = string.Format("[{0}] 조치 완료 - 수동 확인 대기", currentItemId);
				}
				catch (System.Exception ex)
				{
					rtbGuideline.AppendText(string.Format(" -> [오류] 자동 조치 실패: {0}\n\n", ex.Message));
				}
			}
			else
			{
				rtbGuideline.AppendText(" -> 상태가 양호 또는 수동 조치이므로 추가 자동 조치를 건너뜁니다.\n\n");
			}
			SpawnWindowsSettingsUI(pSObject);
			btnNext.Enabled = true;
		}

		private string ReportsDirFallback(string subFolder)
		{
			string text = System.IO.Path.Combine(scriptDir, subFolder);
			if (!System.IO.Directory.Exists(text))
			{
				System.IO.Directory.CreateDirectory(text);
			}
			return text;
		}

		private void SpawnWindowsSettingsUI(System.Management.Automation.PSObject resultObj)
		{
			string text = "gpedit.msc";
			string arguments = "";
			string text2 = resultObj.Properties["ItemId"].Value.ToString();
			string text3 = resultObj.Properties["Title"].Value.ToString();
			string a = resultObj.Properties["TechType"].Value.ToString();
			dynamic value = resultObj.Properties["ConfigItem"].Value;
			string text4 = null;
			string text5 = null;
			string text6 = null;
			string text7 = null;
			if (value != null)
			{
				try
				{
					text4 = ((value.RegistryPath != null) ? value.RegistryPath.ToString() : null);
				}
				catch
				{
				}
				try
				{
					text5 = ((value.RegistryName != null) ? value.RegistryName.ToString() : null);
				}
				catch
				{
				}
				try
				{
					text6 = ((value.SecureValue != null) ? value.SecureValue.ToString() : null);
				}
				catch
				{
				}
				try
				{
					text7 = ((value.SeceditKey != null) ? value.SeceditKey.ToString() : null);
				}
				catch
				{
				}
			}
			rtbGuideline.AppendText("[시각 및 기술 검증 상세 경로]\n");
			if (text2 == "W-03" || text2 == "W-06" || text2 == "W-14")
			{
				text = "lusrmgr.msc";
				rtbGuideline.AppendText(" - 대상 도구: 로컬 사용자 및 그룹 (lusrmgr.msc)\n");
				if (text2 == "W-03")
				{
					rtbGuideline.AppendText(" - 확인 위치: [사용자] -> 불필요한 계정 정리 확인\n");
				}
				else if (text2 == "W-06")
				{
					rtbGuideline.AppendText(" - 확인 위치: [그룹] -> Administrators 그룹의 구성원 확인\n");
				}
				else if (text2 == "W-14")
				{
					rtbGuideline.AppendText(" - 확인 위치: [그룹] -> Remote Desktop Users 그룹의 구성원 확인\n");
				}
			}
			else if (text2 == "W-01" || text2 == "W-02" || text2 == "W-04" || text2 == "W-05" || text2 == "W-07" || text2 == "W-08" || text2 == "W-08_Reset" || text2 == "W-09" || text2 == "W-09_Complexity" || text2 == "W-09_History" || text2 == "W-09_MaxAge" || text2 == "W-09_MinAge" || text2 == "W-10" || text2 == "W-11" || text2 == "W-12" || text2 == "W-13" || text2 == "W-15" || text2 == "W-43" || text2 == "W-52" || text2 == "W-53" || text2 == "W-51" || text2 == "W-56" || text2 == "W-55" || text2 == "W-59" || text2 == "W-60" || text2 == "W-59")
			{
				text = "secpol.msc";
				rtbGuideline.AppendText(" - 대상 도구: 로컬 보안 정책 (secpol.msc)\n");
				if (text2.StartsWith("W-09") || text2 == "W-05")
				{
					rtbGuideline.AppendText(" - 확인 위치: [보안 설정] -> [계정 정책] -> [암호 정책]\n");
				}
				else if (text2 == "W-04" || text2 == "W-08" || text2 == "W-08_Reset")
				{
					rtbGuideline.AppendText(" - 확인 위치: [보안 설정] -> [계정 정책] -> [계정 잠금 정책]\n");
				}
				else if (text2 == "W-11" || text2 == "W-52" || text2 == "W-56" || text2 == "W-55")
				{
					rtbGuideline.AppendText(" - 확인 위치: [보안 설정] -> [로컬 정책] -> [사용자 권한 지정]\n");
				}
				else if (text2 == "W-43")
				{
					rtbGuideline.AppendText(" - 확인 위치: [보안 설정] -> [로컬 정책] -> [감사 정책]\n");
				}
				else if (text2 == "W-01" || text2 == "W-02" || text2 == "W-07" || text2 == "W-10" || text2 == "W-12" || text2 == "W-13" || text2 == "W-15" || text2 == "W-53" || text2 == "W-51" || text2 == "W-59" || text2 == "W-60" || text2 == "W-59")
				{
					rtbGuideline.AppendText(" - 확인 위치: [보안 설정] -> [로컬 정책] -> [보안 옵션]\n");
				}
				rtbGuideline.AppendText(string.Format(" - 설정 식별자(SeceditKey/Registry): {0}\n - 권장 기준치: {1}\n", text7 ?? text5 ?? "N/A", text6 ?? "N/A"));
			}
			else if (text2 == "W-16" || text2 == "W-17")
			{
				text = "fsmgmt.msc";
				if (text2 == "W-16")
				{
					rtbGuideline.AppendText(" - 대상 도구: 공유 폴더 관리 (fsmgmt.msc)\n - 확인 위치: [공유] -> 공유 폴더 목록 및 Everyone 권한 부여 현황 점검\n");
				}
				else
				{
					rtbGuideline.AppendText(" - 대상 도구: 공유 폴더 관리 (fsmgmt.msc)\n - 확인 위치: [공유] -> 기본 공유(C$, ADMIN$ 등) 비활성화 현황 점검\n");
				}
			}
			else if (text2 == "W-18" || text2 == "W-47" || text2 == "W-48")
			{
				text = "services.msc";
				rtbGuideline.AppendText(" - 대상 도구: 서비스 관리 (services.msc)\n");
				if (text2 == "W-18")
				{
					rtbGuideline.AppendText(" - 확인 위치: 불필요한 서비스(Alerter, RemoteRegistry 등)의 시작 유형 및 상태\n");
				}
				else if (text2 == "W-47")
				{
					rtbGuideline.AppendText(" - 확인 위치: Remote Registry 서비스의 시작 유형 및 상태 (중지 및 사용 안 함)\n");
				}
				else if (text2 == "W-48")
				{
					rtbGuideline.AppendText(" - 확인 위치: Windows Defender Antivirus Service (WinDefend) 서비스 상태 (실행 중)\n");
				}
			}
			else if (text2 == "W-20")
			{
				text = "ncpa.cpl";
				rtbGuideline.AppendText(" - 대상 도구: 네트워크 연결 (ncpa.cpl)\n - 확인 위치: 어댑터 속성 -> IPv4 -> 고급 -> WINS 탭 -> NetBIOS 설정 비활성화 여부\n");
			}
			else if (text2 == "W-41")
			{
				text = "explorer.exe";
				arguments = "ms-settings:windowsupdate";
				rtbGuideline.AppendText(" - 대상 도구: Windows 업데이트 설정 (ms-settings:windowsupdate)\n - 확인 위치: 최신 업데이트 및 품질 패치 적용 현황\n");
			}
			else if (text2 == "W-30")
			{
				text = "winver.exe";
				rtbGuideline.AppendText(" - 대상 도구: Windows 버전 정보 (winver.exe)\n - 확인 위치: OS 빌드 정보 및 업데이트 버전 상태 확인\n");
			}
			else if (text2 == "W-31" || text2 == "W-39")
			{
				text = "gpedit.msc";
				rtbGuideline.AppendText(" - 대상 도구: 로컬 그룹 정책 편집기 (gpedit.msc)\n");
				if (text2 == "W-31")
				{
					rtbGuideline.AppendText(" - 확인 위치: [컴퓨터 구성] -> [관리 템플릿] -> [Windows 구성 요소] -> [터미널 서비스] -> [원격 데스크톱 세션 호스트] -> [보안] -> [클라이언트 연결 암호화 수준 설정]\n");
				}
				else if (text2 == "W-39")
				{
					rtbGuideline.AppendText(" - 확인 위치: [컴퓨터 구성] -> [관리 템플릿] -> [Windows 구성 요소] -> [터미널 서비스] -> [원격 데스크톱 세션 호스트] -> [세션 시간 제한] -> [활성 상태지만 유휴 터미널 서비스 세션에 시간 제한 설정]\n");
				}
			}
			else if (text2 == "W-38")
			{
				text = "odbcad32.exe";
				rtbGuideline.AppendText(" - 대상 도구: ODBC 데이터 원본 관리자 (odbcad32.exe)\n - 확인 위치: [시스템 DSN] 탭 -> 등록된 불필요 데이터 소스 검토\n");
			}
			else if (text2 == "W-44")
			{
				text = "timedate.cpl";
				rtbGuideline.AppendText(" - 대상 도구: 날짜 및 시간 (timedate.cpl)\n - 확인 위치: [인터넷 시간] 탭 -> 설정 변경 -> NTP 동기화 점검\n");
			}
			else if (text2 == "W-40")
			{
				text = "taskschd.msc";
				rtbGuideline.AppendText(" - 대상 도구: 작업 스케줄러 (taskschd.msc)\n - 확인 위치: 작업 스케줄러 라이브러리 -> 의심스러운 예약된 작업 목록 점검\n");
			}
			else if (text2 == "W-42")
			{
				text = "explorer.exe";
				arguments = "windowsdefender:";
				rtbGuideline.AppendText(" - 대상 도구: Windows 보안 센터 (windowsdefender:)\n - 확인 위치: 바이러스 및 위협 방지 -> 업데이트 상태 확인\n");
			}
			else if (text2 == "W-45")
			{
				text = "eventvwr.msc";
				rtbGuideline.AppendText(" - 대상 도구: 이벤트 뷰어 (eventvwr.msc)\n - 확인 위치: [Windows 로그] -> [보안] 우클릭 -> [속성] -> 최대 로그 크기(10,240KB 이상) 확인\n");
			}
			else if (text2 == "W-46")
			{
				text = "explorer.exe";
				string arg = System.Environment.GetFolderPath(System.Environment.SpecialFolder.System) + "\\Config";
				arguments = string.Format("/select,\"{0}\"", arg);
				rtbGuideline.AppendText(string.Format(" - 대상 도구: 파일 탐색기 (Config 및 LogFiles 폴더 보안 권한 확인)\n - 경로: {0} 및 \\LogFiles\n - 확인 방법: 폴더 속성 -> [보안] 탭 -> Everyone 권한 유무 확인 (제외 필요)\n", arg));
			}
			else if (text2 == "W-49")
			{
				text = "explorer.exe";
				string arg = System.Environment.GetFolderPath(System.Environment.SpecialFolder.System) + "\\Config\\SAM";
				arguments = string.Format("/select,\"{0}\"", arg);
				rtbGuideline.AppendText(string.Format(" - 대상 도구: 파일 탐색기 (SAM 파일 보안 권한 확인)\n - 경로: {0}\n - 확인 방법: 파일 속성 -> [보안] 탭 -> Everyone 권한 유무 확인 (제외 필요)\n", arg));
			}
			else if (text2 == "W-64")
			{
				text = "wf.msc";
				rtbGuideline.AppendText(" - 대상 도구: 고급 보안이 설정된 Windows 방화벽 (wf.msc)\n - 확인 위치: 도메인/개인/공용 프로필에 방화벽 활성화 상태 점검\n");
			}
			else if (a == "Type_Registry" || text4 != null)
			{
				text = "regedit.exe";
				string text8 = text4 ?? "";
				string arg2 = text5 ?? "";
				string text9 = text8.Replace('/', '\\');
				if (text9.StartsWith("HKLM:", System.StringComparison.OrdinalIgnoreCase))
				{
					text9 = "HKEY_LOCAL_MACHINE" + text9.Substring(5);
				}
				else if (text9.StartsWith("HKCU:", System.StringComparison.OrdinalIgnoreCase))
				{
					text9 = "HKEY_CURRENT_USER" + text9.Substring(5);
				}
				rtbGuideline.AppendText(string.Format(" - 대상 도구: 레지스트리 편집기 (regedit.exe)\n - 경로: {0}\n - 값 이름: {1}\n - 권장 데이터: {2}\n", text8, arg2, text6 ?? "N/A"));
				try
				{
					System.Diagnostics.ProcessStartInfo processStartInfo = new System.Diagnostics.ProcessStartInfo("taskkill", "/f /im regedit.exe");
					processStartInfo.CreateNoWindow = true;
					processStartInfo.UseShellExecute = false;
					using (System.Diagnostics.Process process = System.Diagnostics.Process.Start(processStartInfo))
					{
						process.WaitForExit();
					}
					System.Threading.Thread.Sleep(150);
					using (Microsoft.Win32.RegistryKey registryKey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\Regedit", writable: true))
					{
						if (registryKey != null)
						{
							string str = "Computer";
							try
							{
								if (System.Globalization.CultureInfo.CurrentCulture.TwoLetterISOLanguageName.Equals("ko", System.StringComparison.OrdinalIgnoreCase) || System.Globalization.CultureInfo.InstalledUICulture.TwoLetterISOLanguageName.Equals("ko", System.StringComparison.OrdinalIgnoreCase))
								{
									str = "컴퓨터";
								}
							}
							catch
							{
							}
							string value2 = str + "\\" + text9;
							registryKey.SetValue("LastKey", value2);
						}
					}
				}
				catch
				{
				}
			}
			try
			{
				System.Diagnostics.ProcessStartInfo processStartInfo2 = new System.Diagnostics.ProcessStartInfo(text, arguments);
				processStartInfo2.UseShellExecute = true;
				System.Diagnostics.ProcessStartInfo startInfo = processStartInfo2;
				activeUIProcess = System.Diagnostics.Process.Start(startInfo);
				System.IntPtr zero = System.IntPtr.Zero;
				for (int i = 0; i < 20; i++)
				{
					zero = GetTargetWindowHandle(text2, text);
					if (zero != System.IntPtr.Zero)
					{
						AlignTargetWindowToRight(zero);
						System.Threading.Thread.Sleep(300);
						AlignTargetWindowToRight(zero);
						break;
					}
					System.Threading.Thread.Sleep(500);
				}
				if (text2 == "W-46" || text2 == "W-49")
				{
					AutomateExplorerNavigation(text2, zero);
				}
				else
				{
					AutomateMscNavigation(text2, text);
				}
			}
			catch (System.Exception ex)
			{
				rtbGuideline.AppendText(string.Format("\n[오류] 윈도우 UI 팝업 실패: {0}", ex.Message));
			}
		}

		private void BtnStop_Click(object sender, System.EventArgs e)
		{
			stopRequested = true;
			btnStop.Enabled = false;
			btnNext.Enabled = false;
			AppendLog("\n\n", LogLevel.Meta);
			AppendLog("━ 사용자 요청으로 보안 패치 진행이 중지되었습니다.\n", LogLevel.Warn);
			CleanupSpawnedWindows(currentItemId);
			pnlSelection.Visible = true;
			pnlWork.Visible      = false;
			// 스플래시 화면 크기 복원 (Claude 테마 기본값)
			System.Drawing.Rectangle wa = System.Windows.Forms.Screen.PrimaryScreen.WorkingArea;
			base.Size     = new System.Drawing.Size(1020, 720);
			base.Location = new System.Drawing.Point((wa.Width - 1020) / 2, (wa.Height - 720) / 2);
			// 상태 초기화
			itemStatusMap.Clear();
			if (progBar != null) progBar.Value = 0;
			if (lblProgress != null) lblProgress.Text = "";
		}

		private void btnNext_Click(object sender, System.EventArgs e)
		{
			btnNext.Enabled = false;
			CaptureEvidence(currentItemId);
			CleanupSpawnedWindows(currentItemId);
			currentItemIndex++;
			ProcessNextItem();
		}

		private void CaptureEvidence(string itemId)
		{
			// 파일명 정규화 (W-01_Complexity -> W-1.png, W-51_SAM -> W-51.png)
			string normId = itemId;
			if (normId.StartsWith("W-0"))
			{
				normId = "W-" + normId.Substring(3);
			}
			int underIdx = normId.IndexOf('_');
			if (underIdx > 0)
			{
				normId = normId.Substring(0, underIdx);
			}
			
			string text = System.IO.Path.Combine(evidenceDir, string.Format("{0}.png", normId));
			try
			{
				System.Drawing.Rectangle rectangle = System.Drawing.Rectangle.Empty;
				bool flag = false;
				System.IntPtr intPtr = System.IntPtr.Zero;
				bool flag2 = false;
				if (itemId.StartsWith("W-0") || itemId.StartsWith("W-1") || itemId.StartsWith("W-2") || itemId.StartsWith("W-3") || itemId.StartsWith("W-4") || itemId.StartsWith("W-5") || itemId.StartsWith("W-6"))
				{
					flag2 = true;
				}
				if (flag2)
				{
					for (int i = 0; i < 20; i++)
					{
						intPtr = FindWindowByClassAndTitle("#32770", new string[11]
						{
							"속성",
							"Properties",
							"고급",
							"Advanced",
							"정보",
							"About",
							"ODBC",
							"시간",
							"Time",
							"날짜",
							"Date"
						});
						if (intPtr != System.IntPtr.Zero)
						{
							break;
						}
						System.Threading.Thread.Sleep(500);
						System.Windows.Forms.Application.DoEvents();
					}
				}
				if (intPtr == System.IntPtr.Zero)
				{
					intPtr = GetTargetWindowHandle(itemId, null);
				}
				if (intPtr != System.IntPtr.Zero)
				{
					try
					{
						SetForegroundWindow(intPtr);
						AlignTargetWindowToRight(intPtr);
						System.Threading.Thread.Sleep(300);
						KisaAutoPatcher.MainForm.RECT lpRect;
						// DWMWA_EXTENDED_FRAME_BOUNDS = 9
						int hres = DwmGetWindowAttribute(intPtr, 9, out lpRect, System.Runtime.InteropServices.Marshal.SizeOf(typeof(KisaAutoPatcher.MainForm.RECT)));
						if (hres == 0) // S_OK
						{
							int num = lpRect.Right - lpRect.Left;
							int num2 = lpRect.Bottom - lpRect.Top;
							if (num > 0 && num2 > 0)
							{
								rectangle = new System.Drawing.Rectangle(lpRect.Left, lpRect.Top, num, num2);
								flag = true;
							}
						}
						
						// DwmGetWindowAttribute 실패 시 GetWindowRect로 폴백
						if (!flag && GetWindowRect(intPtr, out lpRect))
						{
							int num = lpRect.Right - lpRect.Left;
							int num2 = lpRect.Bottom - lpRect.Top;
							if (num > 0 && num2 > 0)
							{
								rectangle = new System.Drawing.Rectangle(lpRect.Left, lpRect.Top, num, num2);
								flag = true;
							}
						}
					}
					catch
					{
					}
				}
				if (!flag)
				{
					rectangle = System.Windows.Forms.Screen.PrimaryScreen.Bounds;
				}
				if (intPtr != System.IntPtr.Zero)
				{
					// [DPI 가상화 방어] BitBlt Direct HDC 복사
					System.IntPtr winDC = GetWindowDC(intPtr);
					if (winDC != System.IntPtr.Zero)
					{
						try
						{
							KisaAutoPatcher.MainForm.RECT realRect;
							GetWindowRect(intPtr, out realRect);
							int w = realRect.Right - realRect.Left;
							int h = realRect.Bottom - realRect.Top;
							if (w <= 0) w = rectangle.Width;
							if (h <= 0) h = rectangle.Height;

							using (System.Drawing.Bitmap bitmap = new System.Drawing.Bitmap(w, h))
							{
								using (System.Drawing.Graphics graphics = System.Drawing.Graphics.FromImage(bitmap))
								{
									System.IntPtr hdcDest = graphics.GetHdc();
									// SRCCOPY = 13369376 (0x00CC0020)
									BitBlt(hdcDest, 0, 0, w, h, winDC, 0, 0, 13369376u);
									graphics.ReleaseHdc(hdcDest);
								}
								bitmap.Save(text, System.Drawing.Imaging.ImageFormat.Png);
								flag = true;
							}
						}
						catch {}
						finally
						{
							ReleaseDC(intPtr, winDC);
						}
					}
				}
				
				if (!flag)
				{
					// 폴백 (전체 화면 캡처)
					using (System.Drawing.Bitmap bitmap = new System.Drawing.Bitmap(rectangle.Width, rectangle.Height))
					{
						using (System.Drawing.Graphics graphics = System.Drawing.Graphics.FromImage(bitmap))
						{
							graphics.CopyFromScreen(rectangle.Location, System.Drawing.Point.Empty, rectangle.Size);
						}
						bitmap.Save(text, System.Drawing.Imaging.ImageFormat.Png);
					}
				}
				rtbGuideline.AppendText(string.Format("\n[캡처 완료] 증빙 파일 저장됨: {0}", text));
			}
			catch (System.Exception ex)
			{
				System.Windows.Forms.MessageBox.Show(string.Format("스크린샷 캡처 실패: {0}", ex.Message), "에러", System.Windows.Forms.MessageBoxButtons.OK, System.Windows.Forms.MessageBoxIcon.Hand);
			}
		}

		private string QueryVulnerabilityStatusFromPowerShell(string itemId)
		{
			return "취약";
		}

		private void ExecuteRemediationViaPowerShell(string itemId)
		{
		}

		private void RunFullAutoMode()
		{
			pnlWork.Visible  = true;
			lstItems.Enabled = false;
			btnNext.Enabled  = false;
			rtbGuideline.Clear();
			AppendLog("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", LogLevel.Warn);
			AppendLog("  ⚡  전체 자동 패치 모드  —  모든 항목 자동 조치 & 캡처\n", LogLevel.Warn);
			AppendLog("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n", LogLevel.Warn);
			try
			{
				lblItemInfo.Text    = "취약점 스캔 진행 중입니다. 잠시만 기다려주세요...";
				lblDescription.Text = "시스템 스캔 진행 중...";
				AppendLog("[1단계]  전체 시스템 취약점 검출 시작...\n", LogLevel.Meta);
				System.Windows.Forms.Application.DoEvents();
				vulnerabilityResults = psController.GetVulnerabilityStatus(configPath);
				LoadCriteria();
				AppendLog(string.Format("  → 검출 완료: 총 {0}개 항목 로드됨\n\n", vulnerabilityResults.Count), LogLevel.Good);
				System.Windows.Forms.Application.DoEvents();
				for (int i = 0; i < vulnerabilityResults.Count; i++)
				{
					if (stopRequested) break;
					lstItems.SelectedIndex = i;
					System.Management.Automation.PSObject pSObject = vulnerabilityResults[i];
					string itemId  = pSObject.Properties["ItemId"].Value.ToString();
					string title   = pSObject.Properties["Title"].Value.ToString();
					string status  = pSObject.Properties["Status"].Value.ToString();
					bool   isVuln  = status.Contains("취약");

					// 사이드바 배지 + 진행률 업데이트
					itemStatusMap[i] = isVuln ? "vuln" : "good";
					lstItems.Invalidate();
					UpdateProgress(i + 1, vulnerabilityResults.Count);

					lblItemInfo.Text    = string.Format("{0}  [{1}/{2}]  {3}", itemId, i + 1, vulnerabilityResults.Count, isVuln ? "⚠ 취약" : "✔ 양호");
					lblDescription.Text = title;

					AppendLog(string.Format("┌ [{0}]  {1}\n", itemId, title), LogLevel.Warn);
					AppendLog(string.Format("│  상태: {0}\n", status), isVuln ? LogLevel.Error : LogLevel.Good);
					System.Windows.Forms.Application.DoEvents();

					if (isVuln)
					{
						AppendLog("│  → 자동 보안 조치(Remediation) 적용 중...\n", LogLevel.Warn);
						System.Windows.Forms.Application.DoEvents();
						try
						{
							psController.InvokeRemediation(pSObject, ReportsDirFallback("Backups"), evidenceDir);
							AppendLog("│  ✔ 조치 성공.  정책 기준치에 맞게 자동 교정되었습니다.\n", LogLevel.Good);
						}
						catch (System.Exception ex)
						{
							AppendLog(string.Format("│  ✗ [오류] 자동 조치 실패: {0}\n", ex.Message), LogLevel.Error);
						}
						System.Windows.Forms.Application.DoEvents();
					}
					else
					{
						AppendLog("│  ✔ 상태 양호  —  조치를 건너뜁니다.\n", LogLevel.Good);
						System.Windows.Forms.Application.DoEvents();
					}
					if (stopRequested) break;
					AppendLog("│  → 기술 검증용 Windows 설정 도구 자동 실행 중...\n", LogLevel.Meta);
					System.Windows.Forms.Application.DoEvents();
					SpawnWindowsSettingsUI(pSObject);
					System.Windows.Forms.Application.DoEvents();
					int waitLimit = 100; // 최대 25초
					while (isNavigationActive && waitLimit > 0 && !stopRequested)
					{
						System.Threading.Thread.Sleep(250);
						System.Windows.Forms.Application.DoEvents();
						waitLimit--;
					}
					System.Threading.Thread.Sleep(800);
					if (stopRequested) break;
					AppendLog("│  → 상세 설정창 영역 자동 캡처 진행...\n", LogLevel.Meta);
					System.Windows.Forms.Application.DoEvents();
					CaptureEvidence(itemId);
					CleanupSpawnedWindows(itemId);
					AppendLog("└  ✔ 증빙 캡처 완료\n\n", LogLevel.Good);
					System.Windows.Forms.Application.DoEvents();
				}
				if (!stopRequested)
				{
					UpdateProgress(vulnerabilityResults.Count, vulnerabilityResults.Count);
					AppendLog("[3단계]  최종 보고서 생성 및 재검증 중...\n", LogLevel.Meta);
					System.Windows.Forms.Application.DoEvents();
					System.Collections.ObjectModel.Collection<System.Management.Automation.PSObject> vulnerabilityStatus = psController.GetVulnerabilityStatus(configPath);
					psController.InvokeReporting(vulnerabilityResults, vulnerabilityStatus, reportsDir, evidenceDir);
					AppendLog("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", LogLevel.Good);
					AppendLog("  ✔  모든 KISA 보안 조치 및 보고서 자산화가 완료되었습니다!\n", LogLevel.Good);
					AppendLog("  →  Reports/Security_Patch_Report.md 파일을 확인하세요.\n", LogLevel.Good);
					AppendLog("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", LogLevel.Good);
					System.Windows.Forms.Application.DoEvents();
					System.Windows.Forms.MessageBox.Show("전체 자동 보안 패치 및 시각 증빙 수집이 완료되었습니다!", "완료", System.Windows.Forms.MessageBoxButtons.OK, System.Windows.Forms.MessageBoxIcon.Information);
					Close();
				}
			}
			catch (System.Exception ex)
			{
				if (!stopRequested)
					System.Windows.Forms.MessageBox.Show(string.Format("전체 자동 조치 도중 에러가 발생했습니다: {0}", ex.Message), "오류", System.Windows.Forms.MessageBoxButtons.OK, System.Windows.Forms.MessageBoxIcon.Hand);
			}
		}


		private void InitializeComponentLayout()
		{
			// ── 전체 폼 기본 설정 ──────────────────────────────────────────────
			Text = "KISA 보안 패치 에이전트  ·  주요정보통신기반시설 자동 취약점 조치 시스템";
			base.Size = new System.Drawing.Size(1020, 720);
			MinimumSize = new System.Drawing.Size(920, 640);
			base.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
			BackColor = System.Drawing.Color.FromArgb(28, 25, 23);
			FormBorderStyle = System.Windows.Forms.FormBorderStyle.Sizable;

			// ── 컬러 팔레트 (Claude 테마) ───────────────────────────────────────
			System.Drawing.Color colBg         = System.Drawing.Color.FromArgb(28,  25,  23); // 딥 차콜
			System.Drawing.Color colPanel      = System.Drawing.Color.FromArgb(38,  34,  30); // 사이드바
			System.Drawing.Color colCard       = System.Drawing.Color.FromArgb(45,  40,  36); // 카드 배경
			System.Drawing.Color colAccent     = System.Drawing.Color.FromArgb(204, 120,  92); // 앰버 테라코타
			System.Drawing.Color colAccentDim  = System.Drawing.Color.FromArgb(150,  88,  66); // 호버
			System.Drawing.Color colCream      = System.Drawing.Color.FromArgb(232, 213, 183); // 크림 화이트
			System.Drawing.Color colMuted      = System.Drawing.Color.FromArgb(140, 128, 114); // 뮤트 텍스트
			System.Drawing.Color colBorder     = System.Drawing.Color.FromArgb(60,  52,  46); // 구분선
			System.Drawing.Color colSuccess    = System.Drawing.Color.FromArgb( 74, 160, 120); // 양호 녹색
			System.Drawing.Color colDanger     = System.Drawing.Color.FromArgb(190,  70,  60); // 위험 빨강

			// ── 폰트 ──────────────────────────────────────────────────────────
			System.Drawing.Font fntTitle    = new System.Drawing.Font("Malgun Gothic", 22f, System.Drawing.FontStyle.Bold);
			System.Drawing.Font fntSub      = new System.Drawing.Font("Malgun Gothic",  9.5f, System.Drawing.FontStyle.Regular);
			System.Drawing.Font fntSmall    = new System.Drawing.Font("Malgun Gothic",  8.5f, System.Drawing.FontStyle.Regular);
			System.Drawing.Font fntSideHdr  = new System.Drawing.Font("Malgun Gothic", 8f, System.Drawing.FontStyle.Bold);
			System.Drawing.Font fntListItem = new System.Drawing.Font("Malgun Gothic",  9f, System.Drawing.FontStyle.Regular);
			System.Drawing.Font fntBtn      = new System.Drawing.Font("Malgun Gothic", 11f, System.Drawing.FontStyle.Bold);
			System.Drawing.Font fntMono     = new System.Drawing.Font("Consolas", 9.5f, System.Drawing.FontStyle.Regular);
			System.Drawing.Font fntHeaderId = new System.Drawing.Font("Malgun Gothic", 12f, System.Drawing.FontStyle.Bold);
			System.Drawing.Font fntHeaderDesc = new System.Drawing.Font("Malgun Gothic", 9f, System.Drawing.FontStyle.Regular);

			// ═══════════════════════════════════════════════════════════════════
			//  [ 스플래시 / 모드 선택 패널 ]  pnlSelection
			// ═══════════════════════════════════════════════════════════════════
			pnlSelection = new System.Windows.Forms.Panel
			{
				Dock = System.Windows.Forms.DockStyle.Fill,
				BackColor = colBg
			};

			// ── 스플래시 헤더: 모든 콘텐츠를 Paint 이벤트 하나에서 직접 그림 ──────────────────
			// (AutoSize 레이블의 Resize 타이밍 버그 완전 제거)
			System.Windows.Forms.Panel pnlSplashHeader = new System.Windows.Forms.Panel
			{
				Dock      = System.Windows.Forms.DockStyle.Top,
				Height    = 220,
				BackColor = System.Drawing.Color.Transparent
			};
			pnlSplashHeader.Paint += delegate(object s, System.Windows.Forms.PaintEventArgs pe)
			{
				System.Drawing.Graphics g   = pe.Graphics;
				g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
				g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
				int W = pnlSplashHeader.Width;

				// 그라데이션 배경
				using (System.Drawing.Drawing2D.LinearGradientBrush gb = new System.Drawing.Drawing2D.LinearGradientBrush(
					new System.Drawing.Rectangle(0, 0, W, pnlSplashHeader.Height),
					System.Drawing.Color.FromArgb(56, 44, 36),
					System.Drawing.Color.FromArgb(28, 25, 23), 90f))
					g.FillRectangle(gb, 0, 0, W, pnlSplashHeader.Height);

				// 하단 강조선
				using (System.Drawing.Pen ap = new System.Drawing.Pen(System.Drawing.Color.FromArgb(204, 120, 92), 2f))
					g.DrawLine(ap, 0, pnlSplashHeader.Height - 1, W, pnlSplashHeader.Height - 1);

				// ── 방패 아이콘 (중앙 상단) ──
				int shieldCx = W / 2;
				int shieldTop = 22;
				System.Drawing.Drawing2D.GraphicsPath shield = new System.Drawing.Drawing2D.GraphicsPath();
				shield.AddPolygon(new System.Drawing.PointF[] {
					new System.Drawing.PointF(shieldCx,      shieldTop + 0),
					new System.Drawing.PointF(shieldCx + 34, shieldTop + 12),
					new System.Drawing.PointF(shieldCx + 34, shieldTop + 42),
					new System.Drawing.PointF(shieldCx,      shieldTop + 74),
					new System.Drawing.PointF(shieldCx - 34, shieldTop + 42),
					new System.Drawing.PointF(shieldCx - 34, shieldTop + 12)
				});
				using (System.Drawing.SolidBrush sb = new System.Drawing.SolidBrush(System.Drawing.Color.FromArgb(70, 204, 120, 92)))
					g.FillPath(sb, shield);
				using (System.Drawing.Pen sp = new System.Drawing.Pen(System.Drawing.Color.FromArgb(204, 120, 92), 2.5f))
					g.DrawPath(sp, shield);
				using (System.Drawing.Pen cp = new System.Drawing.Pen(System.Drawing.Color.FromArgb(232, 213, 183), 4f))
				{
					cp.StartCap = System.Drawing.Drawing2D.LineCap.Round;
					cp.EndCap   = System.Drawing.Drawing2D.LineCap.Round;
					cp.LineJoin = System.Drawing.Drawing2D.LineJoin.Round;
					g.DrawLine(cp, shieldCx - 14, shieldTop + 36, shieldCx - 3, shieldTop + 50);
					g.DrawLine(cp, shieldCx -  3, shieldTop + 50, shieldCx + 18, shieldTop + 24);
				}

				// ── 타이틀 ──
				int titleY = shieldTop + 86;
				using (System.Drawing.Font fT = new System.Drawing.Font("Malgun Gothic", 22f, System.Drawing.FontStyle.Bold))
				using (System.Drawing.SolidBrush tb = new System.Drawing.SolidBrush(System.Drawing.Color.FromArgb(232, 213, 183)))
				{
					System.Drawing.SizeF sz = g.MeasureString("KISA Auto-Patcher", fT);
					g.DrawString("KISA Auto-Patcher", fT, tb, (W - sz.Width) / 2f, titleY);
				}

				// ── 부제 ──
				string sub = "주요정보통신기반시설  기술적 취약점 자동 조치 & 시각 증빙 에이전트  ·  2026";
				using (System.Drawing.Font fS = new System.Drawing.Font("Malgun Gothic", 9f, System.Drawing.FontStyle.Regular))
				using (System.Drawing.SolidBrush sb2 = new System.Drawing.SolidBrush(System.Drawing.Color.FromArgb(120, 108, 96)))
				{
					System.Drawing.SizeF sz2 = g.MeasureString(sub, fS);
					g.DrawString(sub, fS, sb2, (W - sz2.Width) / 2f, titleY + 36f);
				}

				// ── KISA 배지 ──
				string badge = "  KISA  ";
				using (System.Drawing.Font fB = new System.Drawing.Font("Malgun Gothic", 7.5f, System.Drawing.FontStyle.Bold))
				using (System.Drawing.SolidBrush bfill = new System.Drawing.SolidBrush(System.Drawing.Color.FromArgb(55, 204, 120, 92)))
				using (System.Drawing.SolidBrush btext = new System.Drawing.SolidBrush(System.Drawing.Color.FromArgb(204, 120, 92)))
				using (System.Drawing.Pen bpen = new System.Drawing.Pen(System.Drawing.Color.FromArgb(204, 120, 92), 1f))
				{
					System.Drawing.SizeF bsz = g.MeasureString(badge, fB);
					float bx = (W - bsz.Width) / 2f;
					float by = titleY + 64f;
					g.FillRectangle(bfill, bx, by, bsz.Width, bsz.Height);
					g.DrawRectangle(bpen, bx, by, bsz.Width, bsz.Height);
					g.DrawString(badge, fB, btext, bx, by);
				}
			};

			// ── 모드 선택 카드 컨테이너 ──────────────────────────────────────
			System.Windows.Forms.Panel pnlModeCards = new System.Windows.Forms.Panel
			{
				Dock      = System.Windows.Forms.DockStyle.Fill,
				BackColor = System.Drawing.Color.Transparent,
				Padding   = new System.Windows.Forms.Padding(60, 20, 60, 30)
			};

			// ──────────────────────────────────────────────────────────────────
			// 카드 생성 헬퍼 (투명 오버레이 버튼 방식 폐기)
			// → 카드 패널 + 모든 자식 컨트롤에 클릭 이벤트 직접 연결
			// ──────────────────────────────────────────────────────────────────
			System.Action<System.Windows.Forms.Control, System.EventHandler,
			              System.Drawing.Color, System.Drawing.Color> WireHover =
				(ctl, onClick, normalBg, hoverBg) =>
			{
				ctl.Click      += onClick;
				ctl.Cursor      = System.Windows.Forms.Cursors.Hand;
				ctl.MouseEnter += delegate { ((System.Windows.Forms.Control)ctl.Parent ?? ctl).BackColor = hoverBg; };
				ctl.MouseLeave += delegate { ((System.Windows.Forms.Control)ctl.Parent ?? ctl).BackColor = normalBg; };
			};

			System.Func<string, string, string, System.Drawing.Color, System.EventHandler, System.Windows.Forms.Panel> MakeCard2 =
				(cardTitle, cardDesc, icon, accent, onClickHandler) =>
			{
				System.Drawing.Color cardNormal = colCard;
				System.Drawing.Color cardHover  = System.Drawing.Color.FromArgb(
					System.Math.Min(colCard.R + 14, 255),
					System.Math.Min(colCard.G + 12, 255),
					System.Math.Min(colCard.B + 10, 255));

				System.Windows.Forms.Panel card = new System.Windows.Forms.Panel
				{
					BackColor = cardNormal,
					Cursor    = System.Windows.Forms.Cursors.Hand
				};
				card.Click      += onClickHandler;
				card.MouseEnter += delegate { card.BackColor = cardHover; };
				card.MouseLeave += delegate { card.BackColor = cardNormal; };

				card.Paint += delegate(object s2, System.Windows.Forms.PaintEventArgs pe2)
				{
					pe2.Graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
					// 테두리
					using (System.Drawing.Pen bp = new System.Drawing.Pen(colBorder, 1))
						pe2.Graphics.DrawRectangle(bp, 0, 0, card.Width - 1, card.Height - 1);
					// 왼쪽 엑센트 바
					using (System.Drawing.SolidBrush ab = new System.Drawing.SolidBrush(accent))
						pe2.Graphics.FillRectangle(ab, 0, 0, 4, card.Height);
				};

				// 아이콘 레이블
				System.Windows.Forms.Label lblIcon2 = new System.Windows.Forms.Label
				{
					Text      = icon,
					Font      = new System.Drawing.Font("Malgun Gothic", 26f),
					ForeColor = accent,
					BackColor = System.Drawing.Color.Transparent,
					Location  = new System.Drawing.Point(18, 16),
					AutoSize  = true
				};
				lblIcon2.Click      += onClickHandler;
				lblIcon2.Cursor      = System.Windows.Forms.Cursors.Hand;
				lblIcon2.MouseEnter += delegate { card.BackColor = cardHover; };
				lblIcon2.MouseLeave += delegate { card.BackColor = cardNormal; };

				// 제목 레이블
				System.Windows.Forms.Label lblT2 = new System.Windows.Forms.Label
				{
					Text      = cardTitle,
					Font      = new System.Drawing.Font("Malgun Gothic", 13f, System.Drawing.FontStyle.Bold),
					ForeColor = colCream,
					BackColor = System.Drawing.Color.Transparent,
					Location  = new System.Drawing.Point(18, 68),
					AutoSize  = true
				};
				lblT2.Click      += onClickHandler;
				lblT2.Cursor      = System.Windows.Forms.Cursors.Hand;
				lblT2.MouseEnter += delegate { card.BackColor = cardHover; };
				lblT2.MouseLeave += delegate { card.BackColor = cardNormal; };

				// 설명 레이블
				System.Windows.Forms.Label lblD2 = new System.Windows.Forms.Label
				{
					Text      = cardDesc,
					Font      = fntSmall,
					ForeColor = colMuted,
					BackColor = System.Drawing.Color.Transparent,
					Location  = new System.Drawing.Point(18, 96),
					Width     = 230,
					Height    = 50
				};
				lblD2.Click      += onClickHandler;
				lblD2.Cursor      = System.Windows.Forms.Cursors.Hand;
				lblD2.MouseEnter += delegate { card.BackColor = cardHover; };
				lblD2.MouseLeave += delegate { card.BackColor = cardNormal; };

				card.Controls.AddRange(new System.Windows.Forms.Control[] { lblIcon2, lblT2, lblD2 });
				return card;
			};

			// btnFullAuto / btnInteractive는 필드 참조 유지용으로 더미 버튼 할당
			btnFullAuto   = new System.Windows.Forms.Button { Visible = false };
			btnInteractive = new System.Windows.Forms.Button { Visible = false };

			System.Windows.Forms.Panel cardAuto = MakeCard2(
				"전체 자동 패치",
				"모든 항목을 자동 조치·캡처합니다.\nFull Auto Mode",
				"⚡", colAccent,
				delegate { StartPatching(interactive: false); });

			System.Windows.Forms.Panel cardStep = MakeCard2(
				"단계별 순차 검증",
				"항목별로 직접 확인 후 진행합니다.\nInteractive Step Mode",
				"🔍", colSuccess,
				delegate { StartPatching(interactive: true); });

			// 카드 위치: Resize 이벤트로 동적 배치
			pnlModeCards.Resize += delegate
			{
				int pad = 60;
				int cw  = (pnlModeCards.ClientSize.Width - pnlModeCards.Padding.Left - pnlModeCards.Padding.Right - pad) / 2;
				int ch  = 170;
				int cy  = (pnlModeCards.ClientSize.Height - ch) / 2;
				int x0  = pnlModeCards.Padding.Left;
				cardAuto.Bounds = new System.Drawing.Rectangle(x0,       cy, cw, ch);
				cardStep.Bounds = new System.Drawing.Rectangle(x0 + cw + pad, cy, cw, ch);
			};
			pnlModeCards.Controls.Add(cardAuto);
			pnlModeCards.Controls.Add(cardStep);

			// 하단 버전 레이블
			System.Windows.Forms.Label lblVersion = new System.Windows.Forms.Label
			{
				Text      = "v2026  ·  관리자 권한으로 실행 중",
				Font      = fntSmall,
				ForeColor = colMuted,
				Dock      = System.Windows.Forms.DockStyle.Bottom,
				Height    = 28,
				TextAlign = System.Drawing.ContentAlignment.MiddleCenter,
				BackColor = System.Drawing.Color.FromArgb(22, 19, 17)
			};

			pnlSelection.Controls.Add(pnlModeCards);
			pnlSelection.Controls.Add(lblVersion);
			pnlSelection.Controls.Add(pnlSplashHeader);


			// ═══════════════════════════════════════════════════════════════════
			//  [ 작업 패널 ]  pnlWork
			// ═══════════════════════════════════════════════════════════════════
			pnlWork = new System.Windows.Forms.Panel
			{
				Dock = System.Windows.Forms.DockStyle.Fill,
				Visible = false,
				BackColor = colBg
			};

			// ── 사이드바 ────────────────────────────────────────────────────
			System.Windows.Forms.Panel pnlSidebar = new System.Windows.Forms.Panel
			{
				Dock  = System.Windows.Forms.DockStyle.Left,
				Width = 258,
				BackColor = colPanel
			};
			pnlSidebar.Paint += delegate(object s, System.Windows.Forms.PaintEventArgs pe)
			{
				using (System.Drawing.Pen bp = new System.Drawing.Pen(colBorder, 1))
					pe.Graphics.DrawLine(bp, pnlSidebar.Width - 1, 0, pnlSidebar.Width - 1, pnlSidebar.Height);
			};

			// 사이드바 헤더
			System.Windows.Forms.Panel pnlSideHdr = new System.Windows.Forms.Panel
			{
				Dock = System.Windows.Forms.DockStyle.Top,
				Height = 50,
				BackColor = System.Drawing.Color.FromArgb(34, 30, 27)
			};
			pnlSideHdr.Paint += delegate(object s, System.Windows.Forms.PaintEventArgs pe)
			{
				pe.Graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
				// 상단 엑센트 라인
				using (System.Drawing.Pen ap = new System.Drawing.Pen(colAccent, 2))
					pe.Graphics.DrawLine(ap, 0, 0, pnlSideHdr.Width, 0);
				// 하단 구분선
				using (System.Drawing.Pen dp = new System.Drawing.Pen(colBorder, 1))
					pe.Graphics.DrawLine(dp, 0, pnlSideHdr.Height - 1, pnlSideHdr.Width, pnlSideHdr.Height - 1);
				// 로고 + 텍스트
				System.Windows.Forms.TextRenderer.DrawText(pe.Graphics, "● 점검 항목",
					fntSideHdr, new System.Drawing.Rectangle(14, 0, 200, pnlSideHdr.Height),
					colAccent, System.Windows.Forms.TextFormatFlags.VerticalCenter);
			};

			lstItems = new System.Windows.Forms.ListBox
			{
				Dock        = System.Windows.Forms.DockStyle.Fill,
				BackColor   = colPanel,
				ForeColor   = System.Drawing.Color.FromArgb(178, 168, 155),
				Font        = fntListItem,
				BorderStyle = System.Windows.Forms.BorderStyle.None,
				DrawMode    = System.Windows.Forms.DrawMode.OwnerDrawFixed,
				ItemHeight  = 38,
				ScrollAlwaysVisible = false
			};
			lstItems.DrawItem += LstItems_DrawItem;
			lstItems.SelectedIndexChanged += LstItems_SelectedIndexChanged;

			pnlSidebar.Controls.Add(lstItems);
			pnlSidebar.Controls.Add(pnlSideHdr);

			// ── 메인 콘텐츠 영역 ───────────────────────────────────────────
			System.Windows.Forms.Panel pnlContent = new System.Windows.Forms.Panel
			{
				Dock    = System.Windows.Forms.DockStyle.Fill,
				Padding = new System.Windows.Forms.Padding(18, 14, 18, 14),
				BackColor = colBg
			};

			// ── 헤더 카드 (현재 항목 정보) ──────────────────────────────────
			System.Windows.Forms.Panel pnlHeaderCard = new System.Windows.Forms.Panel
			{
				Dock      = System.Windows.Forms.DockStyle.Top,
				Height    = 96,
				BackColor = colCard
			};
			pnlHeaderCard.Paint += delegate(object s, System.Windows.Forms.PaintEventArgs pe)
			{
				pe.Graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
				// 왼쪽 엑센트 바
				using (System.Drawing.SolidBrush ab = new System.Drawing.SolidBrush(colAccent))
					pe.Graphics.FillRectangle(ab, 0, 0, 4, pnlHeaderCard.Height);
				// 테두리
				using (System.Drawing.Pen bp = new System.Drawing.Pen(colBorder, 1))
					pe.Graphics.DrawRectangle(bp, 0, 0, pnlHeaderCard.Width - 1, pnlHeaderCard.Height - 1);
			};

			// 진행률 바 (하단 앰버 슬리머)
			progBar = new System.Windows.Forms.ProgressBar
			{
				Dock    = System.Windows.Forms.DockStyle.Bottom,
				Height  = 4,
				Minimum = 0,
				Maximum = 100,
				Value   = 0,
				Style   = System.Windows.Forms.ProgressBarStyle.Continuous
			};

			// [N / total] 카운터
			lblProgress = new System.Windows.Forms.Label
			{
				Dock      = System.Windows.Forms.DockStyle.Bottom,
				Height    = 18,
				Font      = new System.Drawing.Font("Malgun Gothic", 7.5f, System.Drawing.FontStyle.Regular),
				ForeColor = colMuted,
				BackColor = System.Drawing.Color.Transparent,
				Text      = "",
				TextAlign = System.Drawing.ContentAlignment.MiddleRight,
				Padding   = new System.Windows.Forms.Padding(0, 0, 8, 0)
			};

			lblItemInfo = new System.Windows.Forms.Label
			{
				Dock      = System.Windows.Forms.DockStyle.Top,
				Height    = 36,
				Font      = fntHeaderId,
				ForeColor = colCream,
				BackColor = System.Drawing.Color.Transparent,
				Text      = "진단 데이터를 로드하는 중입니다...",
				Padding   = new System.Windows.Forms.Padding(14, 0, 0, 0)
			};
			lblDescription = new System.Windows.Forms.Label
			{
				Dock      = System.Windows.Forms.DockStyle.Fill,
				Font      = fntHeaderDesc,
				ForeColor = colMuted,
				BackColor = System.Drawing.Color.Transparent,
				Text      = "항목 설명",
				Padding   = new System.Windows.Forms.Padding(14, 0, 0, 0)
			};
			// Add 순서: Bottom-docked controls first, then Fill, then Top
			pnlHeaderCard.Controls.Add(lblDescription);
			pnlHeaderCard.Controls.Add(lblProgress);
			pnlHeaderCard.Controls.Add(progBar);
			pnlHeaderCard.Controls.Add(lblItemInfo);


			// ── 로그/가이드라인 영역 ────────────────────────────────────────
			System.Windows.Forms.Panel pnlLog = new System.Windows.Forms.Panel
			{
				Dock      = System.Windows.Forms.DockStyle.Fill,
				Padding   = new System.Windows.Forms.Padding(0, 10, 0, 0),
				BackColor = System.Drawing.Color.Transparent
			};
			rtbGuideline = new System.Windows.Forms.RichTextBox
			{
				Dock        = System.Windows.Forms.DockStyle.Fill,
				ReadOnly    = true,
				BackColor   = System.Drawing.Color.FromArgb(24, 21, 19),
				ForeColor   = System.Drawing.Color.FromArgb(200, 188, 172),
				Font        = fntMono,
				BorderStyle = System.Windows.Forms.BorderStyle.None,
				ScrollBars  = System.Windows.Forms.RichTextBoxScrollBars.Vertical
			};
			pnlLog.Controls.Add(rtbGuideline);

			// ── 하단 액션 바 ─────────────────────────────────────────────────
			System.Windows.Forms.Panel pnlActionBar = new System.Windows.Forms.Panel
			{
				Dock      = System.Windows.Forms.DockStyle.Bottom,
				Height    = 62,
				BackColor = System.Drawing.Color.FromArgb(34, 30, 27)
			};
			pnlActionBar.Paint += delegate(object s, System.Windows.Forms.PaintEventArgs pe)
			{
				using (System.Drawing.Pen tp = new System.Drawing.Pen(colBorder, 1))
					pe.Graphics.DrawLine(tp, 0, 0, pnlActionBar.Width, 0);
			};

			// Next 버튼
			btnNext = new System.Windows.Forms.Button
			{
				Text      = "확인 완료  →  다음 항목으로",
				Font      = fntBtn,
				ForeColor = System.Drawing.Color.FromArgb(28, 25, 23),
				BackColor = colAccent,
				FlatStyle = System.Windows.Forms.FlatStyle.Flat,
				Cursor    = System.Windows.Forms.Cursors.Hand,
				Dock      = System.Windows.Forms.DockStyle.Fill
			};
			btnNext.FlatAppearance.BorderSize = 0;
			btnNext.Enabled = false;
			btnNext.Click  += btnNext_Click;
			StyleButton(btnNext, colAccent, colAccentDim, System.Drawing.Color.FromArgb(120, 65, 48));

			// Stop 버튼
			btnStop = new System.Windows.Forms.Button
			{
				Text      = "중지 (Stop)",
				Font      = fntBtn,
				ForeColor = System.Drawing.Color.FromArgb(190, 70, 60),
				BackColor = System.Drawing.Color.FromArgb(55, 40, 38),
				FlatStyle = System.Windows.Forms.FlatStyle.Flat,
				Cursor    = System.Windows.Forms.Cursors.Hand,
				Dock      = System.Windows.Forms.DockStyle.Right,
				Width     = 150
			};
			btnStop.FlatAppearance.BorderSize    = 0;
			btnStop.FlatAppearance.BorderColor   = System.Drawing.Color.FromArgb(90, 50, 48);
			btnStop.FlatAppearance.MouseOverBackColor = System.Drawing.Color.FromArgb(80, 48, 46);
			btnStop.Click += BtnStop_Click;
			StyleButton(btnStop, System.Drawing.Color.FromArgb(55, 40, 38), System.Drawing.Color.FromArgb(80, 48, 46), System.Drawing.Color.FromArgb(100, 40, 38));

			pnlActionBar.Controls.Add(btnNext);
			pnlActionBar.Controls.Add(btnStop);

			pnlContent.Controls.Add(pnlLog);
			pnlContent.Controls.Add(pnlHeaderCard);
			pnlContent.Controls.Add(pnlActionBar);

			pnlWork.Controls.Add(pnlContent);
			pnlWork.Controls.Add(pnlSidebar);

			base.Controls.Add(pnlSelection);
			base.Controls.Add(pnlWork);
		}

		private void StyleButton(System.Windows.Forms.Button btn, System.Drawing.Color normalBack, System.Drawing.Color hoverBack, System.Drawing.Color clickBack)
		{
			btn.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
			btn.FlatAppearance.BorderSize = 0;
			btn.BackColor = normalBack;
			btn.Cursor = System.Windows.Forms.Cursors.Hand;
			btn.MouseEnter += delegate { btn.BackColor = hoverBack; };
			btn.MouseLeave += delegate { btn.BackColor = normalBack; };
			btn.MouseDown  += delegate { btn.BackColor = clickBack; };
			btn.MouseUp    += delegate { btn.BackColor = hoverBack; };
		}

		private void AutomateMscNavigation(string itemId, string appName)
		{
			isNavigationActive = true;
			ShowNavigationPopup(itemId);
			System.Threading.ThreadPool.QueueUserWorkItem(delegate
			{
				try
				{
					System.IntPtr intPtr = System.IntPtr.Zero;
					string text = System.IO.Path.Combine(evidenceDir, string.Format("uia_debug_{0}.log", itemId));
					try
					{
						KisaAutoPatcher.File.WriteAllText(text, string.Format("Starting navigation for {0}.\n", itemId), System.Text.Encoding.UTF8);
					}
					catch
					{
					}
					for (int i = 0; i < 20; i++)
					{
						// [보안 템플릿 경고창 자동 처리]
						System.IntPtr warningHwnd = FindWindow(null, "보안 템플릿");
						if (warningHwnd != System.IntPtr.Zero)
						{
							SendMessage(warningHwnd, 16u, System.IntPtr.Zero, System.IntPtr.Zero);
							System.Threading.Thread.Sleep(300);
						}

						intPtr = GetTargetWindowHandle(itemId, appName);
						if (intPtr != System.IntPtr.Zero)
						{
							break;
						}
						System.Threading.Thread.Sleep(500);
					}
					try
					{
						KisaAutoPatcher.File.AppendAllText(text, string.Format("Target HWND: {0}\n", intPtr), System.Text.Encoding.UTF8);
					}
					catch
					{
					}
					if (intPtr == System.IntPtr.Zero)
					{
						try
						{
							KisaAutoPatcher.File.AppendAllText(text, "Error: HWND is Zero after 10 seconds.\n", System.Text.Encoding.UTF8);
						}
						catch
						{
						}
					}
					else
					{
						SetForegroundWindow(intPtr);
						AlignTargetWindowToRight(intPtr);
						System.Threading.Thread.Sleep(300);
						try
						{
							System.Windows.Automation.AutomationElement automationElement = System.Windows.Automation.AutomationElement.FromHandle(intPtr);
							if (automationElement == null)
							{
								try
								{
									KisaAutoPatcher.File.AppendAllText(text, "Error: Root element is null.\n", System.Text.Encoding.UTF8);
								}
								catch
								{
								}
							}
							else if (itemId == "W-20")
							{
								AutomateNcpaNavigation(automationElement, text);
							}
							else if (itemId == "W-38")
							{
								AutomateOdbcNavigation(automationElement, text);
							}
							else if (itemId == "W-44")
							{
								AutomateTimeDateNavigation(automationElement, text);
							}
							else
							{
								System.Windows.Automation.AutomationElement automationElement2 = null;
								for (int i = 0; i < 10; i++)
								{
									automationElement2 = automationElement.FindFirst(System.Windows.Automation.TreeScope.Descendants, new System.Windows.Automation.PropertyCondition(System.Windows.Automation.AutomationElement.ControlTypeProperty, System.Windows.Automation.ControlType.Tree));
									if (automationElement2 != null)
									{
										break;
									}
									System.Threading.Thread.Sleep(500);
								}
								if (automationElement2 == null)
								{
									try
									{
										KisaAutoPatcher.File.AppendAllText(text, "Error: Tree control not found after 5 seconds.\n", System.Text.Encoding.UTF8);
									}
									catch
									{
									}
								}
								else
								{
									try
									{
										KisaAutoPatcher.File.AppendAllText(text, "Tree control successfully found.\n", System.Text.Encoding.UTF8);
									}
									catch
									{
									}
									string[][] array = null;
									string[][] array2 = null;
									if (itemId.StartsWith("W-09") || itemId == "W-05")
									{
										array = new string[3][]
										{
											new string[2]
											{
												"보안 설정",
												"Security Settings"
											},
											new string[2]
											{
												"계정 정책",
												"Account Policies"
											},
											new string[2]
											{
												"암호 정책",
												"Password Policy"
											}
										};
										if (itemId == "W-09_History")
										{
											array2 = new string[1][]
											{
												new string[2]
												{
													"최근 암호 기억",
													"Enforce password history"
												}
											};
										}
										else if (itemId == "W-09_MaxAge")
										{
											array2 = new string[1][]
											{
												new string[2]
												{
													"최대 암호 사용 기간",
													"Maximum password age"
												}
											};
										}
										else if (itemId == "W-09_MinAge")
										{
											array2 = new string[1][]
											{
												new string[2]
												{
													"최소 암호 사용 기간",
													"Minimum password age"
												}
											};
										}
										else if (itemId == "W-09")
										{
											array2 = new string[1][]
											{
												new string[2]
												{
													"최소 암호 길이",
													"Minimum password length"
												}
											};
										}
										else if (itemId == "W-05")
										{
											array2 = new string[1][]
											{
												new string[2]
												{
													"해독 가능한 암호화",
													"reversible encryption"
												}
											};
										}
										else if (itemId == "W-09_Complexity")
										{
											array2 = new string[1][]
											{
												new string[2]
												{
													"복잡성",
													"complexity requirements"
												}
											};
										}
									}
									else if (itemId == "W-04" || itemId == "W-08" || itemId == "W-08_Reset")
									{
										array = new string[3][]
										{
											new string[2]
											{
												"보안 설정",
												"Security Settings"
											},
											new string[2]
											{
												"계정 정책",
												"Account Policies"
											},
											new string[2]
											{
												"계정 잠금 정책",
												"Account Lockout Policy"
											}
										};
										if (itemId == "W-08")
										{
											array2 = new string[1][]
											{
												new string[2]
												{
													"계정 잠금 기간",
													"Account lockout duration"
												}
											};
										}
										else if (itemId == "W-04")
										{
											array2 = new string[1][]
											{
												new string[2]
												{
													"계정 잠금 임계값",
													"Account lockout threshold"
												}
											};
										}
										else if (itemId == "W-08_Reset")
										{
											array2 = new string[1][]
											{
												new string[2]
												{
													"계정 잠금 수를 원래대로",
													"Reset account lockout counter"
												}
											};
										}
									}
									else if (itemId == "W-11" || itemId == "W-52" || itemId == "W-56" || itemId == "W-55")
									{
										array = new string[3][]
										{
											new string[2]
											{
												"보안 설정",
												"Security Settings"
											},
											new string[2]
											{
												"로컬 정책",
												"Local Policies"
											},
											new string[3]
											{
												"사용자 권한 지정",
												"사용자 권한 할당",
												"User Rights Assignment"
											}
										};
										if (itemId == "W-11")
										{
											array2 = new string[1][]
											{
												new string[2]
												{
													"로컬 로그온 허용",
													"Allow log on locally"
												}
											};
										}
										else if (itemId == "W-52")
										{
											array2 = new string[1][]
											{
												new string[2]
												{
													"시스템 강제 종료",
													"Force shutdown from a remote system"
												}
											};
										}
										else if (itemId == "W-56")
										{
											array2 = new string[1][]
											{
												new string[2]
												{
													"원격 시스템에서 강제 종료",
													"Force shutdown from a remote system"
												}
											};
										}
										else if (itemId == "W-55")
										{
											array2 = new string[1][]
											{
												new string[2]
												{
													"감사 및 보안 로그 관리",
													"Manage auditing and security log"
												}
											};
										}
									}
									else if (itemId == "W-43")
									{
										array = new string[3][]
										{
											new string[2]
											{
												"보안 설정",
												"Security Settings"
											},
											new string[2]
											{
												"로컬 정책",
												"Local Policies"
											},
											new string[2]
											{
												"감사 정책",
												"Audit Policy"
											}
										};
										array2 = new string[1][]
										{
											new string[2]
											{
												"로그온 이벤트 감사",
												"Audit logon events"
											}
										};
									}
									else if (itemId == "W-01" || itemId == "W-02" || itemId == "W-07" || itemId == "W-10" || itemId == "W-12" || itemId == "W-13" || itemId == "W-15" || itemId == "W-53" || itemId == "W-51" || itemId == "W-59" || itemId == "W-60" || itemId == "W-59")
									{
										array = new string[3][]
										{
											new string[2]
											{
												"보안 설정",
												"Security Settings"
											},
											new string[2]
											{
												"로컬 정책",
												"Local Policies"
											},
											new string[2]
											{
												"보안 옵션",
												"Security Options"
											}
										};
										if (itemId == "W-01")
										{
											array2 = new string[1][]
											{
												new string[2]
												{
													"Administrator 계정 이름",
													"Rename administrator account"
												}
											};
										}
										else if (itemId == "W-02")
										{
											array2 = new string[1][]
											{
												new string[2]
												{
													"Guest 계정 상태",
													"Guest account status"
												}
											};
										}
										else if (itemId == "W-07")
										{
											array2 = new string[1][]
											{
												new string[2]
												{
													"Everyone 사용 권한을 익명 사용자에게 적용",
													"Let Everyone permissions apply to anonymous users"
												}
											};
										}
										else if (itemId == "W-10")
										{
											array2 = new string[1][]
											{
												new string[3]
												{
													"마지막 사용자",
													"마지막 로그인",
													"last user"
												}
											};
										}
										else if (itemId == "W-12")
										{
											array2 = new string[1][]
											{
												new string[2]
												{
													"익명 SID/이름 변환 허용",
													"Allow anonymous SID/name translation"
												}
											};
										}
										else if (itemId == "W-13")
										{
											array2 = new string[1][]
											{
												new string[2]
												{
													"빈 암호 사용 제한",
													"Limit local account use of blank passwords"
												}
											};
										}
										else if (itemId == "W-15")
										{
											array2 = new string[1][]
											{
												new string[2]
												{
													"강력한 키 보호 사용",
													"Force strong key protection for user keys"
												}
											};
										}
										else if (itemId == "W-53")
										{
											array2 = new string[1][]
											{
												new string[2]
												{
													"로그온할 수 없는 경우 즉시 시스템 종료",
													"Shut down system immediately if unable to log security audits"
												}
											};
										}
										else if (itemId == "W-51")
										{
											array2 = new string[1][]
											{
												new string[2]
												{
													"보안 감사 크기",
													"Audit: Shut down system immediately"
												}
											};
										}
										else if (itemId == "W-59")
										{
											array2 = new string[1][]
											{
												new string[2]
												{
													"복구 콘솔: 자동 관리자 로그온 허용",
													"Recovery console: Allow automatic administrative logon"
												}
											};
										}
										else if (itemId == "W-60")
										{
											array2 = new string[1][]
											{
												new string[2]
												{
													"복구 콘솔: 모든 드라이브 및 폴더에 복사 및 엑세스 허용",
													"Recovery console: Allow floppy copy and access to all drives"
												}
											};
										}
										else if (itemId == "W-59")
										{
											array2 = new string[1][]
											{
												new string[2]
												{
													"이동식 미디어에 서식 지정 및 꺼내기 허용",
													"Allowed to format and eject removable media"
												}
											};
										}
									}
									else if (itemId == "W-03" || itemId == "W-06" || itemId == "W-14")
									{
										if (itemId == "W-03")
										{
											array = new string[2][]
											{
												new string[2]
												{
													"로컬 사용자 및 그룹",
													"Local Users and Groups"
												},
												new string[2]
												{
													"사용자",
													"Users"
												}
											};
											array2 = null;
										}
										else
										{
											array = new string[2][]
											{
												new string[2]
												{
													"로컬 사용자 및 그룹",
													"Local Users and Groups"
												},
												new string[2]
												{
													"그룹",
													"Groups"
												}
											};
											if (itemId == "W-06")
											{
												array2 = new string[1][]
												{
													new string[2]
													{
														"Administrators",
														"관리자"
													}
												};
											}
											else if (itemId == "W-14")
											{
												array2 = new string[1][]
												{
													new string[2]
													{
														"Remote Desktop Users",
														"원격 데스크톱 사용자"
													}
												};
											}
										}
									}
									else if (itemId == "W-16" || itemId == "W-17")
									{
										array = new string[2][]
										{
											new string[2]
											{
												"공유 폴더",
												"Shared Folders"
											},
											new string[2]
											{
												"공유",
												"Shares"
											}
										};
									}
									else if (itemId == "W-18" || itemId == "W-47" || itemId == "W-48")
									{
										array = null; // services.msc는 트리 탐색 없이 바로 서비스 목록 스캔 가능하므로 null 지정
										if (itemId == "W-18" || itemId == "W-47")
										{
											array2 = new string[1][]
											{
												new string[2]
												{
													"Remote Registry",
													"원격 레지스트리"
												}
											};
										}
										else if (itemId == "W-48")
										{
											array2 = new string[1][]
											{
												new string[5]
												{
													"Windows Defender Antivirus Service",
													"Windows Defender 서비스",
													"Microsoft Defender Antivirus Service",
													"Microsoft Defender 백신 서비스",
													"WinDefend"
												}
											};
										}
									}
									else if (itemId == "W-31" || itemId == "W-39")
									{
										array = new string[7][]
										{
											new string[2] { "로컬 컴퓨터 정책", "Local Computer Policy" },
											new string[2] { "컴퓨터 구성", "Computer Configuration" },
											new string[2] { "관리 템플릿", "Administrative Templates" },
											new string[2] { "Windows 구성 요소", "Windows Components" },
											new string[4] { "터미널 서비스", "원격 데스크톱 서비스", "Terminal Services", "Remote Desktop Services" },
											new string[2] { "원격 데스크톱 세션 호스트", "Remote Desktop Session Host" },
											(itemId == "W-31") ? new string[2] { "보안", "Security" } : new string[2] { "세션 시간 제한", "Session Time Limits" }
										};

										if (itemId == "W-31")
										{
											array2 = new string[1][]
											{
												new string[2] { "클라이언트 연결 암호화 수준 설정", "Set client connection encryption level" }
											};
										}
										else if (itemId == "W-39")
										{
											array2 = new string[1][]
											{
												new string[2] { "활성 상태지만 유휴 터미널 서비스 세션에 시간 제한 설정", "Set time limit for active but idle Remote Desktop Services sessions" }
											};
										}
									}
									else if (itemId == "W-40")
									{
										array = new string[2][]
										{
											new string[2]
											{
												"작업 스케줄러",
												"Task Scheduler"
											},
											new string[2]
											{
												"작업 스케줄러 라이브러리",
												"Task Scheduler Library"
											}
										};
									}
									else if (itemId == "W-45")
									{
										array = new string[3][]
										{
											new string[2]
											{
												"이벤트 뷰어",
												"Event Viewer"
											},
											new string[2]
											{
												"Windows 로그",
												"Windows Logs"
											},
											new string[2]
											{
												"보안",
												"Security"
											}
										};
									}
									else if (itemId == "W-64")
									{
										array = new string[1][]
										{
											new string[4]
											{
												"고급 보안",
												"Advanced Security",
												"방화벽",
												"Firewall"
											}
										};
									}
									if (array != null)
									{
										System.Windows.Automation.AutomationElement automationElement3 = automationElement2;
										string[][] array3 = array;
										string[][] array4 = array3;
										foreach (string[] array5 in array4)
										{
											try
											{
												KisaAutoPatcher.File.AppendAllText(text, string.Format("Searching for tree node matching: {0}\n", string.Join("/", array5)), System.Text.Encoding.UTF8);
											}
											catch
											{
											}
											System.Windows.Automation.AutomationElement automationElement4 = null;
											for (int i = 0; i < 10; i++)
											{
												automationElement4 = FindTreeItem(automationElement3, array5);
												if (automationElement4 == null)
												{
													automationElement4 = FindTreeItemDescendant(automationElement2, array5);
												}
												if (automationElement4 != null)
												{
													break;
												}
												System.Threading.Thread.Sleep(300);
											}
											if (automationElement4 != null)
											{
												try
												{
													KisaAutoPatcher.File.AppendAllText(text, string.Format("Found tree node: '{0}'. Expanding.\n", automationElement4.Current.Name), System.Text.Encoding.UTF8);
												}
												catch
												{
												}
												object patternObject;
												if (automationElement4.TryGetCurrentPattern(System.Windows.Automation.ScrollItemPattern.Pattern, out patternObject))
												{
													try
													{
														((System.Windows.Automation.ScrollItemPattern)patternObject).ScrollIntoView();
													}
													catch
													{
													}
													System.Threading.Thread.Sleep(100);
												}
												ExpandTreeItem(automationElement4);
												automationElement3 = automationElement4;
											}
											else
											{
												try
												{
													KisaAutoPatcher.File.AppendAllText(text, "Error: Tree node not found in children or descendants.\n", System.Text.Encoding.UTF8);
												}
												catch
												{
												}
										}
										object patternObject2;
										if (automationElement3.TryGetCurrentPattern(System.Windows.Automation.SelectionItemPattern.Pattern, out patternObject2))
										{
											try
											{
												KisaAutoPatcher.File.AppendAllText(text, string.Format("Selecting tree node: '{0}'\n", automationElement3.Current.Name), System.Text.Encoding.UTF8);
											}
											catch
											{
											}
											((System.Windows.Automation.SelectionItemPattern)patternObject2).Select();
											System.Threading.Thread.Sleep(300);
										}
										if (itemId == "W-45")
										{
											try
											{
												KisaAutoPatcher.File.AppendAllText(text, "W-45: Setting focus on Security tree node and sending Alt+Enter\n", System.Text.Encoding.UTF8);
											}
											catch
											{
											}
											automationElement3.SetFocus();
											System.Threading.Thread.Sleep(300);
											System.Windows.Forms.SendKeys.SendWait("%{ENTER}");
											System.Threading.Thread.Sleep(1000);
										}
									}
										if (array2 != null)
										{
											try
											{
												KisaAutoPatcher.File.AppendAllText(text, "Searching for list items...\n", System.Text.Encoding.UTF8);
											}
											catch
											{
											}
											System.Windows.Automation.AutomationElement automationElement5 = null;
											System.Windows.Automation.AutomationElement searchRoot = (array == null) ? automationElement2 : automationElement;
											for (int i = 0; i < 10; i++)
											{
												automationElement5 = FindListItemWithScrolling(searchRoot, array2);
												if (automationElement5 != null)
												{
													break;
												}
												System.Threading.Thread.Sleep(500);
											}
											if (automationElement5 != null)
											{
												try
												{
													KisaAutoPatcher.File.AppendAllText(text, string.Format("Found list item: '{0}'. Selecting.\n", automationElement5.Current.Name), System.Text.Encoding.UTF8);
												}
												catch
												{
												}
												object patternObject3;
												if (automationElement5.TryGetCurrentPattern(System.Windows.Automation.ScrollItemPattern.Pattern, out patternObject3))
												{
													try
													{
														((System.Windows.Automation.ScrollItemPattern)patternObject3).ScrollIntoView();
													}
													catch
													{
													}
													System.Threading.Thread.Sleep(150);
												}
												object patternObject4;
												if (automationElement5.TryGetCurrentPattern(System.Windows.Automation.SelectionItemPattern.Pattern, out patternObject4))
												{
													((System.Windows.Automation.SelectionItemPattern)patternObject4).Select();
													System.Threading.Thread.Sleep(100);
												}
												// W-40의 경우 대화상자를 열지 않고 현재 리스트 선택 상태를 증빙으로 사용
												if (itemId == "W-43")
												{
													try
													{
														KisaAutoPatcher.File.AppendAllText(text, "Bypassing dialog open for W-43 to capture the selected list item.\n", System.Text.Encoding.UTF8);
													}
													catch {}
													return;
												}

												object patternObject5;
												if (automationElement5.TryGetCurrentPattern(System.Windows.Automation.InvokePattern.Pattern, out patternObject5))
												{
													try
													{
														KisaAutoPatcher.File.AppendAllText(text, "Selecting and sending Enter key to open setting dialog.\n", System.Text.Encoding.UTF8);
													}
													catch {}

													try
													{
														object selItemPat;
														if (automationElement5.TryGetCurrentPattern(System.Windows.Automation.SelectionItemPattern.Pattern, out selItemPat))
														{
															((System.Windows.Automation.SelectionItemPattern)selItemPat).Select();
															System.Threading.Thread.Sleep(200);
														}
														automationElement5.SetFocus();
														System.Threading.Thread.Sleep(300);
														
														// 오직 엔터키 전송만으로 깔끔하게 창 팝업 유도
														System.Windows.Forms.SendKeys.SendWait("{ENTER}");
														System.Threading.Thread.Sleep(1500);
													}
													catch {}
												}
											}
											
											if (itemId == "W-31" || itemId == "W-39")
											{
												// 정책 창이 팝업되고 포커스를 가질 수 있도록 짧은 대기
												System.Threading.Thread.Sleep(1000); 

												// 1. 사용(Alt+E) 활성화 송출
												System.Windows.Forms.SendKeys.SendWait("%e");
												System.Threading.Thread.Sleep(400);

												if (itemId == "W-31")
												{
													// Tab 3회로 암호화 수준 콤보박스로 포커스 이동
													System.Windows.Forms.SendKeys.SendWait("{TAB}{TAB}{TAB}");
													System.Threading.Thread.Sleep(300);

													// F4로 드롭다운 목록을 아래로 펼친 후 조작
													System.Windows.Forms.SendKeys.SendWait("{F4}");
													System.Threading.Thread.Sleep(300);

													// {HOME}으로 맨 위 항목(낮은 수준) 이동 후 {DOWN} 2회로 세 번째 항목(클라이언트 호환 가능) 선택
													System.Windows.Forms.SendKeys.SendWait("{HOME}");
													System.Threading.Thread.Sleep(200);
													System.Windows.Forms.SendKeys.SendWait("{DOWN}{DOWN}");
													System.Threading.Thread.Sleep(200);

													// 선택한 항목 확정 및 콤보박스 드롭다운 닫기 (Enter)
													System.Windows.Forms.SendKeys.SendWait("{ENTER}");
													System.Threading.Thread.Sleep(300);
												}
												else if (itemId == "W-39")
												{
													// Tab 3회로 유휴 시간제한 콤보박스로 포커스 이동
													System.Windows.Forms.SendKeys.SendWait("{TAB}{TAB}{TAB}");
													System.Threading.Thread.Sleep(300);

													// '30분' 선택을 위해 '3' 키 송출
													System.Windows.Forms.SendKeys.SendWait("3");
													System.Threading.Thread.Sleep(200);
												}

												// 적용 및 저장 종료 (Enter)
												System.Windows.Forms.SendKeys.SendWait("{ENTER}");
												System.Threading.Thread.Sleep(500);
											}
											else
											{
												try
												{
													KisaAutoPatcher.File.AppendAllText(text, "Error: List item not found after 5 seconds.\n", System.Text.Encoding.UTF8);
												}
												catch
												{
												}
											}
										}
								}
							}
						}
						}
						catch (System.Exception ex)
						{
							try
							{
								KisaAutoPatcher.File.AppendAllText(text, "UI Automation Exception: " + ex.ToString() + "\n", System.Text.Encoding.UTF8);
							}
							catch
							{
							}
							System.Console.WriteLine("UI Automation navigation failed: " + ex.Message);
						}
					}
				}
				finally
				{
					isNavigationActive = false;
					CloseNavigationPopup();
				}
			});
		}

		private void AutomateNcpaNavigation(System.Windows.Automation.AutomationElement rootElement, string debugPath)
		{
			try
			{
				string strEthernet = "\uC774\uB354\uB13B"; // 이더넷
				string strProperties = "\uC18D\uC131"; // 속성
				string strProtocolFallback = "\uD504\uB85C\uD1A0\uCF5C \uBC84\uC804 4"; // 프로토콜 버전 4

				KisaAutoPatcher.File.AppendAllText(debugPath, "Starting ncpa.cpl automation...\n", System.Text.Encoding.UTF8);
				System.Windows.Automation.AutomationElement listCtrl = null;
				for (int i = 0; i < 20; i++)
				{
					listCtrl = rootElement.FindFirst(System.Windows.Automation.TreeScope.Descendants, 
						new System.Windows.Automation.OrCondition(
							new System.Windows.Automation.PropertyCondition(System.Windows.Automation.AutomationElement.ControlTypeProperty, System.Windows.Automation.ControlType.List),
							new System.Windows.Automation.PropertyCondition(System.Windows.Automation.AutomationElement.ControlTypeProperty, System.Windows.Automation.ControlType.Table),
							new System.Windows.Automation.PropertyCondition(System.Windows.Automation.AutomationElement.ControlTypeProperty, System.Windows.Automation.ControlType.DataGrid)
						));
					if (listCtrl != null) break;
					System.Threading.Thread.Sleep(500);
				}

				if (listCtrl == null)
				{
					KisaAutoPatcher.File.AppendAllText(debugPath, "Error: Adapter list control not found.\n", System.Text.Encoding.UTF8);
					return;
				}

				System.Windows.Automation.AutomationElementCollection adapters = listCtrl.FindAll(System.Windows.Automation.TreeScope.Descendants, 
					new System.Windows.Automation.OrCondition(
						new System.Windows.Automation.PropertyCondition(System.Windows.Automation.AutomationElement.ControlTypeProperty, System.Windows.Automation.ControlType.ListItem),
						new System.Windows.Automation.PropertyCondition(System.Windows.Automation.AutomationElement.ControlTypeProperty, System.Windows.Automation.ControlType.DataItem)
					));

				string strLocalArea = "\uB85C\uCEEC \uC601\uC5ED"; // 로컬 영역
				string strWireless = "\uBB34\uC2E0"; // 무선
				string strBluetooth = "Bluetooth";

				System.Windows.Automation.AutomationElement targetAdapter = null;
				
				// 1순위: 물리 유선 이더넷 카드 우선 선택 (Wi-Fi, Wireless, Bluetooth, Virtual, 가상, vEthernet 등 제외한 모든 유선 어댑터)
				foreach (System.Windows.Automation.AutomationElement item in adapters)
				{
					string name = "";
					try { name = item.Current.Name; } catch {}
					if (string.IsNullOrEmpty(name)) continue;

					// 제외 키워드 필터링
					if (name.IndexOf(strBluetooth, System.StringComparison.OrdinalIgnoreCase) >= 0 ||
						name.IndexOf("Wi-Fi", System.StringComparison.OrdinalIgnoreCase) >= 0 ||
						name.IndexOf("Wifi", System.StringComparison.OrdinalIgnoreCase) >= 0 ||
						name.IndexOf(strWireless, System.StringComparison.OrdinalIgnoreCase) >= 0 ||
						name.IndexOf("Wireless", System.StringComparison.OrdinalIgnoreCase) >= 0 ||
						name.IndexOf("Virtual", System.StringComparison.OrdinalIgnoreCase) >= 0 ||
						name.IndexOf("vEthernet", System.StringComparison.OrdinalIgnoreCase) >= 0 ||
						name.IndexOf("가상", System.StringComparison.OrdinalIgnoreCase) >= 0)
					{
						continue;
					}

					// 남은 어댑터 중 이름에 "이더넷", "Ethernet", "로컬", "Local" 또는 "연결"이 있으면 유선 카드로 낙점
					if (name.IndexOf(strEthernet, System.StringComparison.OrdinalIgnoreCase) >= 0 ||
						name.IndexOf("Ethernet", System.StringComparison.OrdinalIgnoreCase) >= 0 ||
						name.IndexOf(strLocalArea, System.StringComparison.OrdinalIgnoreCase) >= 0 ||
						name.IndexOf("Local", System.StringComparison.OrdinalIgnoreCase) >= 0 ||
						name.IndexOf("연결", System.StringComparison.OrdinalIgnoreCase) >= 0)
					{
						targetAdapter = item;
						break;
					}
				}

				// 2순위: 1순위 매칭 실패시, 예외 키워드 제외한 아무 유선 어댑터나 선택
				if (targetAdapter == null)
				{
					foreach (System.Windows.Automation.AutomationElement item in adapters)
					{
						string name = "";
						try { name = item.Current.Name; } catch {}
						if (string.IsNullOrEmpty(name)) continue;

						if (name.IndexOf(strBluetooth, System.StringComparison.OrdinalIgnoreCase) >= 0 ||
							name.IndexOf("Wi-Fi", System.StringComparison.OrdinalIgnoreCase) >= 0 ||
							name.IndexOf("Wifi", System.StringComparison.OrdinalIgnoreCase) >= 0 ||
							name.IndexOf(strWireless, System.StringComparison.OrdinalIgnoreCase) >= 0 ||
							name.IndexOf("Wireless", System.StringComparison.OrdinalIgnoreCase) >= 0 ||
							name.IndexOf("Virtual", System.StringComparison.OrdinalIgnoreCase) >= 0 ||
							name.IndexOf("vEthernet", System.StringComparison.OrdinalIgnoreCase) >= 0 ||
							name.IndexOf("가상", System.StringComparison.OrdinalIgnoreCase) >= 0)
						{
							continue;
						}

						targetAdapter = item;
						break;
					}
				}

				// 3순위: 그래도 없으면 Wi-Fi / 무선 연결 선택
				if (targetAdapter == null)
				{
					foreach (System.Windows.Automation.AutomationElement item in adapters)
					{
						string name = "";
						try { name = item.Current.Name; } catch {}
						if (string.IsNullOrEmpty(name)) continue;
						if (name.IndexOf(strBluetooth, System.StringComparison.OrdinalIgnoreCase) >= 0)
							continue;

						if (name.IndexOf("Wi-Fi", System.StringComparison.OrdinalIgnoreCase) >= 0 ||
							name.IndexOf("Wifi", System.StringComparison.OrdinalIgnoreCase) >= 0 ||
							name.IndexOf(strWireless, System.StringComparison.OrdinalIgnoreCase) >= 0 ||
							name.IndexOf("Wireless", System.StringComparison.OrdinalIgnoreCase) >= 0)
						{
							targetAdapter = item;
							break;
						}
					}
				}

				// 4순위: Bluetooth가 아닌 어댑터
				if (targetAdapter == null)
				{
					foreach (System.Windows.Automation.AutomationElement item in adapters)
					{
						string name = "";
						try { name = item.Current.Name; } catch {}
						if (name.IndexOf(strBluetooth, System.StringComparison.OrdinalIgnoreCase) >= 0)
							continue;

						targetAdapter = item;
						break;
					}
				}

				// 최종 fallback
				if (targetAdapter == null && adapters.Count > 0)
				{
					targetAdapter = adapters[0];
				}

				if (targetAdapter == null)
				{
					KisaAutoPatcher.File.AppendAllText(debugPath, "Error: No adapter item found.\n", System.Text.Encoding.UTF8);
					return;
				}

				KisaAutoPatcher.File.AppendAllText(debugPath, string.Format("Step 1: Found adapter '{0}'. Triggering properties...\n", targetAdapter.Current.Name), System.Text.Encoding.UTF8);
				
				// 이더넷 속성 열기
				System.IntPtr winPtr = System.IntPtr.Zero;
				try
				{
					winPtr = (System.IntPtr)rootElement.Current.NativeWindowHandle;
					ShowWindow(winPtr, 9); // RESTORE
					SetForegroundWindow(winPtr);
					System.Threading.Thread.Sleep(300);
				}
				catch {}

				try
				{
					object selPat = null;
					if (targetAdapter.TryGetCurrentPattern(System.Windows.Automation.SelectionItemPattern.Pattern, out selPat))
					{
						((System.Windows.Automation.SelectionItemPattern)selPat).Select();
						System.Threading.Thread.Sleep(200);
					}
				}
				catch {}

				try
				{
					targetAdapter.SetFocus();
					System.Threading.Thread.Sleep(200);
				}
				catch {}

				System.Windows.Rect rect = targetAdapter.Current.BoundingRectangle;
				int targetX = 0;
				int targetY = 0;
				bool hasPoint = false;

				try
				{
					System.Windows.Point pt;
					if (targetAdapter.TryGetClickablePoint(out pt))
					{
						targetX = (int)pt.X;
						targetY = (int)pt.Y;
						hasPoint = true;
					}
				}
				catch {}

				if (!hasPoint && rect.Width > 0 && rect.Height > 0)
				{
					targetX = (int)(rect.Left + rect.Width / 2);
					targetY = (int)(rect.Top + rect.Height / 2);
					hasPoint = true;
				}

				// 강제 활성화 시도
				if (winPtr != System.IntPtr.Zero)
				{
					SetForegroundWindow(winPtr);
					System.Threading.Thread.Sleep(200);
				}

				// 방법 1: Alt+Enter 키 송출 (속성창 팝업 표준 단축키)
				try
				{
					if (winPtr != System.IntPtr.Zero) SetForegroundWindow(winPtr);
					targetAdapter.SetFocus();
					System.Threading.Thread.Sleep(200);

					System.Windows.Forms.SendKeys.SendWait("%{ENTER}");
					System.Threading.Thread.Sleep(1500);
				}
				catch {}

				// 속성 창 감지 1
				System.Windows.Automation.AutomationElement propWin = null;
				for (int i = 0; i < 8; i++)
				{
					// 1) RootElement의 Children/Descendants에서 수집
					System.Windows.Automation.AutomationElementCollection wins = System.Windows.Automation.AutomationElement.RootElement.FindAll(
						System.Windows.Automation.TreeScope.Children, 
						new System.Windows.Automation.PropertyCondition(System.Windows.Automation.AutomationElement.ClassNameProperty, "#32770"));
					foreach (System.Windows.Automation.AutomationElement w in wins)
					{
						if (w.Current.NativeWindowHandle != (int)this.Handle)
						{
							propWin = w;
							break;
						}
					}
					if (propWin != null) break;

					// 2) ncpa.cpl 부모 창 내부의 모달/대화상자 스캔
					if (winPtr != System.IntPtr.Zero)
					{
						try
						{
							System.Windows.Automation.AutomationElement ncpaWin = System.Windows.Automation.AutomationElement.FromHandle(winPtr);
							if (ncpaWin != null)
							{
								System.Windows.Automation.AutomationElementCollection innerWins = ncpaWin.FindAll(
									System.Windows.Automation.TreeScope.Descendants,
									new System.Windows.Automation.PropertyCondition(System.Windows.Automation.AutomationElement.ClassNameProperty, "#32770"));
								if (innerWins.Count > 0)
								{
									propWin = innerWins[0];
									break;
								}
							}
						}
						catch {}
					}
					System.Threading.Thread.Sleep(400);
				}

				// 방법 2: 감지되지 않았으면 Shift+F10 -> 단축키 'r'
				if (propWin == null && hasPoint)
				{
					try
					{
						if (winPtr != System.IntPtr.Zero) SetForegroundWindow(winPtr);
						targetAdapter.SetFocus();
						System.Threading.Thread.Sleep(200);

						SetCursorPos(targetX, targetY);
						System.Threading.Thread.Sleep(100);
						mouse_event(2u, (uint)targetX, (uint)targetY, 0u, 0); // Left click to focus
						mouse_event(4u, (uint)targetX, (uint)targetY, 0u, 0);
						System.Threading.Thread.Sleep(150);

						System.Windows.Forms.SendKeys.SendWait("+{F10}");
						System.Threading.Thread.Sleep(500);
						System.Windows.Forms.SendKeys.SendWait("r");
						System.Threading.Thread.Sleep(1500);
					}
					catch {}

					for (int i = 0; i < 8; i++)
					{
						System.Windows.Automation.AutomationElementCollection wins = System.Windows.Automation.AutomationElement.RootElement.FindAll(
							System.Windows.Automation.TreeScope.Children, 
							new System.Windows.Automation.PropertyCondition(System.Windows.Automation.AutomationElement.ClassNameProperty, "#32770"));
						foreach (System.Windows.Automation.AutomationElement w in wins)
						{
							if (w.Current.NativeWindowHandle != (int)this.Handle)
							{
								propWin = w;
								break;
							}
						}
						if (propWin != null) break;

						if (winPtr != System.IntPtr.Zero)
						{
							try
							{
								System.Windows.Automation.AutomationElement ncpaWin = System.Windows.Automation.AutomationElement.FromHandle(winPtr);
								if (ncpaWin != null)
								{
									System.Windows.Automation.AutomationElementCollection innerWins = ncpaWin.FindAll(
										System.Windows.Automation.TreeScope.Descendants,
										new System.Windows.Automation.PropertyCondition(System.Windows.Automation.AutomationElement.ClassNameProperty, "#32770"));
									if (innerWins.Count > 0)
									{
										propWin = innerWins[0];
										break;
									}
								}
							}
							catch {}
						}
						System.Threading.Thread.Sleep(400);
					}
				}

				// 방법 3: 감지되지 않았으면 우클릭 직접 시뮬레이션 -> 단축키 'r'
				if (propWin == null && hasPoint)
				{
					try
					{
						if (winPtr != System.IntPtr.Zero) SetForegroundWindow(winPtr);
						targetAdapter.SetFocus();
						System.Threading.Thread.Sleep(200);

						SetCursorPos(targetX, targetY);
						System.Threading.Thread.Sleep(150);
						mouse_event(8u, (uint)targetX, (uint)targetY, 0u, 0); // Right down
						mouse_event(16u, (uint)targetX, (uint)targetY, 0u, 0); // Right up
						System.Threading.Thread.Sleep(500);
						System.Windows.Forms.SendKeys.SendWait("r");
						System.Threading.Thread.Sleep(1500);
					}
					catch {}

					for (int i = 0; i < 10; i++)
					{
						System.Windows.Automation.AutomationElementCollection wins = System.Windows.Automation.AutomationElement.RootElement.FindAll(
							System.Windows.Automation.TreeScope.Children, 
							new System.Windows.Automation.PropertyCondition(System.Windows.Automation.AutomationElement.ClassNameProperty, "#32770"));
						foreach (System.Windows.Automation.AutomationElement w in wins)
						{
							if (w.Current.NativeWindowHandle != (int)this.Handle)
							{
								propWin = w;
								break;
							}
						}
						if (propWin != null) break;

						if (winPtr != System.IntPtr.Zero)
						{
							try
							{
								System.Windows.Automation.AutomationElement ncpaWin = System.Windows.Automation.AutomationElement.FromHandle(winPtr);
								if (ncpaWin != null)
								{
									System.Windows.Automation.AutomationElementCollection innerWins = ncpaWin.FindAll(
										System.Windows.Automation.TreeScope.Descendants,
										new System.Windows.Automation.PropertyCondition(System.Windows.Automation.AutomationElement.ClassNameProperty, "#32770"));
									if (innerWins.Count > 0)
									{
										propWin = innerWins[0];
										break;
									}
								}
							}
							catch {}
						}
						System.Threading.Thread.Sleep(400);
					}
				}

				if (propWin == null)
				{
					KisaAutoPatcher.File.AppendAllText(debugPath, "Error: Properties dialog not found.\n", System.Text.Encoding.UTF8);
					return;
				}

				KisaAutoPatcher.File.AppendAllText(debugPath, "Step 3: Selecting TCP/IPv4 list item...\n", System.Text.Encoding.UTF8);
				System.Windows.Automation.AutomationElement listCtrl32 = propWin.FindFirst(
					System.Windows.Automation.TreeScope.Descendants,
					new System.Windows.Automation.PropertyCondition(System.Windows.Automation.AutomationElement.ClassNameProperty, "SysListView32"));

				bool ipv4Selected = false;
				if (listCtrl32 != null)
				{
					KisaAutoPatcher.File.AppendAllText(debugPath, "Step 3: Found List Control (ClassName: 'SysListView32'). Focusing...\n", System.Text.Encoding.UTF8);
					listCtrl32.SetFocus();
					System.Threading.Thread.Sleep(200);

					System.Windows.Automation.AutomationElementCollection listItems = listCtrl32.FindAll(
						System.Windows.Automation.TreeScope.Children,
						new System.Windows.Automation.PropertyCondition(System.Windows.Automation.AutomationElement.ControlTypeProperty, System.Windows.Automation.ControlType.ListItem));

					KisaAutoPatcher.File.AppendAllText(debugPath, string.Format("--- List Items in Properties Window (Count: {0}) ---\n", listItems.Count), System.Text.Encoding.UTF8);
					
					// 스마트 키보드 스캔 폴백
					KisaAutoPatcher.File.AppendAllText(debugPath, "Step 3 fallback: Scanning list using keyboard navigation...\n", System.Text.Encoding.UTF8);
					System.Windows.Forms.SendKeys.SendWait("{HOME}");
					System.Threading.Thread.Sleep(300);

					for (int d = 0; d < 12; d++)
					{
						System.Windows.Automation.AutomationElement focused = System.Windows.Automation.AutomationElement.FocusedElement;
						if (focused != null)
						{
							string fn = "";
							try { fn = focused.Current.Name; } catch {}
							KisaAutoPatcher.File.AppendAllText(debugPath, string.Format("Step 3 fallback: Focused item name='{0}'\n", fn), System.Text.Encoding.UTF8);
							
							bool matchesFallback = (fn.IndexOf("TCP/IPv4", System.StringComparison.OrdinalIgnoreCase) >= 0 || 
													fn.IndexOf("Internet Protocol Version 4", System.StringComparison.OrdinalIgnoreCase) >= 0 || 
													fn.IndexOf(strProtocolFallback, System.StringComparison.OrdinalIgnoreCase) >= 0);
							
							if (matchesFallback)
							{
								ipv4Selected = true;
								KisaAutoPatcher.File.AppendAllText(debugPath, string.Format("Step 3 fallback: Found and selected '{0}' at index {1}. Sending Alt+R...\n", fn, d), System.Text.Encoding.UTF8);
								
								SetForegroundWindow((System.IntPtr)propWin.Current.NativeWindowHandle);
								System.Threading.Thread.Sleep(200);
								System.Windows.Forms.SendKeys.SendWait("%r"); // Alt+R 송출
								System.Threading.Thread.Sleep(2000);
								break;
							}
						}
						System.Windows.Forms.SendKeys.SendWait("{DOWN}");
						System.Threading.Thread.Sleep(200);
					}
				}

				// ── Step 4 & 5: 속성(R) 송출 대기 및 고급 창(Alt+V) 즉시 전송 ──────────────────
				KisaAutoPatcher.File.AppendAllText(debugPath, "Step 4 & 5: Already triggered Properties in Step 3. Sending Alt+V directly after delay...\n", System.Text.Encoding.UTF8);
				System.Threading.Thread.Sleep(2000); // 속성 창 로딩 대기
				
				if (!ipv4Selected)
				{
					SetForegroundWindow((System.IntPtr)propWin.Current.NativeWindowHandle);
					System.Threading.Thread.Sleep(200);
					System.Windows.Forms.SendKeys.SendWait("%r");
					System.Threading.Thread.Sleep(2000);
				}
				
				// [포커스 보정] TCP/IPv4 속성 창을 찾아 강제 전면화
				System.Windows.Automation.AutomationElement activeIPv4Dialog = null;
				try
				{
					System.Windows.Automation.AutomationElementCollection wins = System.Windows.Automation.AutomationElement.RootElement.FindAll(
						System.Windows.Automation.TreeScope.Children,
						new System.Windows.Automation.PropertyCondition(System.Windows.Automation.AutomationElement.ClassNameProperty, "#32770"));
					foreach (System.Windows.Automation.AutomationElement w in wins)
					{
						if (w.Current.NativeWindowHandle != (int)this.Handle && w.Current.NativeWindowHandle != (int)propWin.Current.NativeWindowHandle)
						{
							activeIPv4Dialog = w;
							break;
						}
					}
				}
				catch {}
				
				if (activeIPv4Dialog != null)
				{
					SetForegroundWindow((System.IntPtr)activeIPv4Dialog.Current.NativeWindowHandle);
					System.Threading.Thread.Sleep(300);
				}
				
				// 고급(V)... 단축키 Alt+V 전송
				System.Windows.Forms.SendKeys.SendWait("%v");
				System.Threading.Thread.Sleep(2500); // 고급 창 로딩 대기

				// ── Step 7 & 8: 고급 TCP/IP 창 UIA 대기 없이 직접 WINS 탭으로 네비게이션 ──────────
				KisaAutoPatcher.File.AppendAllText(debugPath, "Step 7 & 8: Navigating to WINS tab via Tab control scanning...\n", System.Text.Encoding.UTF8);
				
				// [포커스 보정] 새로 열린 고급 TCP/IP 설정 창(#32770)을 찾아 강제 전면화
				System.Windows.Automation.AutomationElement activeAdvDialog = null;
				try
				{
					System.Windows.Automation.AutomationElementCollection wins = System.Windows.Automation.AutomationElement.RootElement.FindAll(
						System.Windows.Automation.TreeScope.Children,
						new System.Windows.Automation.PropertyCondition(System.Windows.Automation.AutomationElement.ClassNameProperty, "#32770"));
					foreach (System.Windows.Automation.AutomationElement w in wins)
					{
						if (w.Current.NativeWindowHandle != (int)this.Handle && 
							w.Current.NativeWindowHandle != (int)propWin.Current.NativeWindowHandle && 
							(activeIPv4Dialog == null || w.Current.NativeWindowHandle != (int)activeIPv4Dialog.Current.NativeWindowHandle))
						{
							activeAdvDialog = w;
							break;
						}
					}
				}
				catch {}
				
				if (activeAdvDialog != null)
				{
					SetForegroundWindow((System.IntPtr)activeAdvDialog.Current.NativeWindowHandle);
					System.Threading.Thread.Sleep(300);
				}
				else if (activeIPv4Dialog != null)
				{
					// 못 찾았다면 직전 속성 다이얼로그 다음 팝업을 우선 타겟팅
					System.Windows.Forms.SendKeys.SendWait("{ENTER}"); // 윈도우 포커스 리셋용
					System.Threading.Thread.Sleep(200);
				}

				// 상단 탭 컨트롤로 포커스를 보내기 위해 Shift+Tab 전송
				System.Windows.Forms.SendKeys.SendWait("+{TAB}");
				System.Threading.Thread.Sleep(800);

				// 오른쪽 화살표 2번 전송하여 WINS 탭으로 이동 (IP 설정 -> DNS -> WINS)
				System.Windows.Forms.SendKeys.SendWait("{RIGHT}{RIGHT}");
				System.Threading.Thread.Sleep(1200);

				// [포커스 재확인] 단축키 송출 직전 다시 한번 Foreground 보장
				if (activeAdvDialog != null)
				{
					SetForegroundWindow((System.IntPtr)activeAdvDialog.Current.NativeWindowHandle);
					System.Threading.Thread.Sleep(200);
				}

				// ── Step 9: WINS 탭에서 "NetBIOS 사용 안 함(S)" 라디오 버튼 선택 ──────────────
				KisaAutoPatcher.File.AppendAllText(debugPath, "Step 9: Activating 'Disable NetBIOS over TCP/IP' via Alt+S...\n", System.Text.Encoding.UTF8);
				System.Windows.Forms.SendKeys.SendWait("%s"); // Alt+S 전송 (NetBIOS 사용 안 함(S) 대응)
				System.Threading.Thread.Sleep(1000);

				KisaAutoPatcher.File.AppendAllText(debugPath, "SUCCESS: NetBIOS over TCP/IP disabled per Model.pdf!\n", System.Text.Encoding.UTF8);

				// ── Step 10 ~ 12: 창 닫기 연쇄 처리 (전체 자동 모드일 경우에만 자동 닫기 진행) ───────
				if (!isInteractiveMode)
				{
					KisaAutoPatcher.File.AppendAllText(debugPath, "Step 10 ~ 12: Closing all properties windows using Enter keys (Full Auto mode active)...\n", System.Text.Encoding.UTF8);
					// 1. 고급 TCP/IP 설정 창 확인 (Enter)
					System.Windows.Forms.SendKeys.SendWait("{ENTER}");
					System.Threading.Thread.Sleep(1200);
					// 2. TCP/IPv4 속성 창 확인 (Enter)
					System.Windows.Forms.SendKeys.SendWait("{ENTER}");
					System.Threading.Thread.Sleep(1500);
					// 3. 이더넷 속성 창 닫기 (Enter)
					System.Windows.Forms.SendKeys.SendWait("{ENTER}");
					System.Threading.Thread.Sleep(800);
				}
				else
				{
					KisaAutoPatcher.File.AppendAllText(debugPath, "Step 10 ~ 12: Keeping windows open for manual review (Interactive mode active).\n", System.Text.Encoding.UTF8);
				}

				KisaAutoPatcher.File.AppendAllText(debugPath, "W-20 COMPLETE: Model.pdf flow finished (Ethernet → TCP/IPv4 → Advanced → WINS → Disable NetBIOS → OK).\n", System.Text.Encoding.UTF8);
			}
			catch (System.Exception ex)
			{
				try { KisaAutoPatcher.File.AppendAllText(debugPath, "Exception in ncpa automation: " + ex.ToString() + "\n", System.Text.Encoding.UTF8); }
				catch {}
			}
		}

		private void AutomateOdbcNavigation(System.Windows.Automation.AutomationElement rootElement, string debugPath)
		{
			try
			{
				KisaAutoPatcher.File.AppendAllText(debugPath, "Starting odbcad32.exe automation...\n", System.Text.Encoding.UTF8);
				System.Windows.Automation.AutomationElement automationElement = null;
				for (int i = 0; i < 20; i++)
				{
					automationElement = rootElement.FindFirst(System.Windows.Automation.TreeScope.Descendants, new System.Windows.Automation.PropertyCondition(System.Windows.Automation.AutomationElement.ControlTypeProperty, System.Windows.Automation.ControlType.Tab));
					if (automationElement != null)
					{
						break;
					}
					System.Threading.Thread.Sleep(500);
				}
				if (automationElement == null)
				{
					KisaAutoPatcher.File.AppendAllText(debugPath, "Error: Tab control not found in ODBC Administrator.\n", System.Text.Encoding.UTF8);
				}
				else
				{
					System.Windows.Automation.AutomationElement automationElement2 = null;
					System.Windows.Automation.AutomationElementCollection automationElementCollection = automationElement.FindAll(System.Windows.Automation.TreeScope.Children, new System.Windows.Automation.PropertyCondition(System.Windows.Automation.AutomationElement.ControlTypeProperty, System.Windows.Automation.ControlType.TabItem));
					foreach (System.Windows.Automation.AutomationElement item in automationElementCollection)
					{
						string name = item.Current.Name;
						if (name.IndexOf("시스템 DSN", System.StringComparison.OrdinalIgnoreCase) >= 0 || name.IndexOf("System DSN", System.StringComparison.OrdinalIgnoreCase) >= 0)
						{
							automationElement2 = item;
							break;
						}
					}
					if (automationElement2 == null)
					{
						KisaAutoPatcher.File.AppendAllText(debugPath, "Error: System DSN tab not found.\n", System.Text.Encoding.UTF8);
					}
					else
					{
						KisaAutoPatcher.File.AppendAllText(debugPath, string.Format("Selecting System DSN tab: '{0}'\n", automationElement2.Current.Name), System.Text.Encoding.UTF8);
						object patternObject;
						if (automationElement2.TryGetCurrentPattern(System.Windows.Automation.SelectionItemPattern.Pattern, out patternObject))
						{
							((System.Windows.Automation.SelectionItemPattern)patternObject).Select();
							KisaAutoPatcher.File.AppendAllText(debugPath, "Successfully selected System DSN tab!\n", System.Text.Encoding.UTF8);
						}
					}
				}
			}
			catch (System.Exception ex)
			{
				try
				{
					KisaAutoPatcher.File.AppendAllText(debugPath, "Exception in ODBC automation: " + ex.ToString() + "\n", System.Text.Encoding.UTF8);
				}
				catch
				{
				}
			}
		}

		private void AutomateTimeDateNavigation(System.Windows.Automation.AutomationElement rootElement, string debugPath)
		{
			try
			{
				KisaAutoPatcher.File.AppendAllText(debugPath, "Starting timedate.cpl automation...\n", System.Text.Encoding.UTF8);
				System.Windows.Automation.AutomationElement automationElement = null;
				for (int i = 0; i < 20; i++)
				{
					automationElement = rootElement.FindFirst(System.Windows.Automation.TreeScope.Descendants, new System.Windows.Automation.PropertyCondition(System.Windows.Automation.AutomationElement.ControlTypeProperty, System.Windows.Automation.ControlType.Tab));
					if (automationElement != null)
					{
						break;
					}
					System.Threading.Thread.Sleep(500);
				}
				if (automationElement == null)
				{
					KisaAutoPatcher.File.AppendAllText(debugPath, "Error: Tab control not found in Date and Time Properties.\n", System.Text.Encoding.UTF8);
				}
				else
				{
					System.Windows.Automation.AutomationElement automationElement2 = null;
					System.Windows.Automation.AutomationElementCollection automationElementCollection = automationElement.FindAll(System.Windows.Automation.TreeScope.Children, new System.Windows.Automation.PropertyCondition(System.Windows.Automation.AutomationElement.ControlTypeProperty, System.Windows.Automation.ControlType.TabItem));
					foreach (System.Windows.Automation.AutomationElement item in automationElementCollection)
					{
						string name = item.Current.Name;
						if (name.IndexOf("인터넷 시간", System.StringComparison.OrdinalIgnoreCase) >= 0 || name.IndexOf("Internet Time", System.StringComparison.OrdinalIgnoreCase) >= 0)
						{
							automationElement2 = item;
							break;
						}
					}
					if (automationElement2 == null)
					{
						KisaAutoPatcher.File.AppendAllText(debugPath, "Error: Internet Time tab not found.\n", System.Text.Encoding.UTF8);
					}
					else
					{
						KisaAutoPatcher.File.AppendAllText(debugPath, string.Format("Selecting Internet Time tab: '{0}'\n", automationElement2.Current.Name), System.Text.Encoding.UTF8);
						object patternObject;
						if (automationElement2.TryGetCurrentPattern(System.Windows.Automation.SelectionItemPattern.Pattern, out patternObject))
						{
							((System.Windows.Automation.SelectionItemPattern)patternObject).Select();
							System.Threading.Thread.Sleep(300);
						}
						System.Windows.Automation.AutomationElement automationElement4 = null;
						System.Windows.Automation.AutomationElementCollection automationElementCollection2 = rootElement.FindAll(System.Windows.Automation.TreeScope.Descendants, new System.Windows.Automation.PropertyCondition(System.Windows.Automation.AutomationElement.ControlTypeProperty, System.Windows.Automation.ControlType.Button));
						foreach (System.Windows.Automation.AutomationElement item2 in automationElementCollection2)
						{
							string name = item2.Current.Name;
							if (name.IndexOf("설정 변경", System.StringComparison.OrdinalIgnoreCase) >= 0 || name.IndexOf("Change settings", System.StringComparison.OrdinalIgnoreCase) >= 0)
							{
								automationElement4 = item2;
								break;
							}
						}
						if (automationElement4 != null)
						{
							KisaAutoPatcher.File.AppendAllText(debugPath, string.Format("Clicking Change Settings button: '{0}'\n", automationElement4.Current.Name), System.Text.Encoding.UTF8);
							object patternObject2;
							if (automationElement4.TryGetCurrentPattern(System.Windows.Automation.InvokePattern.Pattern, out patternObject2))
							{
								((System.Windows.Automation.InvokePattern)patternObject2).Invoke();
								KisaAutoPatcher.File.AppendAllText(debugPath, "Successfully clicked settings change button!\n", System.Text.Encoding.UTF8);
							}
							else
							{
								automationElement4.SetFocus();
								System.Threading.Thread.Sleep(100);
								System.Windows.Forms.SendKeys.SendWait("{ENTER}");
							}
						}
						else
						{
							KisaAutoPatcher.File.AppendAllText(debugPath, "Warning: Change settings button not found.\n", System.Text.Encoding.UTF8);
						}
					}
				}
			}
			catch (System.Exception ex)
			{
				try
				{
					KisaAutoPatcher.File.AppendAllText(debugPath, "Exception in Internet Time automation: " + ex.ToString() + "\n", System.Text.Encoding.UTF8);
				}
				catch
				{
				}
			}
		}

		private System.Windows.Automation.AutomationElement FindTreeItem(System.Windows.Automation.AutomationElement parent, string[] candidateNames)
		{
			if (parent == null)
			{
				return null;
			}
			System.Windows.Automation.AutomationElementCollection automationElementCollection = parent.FindAll(System.Windows.Automation.TreeScope.Children, new System.Windows.Automation.PropertyCondition(System.Windows.Automation.AutomationElement.ControlTypeProperty, System.Windows.Automation.ControlType.TreeItem));
			foreach (System.Windows.Automation.AutomationElement item in automationElementCollection)
			{
				string name = item.Current.Name;
				foreach (string value in candidateNames)
				{
					if (name.IndexOf(value, System.StringComparison.OrdinalIgnoreCase) >= 0)
					{
						return item;
					}
				}
			}
			return null;
		}

		private System.Windows.Automation.AutomationElement FindTreeItemDescendant(System.Windows.Automation.AutomationElement parent, string[] candidateNames)
		{
			if (parent == null)
			{
				return null;
			}
			System.Windows.Automation.AutomationElementCollection automationElementCollection = parent.FindAll(System.Windows.Automation.TreeScope.Descendants, new System.Windows.Automation.PropertyCondition(System.Windows.Automation.AutomationElement.ControlTypeProperty, System.Windows.Automation.ControlType.TreeItem));
			foreach (System.Windows.Automation.AutomationElement item in automationElementCollection)
			{
				string name = item.Current.Name;
				foreach (string value in candidateNames)
				{
					if (name.IndexOf(value, System.StringComparison.OrdinalIgnoreCase) >= 0)
					{
						return item;
					}
				}
			}
			return null;
		}

		private void ExpandTreeItem(System.Windows.Automation.AutomationElement element)
		{
			object patternObject;
			if (!(element == null) && element.TryGetCurrentPattern(System.Windows.Automation.ExpandCollapsePattern.Pattern, out patternObject))
			{
				System.Windows.Automation.ExpandCollapsePattern expandCollapsePattern = patternObject as System.Windows.Automation.ExpandCollapsePattern;
				if (expandCollapsePattern != null)
				{
					try
					{
						if (expandCollapsePattern.Current.ExpandCollapseState != System.Windows.Automation.ExpandCollapseState.LeafNode)
						{
							expandCollapsePattern.Expand();
							System.Threading.Thread.Sleep(150);
						}
					}
					catch
					{
					}
				}
			}
		}

		private System.Windows.Automation.AutomationElement FindListItem(System.Windows.Automation.AutomationElement root, string[][] candidateItemNames)
		{
			System.Windows.Automation.Condition condition = new System.Windows.Automation.OrCondition(new System.Windows.Automation.PropertyCondition(System.Windows.Automation.AutomationElement.ControlTypeProperty, System.Windows.Automation.ControlType.DataItem), new System.Windows.Automation.PropertyCondition(System.Windows.Automation.AutomationElement.ControlTypeProperty, System.Windows.Automation.ControlType.ListItem));
			System.Windows.Automation.AutomationElementCollection automationElementCollection = root.FindAll(System.Windows.Automation.TreeScope.Descendants, condition);
			
			// 1차 패스: 정확히 일치(Exact Match)하는 것 우선 선택
			foreach (System.Windows.Automation.AutomationElement item in automationElementCollection)
			{
				string name = "";
				try { name = item.Current.Name.Trim(); } catch {}
				foreach (string[] array in candidateItemNames)
				{
					string[] array2 = array;
					string[] array3 = array2;
					foreach (string value in array3)
					{
						if (name.Equals(value.Trim(), System.StringComparison.OrdinalIgnoreCase))
						{
							return item;
						}
					}
				}
			}

			// 2차 패스: 정확히 일치하는 것이 없을 때 부분 일치(Partial Match) 폴백
			foreach (System.Windows.Automation.AutomationElement item in automationElementCollection)
			{
				string name = "";
				try { name = item.Current.Name; } catch {}
				foreach (string[] array in candidateItemNames)
				{
					string[] array2 = array;
					string[] array3 = array2;
					foreach (string value in array3)
					{
						if (name.IndexOf(value, System.StringComparison.OrdinalIgnoreCase) >= 0)
						{
							return item;
						}
					}
				}
			}
			return null;
		}

		private System.Windows.Automation.AutomationElement FindListItemWithScrolling(System.Windows.Automation.AutomationElement rootElement, string[][] targetItems)
		{
			System.Windows.Automation.AutomationElement automationElement = FindListItem(rootElement, targetItems);
			if (automationElement != null)
			{
				return automationElement;
			}
			System.Windows.Automation.AutomationElement automationElement2 = rootElement.FindFirst(System.Windows.Automation.TreeScope.Descendants, new System.Windows.Automation.OrCondition(new System.Windows.Automation.PropertyCondition(System.Windows.Automation.AutomationElement.ControlTypeProperty, System.Windows.Automation.ControlType.List), new System.Windows.Automation.PropertyCondition(System.Windows.Automation.AutomationElement.ControlTypeProperty, System.Windows.Automation.ControlType.Table), new System.Windows.Automation.PropertyCondition(System.Windows.Automation.AutomationElement.ControlTypeProperty, System.Windows.Automation.ControlType.DataGrid)));
			if (automationElement2 == null)
			{
				return null;
			}
			object patternObject;
			if (automationElement2.TryGetCurrentPattern(System.Windows.Automation.ScrollPattern.Pattern, out patternObject))
			{
				System.Windows.Automation.ScrollPattern scrollPattern = (System.Windows.Automation.ScrollPattern)patternObject;
				if (scrollPattern.Current.VerticallyScrollable)
				{
					try
					{
						scrollPattern.SetScrollPercent(-1.0, 0.0);
					}
					catch
					{
					}
					System.Threading.Thread.Sleep(300);
					for (int i = 0; i < 40; i++)
					{
						automationElement = FindListItem(automationElement2, targetItems);
						if (automationElement != null)
						{
							return automationElement;
						}
						try
						{
							for (int j = 0; j < 3; j++)
							{
								scrollPattern.Scroll(System.Windows.Automation.ScrollAmount.NoAmount, System.Windows.Automation.ScrollAmount.SmallIncrement);
								System.Threading.Thread.Sleep(50);
							}
						}
						catch
						{
							goto IL_0170;
						}
						System.Threading.Thread.Sleep(250);
					}
				}
			}
			goto IL_0170;
			IL_0170:
			return null;
		}

		private void ShowNavigationPopup(string itemId)
		{
			if (base.InvokeRequired)
			{
				BeginInvoke((System.Action)delegate
				{
					ShowNavigationPopup(itemId);
				});
			}
			else
			{
				try
				{
					if (navigationLoadingForm != null)
					{
						navigationLoadingForm.Close();
						navigationLoadingForm = null;
					}
					// ── Claude 테마 탐색 중 팝업 ───────────────────────────────
					navigationLoadingForm = new System.Windows.Forms.Form();
					navigationLoadingForm.Text = "자동 탐색 중...";
					navigationLoadingForm.Size = new System.Drawing.Size(440, 172);
					navigationLoadingForm.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
					navigationLoadingForm.MaximizeBox = false;
					navigationLoadingForm.MinimizeBox = false;
					navigationLoadingForm.StartPosition = System.Windows.Forms.FormStartPosition.Manual;
					navigationLoadingForm.Location = new System.Drawing.Point(
						this.Left + (this.Width  - 440) / 2,
						this.Top  + (this.Height - 172) / 2);
					navigationLoadingForm.BackColor = System.Drawing.Color.FromArgb(38, 34, 30);
					navigationLoadingForm.TopMost   = true;
					
					// 상단 엑센트 바
					System.Windows.Forms.Panel popAccent = new System.Windows.Forms.Panel
					{
						Dock      = System.Windows.Forms.DockStyle.Top,
						Height    = 3,
						BackColor = System.Drawing.Color.FromArgb(204, 120, 92)
					};
					// 아이콘 레이블
					System.Windows.Forms.Label popIcon = new System.Windows.Forms.Label
					{
						Text      = "🔍",
						Font      = new System.Drawing.Font("Malgun Gothic", 22f),
						ForeColor = System.Drawing.Color.FromArgb(204, 120, 92),
						BackColor = System.Drawing.Color.Transparent,
						Location  = new System.Drawing.Point(20, 20),
						Size      = new System.Drawing.Size(44, 44)
					};
					System.Windows.Forms.Label popTitle = new System.Windows.Forms.Label
					{
						Text      = string.Format("[ {0} ]  정책 경로 자동 탐색 중", itemId),
						Font      = new System.Drawing.Font("Malgun Gothic", 10.5f, System.Drawing.FontStyle.Bold),
						ForeColor = System.Drawing.Color.FromArgb(232, 213, 183),
						BackColor = System.Drawing.Color.Transparent,
						Location  = new System.Drawing.Point(70, 22),
						Size      = new System.Drawing.Size(350, 24)
					};
					System.Windows.Forms.Label popMsg = new System.Windows.Forms.Label
					{
						Text      = "UIA 자동화가 실행되는 동안\n키보드·마우스 조작을 잠시 멈춰주세요.",
						Font      = new System.Drawing.Font("Malgun Gothic", 9f),
						ForeColor = System.Drawing.Color.FromArgb(140, 128, 114),
						BackColor = System.Drawing.Color.Transparent,
						Location  = new System.Drawing.Point(70, 50),
						Size      = new System.Drawing.Size(350, 44)
					};
					navigationLoadingForm.Controls.AddRange(new System.Windows.Forms.Control[] {
						popAccent, popIcon, popTitle, popMsg });
					navigationLoadingForm.Show(this);
					navigationLoadingForm.Refresh();
				}
				catch
				{
				}
			}
		}

		private void AutomateExplorerNavigation(string itemId, System.IntPtr hwnd)
		{
			if (itemId != "W-46" && itemId != "W-49") return;
			
			isNavigationActive = true;
			ShowNavigationPopup(itemId);
			System.Threading.ThreadPool.QueueUserWorkItem(delegate
			{
				try
				{
					// 탐색기 창 포커스 및 속성창(Alt+Enter) 호출
					SetForegroundWindow(hwnd);
					System.Threading.Thread.Sleep(300);
					System.Windows.Forms.SendKeys.SendWait("%{ENTER}");
					System.Threading.Thread.Sleep(2000); // 속성 대화상자 로딩 대기
					
					// 새로 열린 속성 대화상자(#32770) 검색
					System.Windows.Automation.AutomationElement propWin = null;
					for (int i = 0; i < 15; i++)
					{
						System.Windows.Automation.AutomationElementCollection wins = System.Windows.Automation.AutomationElement.RootElement.FindAll(
							System.Windows.Automation.TreeScope.Children,
							new System.Windows.Automation.PropertyCondition(System.Windows.Automation.AutomationElement.ClassNameProperty, "#32770"));
						foreach (System.Windows.Automation.AutomationElement w in wins)
						{
							if (w.Current.NativeWindowHandle != (int)this.Handle && w.Current.NativeWindowHandle != (int)hwnd)
							{
								propWin = w;
								break;
							}
						}
						if (propWin != null) break;
						System.Threading.Thread.Sleep(400);
					}
					
					if (propWin != null)
					{
						// 속성 창 전면화
						SetForegroundWindow((System.IntPtr)propWin.Current.NativeWindowHandle);
						System.Threading.Thread.Sleep(300);
						
						// 보안 탭으로 전환 (Ctrl+Tab 2회 내지 3회 송출)
						System.Windows.Forms.SendKeys.SendWait("^{TAB}");
						System.Threading.Thread.Sleep(200);
						System.Windows.Forms.SendKeys.SendWait("^{TAB}");
						System.Threading.Thread.Sleep(500);
					}
				}
				catch (System.Exception ex)
				{
					System.Console.WriteLine("Explorer UIA navigation failed: " + ex.Message);
				}
				finally
				{
					isNavigationActive = false;
					CloseNavigationPopup();
				}
			});
		}

		private void CloseNavigationPopup()
		{
			if (base.InvokeRequired)
			{
				BeginInvoke(new System.Action(CloseNavigationPopup));
			}
			else
			{
				try
				{
					if (navigationLoadingForm != null)
					{
						navigationLoadingForm.Close();
						navigationLoadingForm = null;
					}
				}
				catch
				{
				}
			}
		}

		private bool TryInvokeLegacyDefaultAction(System.Windows.Automation.AutomationElement element)
		{
			try
			{
				System.Windows.Automation.AutomationPattern automationPattern = System.Windows.Automation.AutomationPattern.LookupById(10018);
				object patternObject;
				if (automationPattern != null && element.TryGetCurrentPattern(automationPattern, out patternObject) && patternObject != null)
				{
					System.Reflection.MethodInfo method = patternObject.GetType().GetMethod("DoDefaultAction");
					if (method != null)
					{
						method.Invoke(patternObject, null);
						return true;
					}
				}
			}
			catch
			{
			}
			return false;
		}

		[System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
		private static extern bool SetWindowPos(System.IntPtr hWnd, System.IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);

		[System.Runtime.InteropServices.DllImport("user32.dll")]
		[return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
		private static extern bool GetWindowRect(System.IntPtr hWnd, out KisaAutoPatcher.MainForm.RECT lpRect);

		[System.Runtime.InteropServices.DllImport("user32.dll")]
		[return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
		private static extern bool SetForegroundWindow(System.IntPtr hWnd);

		[System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Auto, SetLastError = true)]
		private static extern System.IntPtr FindWindow(string lpClassName, string lpWindowName);

		[System.Runtime.InteropServices.DllImport("user32.dll")]
		[return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
		private static extern bool EnumWindows(KisaAutoPatcher.MainForm.EnumWindowsProc lpEnumFunc, System.IntPtr lParam);

		[System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Auto)]
		private static extern int GetWindowText(System.IntPtr hWnd, System.Text.StringBuilder lpString, int nMaxCount);

		[System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Auto)]
		private static extern int GetClassName(System.IntPtr hWnd, System.Text.StringBuilder lpClassName, int nMaxCount);

		[System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Auto)]
		private static extern System.IntPtr SendMessage(System.IntPtr hWnd, uint Msg, System.IntPtr wParam, System.IntPtr lParam);

		[System.Runtime.InteropServices.DllImport("user32.dll")]
		private static extern bool ShowWindow(System.IntPtr hWnd, int nCmdShow);

		[System.Runtime.InteropServices.DllImport("user32.dll")]
		private static extern bool SetCursorPos(int X, int Y);

		[System.Runtime.InteropServices.DllImport("user32.dll")]
		private static extern void mouse_event(uint dwFlags, uint dx, uint dy, uint dwData, int dwExtraInfo);

		private void SimulateSingleClick(int x, int y)
		{
			SetCursorPos(x, y);
			System.Threading.Thread.Sleep(50);
			mouse_event(2u, 0u, 0u, 0u, 0);
			mouse_event(4u, 0u, 0u, 0u, 0);
			System.Threading.Thread.Sleep(150);
		}

		private void SimulateDoubleClick(int x, int y)
		{
			SetCursorPos(x, y);
			System.Threading.Thread.Sleep(50);
			mouse_event(2u, 0u, 0u, 0u, 0);
			mouse_event(4u, 0u, 0u, 0u, 0);
			System.Threading.Thread.Sleep(50);
			mouse_event(2u, 0u, 0u, 0u, 0);
			mouse_event(4u, 0u, 0u, 0u, 0);
			System.Threading.Thread.Sleep(150);
		}

		private void AlignTargetWindowToRight(System.IntPtr targetHwnd)
		{
			if (!(targetHwnd == System.IntPtr.Zero))
			{
				ShowWindow(targetHwnd, 9);
				System.Drawing.Rectangle workingArea = System.Windows.Forms.Screen.PrimaryScreen.WorkingArea;
				int num = workingArea.Width / 2;
				int height = workingArea.Height;
				SetWindowPos(targetHwnd, System.IntPtr.Zero, num, 0, num, height, 68u);
			}
		}

		private System.IntPtr GetTargetWindowHandle(string itemId, string appName)
		{
			System.IntPtr intPtr = FindWindowByClassAndTitle("#32770", new string[11]
			{
				"속성",
				"Properties",
				"고급",
				"Advanced",
				"정보",
				"About",
				"ODBC",
				"시간",
				"Time",
				"날짜",
				"Date"
			});
			if (intPtr != System.IntPtr.Zero)
			{
				return intPtr;
			}
			if (activeUIProcess != null)
			{
				try
				{
					activeUIProcess.Refresh();
					if (!activeUIProcess.HasExited)
					{
						System.IntPtr mainWindowHandle = activeUIProcess.MainWindowHandle;
						if (mainWindowHandle != System.IntPtr.Zero)
						{
							return mainWindowHandle;
						}
					}
				}
				catch
				{
				}
			}
			if (itemId == "W-30" || itemId == "W-41" || (appName != null && appName.Contains("ms-settings")))
			{
				System.IntPtr intPtr2 = FindWindowByClassAndTitle("ApplicationFrameWindow", new string[2]
				{
					"설정",
					"Settings"
				});
				if (intPtr2 != System.IntPtr.Zero)
				{
					return intPtr2;
				}
			}
			if (itemId == "W-42" || (appName != null && appName.Contains("windowsdefender")))
			{
				System.IntPtr intPtr3 = FindWindowByClassAndTitle("ApplicationFrameWindow", new string[2]
				{
					"보안",
					"Security"
				});
				if (intPtr3 != System.IntPtr.Zero)
				{
					return intPtr3;
				}
			}
			if (appName != null && (appName.EndsWith(".msc", System.StringComparison.OrdinalIgnoreCase) || appName.Equals("services.msc", System.StringComparison.OrdinalIgnoreCase)))
			{
				System.IntPtr intPtr4 = FindWindow("MMCMainFrame", null);
				if (intPtr4 != System.IntPtr.Zero)
				{
					return intPtr4;
				}
			}
			if (appName != null && appName.Equals("regedit.exe", System.StringComparison.OrdinalIgnoreCase))
			{
				System.IntPtr intPtr5 = FindWindow("RegEdit_RegEdit", null);
				if (intPtr5 != System.IntPtr.Zero)
				{
					return intPtr5;
				}
			}
			if (itemId == "W-20" || (appName != null && appName.Equals("ncpa.cpl", System.StringComparison.OrdinalIgnoreCase)))
			{
				System.IntPtr intPtr6 = FindWindowByClassAndTitle("CabinetWClass", new string[2]
				{
					"네트워크 연결",
					"Network Connections"
				});
				if (intPtr6 != System.IntPtr.Zero)
				{
					return intPtr6;
				}
				System.IntPtr intPtr7 = FindWindow("CabinetWClass", null);
				if (intPtr7 != System.IntPtr.Zero)
				{
					return intPtr7;
				}
			}
			if (itemId == "W-46" || itemId == "W-49")
			{
				System.IntPtr intPtr6 = FindWindowByClassAndTitle("CabinetWClass", new string[3]
				{
					"Config",
					"System32",
					"보안"
				});
				if (intPtr6 != System.IntPtr.Zero)
				{
					return intPtr6;
				}
				System.IntPtr intPtr7 = FindWindow("CabinetWClass", null);
				if (intPtr7 != System.IntPtr.Zero)
				{
					return intPtr7;
				}
			}
			if (itemId == "W-30" || itemId == "W-41" || itemId == "W-42")
			{
				System.IntPtr intPtr2 = FindWindowByClassAndTitle("ApplicationFrameWindow", new string[2]
				{
					"설정",
					"Settings"
				});
				if (intPtr2 != System.IntPtr.Zero)
				{
					return intPtr2;
				}
				System.IntPtr intPtr3 = FindWindowByClassAndTitle("ApplicationFrameWindow", new string[2]
				{
					"보안",
					"Security"
				});
				if (intPtr3 != System.IntPtr.Zero)
				{
					return intPtr3;
				}
			}
			System.IntPtr intPtr8 = FindWindow("MMCMainFrame", null);
			if (intPtr8 != System.IntPtr.Zero)
			{
				return intPtr8;
			}
			System.IntPtr intPtr9 = FindWindow("RegEdit_RegEdit", null);
			if (intPtr9 != System.IntPtr.Zero)
			{
				return intPtr9;
			}
			System.IntPtr intPtr10 = FindWindowByClassAndTitle("ApplicationFrameWindow", new string[2]
			{
				"설정",
				"Settings"
			});
			if (intPtr10 != System.IntPtr.Zero)
			{
				return intPtr10;
			}
			System.IntPtr intPtr11 = FindWindowByClassAndTitle("ApplicationFrameWindow", new string[2]
			{
				"보안",
				"Security"
			});
			if (intPtr11 != System.IntPtr.Zero)
			{
				return intPtr11;
			}
			System.IntPtr intPtr12 = FindWindow("CabinetWClass", null);
			if (intPtr12 != System.IntPtr.Zero)
			{
				return intPtr12;
			}
			return System.IntPtr.Zero;
		}

		[System.Runtime.InteropServices.DllImport("user32.dll")]
		private static extern bool PrintWindow(System.IntPtr hwnd, System.IntPtr hdcBnd, uint nFlags);

		[System.Runtime.InteropServices.DllImport("user32.dll")]
		private static extern System.IntPtr GetWindowDC(System.IntPtr hwnd);

		[System.Runtime.InteropServices.DllImport("user32.dll")]
		private static extern int ReleaseDC(System.IntPtr hwnd, System.IntPtr hdc);

		[System.Runtime.InteropServices.DllImport("gdi32.dll")]
		private static extern bool BitBlt(System.IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, System.IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);

		[System.Runtime.InteropServices.DllImport("dwmapi.dll")]
		private static extern int DwmGetWindowAttribute(System.IntPtr hwnd, int dwAttribute, out KisaAutoPatcher.MainForm.RECT pvAttribute, int cbAttribute);

		private System.IntPtr FindWindowByClassAndTitle(string targetClass, string[] titleKeywords)
		{
			System.IntPtr foundHwnd = System.IntPtr.Zero;
			EnumWindows(delegate(System.IntPtr hwnd, System.IntPtr lParam)
			{
				System.Text.StringBuilder stringBuilder = new System.Text.StringBuilder(256);
				GetClassName(hwnd, stringBuilder, 256);
				if (stringBuilder.ToString().Equals(targetClass, System.StringComparison.OrdinalIgnoreCase))
				{
					System.Text.StringBuilder stringBuilder2 = new System.Text.StringBuilder(256);
					GetWindowText(hwnd, stringBuilder2, 256);
					string text = stringBuilder2.ToString();
					string[] array = titleKeywords;
					string[] array2 = array;
					foreach (string value in array2)
					{
						if (text.IndexOf(value, System.StringComparison.OrdinalIgnoreCase) >= 0)
						{
							foundHwnd = hwnd;
							return false;
						}
					}
				}
				return true;
			}, System.IntPtr.Zero);
			return foundHwnd;
		}

		private void CleanupSpawnedWindows(string itemId)
		{
			if (activeUIProcess != null)
			{
				try
				{
					if (!activeUIProcess.HasExited)
					{
						activeUIProcess.Kill();
					}
				}
				catch
				{
				}
				activeUIProcess = null;
			}
			try
			{
				if (itemId == "W-20")
				{
					// W-20 네트워크 관련 열린 모든 대화상자(#32770) 및 폴더 창(CabinetWClass) 정리
					System.Windows.Automation.AutomationElementCollection wins = System.Windows.Automation.AutomationElement.RootElement.FindAll(
						System.Windows.Automation.TreeScope.Children,
						new System.Windows.Automation.OrCondition(
							new System.Windows.Automation.PropertyCondition(System.Windows.Automation.AutomationElement.ClassNameProperty, "#32770"),
							new System.Windows.Automation.PropertyCondition(System.Windows.Automation.AutomationElement.ClassNameProperty, "CabinetWClass")
						));

					string strProperties = "\uC18D\uC131"; // 속성
					string strAdvanced = "\uACE0\uAE09"; // 고급
					string strStatus = "\uC0C1\uD0DC"; // 상태
					string strNetwork = "\uB2E4\uD2B8\uC6CC\uD06C"; // 네트워크 (네'트워크' 부분 매칭 유니코드: 네트워크 = \uB124\uD2B8\uC601\uD06C 아님, 네=\uB124, 트=\uD2B8, 워=\uC6CC, 크=\uC0AC)
					// 네트워크 유니코드 정확한 정의: 네=\uB124, 트=\uD2B8, 워=\uC6CC, 크=\uD06C. 네트워크 = "\uB124\uD2B8\uC6CC\uD06C"
					string strNetK = "\uB124\uD2B8\uC6CC\uD06C";

					foreach (System.Windows.Automation.AutomationElement w in wins)
					{
						string name = "";
						try { name = w.Current.Name; } catch {}
						string cls = "";
						try { cls = w.Current.ClassName; } catch {}

						bool shouldClose = false;
						if (cls == "#32770")
						{
							if (name.Contains(strProperties) || name.Contains("Properties") || 
								name.Contains(strAdvanced) || name.Contains("Advanced") ||
								name.Contains(strStatus) || name.Contains("Status") ||
								name.Contains("IP"))
							{
								shouldClose = true;
							}
						}
						else if (cls == "CabinetWClass")
						{
							if (name.Contains(strNetK) || name.Contains("Network"))
							{
								shouldClose = true;
							}
						}

						if (shouldClose)
						{
							System.IntPtr hwnd = (System.IntPtr)w.Current.NativeWindowHandle;
							if (hwnd != System.IntPtr.Zero && hwnd != this.Handle)
							{
								SendMessage(hwnd, 16u, System.IntPtr.Zero, System.IntPtr.Zero);
							}
						}
					}
				}
				else
				{
					System.IntPtr targetWindowHandle = GetTargetWindowHandle(itemId, null);
					if (targetWindowHandle != System.IntPtr.Zero)
					{
						SendMessage(targetWindowHandle, 16u, System.IntPtr.Zero, System.IntPtr.Zero);
					}
				}
			}
			catch
			{
			}
			string[] array = new string[4]
			{
				"mmc",
				"regedit",
				"SystemSettings",
				"SecHealthUI"
			};
			string[] array2 = array;
			string[] array3 = array2;
			foreach (string processName in array3)
			{
				try
				{
					System.Diagnostics.Process[] processesByName = System.Diagnostics.Process.GetProcessesByName(processName);
					System.Diagnostics.Process[] array4 = processesByName;
					foreach (System.Diagnostics.Process process in array4)
					{
						try
						{
							process.Kill();
						}
						catch
						{
						}
					}
				}
				catch
				{
				}
			}
		}
	}
	internal static class File
	{
		public static void WriteAllText(string path, string contents, System.Text.Encoding encoding)
		{
			if (!path.EndsWith(".txt", System.StringComparison.OrdinalIgnoreCase))
			{
				System.IO.File.WriteAllText(path, contents, encoding);
			}
		}

		public static void AppendAllText(string path, string contents, System.Text.Encoding encoding)
		{
			if (!path.EndsWith(".txt", System.StringComparison.OrdinalIgnoreCase))
			{
				System.IO.File.AppendAllText(path, contents, encoding);
			}
		}
	}
	public class PowerShellController
	{
		private string scriptDir;

		public PowerShellController(string scriptDir)
		{
			this.scriptDir = scriptDir;
		}

		public System.Collections.ObjectModel.Collection<System.Management.Automation.PSObject> GetVulnerabilityStatus(string configPath)
		{
			return RunScriptInPowerShellHost(delegate(System.Management.Automation.PowerShell ps)
			{
				ps.AddCommand("Import-Module").AddParameter("Name", System.IO.Path.Combine(scriptDir, "Core", "Detector.psm1")).AddParameter("Force", true);
				ps.Invoke();
				ps.Commands.Clear();
				ps.AddCommand("Get-VulnerabilityStatus").AddParameter("ConfigPath", configPath);
				return ps.Invoke();
			});
		}

		public void InvokeRemediation(System.Management.Automation.PSObject vulnerabilityResult, string backupDir, string evidenceDir)
		{
			RunScriptInPowerShellHost(delegate(System.Management.Automation.PowerShell ps)
			{
				ps.AddCommand("Import-Module").AddParameter("Name", System.IO.Path.Combine(scriptDir, "Core", "Remediation.psm1")).AddParameter("Force", true);
				ps.Invoke();
				ps.Commands.Clear();
				ps.AddCommand("Invoke-Remediation").AddParameter("VulnerabilityResults", new System.Management.Automation.PSObject[1]
				{
					vulnerabilityResult
				}).AddParameter("BackupDir", backupDir)
					.AddParameter("EvidenceDir", evidenceDir);
				return ps.Invoke();
			});
		}

		public void InvokeReporting(System.Collections.ObjectModel.Collection<System.Management.Automation.PSObject> initialResults, System.Collections.ObjectModel.Collection<System.Management.Automation.PSObject> finalResults, string reportDir, string evidenceDir)
		{
			RunScriptInPowerShellHost(delegate(System.Management.Automation.PowerShell ps)
			{
				ps.AddCommand("Import-Module").AddParameter("Name", System.IO.Path.Combine(scriptDir, "Core", "Reporter.psm1")).AddParameter("Force", true);
				ps.Invoke();
				ps.Commands.Clear();
				ps.AddCommand("Invoke-Reporting").AddParameter("InitialResults", initialResults).AddParameter("FinalResults", finalResults)
					.AddParameter("ReportDir", reportDir)
					.AddParameter("EvidenceDir", evidenceDir);
				return ps.Invoke();
			});
		}

		private System.Collections.ObjectModel.Collection<System.Management.Automation.PSObject> RunScriptInPowerShellHost(System.Func<System.Management.Automation.PowerShell, System.Collections.ObjectModel.Collection<System.Management.Automation.PSObject>> action)
		{
			System.Management.Automation.Runspaces.InitialSessionState initialSessionState = System.Management.Automation.Runspaces.InitialSessionState.CreateDefault();
			initialSessionState.ExecutionPolicy = Microsoft.PowerShell.ExecutionPolicy.Bypass;
			using (System.Management.Automation.Runspaces.Runspace runspace = System.Management.Automation.Runspaces.RunspaceFactory.CreateRunspace(initialSessionState))
			{
				runspace.Open();
				using (System.Management.Automation.PowerShell powerShell = System.Management.Automation.PowerShell.Create())
				{
					powerShell.Runspace = runspace;
					
					// 파워쉘 인코딩 환경 전역 강제 지정
					powerShell.AddScript("[Console]::OutputEncoding = [System.Text.Encoding]::UTF8");
					powerShell.AddScript("$OutputEncoding = [System.Text.Encoding]::UTF8");
					powerShell.Invoke();
					powerShell.Commands.Clear();
					
					return action(powerShell);
				}
			}
		}
	}
	internal static class Program
	{
		[System.Runtime.InteropServices.DllImport("user32.dll")]
		private static extern bool SetProcessDPIAware();

		[System.STAThread]
		private static void Main()
		{
			try
			{
				SetProcessDPIAware();
			}
			catch {}

			if (!IsRunAsAdmin())
			{
				try
				{
					System.Diagnostics.ProcessStartInfo processStartInfo = new System.Diagnostics.ProcessStartInfo();
					processStartInfo.UseShellExecute = true;
					processStartInfo.WorkingDirectory = System.Environment.CurrentDirectory;
					processStartInfo.FileName = System.Windows.Forms.Application.ExecutablePath;
					processStartInfo.Verb = "runas";
					System.Diagnostics.Process.Start(processStartInfo);
				}
				catch (System.Exception ex)
				{
					System.Windows.Forms.MessageBox.Show("이 프로그램은 관리자 권한이 필요합니다: " + ex.Message, "권한 필요", System.Windows.Forms.MessageBoxButtons.OK, System.Windows.Forms.MessageBoxIcon.Exclamation);
				}
				return;
			}
			System.Windows.Forms.Application.EnableVisualStyles();
			System.Windows.Forms.Application.SetCompatibleTextRenderingDefault(defaultValue: false);
			System.Windows.Forms.Application.Run(new KisaAutoPatcher.MainForm());
		}

		private static bool IsRunAsAdmin()
		{
			try
			{
				System.Security.Principal.WindowsIdentity current = System.Security.Principal.WindowsIdentity.GetCurrent();
				System.Security.Principal.WindowsPrincipal windowsPrincipal = new System.Security.Principal.WindowsPrincipal(current);
				return windowsPrincipal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
			}
			catch
			{
				return false;
			}
		}
	}
}
