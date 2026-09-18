# Windows 실행 피드백 반영 — 20260911-feedback-2

실행 흐름: 스캔 → 대상 창 오른쪽 배치 → 조치·재조회 → 대상 확인·캡처 → 종료 확인 → 다음 항목.
기존 fix/evidence-verification 브랜치에 적용하며 main과 기존 EXE는 자동 갱신되지 않는다.

| 항목 | 변경 및 검증 범위 |
|---|---|
| W-26 | IIS 생략 선택 시 조치·캡처 모두 생략 목록에 포함. 미사용 검증 판정과 구분. |
| W-28 | 실제 조치하는 RDP-Tcp/MinEncryptionLevel 경로 확인 후 캡처. 도메인 유효 GPO 검토 별도. |
| W-35 | 공백 없는 ODBC 관리자(64비트) 제목 인식과 Windows 입력 스레드 연결을 통한 포커스 획득 보완. |
| W-36 | 실제 MaxIdleTime 정책 레지스트리 경로와 값 확인 후 캡처. |
| W-40 | Model.pdf p.236의 6개 감사 범주를 유효 고급 감사 하위 범주에 적용. 기존 성공/실패 비트 보존, 고급 감사 우선 설정 포함 백업·실패 시 복원. 도메인 변경 제한 유지. |
| W-49 | USER_RIGHTS의 SeRemoteShutdownPrivilege 실제 원문과 Administrators SID 비교를 전용 창에 표시. 권한 목록은 자동 변경하지 않음. |
| W-56 | 두 설정 개별 PNG 및 합친 대표 PNG 저장. 개수 검증·보고서 전체 파일 링크. |
| W-57 | 제목 Warning!, 본문 관리자외 접근을 허용하지 않습니다. 정확히 일치해야 양호로 판정. |
| W-62 | 작업 관리자 시작프로그램 탭 진입 및 시작 영향 열 확인. 프로세스 탭 대체 캡처 금지. |
| W-63 | w32tm source/status/peers/configuration, 실제 원본 stripchart 3개 샘플과 반환 코드·원문 저장. 응답과 최근 동기화 상태 구분. |
| 레지스트리 | 주소창 입력과 별도로 상태 표시줄 실제 선택 키 확인. 경로가 다르면 캡처 실패. |

## 감사 범위
Model.pdf p.236: 계정 관리·디렉터리 서비스 액세스는 실패, 계정 로그온·권한 사용·로그온·정책 변경은 성공/실패 감사.
해당 현대 Windows 범주의 하위 범주를 적용하고 다른 범주는 변경하지 않는다.
로그 발생량·보존 용량은 운영 환경에서 검토해야 한다.
고급 감사 유효값이 기준이며 기본 감사 대화상자에 같은 값이 표시된다는 보장은 하지 않는다.

## 증빙
W-40/W-49/W-63은 실제 명령/API 조회 결과를 표시하는 전용 창을 우측 배치하여 페이지별 캡처한다.
Windows 설정 창을 모사하지 않는다. 원본은 항목명_diagnostic.json이며 증빙 JSON에 해시를 기록한다.
NTP 응답만으로 동기화 이력 또는 Model.pdf W-63의 Kerberos 허용 오차 적합 판정을 하지 않는다.
NTP 원본을 임의의 공용 서버로 바꾸거나 시계를 강제 변경하지 않는다.
W-49·W-63은 수동 판정을 유지한다.

## 실행 확인
새 브랜치 ZIP의 KISA-AutoPatcher-Python 폴더에서 build.ps1을 실행하거나 아래 명령을 사용한다.

    py -m pip install -r requirements.txt pyinstaller
    py -m PyInstaller --clean --noconfirm --onefile --noconsole --uac-admin --name KISA-AutoPatcher --add-data "config;config" --collect-all customtkinter --collect-all uiautomation main.py

로그 버전 20260911-feedback-2를 확인한다.
W-26은 IIS 생략 시 창이 열리지 않아야 하며 W-56 대표 이미지에는 두 화면이 있어야 한다.
W-28/W-36 경로·값 이름, W-62 시작 영향 열, W-63 실제 원본·응답·최근 성공 시각을 확인한다.
본 환경에서는 Windows 실기 및 EXE 빌드를 수행하지 않았다. 모의 회귀 테스트는 실기 검증을 대신하지 않는다.

## 구현 근거
- [감사 범주 GUID](https://learn.microsoft.com/en-us/windows/win32/secauthz/auditing-constants)
- [유효 감사 조회](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-auditquerysystempolicy)
- [감사 적용 및 권한](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-auditsetsystempolicy)
- [감사 플래그: 0은 변경 없음, 4는 감사 없음](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-audit_policy_information)
- [Windows 시간 서비스 진단](https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings)
- [입력 스레드 연결](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-attachthreadinput)
