# KISA

Windows 보안 가이드의 설정값 진단·조치와 화면 증빙을 함께 수행하는 프로그램입니다.

## 실행 흐름

스캔 → 대상 관리 창 열기 → 오른쪽 정렬 확인 → 조치·값 재조회 → 증빙 대상 탐색·캡처 → 창 닫힘 확인 → 다음 항목.

- 설정 변경은 지원되는 레지스트리·Secedit·PowerShell API로 수행합니다. 화면 클릭 결과만으로 양호를 판정하지 않습니다.
- 오른쪽 정렬에 실패하면 해당 항목의 변경을 시작하지 않습니다. 캡처 실패 시에도 창 정리를 시도합니다. 창이 남으면 다음 항목을 중단합니다.
- MMC 속성 창은 본창과 소유자 연결이 없어도 이번에 실행한 MMC 프로세스와 정확한 정책 제목으로 찾습니다. 속성 창을 먼저 닫고 창 목록을 다시 조회한 뒤 본창을 닫습니다. 속성 창 종료에 실패하면 본창에 닫기 요청을 보내지 않습니다.
- 속성 창이 일반 닫기 요청에 응답하지 않으면 해당 창의 취소 명령으로 닫기를 시도합니다. 종료 과정에서 확인/적용 버튼을 누르지는 않으므로, 수동 입력값은 캡처 진행 전에 직접 적용해야 합니다.
- 화면보호기 등 열린 시점의 값을 유지하는 설정 창은 변경 후 닫았다가 다시 열어 최신 값을 표시합니다.
- 복합 항목은 조치를 한 번 수행하고 설정별로 캡처합니다. 각 캡처 사이에 창을 닫습니다.
- 같은 단일 실행 관리 앱이 이미 열려 있으면 해당 항목은 오류로 남깁니다. 기존 사용자 창을 임의로 닫거나 재사용하지 않습니다.
- 실제 변경 지원 범위는 정책 파일 65개 중 24개입니다. 업무별 계정·서비스·접속 규칙 판단이 필요한 항목을 전부 자동 변경하지는 않습니다.

## Windows 빌드

압축을 푼 뒤 `Security Project - 복사본/KISA-AutoPatcher-Python` 폴더에서 실행합니다.

```powershell
py -m pip install -r requirements.txt pyinstaller
py -m PyInstaller --clean --noconfirm --onefile --noconsole --name KISA-AutoPatcher --add-data "config;config" --collect-all customtkinter --collect-all uiautomation main.py
```

결과: `dist/KISA-AutoPatcher.exe`. 관리자 권한으로 실행합니다. 이전 EXE를 재실행하면 수정 코드가 적용되지 않습니다.

증빙은 `dist/evidence/실행ID/`에 PNG·JSON·로그·보고서로 저장합니다. JSON의 `ExecutionStages`에서 어느 단계까지 진행됐는지 확인할 수 있습니다. 창 정리 실패 전 저장된 이미지도 해시와 오류를 함께 남깁니다.

## 검증 범위

Linux에서 모의 Windows API를 사용한 회귀 테스트 65개와 문법 검사를 통과했습니다. 소유자 연결 없는 MMC 속성 창, 속성 창 종료 실패 시 본창 보호, 종료 중 새 대화상자 출현, 취소 명령 대체 경로를 포함합니다. 실제 Windows UI 및 EXE 검증은 별도로 필요합니다. 테스트 PC에서 W-01 → W-02 전환, W-08 두 설정, W-47 변경 후 화면, 오른쪽 정렬, 항목 사이 창 종료를 확인한 뒤 운영 장비에 적용하세요.

구현 참고: Microsoft [EnumWindows](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumwindows), [WM_CLOSE](https://learn.microsoft.com/en-us/windows/win32/winmsg/wm-close).

이전 증빙 52개의 기준 대조 결과는 [검토 문서](EVIDENCE_REVIEW_20260911.md)에 있습니다.
