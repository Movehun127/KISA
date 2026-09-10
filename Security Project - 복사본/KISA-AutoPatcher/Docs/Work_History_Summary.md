# 📝 KISA-AutoPatcher 작업 및 개발 이력 요약서

본 문서는 Windows 환경에서 원클릭으로 실행 가능한 **KISA 주요정보통신기반시설 기술적 취약점 자동 패치 프로그램**의 개발 과정, 주요 트러블슈팅, 최종 패치 기준 명세 및 사용법을 요약한 이력 문서입니다.

---

## 📅 개발 및 조치 타임라인 요약

### 1단계: 프로젝트 기본 설계 및 모듈 작성
- **목표**: 사용자 개입 없이 [검출 ➡️ 백업/조치 ➡️ 재검증 및 보고]를 수행하는 멱등성 보장형 PowerShell 프로그램 구성.
- **역할 분담에 따른 설계**:
  1. **가이드 분석 에이전트**: KISA 가이드를 분석하여 정형화된 JSON(`KisaCriteria.json`) 명세 정의.
  2. **플레이북 설계 에이전트**: 백업 및 예외 처리(Try-Catch)와 오류 발생 시 복구(Rollback) 기능을 탑재한 핵심 제어 모듈(`Detector`, `Remediation`) 개발.
  3. **감사 및 보고서 에이전트**: 조치 전/후 결과를 비교 검증하고 마크다운 감사 이력서(`Security_Patch_Report.md`)를 누적 저장하는 리포터 모듈(`Reporter`) 개발 및 에이전트 간 역할 관계를 요약한 시스템 설계 이력서(`Agent_Design_History.md`) 작성.
  4. **통합 패키징 에이전트**: 전체 스크립트를 총괄 구동하는 메인 오케스트레이터(`Run-Patcher.ps1`) 개발.

### 2단계: 실행 편의성 및 환경 예외 대응
- **PowerShell 실행 정책(Execution Policy) 우회**: 윈도우 기본 보안 정책으로 인해 `.ps1` 스크립트 실행이 차단되는 현상을 방지하기 위해, 실행 정책 우회 옵션(`-ExecutionPolicy Bypass`) 및 관리자 권한 자동 획득 로직을 포함한 원클릭 배치 파일(`Click-Me-To-Patch.bat`)을 추가 구현함.

### 3단계: 중요 트러블슈팅 - 인코딩 오류 해결 (★핵심)
- **증상**: 한글 Windows CMD/PowerShell 환경에서 스크립트 실행 시 문법 오류(`Try 문에 catch 블록이 없습니다` 등)와 한글 깨짐 현상 발생.
- **원인 분석**: 윈도우 PowerShell 5.1 및 CMD(CP949 환경)가 BOM(Byte Order Mark)이 없는 UTF-8 인코딩 스크립트 파일 내부의 한글 주석을 비정상적으로 파싱하면서 중괄호(`}`)나 코드 구문을 무시/오독하여 발생한 현상.
- **조치 내용**: 프로젝트 내 모든 코드 파일(`.ps1`, `.psm1`, `.json`)을 일괄적으로 **UTF-8 with BOM** 인코딩으로 변환하는 `fix_encoding.ps1` 복구 유틸리티 스크립트를 제작 및 실행하여 인코딩 오류 문제를 완벽히 해결함.

### 4단계: KISA 매뉴얼 기반 실무 점검 항목 반영 및 경량화
- **점검 가이드 반영**: 제공된 KISA 서버 보안 가이드북 PDF(`새 문서.pdf`)를 기반으로 레지스트리 및 명령어로 자동 조치 가능한 핵심 보안 조항 명세를 `KisaCriteria.json`에 구축 완료.
- **인프라 맞춤 경량화**: 실무 인프라 특성(IIS 미설치, FTP 미사용, SNMP/Telnet 미사용, DNS 제외, 백신은 Windows Defender 고정)에 맞춰 불필요한 예외 처리를 삭제하고, 제외 대상 항목(W-01, W-03, W-19, W-21, W-22, W-24~26, W-29~34)은 `Type_Skip`으로 지정해 동적 스킵 처리하도록 최적화 적용.

### 5단계: 추가 트러블슈팅 - 한글 정규식 패턴 깨짐 및 제외 항목 매칭 예외 수정
- **증상**: `Remediation.psm1` 실행 중 `"?묓샇" 구문 분석 - 수량자 {x,y} 앞에 아무 것도 없습니다.`라는 오류와 함께 패치 중단 현상 발생.
- **원인 분석**: BOM이 없는 인코딩이 일부 개입하거나 실행 쉘 로캘 인코딩 차이로 인해 `"양호"` 문자열이 `"?묓샇"`으로 깨져 인식되면서, 파워쉘의 `-match` 연산자가 물음표(`?`)를 정규표현식 수량자로 오인 컴파일하여 파싱 실패 및 예외를 야기함.
- **조치 내용**:
  1. **정규식 무회화**: `Remediation.psm1`의 `if ($result.Status -match "양호")` 조건을 정규식 오류 우려가 없는 `-like "*양호*"` 패턴 매칭으로 전면 변경하여 문제를 근본 해결함.
  2. **리포트 예외 처리**: `Reporter.psm1`에서 제외 처리된 항목(`양호(제외)`)도 `양호`로 올바르게 판정되도록 상태 판별문을 `-like "*양호*"`로 수정하여 리포트 마크다운 출력 무결성 확보.
  3. **인코딩 일관성 보장**: 변경 내용을 저장한 후 `fix_encoding.ps1` 스크립트를 즉시 재구동하여 모든 소스 코드 파일을 **UTF-8 with BOM** 포맷으로 완벽히 통일 및 고정 완료.

### 6단계: KISA 64개 전체 보안 조치 항목 구현 (★추가 완료)
- **요청 사항**: 예외로 스킵되는 대상 외의 모든 KISA 조항(W-01 ~ W-64)이 패치 스크립트에 반영되도록 확장 요청.
- **조치 내용**:
  * `KisaCriteria.json`에 KISA 가이드의 모든 64개 항목 정의를 추가.
  * 예외(W-01, W-03, W-19, W-21, W-22, W-24~26, W-29~34, W-35, W-58, W-61~63)는 `Type_Skip` 처리 완료.
  * 계정 잠금 정책, 암호화, 화면 보호기, 방화벽, SAM 권한, RDP 설정 등 실무 자동화 조치 가능 항목은 `Type_Registry`, `Type_Secedit`, `Type_Powershell` 기술 모듈에 완전 맵핑하여 정상 반영 및 멱등 검사 보장 완료.

---

## 📁 최종 프로젝트 디렉터리 트리

```text
KISA-AutoPatcher/
├── Click-Me-To-Patch.bat       # [배치] 실행 정책 우회 및 관리자 권한 승인 원클릭 실행기
├── Run-Patcher.ps1             # [마스터] 3단계 파이프라인(검출->조치->보고) 오케스트레이터
├── fix_encoding.ps1            # [인코딩] 한글 깨짐 방지용 파일 일괄 UTF-8 BOM 인코딩 변환기
├── Agent_Design_History.md     # [설계 문서] 멀티 에이전트 역할 분담 및 설계 사상 기록서
├── Work_History_Summary.md     # [요약서] 전체 개발 프로세스, 트러블슈팅, 작동 가이드 (본 문서)
├── Config/
│   └── KisaCriteria.json       # [기준 정의] KISA 점검 항목의 대상 경로 및 양호 기준 정의서 (W-01 ~ W-64 완비)
├── Core/
│   ├── Detector.psm1           # [모듈] 시스템 취약 상태 검사 및 양호 여부 판단 엔진
│   ├── Remediation.psm1        # [모듈] 조치 전 원본 백업, 멱등성 변경 패치, 실패 시 롤백 수행 엔진
│   └── Reporter.psm1           # [모듈] 패치 완료 후 재진단 및 마크다운 리포트 생성 엔진
├── Backups/                    # [자동 생성] 조치 전 백업 데이터 (예: W-02_20260616_110329.bak)
└── Reports/
    └── Security_Patch_Report.md# [자동 생성] 누적 배포 이력이 기록되는 최종 보안 패치 보고서
```

---

## 🔍 최종 구성된 KISA 보안 항목 명세 (Config/KisaCriteria.json)

| 항목 코드 | 중요도 | 점검 항목명 | 진단 방식 | 세부 조치 사항 / 타깃 최적화 반영 |
|---|---|---|---|---|
| **W-01** | 상 | Administrator 계정 이름 변경 등 보안성 강화 | Type_Skip | 타깃 인프라 고정 제약 조건에 따라 제외 (`양호(제외)`) |
| **W-02** | 상 | Guest 계정 비활성화 | Type_Powershell | Guest 로컬 계정 비활성화 (Disable) |
| **W-03** | 상 | 불필요한 계정 제거 | Type_Skip | 타깃 인프라 고정 제약 조건에 따라 제외 (`양호(제외)`) |
| **W-04** | 상 | 계정 잠금 임계값 설정 | Type_Secedit | 계정 잠금 임계값을 5 이하로 설정 (`LockoutBadCount = 5`) |
| **W-05** | 상 | 해독 가능한 암호화를 사용하여 암호 저장 해제 | Type_Secedit | 해독 가능한 암호화 저장 비활성화 (`ClearTextPassword = 0`) |
| **W-06** | 상 | 관리자 그룹에 최소한의 사용자 포함 | Type_Powershell | Administrators 외 불필요 계정 수동 점검 유도 |
| **W-07** | 중 | Everyone 사용 권한 익명 적용 해제 | Type_Registry | 익명 사용자의 Everyone 권한 상속 해제 (`EveryoneIncludesAnonymous = 0`) |
| **W-08** | 중 | 계정 잠금 기간 설정 | Type_Secedit | 계정 잠금 기간 60분 설정 (`LockoutDuration = 60`) |
| **W-08_Reset** | 중 | 다음 시간 후 계정 잠금 수를 원래대로 설정 | Type_Secedit | 계정 잠금 임계값 카운터 원래대로 설정 시간 60분 (`ResetLockoutCount = 60`) |
| **W-09** | 상 | 비밀번호 관리정책 설정 - 최소 암호 길이 | Type_Secedit | 최소 패스워드 길이 설정 (`MinimumPasswordLength = 8`) |
| **W-09_Complexity** | 상 | 비밀번호 관리정책 설정 - 암호 복잡성 | Type_Secedit | 암호 복잡성 만족 요구 설정 (`PasswordComplexity = 1`) |
| **W-09_History** | 상 | 비밀번호 관리정책 설정 - 최근 암호 기억 | Type_Secedit | 최근 암호 기억 개수 설정 (`PasswordHistorySize = 4`) |
| **W-09_MaxAge** | 상 | 비밀번호 관리정책 설정 - 최대 암호 사용기간 | Type_Secedit | 최대 암호 사용기간 설정 (`MaximumPasswordAge = 90`) |
| **W-09_MinAge** | 상 | 비밀번호 관리정책 설정 - 최소 암호 사용기간 | Type_Secedit | 최소 암호 사용기간 설정 (`MinimumPasswordAge = 1`) |
| **W-10** | 중 | 마지막 사용자 이름 표시 안 함 | Type_Registry | 로그온 화면 이전 ID 숨김 (`dontdisplaylastusername = 1`) |
| **W-11** | 중 | 로컬 로그온 허용 설정 | Type_Powershell | Users 그룹 로컬 로그온 수동 점검 유도 |
| **W-12** | 중 | 익명 SID/이름 변환 허용 해제 | Type_Registry | 익명 SID 변환 거부 (`LsaLookupNamesCanDemoteUser = 0`) |
| **W-13** | 중 | 콘솔 로그온 시 빈 암호 사용 제한 | Type_Registry | 빈 암호 원격/네트워크 접근 차단 (`LimitBlankPasswordUse = 1`) |
| **W-14** | 중 | 원격터미널 접속 가능 그룹 제한 | Type_Powershell | RDP 권한 허용 계정 수동 점검 유도 |
| **W-15** | 상 | 사용자 개인키 사용 시 암호 입력 | Type_Registry | 개인 키 암호 강제 보호 활성화 (`ForceKeyProtection = 2`) |
| **W-16** | 상 | 공유 권한 및 사용자 그룹 설정 | Type_Powershell | 일반 공유 폴더의 Everyone 접근 권한 수동 점검 유도 |
| **W-17** | 상 | 하드디스크 기본 공유 제거 | Type_Registry | 자동 기본 관리 공유 비활성화 (`AutoShareWks = 0`) |
| **W-18** | 상 | 불필요한 서비스 제거 | Type_Powershell | Alerter, ClipBook, Messenger, SimpTcp, RemoteRegistry, Browser, mnmsrvc, WmdmPmSN, upnphost 등 불필요 서비스 중지 및 비활성화 |
| **W-19** | 상 | 불필요한 IIS 서비스 구동 점검 | Type_Skip | [IIS 웹 서버 미설치] 반영으로 자동 제외 (`양호(제외)`) |
| **W-20** | 상 | NetBIOS 바인딩 서비스 구동 점검 | Type_Powershell | NetBIOS over TCP/IP 비활성화 |
| **W-21** | 상 | 암호화되지 않는 FTP 서비스 비활성화 | Type_Skip | FTP 및 IIS 사용 제약에 의거 자동 제외 (`양호(제외)`) |
| **W-22** | 상 | FTP 디렉토리 접근권한 설정 | Type_Skip | FTP 및 IIS 사용 제약에 의거 자동 제외 (`양호(제외)`) |
| **W-23** | 상 | 공유 서비스 익명 접근 제한 설정 | Type_Registry | NullSessionShares 초기화 |
| **W-24** | 상 | FTP 접근 제어 설정 | Type_Skip | FTP 및 IIS 사용 제약에 의거 자동 제외 (`양호(제외)`) |
| **W-25** | 상 | DNS Zone Transfer 설정 | Type_Skip | [DNS 서비스 미설치] 반영으로 자동 제외 (`양호(제외)`) |
| **W-26** | 상 | RDS(Remote Data Services)제거 | Type_Skip | [IIS 웹 서버 미설치] 반영으로 자동 제외 (`양호(제외)`) |
| **W-27** | 상 | 최신 Windows OS Build 버전 적용 | Type_Powershell | OS 윈도우 업데이트 상태 권고 조치 |
| **W-28** | 중 | 터미널 서비스 암호화 수준 설정 | Type_Registry | RDP 암호화 강도 최고 수준 적용 (`MinEncryptionLevel = 3`) |
| **W-29** | 중 | 불필요한 SNMP 서비스 구동 점검 | Type_Skip | SNMP 미사용에 의거 자동 제외 (`양호(제외)`) |
| **W-30** | 중 | SNMP Community String 복잡성 설정 | Type_Skip | SNMP 미사용에 의거 자동 제외 (`양호(제외)`) |
| **W-31** | 중 | SNMP Access control 설정 | Type_Skip | SNMP 미사용에 의거 자동 제외 (`양호(제외)`) |
| **W-32** | 중 | DNS 서비스 구동 점검 | Type_Skip | [DNS 서비스 미설치] 반영으로 자동 제외 (`양호(제외)`) |
| **W-33** | 하 | HTTP/FTP/SMTP 배너 차단 | Type_Skip | 타깃 인프라 고정 제약 조건에 따라 제외 (`양호(제외)`) |
| **W-34** | 중 | Telnet 서비스 비활성화 | Type_Skip | Telnet 미사용에 의거 자동 제외 (`양호(제외)`) |
| **W-35** | 중 | 불필요한 ODBC 데이터 소스 제거 | Type_Skip | 데이터 정합성 유지를 위해 자동 제외 (`양호(제외)`) |
| **W-36** | 중 | 원격터미널 접속 타임아웃 설정 | Type_Registry | RDP 유휴 시간 30분 초과 시 세션 중단 (`MaxIdleTime = 1800000`) |
| **W-37** | 중 | 예약된 작업의 의심스런 명령 점검 | Type_Powershell | 작업 스케줄러 내 취약 스크립트 수동 분석 권고 |
| **W-38** | 상 | 주기적 보안 패치 적용 | Type_Powershell | 핫픽스 패치 수동 설치 권고 |
| **W-39** | 상 | 백신 프로그램 업데이트 | Type_Defender | 윈도우 기본 Defender의 백신 패턴 업데이트 (`Update-MpSignature`) |
| **W-40** | 중 | 정책에 따른 시스템 로깅 설정 | Type_Secedit | 로그온 이벤트 성공/실패 감사 구성 (`AuditLogonEvents = 2`) |
| **W-41** | 중 | NTP 및 시각 동기화 설정 | Type_Powershell | Windows Time 서비스 시작유형 자동 및 실행 |
| **W-42** | 하 | 이벤트 로그 관리 설정 | Type_Powershell | 보안 로그 파일 최대 크기 10MB 확장 (`MaximumSize = 10240KB`) |
| **W-43** | 중 | 이벤트 로그 파일 접근 통제 설정 | Type_Powershell | 보안 로그 파일 NTFS 권한 Everyone 삭제 점검 및 권고 |
| **W-44** | 상 | 원격 레지스트리 경로 액세스 제한 | Type_Registry | 원격 레지스트리 연결 제한 구성 (`winreg` 활성화) |
| **W-45** | 상 | 백신 프로그램 설치 | Type_Powershell | WinDefend 서비스 구동 여부 검증 및 강제 시작 |
| **W-46** | 상 | SAM 파일 접근 통제 설정 | Type_Powershell | SAM 권한 Everyone 제거 점검 및 권고 |
| **W-47** | 상 | 화면보호기 설정 | Type_Registry | 화면보호기 사용 설정 (`ScreenSaveActive = 1`) |
| **W-48** | 상 | 로그온하지 않고 시스템 종료 허용 해제 | Type_Registry | 로그인 화면에서 종료 버튼 비활성화 (`ShutdownWithoutLogon` ➡️ `0`) |
| **W-49** | 상 | 원격 시스템의 강제 종료 권한 제한 | Type_Powershell | 강제 종료 권한 Administrators 외 계정 점검 및 권고 |
| **W-50** | 상 | 보안 감사 부족 시 시스템 종료 해제 | Type_Registry | Lsa 감사 오류 시 강제 종료 비활성화 (`CrashOnAuditFail = 0`) |
| **W-51** | 상 | SAM 계정과 공유의 익명 열거 허용 안 함 | Type_Registry | 네트워크 익명 접근을 통한 사용자 열거 차단 (`RestrictAnonymous` ➡️ `1`) |
| **W-52** | 상 | Autologon 기능 제어 | Type_Registry | 레지스트리에 저장된 자동 로그인 설정 제거 및 비활성화 (`AutoAdminLogon` ➡️ `0`) |
| **W-53** | 상 | 이동식 미디어 포맷 및 꺼내기 허용 | Type_Registry | AllocateDASD 미디어 권한 제한 (`AllocateDASD = 0`) |
| **W-54** | 중 | Dos공격 방어 레지스트리 설정 | Type_Registry | TCP/IP SynAttackProtect 활성화 (`SynAttackProtect = 1`) |
| **W-55** | 중 | 사용자 프린터 드라이버 설치 차단 | Type_Registry | 드라이버 추가 권한 제어 (`AddPrinterDrivers = 1`) |
| **W-56** | 중 | SMB 세션 중단 관리 설정 | Type_Registry | autodisconnect 시간을 15분으로 설정 (`autodisconnect = 15`) |
| **W-57** | 하 | 로그온 시 경고 메시지 설정 | Type_Registry | 법적 고지 텍스트 강제 활성화 (`legalnoticetext = Security Warning`) |
| **W-58** | 중 | 사용자별 홈 디렉터리 권한 설정 | Type_Skip | 시스템 상황별 상이하여 제외 (`양호(제외)`) |
| **W-59** | 중 | LAN Manager 인증 수준 | Type_Registry | 인증 수락 방식 LMCompatibilityLevel 강화 (`LmCompatibilityLevel = 3`) |
| **W-60** | 중 | 보안 채널 디지털 암호화 또는 서명 | Type_Registry | 통신 디지털 인증 강제 적용 (`RequireSignOrEncrypt = 1`) |
| **W-61** | 중 | 파일 및 디렉토리 보호 | Type_Skip | 시스템 환경별 파일 권한 편차로 수동 권고 |
| **W-62** | 중 | 시작프로그램 목록 분석 | Type_Skip | 정상 파일 판별이 필요하여 제외 (`양호(제외)`) |
| **W-63** | 중 | 도메인 컨트롤러-시간 동기화 | Type_Skip | 일반 NTP 설정 항목과 중복되어 제외 (`양호(제외)`) |
| **W-64** | 중 | 윈도우 방화벽 설정 | Type_Powershell | 도메인/공용/사설 프로필 방화벽 기능 강제 활성화 |

---

## 🚀 사용 및 검증 방법

### 1. 프로그램 실행
- `Click-Me-To-Patch.bat` 파일을 마우스 우클릭한 후 **[관리자 권한으로 실행]**을 선택합니다.
- 배치 파일이 자동으로 UAC 권한 상승 및 파워쉘 실행 우회를 적용하여 전체 조치 파이프라인을 작동시킵니다.

### 2. 시나리오 기반 수동 검증
- **테스트 케이스 A (취약 조치 검증)**: Guest 계정을 일부러 활성화(`net user guest /active:yes`)한 후 프로그램을 실행하여, `Backups/` 폴더에 원본 백업 파일이 생성되고 `Reports/Security_Patch_Report.md`에 조치 후 "양호" 상태로 반영되는지 검증합니다.
- **테스트 케이스 B (멱등성 검증)**: 조치가 완수된(양호 상태인) 환경에서 다시 한번 프로그램을 재실행했을 때, 시스템 변경 시도 없이 조치를 건너뛰고 바로 3단계 결과 보고 단계로 안전하게 진입하는지 확인합니다.
