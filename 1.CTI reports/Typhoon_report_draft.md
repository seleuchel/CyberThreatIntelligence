# Volt Typhoon APT 위협 인텔리전스 분석 보고서

**분류:** TLP:WHITE  
**작성일:** 2026년 6월  
**출처:** CISA Advisory AA24-038A  
**작성자:** [이름]

---

## 1. 개요 (Executive Summary)

미국 CISA·NSA·FBI의 공동 평가에 따르면, 중국 정부의 지원을 받는 사이버 위협 행위자 **Volt Typhoon**은 미국 핵심 기반시설 내 사전 거점 확보(Pre-positioning)를 목표로 활동하고 있다. 이들의 최종 목적은 유사시 파괴적 사이버 공격을 수행하기 위한 장기적 잠복이다.

**핵심 특징:**
- 정상 시스템 도구만 사용하는 LOTL(Living off the Land) 기법
- 장기간 탐지 회피를 위한 은밀한 침투 유지
- 군사·외교적 긴장 고조 시 활용 가능한 파괴적 공격 역량 준비

---

## 2. 위협 행위자 프로파일

| 항목 | 내용 |
|------|------|
| 명칭 | Volt Typhoon (Bronze Silhouette, Vanguard Panda) |
| 국적 | 중국 (정부 지원 추정) |
| 활동 시기 | 최소 2021년부터 확인 |
| 주요 목표 | 미국 핵심 기반시설 |
| 동기 | 사전 거점 확보 / 유사시 파괴적 공격 준비 |

---

## 3. 피해 대상 섹터

CISA 어드바이저리 기준 주요 피해 섹터:

- **Communications** — 통신 인프라
- **Energy** — 에너지 (전력·가스)
- **Transportation Systems** — 교통 시스템
- **Water and Wastewater Systems** — 수자원

### 한국 내 유사 위협 대상 (Korea Context)

미국과 동일한 섹터 분류 기준을 적용하면, 한국의 주요 위협 노출 기관은 다음과 같다:

| 섹터 | 한국 주요 기관 |
|------|--------------|
| 통신 | KT, SKT, LGU+ |
| 에너지 | 한국전력(KEPCO), 발전 자회사 |
| 교통 | 코레일, 인천국제공항공사 |
| 수자원 | 한국수자원공사(K-water) |

> **분석 의견:** 중국과 군사·경제적 긴장 관계에 있는 한국은 미국과 동일한 벡터의 위협에 노출될 가능성이 있다. 특히 한미 동맹 관련 통신 인프라가 고위험군으로 판단된다.

---

## 4. 전술·기법·절차 (TTPs) 분석

### 4.1 LOTL (Living off the Land) 기법

Volt Typhoon의 가장 두드러진 특징은 별도의 악성코드 없이 **정상 운영체제 도구만으로 공격**을 수행한다는 점이다. 이는 기존 시그니처 기반 탐지를 무력화한다.

**사용 확인 도구 목록:**

| 도구 | 용도 | MITRE ATT&CK |
|------|------|--------------|
| `whoami` | 현재 사용자 확인 | T1033 |
| `systeminfo` | 시스템 정보 수집 | T1082 |
| `net user/group` | 계정·그룹 열거 | T1087 |
| `nltest` | 도메인 정보 수집 | T1482 |
| `netstat` | 네트워크 연결 확인 | T1049 |
| `netsh` | 네트워크 설정 조회 | T1049 |
| `ntdsutil` | AD 자격증명 덤프 | T1003.003 |
| `wevtutil` | 이벤트 로그 삭제/조회 | T1070.001 |
| `reg query/save` | 레지스트리 정보 수집 | T1012 |
| `wmic` | WMI 기반 정보 수집 | T1047 |
| `certutil` | 파일 인코딩/다운로드 | T1140 |
| `makecab` | 데이터 압축 (유출 준비) | T1560 |
| `xcopy` | 파일 복사 | T1005 |
| `ping` | 네트워크 탐색 | T1018 |
| `PowerShell` | 스크립트 실행 | T1059.001 |
| `cmd` | 명령 실행 | T1059.003 |
| `ldifde` / `csvde` | AD 데이터 추출 | T1087.002 |
| `quser` | 로그온 세션 확인 | T1033 |
| `tasklist` | 프로세스 열거 | T1057 |
| `dnscmd` | DNS 정보 조회 | T1590.002 |

### 4.2 추가 도구

정상 도구 외 일부 서드파티 도구도 활용이 확인됨:

- `BrightmetricAgent.exe`, `SMSvcService.exe` — 정상 소프트웨어로 위장
- `ScanLine` — 포트 스캐닝 유틸리티
- UPX(Ultimate Packer for Executables) — 실행 파일 패킹으로 탐지 우회

---

## 5. IOC (침해 지표)

### 악성 파일 해시

| 파일 | 해시 유형 | 해시값 |
|------|----------|--------|
| 파일 1 | MD5 | `fd41134e8ead1c18ccad27c62a260aa6` |
| 파일 1 | SHA256 | `edc0c63065e88ec96197c8d7a40662a15a812a9583dc6c82b18ecd7e43b13b70` |
| 파일 2 | MD5 | `b1de37bf229890ac181bdef1ad8ee0c2` |
| 파일 2 | SHA256 | `99b80c5ac352081a64129772ed5e1543d94cad708ba2adc46dc4ab7a0bd563f1` |

---

## 6. 탐지 및 대응 권고사항

### 탐지 포인트

- LOTL 도구의 **비정상적 실행 패턴** 모니터링 (예: `ntdsutil`의 비업무시간 실행)
- `wevtutil`을 통한 이벤트 로그 삭제 시도 탐지
- `makecab` + `xcopy` 연계 사용 시 데이터 유출 의심

### 대응 권고

1. 불필요한 LOTL 도구 실행 제한 (AppLocker/WDAC 정책 적용)
2. 이벤트 로그 중앙 집중식 수집 및 백업
3. AD 환경 `ntdsutil` 접근 권한 최소화
4. 네트워크 분리 및 비정상 내부 횡이동 탐지 강화

---

## 7. 귀속 분석 (Attribution)

### 7.1 공식 귀속

CISA·NSA·FBI 및 파이브아이즈(Five Eyes) 동맹국 정보기관은 본 캠페인을 중국 정부 지원 행위자 **Volt Typhoon**으로 귀속하였다. 최초 공식 귀속은 2023년 5월 공동 어드바이저리를 통해 이루어졌다.

### 7.2 귀속 근거

| 근거 유형 | 내용 |
|----------|------|
| 기술적 | LOTL 기법, 특정 도구 조합이 기존 Volt Typhoon 캠페인과 일치 |
| 운영적 | 핵심 인프라 집중 타겟팅 패턴 반복 |
| 맥락적 | 미국-중국 지정학적 긴장과 공격 시점 연관성 |

### 7.3 귀속 한계 (Caveat)

> **"클라우드 환경으로의 횡이동 시도에 대한 Volt Typhoon 직접 귀속은 불확실(inconclusive)하다."**  
> — CISA Advisory AA24-038A

일부 활동은 Volt Typhoon으로의 직접 귀속이 결론에 이르지 못했다. 이는 LOTL 기법 특성상 행위자 고유의 흔적이 적고, 클라우드 환경에서의 포렌식 증거 수집이 어렵기 때문이다.

**분석 의견:** 본 어드바이저리 내에서 Volt Typhoon 귀속을 뒷받침하는 기술적 근거가 명시되지 않았다. CISA·NSA·FBI의 공식 귀속은 인용하되, 분석자 독립 신뢰도 평가는 **보류(Undetermined)**로 표기한다. 향후 기술적 귀속 근거(코드 유사성, C2 인프라 겹침 등)가 공개될 경우 재평가가 필요하다.

---

## 8. 결론

Volt Typhoon은 단기 금전적 이득이 아닌 **장기 잠복을 통한 전략적 역량 확보**를 목표로 하는 국가 수준의 위협 행위자다. LOTL 기법 특성상 기존 AV/EDR 탐지가 어려우며, 행위 기반 탐지와 위협 헌팅이 핵심 대응 방안이다.

한국의 경우 미국과 동일한 핵심 인프라 섹터가 유사한 위협에 노출될 수 있으며, 특히 한미 동맹 관련 통신·에너지 인프라에 대한 선제적 보안 강화가 필요하다.

---

## 참고 문헌

- CISA Advisory AA24-038A: People's Republic of China State-Sponsored Cyber Actor Living off the Land to Evade Detection
- MITRE ATT&CK Framework: https://attack.mitre.org

---

*본 보고서는 TLP:WHITE 등급으로, 제한 없이 공유 가능합니다.*
