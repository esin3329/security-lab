# security-lab (도구 기반 실전 CTF 및 King of the Hill 실습 환경)

> 로컬 격리 환경 기반의 도구 중심 깃발 획득(CTF) 및 King of the Hill(KoTH) 실습 랩입니다.  
> 보조 학습 플랫폼(Dreamhack, pwn.college, TryHackMe)을 연계하며, 기존 8지표 벤치마킹 체계는 완결 벤치마크 보조 기능으로 분리 유지합니다.

---

## 1. 프로젝트 개요 및 구조

`security-lab`의 주 목표는 사전에 승인된 격리 환경 내에서 보안 분석 도구(Strix, ARTEX-KO, REA, GDB/pwndbg, pwntools)를 활용하여 **실제 깃발(flag)을 획득하는 CTF 실습**과 **공격/방어 점유 경쟁을 다루는 King of the Hill(KoTH) 실습**을 수행하는 것입니다.

초기 8지표/15분/3회 벤치마크 완료나 미확정 ground-truth는 프로젝트의 주 목적이나 깃발 실습의 선행조건이 아니며, 완결된 측정 결과를 검증하는 별도의 보조 관찰 기능으로 유지됩니다.

- **작업 경로 기준:**
  - Windows 호스트 경로: `C:\project\security-lab`
  - WSL / Linux 작업 경로: `/mnt/c/project/security-lab`
  - 코드/문서 통합은 `main`에서 수행한다. 작업 단위 worktree(`.worktrees/*`)는 통합 전 병렬 구현 공간으로만 보존한다.

### 디렉터리 역할

```text
security-lab/
├── infra/                 # 격리 인프라 정의 및 배포
│   ├── compose.targets.yml # Juice Shop v17.1.1, targets-net, CTF mode 환경변수/라벨
│   ├── deploy.py          # tracked 소스 → 서버 Ubuntu VM 원자적 배포 (설치/서비스 기동 없음)
│   └── ssh-tailscale.sh   # deploy.py --ssh-executable 어댑터 (일반 SSH 대신 `tailscale ssh` 사용)
├── targets/               # 실습 대상 환경 안내 (targets/README.md)
├── tools/                 # 보안 도구 실행 래퍼, 실습 컨트롤러 및 안내
│   ├── ctf/               # CTF 컨트롤러 및 플래그 판정기 (코드 통합 완료, VM 실행 미수행)
│   ├── koth/              # KoTH 외부 판정기 및 라운드 매니저 (코드 통합 완료, VM 실행 미수행)
│   ├── lab/               # 도구 설치/진단/실행 통합 컨트롤러 (코드 통합 완료, VM 실행 미수행)
│   ├── strix/             # Strix pin(v1.7.0)/metrics.py (구형 run.ps1 폐기, tools/lab/strix_tool.py로 대체)
│   ├── rea/                # REA 리버싱/MCP 근거 분석 도구 pin (tools/lab/rea_tool.py, 미설치)
│   └── artex-ko/          # ARTEX-KO 자율 공격 경로/방어 관찰 도구 pin (tools/lab/artex_tool.py, 미설치)
├── pwn/                   # 로컬 바이너리 실습 환경 (Ubuntu 24.04, GDB, pwndbg, pwntools)
│   ├── Dockerfile         # pwndbg commit 고정(2026.09.15, 55596aa6) 환경 정의 (빌드 미실행)
│   ├── challenges/        # flag-bearing 바이너리 및 Phoenix Stack Zero 기초 보조 문제 안내
│   └── exploits/          # 안전한 관찰 메모 템플릿 (플래그/페이로드 보관 금지)
├── benchmarks/            # 완결 벤치마크 보조 기능 (game 기록과 분리)
│   ├── metrics.schema.json # 8지표 측정 JSON 스키마 (15분, 반복1..3, UTC 등 강제)
│   ├── metrics.form.md    # 8지표 벤치마크 수기 기록 양식
│   └── ground-truth/      # 버전별 정답지 스텁 (findings: [], 단계 C 차단 유지)
├── logs/                  # CTF·KoTH Markdown 관찰 메모 및 완결 벤치마크 JSONL
└── reports/               # 설계서, 비교표 템플릿(comparison.template.md), 통합 검토 보고서
```

---

## 2. 병렬 구현 통합 및 실행 환경 준비

4개 작업 단위(CTF/KoTH/도구 통합/문서)가 독립 Git worktree에서 병렬 구현한 결과를 코디네이터가 `main`에 통합했습니다. 통합은 코드·문서 병합과 정적 검증(컴파일, 기존/신규 단위 테스트, `infra/deploy.py plan`)까지이며, 서버 VM에서의 실제 설치·실행은 포함하지 않습니다.

### 1) 실행 환경: 기존 Ubuntu VM 연결 확인됨 (Tailscale SSH)

- 사용자의 선택에 따라 실제 Docker/도구/게임 실행 환경은 **기존 Ubuntu VM**(Tailscale 노드명 `<operator-vm>`)으로 확정되었습니다.
- **연결 경로 변경 사실:** 처음 시도한 일반 OpenSSH(Windows SSH config의 `user@<IP>`, BatchMode)는 `authorized_keys`에 등록된 키가 없어 `Permission denied (publickey,password)`로 거부되었습니다. 그 VM에서 Tailscale SSH 기능(`sudo tailscale up --ssh`)을 켠 뒤, `tailscale ssh`의 1회 브라우저 세션 승인을 거쳐 연결에 성공했습니다.
- **`infra/deploy.py check` 실행 결과 (실제 성공):** `infra/ssh-tailscale.sh`를 `--ssh-executable`로 지정해 실행한 `python3 infra/deploy.py check --target user@<operator-vm-ip> --ssh-executable infra/ssh-tailscale.sh`가 아래 실제 VM 메타데이터를 반환했습니다(`services_started: false`, 아무것도 설치·기동하지 않음):
  ```json
  {"home": "/home/user", "os_id": "ubuntu", "os_version": "26.04",
   "platform": "linux", "python": [3, 14, 4], "uid": 1000, "services_started": false}
  ```
- **판정 경계:** 위는 "연결·인증 확인"일 뿐입니다. `infra/deploy.py deploy`로 실제 소스를 전송한 적도, 그 VM에서 Docker/Strix/REA/ARTEX/pwn을 설치·실행한 적도, CTF flag를 획득하거나 KoTH judge를 돌린 적도 없습니다. 이 확인을 실제 설치·게임 성공으로 확대하지 않습니다.

### 2) 작업 단위와 통합 결과
| 작업 단위 | 원 Worktree / Branch | 통합된 범위 | 통합 후 상태 |
|---|---|---|---|
| **CTF 기반** | `.worktrees/ctf-runtime`<br>`practice/ctf-runtime` | `infra/compose.targets.yml` (`NODE_ENV=ctf` + event별 `CTF_KEY`/project/round 라벨), `tools/ctf/practice.py`, `tools/ctf/juice-shop.lock.json`. | 코드 통합·컴파일·`--help` 확인 완료. VM 실행·flag 판정 미수행. |
| **KoTH 외부 판정** | `.worktrees/koth-runtime`<br>`practice/koth-runtime` | `tools/koth/{practice,judge,observer,probe,state}.py`. contest VM 밖의 외부 judge, OpenSSH probe, 15분 round / 5초 tick, king marker 점유 판정, snapshot reset. | 코드 통합·컴파일·`--help` 확인 완료. 외부 judge 실행·실제 점유 판정 미수행. |
| **도구 통합** | `.worktrees/tool-integration`<br>`practice/tool-integration` | `tools/lab/{practice,common,strix_tool,rea_tool,artex_tool,pwn_tool}.py`, `tools/rea/pin.json`, `tools/artex-ko/{pin.json,docker-compose.pinned.yml}`, `tools/strix/strix.lock.json`. 구형 `tools/strix/run.ps1`은 삭제. | 코드 통합·컴파일·`--help` 확인 완료. 설치/실행은 서버 VM에서만 가능하며 미수행. |
| **배포 경로** (본 통합 작업) | `main` 직접 작업 | `infra/deploy.py`, `infra/tests/test_deploy.py`. tracked 소스 패키징 → SSH 전송 → 원자적 release 교체(symlink) 배포. 설치나 서비스 기동은 수행하지 않음. | `plan`/`pack` 로컬 실행 및 수신측 경계 테스트 4종 통과. 실제 `--target` SSH `check`/`deploy`는 미실행(연결 미확정). |
| **실습·운영 문서** | `.worktrees/practice-docs`<br>`practice/documentation` | root `README.md`, `targets/README.md`, 하위 README들, `logs/`, `pwn/`, `benchmarks/` 관련 안내. | 위 코드 통합 결과에 맞춰 코디네이터가 "진행 중" 표현을 "통합 완료/VM 실행 미수행"으로 정합. |

### 3) 개발 Worktree와 실습 격리의 엄격한 구분
- **Git Worktree(`practice/*`)의 역할:** 여러 작업자 간의 파일 수정 충돌을 방지하기 위한 로컬 개발 작업공간일 뿐이며, 보안 격리나 게임 참가자 권한 통제 수단이 아닙니다.
- **실제 실습 격리:** 참가자, 타겟, 판정기의 보안 격리는 인증·연결된 독립 Ubuntu VM 및 격리 네트워크(`targets-net`, `internal: true`, VM snapshot reset)를 통해 물리적/가상화 수준에서 별도로 수행됩니다.

---

## 3. 핵심 운영 정책 및 권한 분리

### 1) Secret 및 Flags의 Private 보관 원칙
- **Git 밖의 Private State 관리:**
  - `CTF_KEY`, event ID, SSH credentials, KoTH judge state(sqlite/json)는 Git 저장소 밖의 operator 전용 runtime 디렉터리에 `0700`(디렉터리) / `0600`(파일) 권한으로 엄격히 보관합니다.
  - 저장소, Git 커밋, 공개 문서, 보고서에 비밀번호, API 키, private key, CTF_KEY를 절대 기록하지 않습니다.
- **Flag 노출 차단:**
  - 플래그는 검증 입력 메모리 또는 비공개 런타임에만 일시적으로 존재하며, stdout 출력이나 로그 파일에 노출되지 않습니다.
  - 출력은 오직 판정 receipt(영수증 식별자), 상태 코드, 안전한 메타데이터로 한정합니다.
- **Managed Agent Credentials 추출 금지:**
  - 호스트나 에이전트의 내부 자격 증명을 추출하지 않으며, 기본 모델이나 비밀 키를 코드에 하드코딩하지 않습니다. 모델/키가 없으면 명시적으로 준비 미비로 거부합니다.

### 2) Participant(참가자)와 Judge(판정기)의 권한 분리
- **관리 영역의 물리적/논리적 분리:**
  - 판정기(judge), 경기 시계(clock), 점수 집계(score DB), VM 리셋 권한은 contest VM 밖의 보호된 관리 영역에 위치합니다.
  - 참가자가 타겟 머신을 장악하더라도 score DB나 reset 권한을 탈취할 수 없도록 엄격히 분리합니다.
- **공격 허용 범위 제한:**
  - 참가자는 오직 지정된 타겟 머신 내부의 실습 범위만 공격할 수 있습니다.
  - 판정기, 관리망, 다른 참가자의 기기에 대한 공격은 절대 금지됩니다.
- **점유 인정 조건:**
  - 보호된 king marker에 사전 승인된 participant ID를 기록하고, 외부 판정기가 이를 직접 읽어 확인했을 때만 점유로 인정합니다.
  - 모델의 성공 주장이나 score API에 대한 임의 POST 요청은 점유로 인정하지 않습니다.

---

## 4. 주 실습 흐름: CTF & KoTH

### 1) CTF (Capture The Flag) 실습 흐름
- **웹 타겟 (OWASP Juice Shop v17.1.1):**
  - **현재 구성 사실:** 현재 Compose는 기본 Juice Shop 구성이며, `NODE_ENV=ctf` 및 event별 private `CTF_KEY`가 포함되어 있지 않습니다.
  - **후속 구성 과제:** 단일 참가자 원칙(single-user instance)에 맞춰 `NODE_ENV=ctf`, private event key, 알림 플래그 표시(`ctf.showFlagsInNotifications=true`, `config/ctf.yml`) 설정을 적용합니다 (참조: https://pwning.owasp-juice.shop/companion-guide/latest/part4/ctf.html).
  - **판정 기준:** 도구가 분석을 수행했다는 사실만으로 성공을 주장할 수 없으며, 실제 flag code 획득 및 로컬 validator/플랫폼 수동 제출 receipt 확인을 통해 판정합니다. 현재 자동 scoreboard/judge/reset 기능은 미구현입니다.
- **바이너리 타겟:**
  - 다운로드 및 로컬 컨테이너 재현이 허용된 flag-bearing 문제를 활용하며 실제 flag/validator로 판정합니다.
  - Phoenix Stack Zero(`https://exploit.education/phoenix/stack-zero/`)는 기초 메모리 버퍼 오버플로우 관찰을 위한 보조 문제이며, 성공 메시지는 실제 CTF flag가 아닙니다 (임의 플래그 획득 주장 금지).

### 2) KoTH (King of the Hill) 실습 흐름
- **Hill 타겟 환경:**
  - 소유 및 서면 허가된 별도의 재설정 가능(snapshot reset 가능) VM을 hill target으로 사용합니다.
  - Juice Shop은 공식 가이드에서 명시된 1인용(single-user) 애플리케이션이므로 다중 참가자가 공유하는 hill로 직접 사용하지 않습니다.
- **운영 및 라운드:**
  - 초기에는 1인의 운영자가 공격/방어 역할을 교대로 실습하며, 이후 로컬 2팀/도구 프로필로 확장합니다.
  - 기본 로컬 훈련 라운드는 **15분**입니다 (기존 scanner attempt 최대 900초와 완전히 별개의 게임 라운드 개념).
  - 외부 judge가 주기적으로(예: 5초마다) 유효 participant marker와 필수 서비스 생존 상태를 확인하며, 검증된 tick만 점수에 반영합니다 (sampling 관측을 연속 시간 증거로 과장하지 않음).
- **단계 및 금지 행위:**
  - 순서: 준비/허가 확인 → 접근 획득 → marker 점유 확인 → 방어/패치 유지 → 상대 재점유 시도 → 종료 집계 → snapshot reset.
  - 금지 행위: 외부 지속성 설치, 계정 탈취, 시스템 파괴, DoS, 판정기 통신 전면 차단, flag/판정기 변조.

---

## 5. 보조 실습 플랫폼 및 준수 규정

공식 플랫폼은 문제 선택, 기초 학습, 힌트 및 규칙 참고를 보조하며, 플랫폼 자체나 공용 인프라에 대한 공격은 절대 금지됩니다:

1. **Dreamhack Wargame (https://dreamhack.io/wargame/):**
   - 웹, pwnable, reversing 교육 문제 학습 및 허용된 문제의 수동 실습/바이너리 다운로드 보조.
2. **pwn.college (https://pwn.college/):**
   - 시스템/바이너리 실습 환경.
   - **공식 규칙 준수:** 문제 해설, writeup, 솔루션 영상의 인터넷 공개 금지 요청에 따라, 저장소에 문제별 정답, 플래그, 공개 풀이를 절대 커밋하지 않습니다.
3. **TryHackMe King of the Hill (https://help.tryhackme.com/en/articles/6498315-king-of-the-hill-overview):**
   - KoTH 게임 규칙 및 수동 실습 참고.
   - **Rule 7 엄격 준수:** 자동 hacking/hardening scripts 사용이 금지되어 있으므로 Strix나 ARTEX-KO를 공용 THM KoTH의 자동화 도구로 안내하거나 사용하지 않습니다.
   - 공식 60분 경기 및 분당 점수 체계는 로컬 15분 라운드 훈련과 별개입니다.
4. **공통 네트워크 경계:**
   - 어떤 외부 플랫폼 링크도 `tools/strix/targets.allow`에 추가하지 않습니다.
   - 로컬 allowlist 3개(`juice-shop:3000`, `127.0.0.1:3000`, `localhost:3000`), `targets-net` (`internal: true`), 호스트 loopback 바인딩은 변경 없이 유지됩니다.

---

## 6. 기록 체계 구분 (CTF/KoTH 관찰 메모 vs 완결 벤치마크)

- **CTF·KoTH 주 실습 기록 (Markdown 관찰 메모):**
  - challenge/round 식별자, 도구 및 버전, 수행 단계.
  - 판정 receipt (플래그 본문 제외 영수증 식별자).
  - 검증된 점유 tick 및 전환 시각, 필수 서비스 생존 여부, 방어 패치 요약, 한계, snapshot reset 근거.
  - 게임 기록은 벤치마크 스키마에 넣지 않으며, 가상의 game writer CLI를 가장하지 않습니다.
- **완결 벤치마크 보조 기능 (JSONL Append-Only):**
  - 8지표가 온전히 확정된 단일 측정 결과만 `benchmarks/metrics.schema.json` 규격으로 `logs/` JSONL에 저장합니다.
  - 확정된 CLI: `python3 tools/strix/metrics.py --record <완결 JSON 파일> --output <JSONL 파일>` (종료 코드 0: 성공, 2: 거부).
  - 스키마 필수 8개 항목(`time_limit_min: 15`, `repeat_index: 1~3`, RFC 3339 UTC, allowlist 3개, 고정 버전 형식) 강제.
  - ground-truth 스텁(`findings: []`)으로 인한 8지표 비교(단계 C) 차단 상태는 보조 기능에 한정되며, CTF/KoTH 실습의 선행조건이 아닙니다.

---

## 7. 현재 상태 및 사실 기반 명시

1. **실제 실행 및 연결 상태:**
   - Ubuntu VM(`<operator-vm>`) 연결·인증은 Tailscale SSH로 **확인 완료**(`infra/deploy.py check` 실제 성공, 2절 참조). 일반 OpenSSH BatchMode 경로는 여전히 키 미등록으로 막혀 있으며, 이번에는 `infra/ssh-tailscale.sh` 어댑터로 우회했습니다.
   - 그 위의 실제 Docker/도구 설치·실행, CTF 플래그 제출, KoTH 인프라 기동, `infra/deploy.py deploy`(실제 소스 전송)는 **모두 미실행** 상태입니다. 연결 확인을 실행·게임 성공으로 확대하지 않습니다.
2. **도구 컨트롤러 구현 상태 (코드 통합 완료):**
   - `tools/ctf`, `tools/koth`, `tools/lab`(+`tools/rea`, `tools/artex-ko`, `tools/strix`의 pin 파일)을 `main`에 통합했습니다. 각 모듈은 `python3 -m py_compile`과 `--help` 인자 파싱으로 로드 가능함을 확인했습니다.
   - `infra/deploy.py`가 요구하는 네 항목(`infra/compose.targets.yml`, `tools/ctf/practice.py`, `tools/koth/practice.py`, `tools/lab/practice.py`)이 모두 추적 파일로 존재하여 `python3 infra/deploy.py plan`이 성공합니다 (서버 전송은 하지 않음).
   - 컨트롤러 내부 로직(실제 Docker 설치/실행 분기, judge 샘플링, flag HMAC 검증 등)은 서버 VM에서 실행해 보지 않았으므로 코드 존재 확인을 실행 검증으로 과장하지 않습니다.
   - 세부 통합 범위와 근거는 [통합 보고서](reports/final-integration.md) 8절을 참조합니다.
3. **운영 정책:**
   - 고정 역할이 아닌 작업 단위 소유권 분담을 유지합니다.
   - 외부 웹 검색 끄기는 사용자 결정에 따라 유지합니다.
