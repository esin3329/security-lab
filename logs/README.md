# Logs (기록 보관소: CTF·KoTH 관찰 메모 및 완결 벤치마크 로그)

> 본 디렉터리는 주 실습인 CTF 및 KoTH의 안전한 관찰 메모와, 보조 기능인 완결 8지표 벤치마크 로그를 보관하는 공간입니다.

---

## 1. 기록 체계 구분 원칙

### 1) CTF 및 KoTH 실습 기록 (주 실습, Markdown 관찰 메모)
- **게임 기록 분리 원칙:** CTF 깃발 획득 및 KoTH 라운드 점유 기록은 벤치마크 스키마(`metrics.schema.json`)에 억지로 넣지 않으며, 안전한 Markdown 메모(`YYYY-MM-DD-<game>-obs.md`)로 수기 작성합니다.
- **가상 도구 가장 금지:** 현재 존재하지 않는 게임 전용 writer CLI나 자동 스키마를 가공하여 설명하지 않습니다.
- **안전한 기록 필수 항목:**
  1. `round_id` / `challenge_id`: 고유 실습 식별자
  2. `tools`: 사용된 도구명 및 버전 (Strix, ARTEX-KO, REA, GDB/pwndbg, pwntools 등)
  3. `steps`: 수행 단계 (정찰, 취약점 식별, 접근 획득, 방어/패치, 재점유 시도)
  4. `receipt`: 실제 플래그 제출 및 판정 영수증 (플래그 문자열 본문 제외)
  5. `koth_ticks`: 외부 judge가 검증한 점유 tick 수, 점유 전환 시각, 필수 서비스 가동 상태
  6. `defense_summary`: 적용된 방어 조치 및 설정/코드 패치 요약
  7. `limitations_reset`: 발생한 한계점, 판정 실패 사유, snapshot reset 근거

### 2) 완결 벤치마크 측정 기록 (보조 기능, JSONL Append-Only)
- **보조 기능 보존:** 8지표가 결측 없이 온전히 확정된 벤치마크 측정 결과만 `benchmarks/metrics.schema.json` 규격에 맞는 단일 줄 JSON 객체로 JSONL 파일 끝에 추가(append-only)합니다.
- **기록 모듈 호출 규격 (확정 CLI):**
  ```bash
  python3 tools/strix/metrics.py --record <완결 JSON 파일> --output <JSONL 파일>
  ```
  - 종료 코드 `0`: 검증 통과 후 1객체 append 및 fsync 성공.
  - 종료 코드 `2`: 스키마/정책 위반, 중복 `run_id`, I/O 에러 시 안전한 거부 및 미추가.
  - 환경 요구: `tools/strix/requirements.txt` (`jsonschema==4.19.2`), POSIX `flock`을 지원하는 Linux/WSL 환경.
  - 무결성 불변식: 중복 키/id, 잘린 행, 비유한 숫자 거부, 실패 시 원래 크기로 롤백(`ftruncate`), 단일 락 동시성 제어.
  - 모의 smoke 검증: `/tmp` smoke 테스트에서 내용 일치, 기존 바이트 보존, 8개 정책 거부, 동일 ID 동시 6회 중 성공 1 / 거부 5 확인 (실측값 아님).
- **시간 개념 구분:** KoTH의 로컬 15분 훈련 라운드와 벤치마크의 래퍼 scanner attempt 최대 900초(15분)는 완전히 별개의 개념입니다.

---

## 2. 벤치마크 스키마 필수 항목 (보조 기능)

통합된 `benchmarks/metrics.schema.json`의 필수 필드는 아래 8개입니다. 선택 `notes`는 필수 목록에 포함하지 않습니다.

1. `run_id`: 고유 식별자
2. `timestamp`: RFC 3339 달력상 유효 UTC 일시 (`Z` 또는 `+00:00`)
3. `tool`: 측정 도구명 (`strix` 또는 `manual`)
4. `tool_version`: 고정 버전 형식 (릴리스 X.Y.Z, Git SHA 40자리, sha256:64자리; 가변 별칭 거부)
5. `target`: 승인된 단일 웹 대상 (`name: "juice-shop"`, allowlist와 정확히 일치하는 `host_port`)
6. `time_limit_min`: 대상 작업 상한 15분 (`const: 15`)
7. `repeat_index`: 반복 번호 (1~3)
8. `metrics`: 결측 없는 기존 8지표 객체

`notes`는 안전하고 간결한 한국어 관찰 메모를 위한 선택 필드입니다.

---

## 3. Secret 보관 위치 및 보안 통제 항목 (엄격 준수)

- **Git 외부 Operator Private State 보관 원칙:**
  - `CTF_KEY`, event ID, SSH 자격 증명, KoTH judge state (SQLite DB, JSON 상태 파일)는 Git 저장소 외부의 operator 전용 runtime 디렉터리에 격리하여 보관합니다.
  - 디렉터리 권한은 `0700`, 상태 파일 권한은 `0600`으로 제한하여 다른 사용자나 프로세스의 접근을 차단합니다.
  - Git 커밋, 저장소 내 파일, 공개 보고서에 비밀번호, API 키, SSH private key, CTF_KEY를 절대 기록하지 않습니다.
- **플래그 및 자격 증명 노출 차단:**
  - 실제 획득한 flag 본문은 판정기 검증 입력 메모리 또는 비공개 런타임에만 일시적으로 존재하며, stdout/stderr 터미널 출력이나 로그 파일에 노출되지 않도록 차단합니다.
  - 로그 및 관찰 메모에는 오직 판정 receipt(영수증 식별자), 상태 코드, 안전한 한국어 관찰 요약만 기록합니다.
- **Managed Agent Credentials 추출 금지:**
  - 호스트 환경이나 관리 에이전트의 내부 자격 증명을 추출하지 않으며, 기본 모델이나 비밀 키를 코드/로그에 하드코딩하지 않습니다.
- **완성된 공격 코드 및 문제 풀이 배제:**
  - 완성된 익스플로잇 스크립트, 쉘코드, 문제별 정답 풀이(writeup) 원본을 커밋하거나 저장하지 않습니다.
- **원시 터미널 출력(stdout/stderr) 덤프 금지:**
  - 비구조화된 대량 터미널 출력이나 디버그 덤프를 직접 저장하지 않으며, 핵심 관찰 사항만 구조화된 메모로 남깁니다.

---

## 4. 결측치 및 상태 표기 원칙

- 벤치마크 측정 시 ground-truth 미확정이나 미측정 항목을 임의의 `0`으로 채우지 않으며, 불완전한 실행은 JSONL 대신 Markdown 관찰 메모로 격리합니다.
- ground-truth의 빈 `findings: []`는 스텁이며 8지표 실측 비교(C단계)는 차단 상태를 유지합니다. 단, 이는 벤치마크 보조 기능의 상태이며 주 실습인 CTF/KoTH 깃발 획득이나 점유 판정의 선행조건이 아닙니다.

