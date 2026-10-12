# Strix 실행 래퍼 안내 (승인된 로컬 웹 탐색/검증)

> 대상: 승인된 로컬 웹 실습 타겟(OWASP Juice Shop)만. 외부 서버 및 공용 실습 사이트 대상 스캔 절대 금지.  
> 구형 PowerShell dry-run 래퍼(`run.ps1`)는 폐기·삭제했습니다. 현재 실행 진입점은 `tools/lab/strix_tool.py`(`python3 tools/lab/practice.py --tool strix ...`)이며, 코드 통합은 완료했으나 실제 서버 VM에서의 설치·실행은 아직 수행하지 않았습니다. 아래 2~4절은 폐기된 과거 산출물 기록이고, 현재 상태는 5절을 따릅니다.

---

## 1. 개요 및 역할

- **도구 역할:** Strix는 사전에 승인된 로컬 웹 환경에 대한 공격 표면 탐색 및 취약점 검증을 보조하는 도구입니다.
- **CTF 실습 역할:** 로컬 Juice Shop 인스턴스의 엔드포인트 및 취약점 탐색을 보조할 수 있으나, 도구 보조만으로 깃발 획득 성공을 판정하지 않으며 실제 flag receipt 확인이 필요합니다.
- **공용 사이트 자동화 금지:** Dreamhack, pwn.college, TryHackMe KoTH 등 외부 공용 플랫폼을 대상으로 한 Strix 자동화 스캔/공격은 절대 금지됩니다 (특히 TryHackMe Rule 7의 자동 해킹 스크립트 금지 규정 준수). 허용 목록(`targets.allow`)에 외부 사이트를 추가하지 않습니다.

---

## 2. 파일 구성

- `run.ps1` — **삭제됨.** 구형 PowerShell 입력 검사/dry-run 설계였고 미지정 `StrixArgs` 처리 결함(코드 7)이 있었다. `tools/lab/strix_tool.py`로 대체했다.
- `targets.allow` — 허용 타겟 목록. 정확히 `juice-shop:3000`, `127.0.0.1:3000`, `localhost:3000` 3개 항목만 유지.
- `metrics.py` — 완결 벤치마크(보조 기능) 전용 JSONL 기록기 (CTF/KoTH 게임 기록은 본 모듈에 넣지 않음).
- `strix.lock.json` — Strix v1.7.0 공식 release pin(commit, sha256, sandbox 이미지 digest, 고정 CLI/argv, 반환 코드표).

---

## 3. (폐기) 구형 `run.ps1` 원본 확인 — 과거 산출물 기록

```powershell
# 1. 허용 타겟 확인 (정확히 3개 유지: juice-shop:3000, 127.0.0.1:3000, localhost:3000)
Get-Content .\targets.allow

# 2. 구형 호출 형태: 현재 미지정 추가 인자 처리 결함으로 코드 7이 관찰됨
# 실습용 정상 호출로 안내하지 않으며 후속 작업에서 입력 검증부터 다시 확인한다.
.\run.ps1 -TargetUrl "http://127.0.0.1:3000"
```

원본에는 실제 Strix 호출이 없고 `-StrixArgs` 전달을 차단합니다. 공식 pin/CLI 조사 결과는 별도 worktree에만 있으며, 이를 설치·실행 검증 완료로 해석하지 않습니다.

---

## 4. (폐기) 구형 반환 코드 설계 — 과거 산출물 기록

| 코드 | 조건 |
|---|---|
| 0 | 입력 허용, dry-run 출력 후 종료. 스캔 성공이나 깃발 획득을 뜻하지 않음. |
| 2 | URL/추가 인자에 CIDR·범위 옵션·`subnet=`·`cidr=` 포함. |
| 3 | 개별 추가 인자에 `-u`, `--update`, `--self-update`, `--selfupdate`, `--upgrade`, `--auto-update` 또는 `=값` 형식 포함. |
| 4 | allowlist 파일 없음, 승인된 3개 항목과 불일치 또는 중복. |
| 5 | URL 파싱 실패 또는 http/https 외 스킴. |
| 6 | URL에서 추출한 `host:port`가 allowlist에 없음. |
| 7 | 위 검사 뒤 남은 모든 추가 인자. |

---

## 5. 현재 구현 상태 및 주의사항

- **구형 `run.ps1` 폐기, 신규 컨트롤러로 대체 (통합 완료):**
  - 구형 PowerShell 입력 검사/dry-run 래퍼(`run.ps1`)는 삭제했습니다. `tools/lab/strix_tool.py` (`python3 tools/lab/practice.py --tool strix <install|doctor|run>`)가 Strix 공식 release pin(v1.7.0, commit `55bc07991aacb1c26a81b43e7ca53148730d2019`, sandbox 1.3.0, `tools/strix/strix.lock.json` 참조) 기반의 설치/진단/실행 컨트롤러로 이를 대체합니다.
  - 기존 구형 래퍼의 `StrixArgs` 미지정 거부 결함(코드 7), unchecked version/argv는 list-form spawn 고정 argv로 해소했고, 컨테이너 정리와 임시 디렉터리 소유권은 `finally` 블록에서 라벨 기준으로 강제합니다.
  - 위 1~4절의 `run.ps1`/코드 0~7 설계는 폐기된 과거 산출물 기록이며 현재 실행 진입점이 아닙니다.
- **실행 환경 및 실제 실행 미수행:**
  - 사용자 선택에 따라 실제 실행 환경은 **기존 Ubuntu VM**(`<operator-vm>`)으로 확정되었습니다. `infra/deploy.py check --ssh-executable infra/ssh-tailscale.sh`로 Tailscale SSH 경로의 연결·인증을 확인했으나, `infra/deploy.py deploy`(실제 소스 전송)는 아직 시도하지 않았습니다.
  - 코드 통합은 완료했으나 실제 VM 환경에서의 Docker/Strix 설치, 실행, 스캔 실습은 모두 **미실행** 상태이며 성공 또는 완료로 표시하지 않습니다.
- **주소 구분 및 격리:**
  - 컨테이너 대상 주소: `juice-shop:3000` (`targets-net`, `internal: true`)
  - VM 호스트 루프백 주소: `127.0.0.1:3000`, `localhost:3000`
  - 컨테이너 내부 loopback을 임의 치환하지 않으며, 외부 LLM 통신을 위해 격리망을 완화하지 않습니다.
- **벤치마크 보조 기능 분리:**
  - `metrics.py` CLI(`python3 tools/strix/metrics.py --record <완결 JSON> --output <JSONL>`)는 완결된 8지표 벤치마크 측정(보조 기능) 전용입니다.
  - CTF/KoTH 게임 기록을 벤치마크 schema에 억지로 넣지 않습니다.
  - 벤치마크의 `time_limit_min: 15`, `repeat_index: 1~3`, `jsonschema==4.19.2`, POSIX flock 계약은 보존되며, KoTH의 로컬 15분 라운드와 scanner attempt 최대 900초는 완전히 별개 개념입니다.

