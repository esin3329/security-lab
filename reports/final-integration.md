# security-lab 통합 검토 및 CTF·KoTH 방향 전환

- 작성일: 2026-10-12 (Asia/Seoul).
- 대상: `C:\project\security-lab` / `/mnt/c/project/security-lab` 전체.
- 작업: `task_4810be274f9d`, Dispatch `ctx_4c11055b3291`.
- **현행 주 목표:** 각 도구를 활용한 깃발 획득(CTF)과 King of the Hill 실습. 실습 사이트는 보조한다. [현행 작업계획](design-lead.md)을 기준으로 작업별 분담·agy 문서 담당·병렬 worktree를 유지한다.
- **아래 1~6절은 최초 벤치마킹 통합 당시의 이력이다.** 기존 Task/Dispatch의 결과와 검증 증거를 소급 변경하지 않는다. 현재 구현·검증·중지 상태는 7절을 따른다.
- 최초 통합 검토는 통과했으나 당시 전체 MVP는 미완료였고, 스키마 정책 강제·실제 실행·실측 비교가 남았다. 이후 보조 기록기와 pwn 수정은 원본에 반영했지만 CTF/KoTH 게임을 구현·실행한 것은 아니다.
- 최초 검토에서는 외부 요청·스캔과 Docker/Strix/pwn 빌드·실행을 하지 않았다. 후속 작업에서도 실제 대상 실행·게임·flag 제출은 하지 않았으며 공식 메타데이터 조회와 로컬 합성 입력 검증만 수행했다.

## 1. 선행 결과 리뷰

수정 전에 [설계서](design-lead.md), omp/agy의 Orca `worker_done` 본문과 변경 목록, 작업 시작 시 일반 파일 19개 전체를 읽었다. 이 폴더는 Git 저장소가 아니므로 파일 내용과 수정 전후 SHA-256을 비교했다.

| 결과 | 실제 인계와 확인 | 통합 판단 |
|---|---|---|
| 설계 | `task_e0150030caf9` / `ctx_582ad78eaa3d`: T2/T3 분해, 8지표·15분·3회, A/B/C 완료 단계, Phase 2 제외 계약. | 설계의 분해안과 실제 배정 범위를 구별했다. 설계서의 최초 현황은 작성 당시 기록으로 유지했다. |
| omp | `task_8dcfb1df3624` / `ctx_bce6f2b952f8`: 빈 findings JSON, 래퍼의 인자/allowlist 거부 보강, [검증 메모](../logs/validation-2026-10-12.md). | 세 파일의 인계 내용 확인. Python 파싱/정적 검사 결과를 재확인했다. `pwsh` 부재와 실제 실행 미수행을 그대로 인정하며 T2 전체 완료로 확대하지 않는다. |
| agy | `task_c7b9bcd79200` / `ctx_f996557bd920`: `targets`, `logs`, `tools/rea`, `tools/artex-ko`, `pwn/exploits`의 README 5개와 `.gitignore`. | 여섯 파일 모두 존재하고 로컬 범위·보관 제한 확인. REA/ARTEX-KO는 안내 스텁뿐이다. 실제 배정 밖의 루트 README·Strix 안내·측정표 수정까지 완료했다고 해석하지 않는다. |

이전 agy 실패 시도의 결과는 사용하지 않고, 위 성공한 Dispatch의 결과를 기준으로 검토했다.

## 2. 충돌 해결과 변경 범위

| 최소 수정 파일 | 충돌과 해결 |
|---|---|
| [Strix 안내](../tools/strix/README.md) | 실제 실행과 `--profile quick` 전달 예시를 현재의 입력 검사/dry-run 계약으로 정정. 모든 추가 인자 거부, 코드 0 및 2~7, VM 호스트/컨테이너 주소 구분, 시간/반복/JSONL 미구현을 명시했다. |
| [래퍼](../tools/strix/run.ps1) | 미확정 `strix:고정버전`과 입력 URL로 Docker 실행 예시를 출력하던 한 줄만 실행 미구현 안내로 교체했다. 입력 검사·허용 범위·실행 기능을 추가하지 않았다. |
| [측정 양식](../benchmarks/metrics.form.md) | 0값·재현 성공을 미리 넣은 JSONL 예시를 제거했다. 완결 측정만 JSONL로 저장하고 결측치는 관찰 메모에 남기는 계약으로 맞췄다. 8지표 정의를 유지했다. |
| [비교표](comparison.template.md) | Strix/수동 각각 3회와 run_id/안전한 기록 연결을 명시했다. 원시 로그 참조 표현을 정정하고 미측정·시도 없음·판정유보 및 실측 차단 상태를 추가했다. |
| [ground-truth 안내](../benchmarks/ground-truth/README.md) | 빈 findings와 `fixed_at`이 정답 확정이나 취약점 0건의 증거가 아님을 명시했다. JSON의 정답 내용은 추가하지 않았다. |
| [로그 안내](../logs/README.md) | 스키마 필수 필드와 시간/반복 정책, 선택 `notes`를 구별했다. `notes`만으로 결측치를 해결할 수 없으며 미완결 실행은 Markdown 관찰 메모로 남기도록 정리했다. |
| [pwn 관찰 안내](../pwn/exploits/README.md) | 환경 양식의 pwndbg 고정 커밋 표현을 실제 확인값/미확정으로 바꿨다. 현재 Dockerfile의 커밋 미고정·설치 오류 무시를 명시했다. |
| `reports/final-integration.md` | 이 통합 결과 보고서를 신규 작성했다. |

기존 파일 7개 수정과 보고서 1개 신규로 한정했다. `metrics.schema.json`, `targets.allow`, `compose.targets.yml`, ground-truth JSON, `pwn/Dockerfile`, 설계서 및 omp 검증 메모의 SHA-256은 작업 시작 시와 같음을 확인했다. 임의 Strix 버전/pwndbg 커밋, 새 지표·null·enum, 타겟·문제·페이로드·실측 JSONL을 추가하지 않았다.

## 3. 정합 체크 4항목

| 정합 항목 | 통과/실패 | 확인 증거와 한계 |
|---|---|---|
| **① 스키마 / Python JSON 파싱** | **형식 통과 / 정책 강제 실패** | `python3 -m json.tool`로 `benchmarks/metrics.schema.json` 파싱 성공(종료 0). `jsonschema.Draft7Validator.check_schema` 통과. `strix`/`manual`, 정확히 8지표와 필수 지표 목록, 반복 1~3, 15분 default 유지 확인. 메모리 내 합성 객체는 통과, TP 음수·PoC 비율 1 초과·설명가능성 6·반복 0/4·필수 지표 누락은 거부했다. 그러나 시간/반복 필드 누락, 30분, `tool_version: latest`, allowlist 밖 host:port 문자열이 스키마를 통과하여 계약 전체의 강제는 실패다. |
| **② allowlist 3줄** | **통과(정적)** | 주석·빈 줄 제외 정확히 `juice-shop:3000`, `127.0.0.1:3000`, `localhost:3000` 3줄이며 소문자·주변 공백 없음·중복 없음. 래퍼의 승인된 세 항목 대조와 추가 인자 거부를 읽어 확인했다. `pwsh`/`powershell` 실행 파일이 없어 모의 반환 코드·거부 동작은 미검증이며 실제 호출 검증 통과로 주장하지 않는다. |
| **③ Compose 핀·internal·restart·volume** | **통과(정적)** | `yaml.safe_load`와 assert로 서비스가 Juice Shop 1개, 이미지가 `bkimminich/juice-shop:v17.1.1`인 고정 태그, 포트가 `127.0.0.1:3000:3000`, 연결망이 `targets-net` 하나이고 `internal: true`, 재시작이 `unless-stopped`, named volume이 `juice-shop-data:/juice-shop/data` 및 local driver임을 확인했다. 이미지 가용성·기동·연결·상태 유지/초기화는 미실행이다. |
| **④ ground-truth** | **스텁 정합 통과 / 정답 판정 차단** | `python3 -m json.tool`로 `benchmarks/ground-truth/juice-shop-v17.1.1.json` 파싱 성공(종료 0). target/version이 Compose의 Juice Shop/`v17.1.1`과 일치하고 `fixed_at`은 UTC date-time 형식이며 `findings`는 빈 배열이다. 빈 배열을 확정 정답으로 사용하지 않으며 TP/FP·완결된 8지표 비교는 차단이다. 실제 findings 확정은 Phase 2로 이월한다. |

검사는 로컬 Python의 `json`, `yaml`, `jsonschema`로 수행했다. 합성 객체와 allowlist 밖 문자열은 메모리 내 검증 입력으로만 사용했고 네트워크 요청이나 파일 저장은 하지 않았다. JSON 파싱·스키마 검증은 실행/측정 증거가 아니다.

추가 정적 검수에서는 Markdown 상대 링크의 실제 파일 존재, 문서의 8지표·15분·3회·결측치 정책, 래퍼의 코드별 거부 분기와 출력 안내를 확인했다. 수정 전후 해시로 위 변경 범위를 확인했으며 문제 바이너리·공격 스크립트·실측/샘플 JSONL 신규 파일은 없다. PowerShell 모의 검사, 컨테이너 테스트, 외부 통신 검사는 수행하지 않았다.

## 4. MVP 잔여와 단계 판정

| 단계 | 판정 | 남은 일 / 담당 |
|---|---|---|
| **A. 구조적 MVP** | **미완료** | 통합 문서와 4항목 정적 검토는 완료. 아래 실행/기록 계약 및 고정 버전 구현·모의 검증, 루트 진입 안내는 남아 있다. 후속 작업은 현행 설계서의 작업별 배정안을 기준으로 코디네이터가 승인 후 배정한다. |
| **B. 로컬 실행 검증** | **미실행** | 사용자 Ubuntu VM에서만 대상 기동·고정 버전 확인·연결·900초 종료/정리·동일 초기 상태의 반복을 확인한다. 이번 작업에서는 실행하지 않았다. |
| **C. 8지표 실측 비교** | **차단** | 실제 기록이 없고 ground-truth와 일부 지표가 미확정이다. Strix/수동 각각 3회, 총 6회의 완결 측정과 사람의 판정 근거가 없다. Phase 2 정답 확정 전 완료로 표시하지 않는다. |

MVP에 남긴 구체적인 작업은 다음과 같다. 이번 통합은 필요한 안내 정정까지만 수행했으며 이를 새 기능 구현으로 확장하지 않았다.

1. **Strix 버전/실행 계약:** 실재 확인된 고정 이미지와 CLI 확정, 확인된 옵션만 허용, 회당 900초 종료와 프로세스/컨테이너 정리, 실패 코드 전달, 실행 ID·UTC·실제 소요 시간·반복번호 기록. 현재 래퍼는 입력 검사와 dry-run뿐이다.
2. **검증/JSONL 계약:** 시간·반복 필수/15분 고정, 고정 버전/allowlist 확인, UTC 확인 및 8지표 검증 계층, append-only 저장, 중복 run_id·잘린 JSON 거부. 결측치 정책이 확정되지 않은 상태에서 스키마에 임의 null/enum을 넣거나 미측정 값을 0으로 채우지 않는다.
3. **PowerShell 모의 검증:** 도구가 있는 환경에서 허용/거부, 모든 추가 인자, 종료 코드 및 실제 실행 호출 0회를 검증한다. 실제 실행 구현 후 시간 초과·정리·기록도 모의 검증한다. 정적 분기 검토로 이 검증을 대신하지 않는다.
4. **pwn 재현 환경:** Ubuntu `24.04`와 `pwntools==4.14.0`은 정적 고정 유지. pwndbg는 기본 브랜치 shallow clone이며 `setup.sh --yes || true`가 오류를 숨긴다. 검증 가능한 커밋 고정과 오류 전파 수정, 사용자 VM의 GDB/pwndbg/pwntools 확인이 필요하다. 임의 커밋을 선택하거나 Dockerfile을 빌드하지 않았다.
5. **진입 안내/VM 조건:** 루트 `README.md`는 아직 없다. 최종 인터페이스 확정 뒤 진입 순서를 작성하고, named volume이 유지하는 상태의 반복별 초기화 기준·VM 자원·모델/도구 설정을 정한다. 컨테이너용 `juice-shop:3000`과 VM 호스트 loopback을 구별하며 `internal: true`를 해제하지 않는다. 외부 LLM 통신 필요 여부는 미확인이다.

## 5. Phase 2 이월

- Juice Shop ground-truth 실제 findings 확정과 이후 사람의 TP/FP 판정. 이번 빈 JSON은 버전/형식 스텁으로 유지한다.
- REA/ARTEX-KO 구현·연동·비교, WebGoat·자작 API·추가 웹 타겟, Stack One/Format Zero 등 추가 pwn 문제.
- 탐지율/FP율 등 파생 지표와 정규화 도구 확장.

위 항목은 이월 목록만 기록했다. 이번 작업에서 Phase 2 내용이나 페이로드를 추가하지 않았다.

## 6. 인계

이번 Dispatch의 acceptance인 최종 보고서 존재와 정합 체크 4항목 기록을 충족했다. 코디네이터는 이번 검토 완료와 전체 MVP 미완료를 구별해 인계하고, A의 잔여 구현 및 B의 사용자 VM 검증을 배정할 수 있다. C는 ground-truth 확정 전 차단으로 유지한다.

## 7. 현행 CTF·KoTH 전환과 후속 작업 상태

### 방향과 보존

- 주 실습은 소유한 로컬 격리 환경의 실제 CTF flag 판정과 KoTH 점유·방어다. 기존 8지표 비교는 보조 관찰이며 새 실습의 선행 완료 조건이 아니다.
- 실습 사이트는 학습·문제 선택·규칙·허가된 수동 실습을 보조한다. 링크를 외부 자동 스캔 허가나 allowlist 추가로 해석하지 않는다.
- 원본은 로컬 Git 기준 커밋 `1c863bd`로 시작했고 `.worktrees/docs`, `metrics-recording`, `pwn-environment`, `strix-runtime`을 만들었다. 원격 저장소와 전역 Git 설정은 바꾸지 않았다.
- 원본 반영된 기존 결과는 pwn 수정(`35124fc`)과 보조 기록기/스키마(`48ab6df`)다. 기록기의 합성 CLI 스모크와 3개 회귀 테스트는 통과했다. 실제 benchmark/CTF/KOTH 측정이나 flag 획득 증거는 아니다.
- Strix의 후속 변경은 Codex가 사용자 목표 변경을 받아 안전 체크포인트에서 저장하고 중지했다. 두 파일(`run.ps1`, `strix.lock.json`)은 `strix-runtime` worktree에 보존하고 원본에 통합하지 않았다. 실제 pwsh/fixture 동작·900초/인터럽트·sidecar/임시 경로 소유권은 미검증 또는 잔여다.

### 실습 계약

- CTF는 고정 Juice Shop의 실제 CTF mode/비공개 event key, 실제 flag code와 판정 receipt, 안전한 기록·reset으로 진행하는 후속 작업이다. 고정 `v17.1.1/config/ctf.yml`의 flag notification 설정은 공식 파일에서 확인했지만 현재 Compose에는 CTF 설정이 없다.
- 바이너리 CTF는 허가된 flag-bearing 문제를 별도 선정한다. Phoenix Stack Zero의 성공 메시지를 실제 flag로 가장하지 않는다.
- KoTH는 별도 owned VM의 protected king marker, 외부 판정기·clock·score/reset, 서비스 상태와 검증된 tick으로 점유를 관측하는 모델이다. 개발 worktree는 참가자 보안 격리가 아니다. 해당 VM/판정/scoreboard는 아직 구현·실행하지 않았다.
- REA는 리버싱/MCP 도구 `morluto/rea`, ARTEX-KO는 `jiwoochris/artex-ko`를 문서 기준으로 정리한다. 실제 설치·고정 버전·연동은 후속 구성 작업이다.
- [Dreamhack](https://dreamhack.io/wargame/), [pwn.college](https://pwn.college/), [TryHackMe KoTH 규칙](https://help.tryhackme.com/en/articles/6498315-king-of-the-hill-overview)을 보조로 사용한다. pwn.college 공개 풀이 제한과 TryHackMe 자동 hacking/hardening script 금지를 지킨다.

### 현재 완료와 다음 배정의 구분

현재 완료하는 범위는 방향·문서·작업 경계의 전환과 검증된 기존 결과 보존이다. 실제 flag 수집·판정, hill 점유/점수, 새로운 tool wrapper, VM 실행 성공은 완료로 표시하지 않는다. 이후 로컬 CTF 기반, 실제 도구 연동, KoTH 기반을 작업 단위로 분리해 배정하고 agy가 확정된 인터페이스의 안내를 맞춘다.

