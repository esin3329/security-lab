# 검증 메모 — 2026-10-12

## 1. 최초 정적 검증 인계

- 대상: `benchmarks/metrics.schema.json`, `benchmarks/ground-truth/juice-shop-v17.1.1.json`, `tools/strix/run.ps1`, `tools/strix/targets.allow`, `infra/compose.targets.yml`.
- `python3 -m json.tool`로 metrics schema와 신규 정답지 JSON 파싱 성공. 1줄짜리 메모리 내 JSONL 예시를 Draft-07 스키마로 검증 성공; 샘플은 검증 전용이며 저장하지 않았고 실측값이 아니다.
- Compose YAML 파싱 및 정적 확인 성공: Juice Shop v17.1.1, `127.0.0.1:3000:3000`, `unless-stopped`, named volume, `targets-net`의 `internal: true`. allowlist의 세 항목은 `juice-shop:3000`, `127.0.0.1:3000`, `localhost:3000`.
- Strix 래퍼는 `-u` 등 업데이트 인자, 범위 입력, 확인되지 않은 추가 인자 및 변경·중복된 allowlist를 거부하도록 정적 보강했다. 이 환경에 `pwsh`가 없어 래퍼 모의 실행은 수행하지 않았다.
- 로컬 Docker/Strix 실행, 외부 요청·스캔은 하지 않았다. ground-truth는 `findings: []`이며 정답 판정은 미확정; Phase 2 및 실제 VM 검증은 미수행.

## 2. 병렬 작업 후 보조 기록기 검증

- 실제 CLI `python3 tools/strix/metrics.py --record <JSON> --output <JSONL>`를 `/tmp`의 합성 자료로 실행했다. 한 행 내용 일치, 기존 바이트 보존, 중복 ID·중복 키·잘린 입력/로그 거부를 확인했다.
- 시간 누락·30분·유효하지 않은 UTC 날짜·비UTC·`latest`·allowlist 밖 target·반복 4·필수 지표 누락을 거부하고 기존 로그가 바뀌지 않음을 확인했다.
- 같은 ID로 동시에 6회 호출해 성공 1회·거부 5회와 손상 없는 한 행을 확인했다. 실제 측정 파일은 저장하지 않았다.
- `python3 -m unittest discover -s tools/strix/tests -p 'test_*.py' -v`: 3개 통과. 동시 중복의 단일 commit/prefix 보존, fsync 실패 시 미확정 append만 rollback, 잘린 기존 tail의 거부/미수정 불변식을 검증했다.
- pwn의 실제 고정 커밋 `55596aa676a2756efb8d67034f31675170eabe48`과 지원 설치 옵션은 공식 metadata/source로 확인했다. Docker 빌드와 실제 도구 동작은 미실행이다.

## 3. 사용자 목표 변경 체크포인트

- 주 목표는 도구 기반 CTF/KoTH, 사이트는 보조로 변경됐다. 기존 benchmark schema/recorder는 별도 완결 관찰 계약으로 유지하며, CTF/KoTH 결과를 그 형식에 넣지 않는다.
- Codex는 기존 Strix 후속 변경을 두 파일에 저장하고 중지했다. 원본 미통합·미검증이며 실제 동작 성공을 주장하지 않는다. VM/Docker/Strix/ARTEX/REA/pwn 실행·CTF flag 제출·KoTH 게임 기동은 수행하지 않았다.
- 공식 Juice Shop CTF 문서와 고정 v17.1.1 설정, 도구 프로젝트, 보조 사이트 규칙만 조회했다. TryHackMe KoTH의 자동 공격·하드닝 script 금지와 pwn.college 공개 풀이 제한을 반영한다.
