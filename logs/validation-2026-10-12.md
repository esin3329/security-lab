# 검증 메모 — 2026-10-12

- 대상: `benchmarks/metrics.schema.json`, `benchmarks/ground-truth/juice-shop-v17.1.1.json`, `tools/strix/run.ps1`, `tools/strix/targets.allow`, `infra/compose.targets.yml`.
- `python3 -m json.tool`로 metrics schema와 신규 정답지 JSON 파싱 성공. 1줄짜리 메모리 내 JSONL 예시를 Draft-07 스키마로 검증 성공; 샘플은 검증 전용이며 저장하지 않았고 실측값이 아니다.
- Compose YAML 파싱 및 정적 확인 성공: Juice Shop v17.1.1, `127.0.0.1:3000:3000`, `unless-stopped`, named volume, `targets-net`의 `internal: true`. allowlist의 세 항목은 `juice-shop:3000`, `127.0.0.1:3000`, `localhost:3000`.
- Strix 래퍼는 `-u` 등 업데이트 인자, 범위 입력, 확인되지 않은 추가 인자 및 변경·중복된 allowlist를 거부하도록 정적 보강했다. 이 환경에 `pwsh`가 없어 래퍼 모의 실행은 수행하지 않았다.
- 로컬 Docker/Strix 실행, 외부 요청·스캔은 하지 않았다. ground-truth는 `findings: []`이며 정답 판정은 미확정; Phase 2 및 실제 VM 검증은 미수행.
