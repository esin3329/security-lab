# Strix 실행 래퍼 사용법 (MVP)

> 대상: 로컬/소유·허가 실습 타겟만. 외부 서버 대상 스캔 금지. 현재 래퍼는 입력 검사 후 dry-run만 출력하며 Docker/Strix를 실행하지 않는다.

## 파일 구성

- `run.ps1` — PowerShell 입력 검사 래퍼. 허용된 입력에도 dry-run만 출력한다. `-DryRun`/`-Execute` 옵션은 없다.
- `targets.allow` — 허용 타겟 목록. `호스트:포트` 형식, 한 줄에 하나.

## 사용법

```powershell
# 1. 허용 타겟 확인 (기본 포함: juice-shop:3000, 127.0.0.1:3000, localhost:3000)
Get-Content .\targets.allow

# 2. 허용된 VM 호스트 주소의 입력 검사 (실제 스캔 없음)
.\run.ps1 -TargetUrl "http://127.0.0.1:3000"
```

위 예시는 `tools/strix/`에서 사용한다. Strix 버전과 CLI가 미확정이므로 `-StrixArgs`는 모두 거부하며, 추가 프로필·대상·업데이트 옵션을 전달하는 실행 예시는 제공하지 않는다.

## 반환 코드 (현재 구현의 정적 계약)

| 코드 | 조건 |
|---|---|
| 0 | 입력 허용, dry-run 출력 후 종료. 스캔 성공을 뜻하지 않음. |
| 2 | URL/추가 인자에 CIDR·범위 옵션·`subnet=`·`cidr=` 포함. |
| 3 | 개별 추가 인자에 `-u`, `--update`, `--self-update`, `--selfupdate`, `--upgrade`, `--auto-update` 또는 `=값` 형식 포함. |
| 4 | allowlist 파일 없음, 승인된 3개 항목과 불일치 또는 중복. |
| 5 | URL 파싱 실패 또는 http/https 외 스킴. |
| 6 | URL에서 추출한 `host:port`가 allowlist에 없음. |
| 7 | 위 검사 뒤 남은 모든 추가 인자. |

검사 순서는 범위 → 업데이트 → 추가 인자 → allowlist 파일 → URL → 대상 대조다. PowerShell 자체의 인자 바인딩 오류는 위 래퍼 코드와 별개이며, `pwsh` 부재로 반환 코드의 모의 실행 검증은 미수행이다.

## 주의사항

- `http`/`https` 스킴만 허용. URL이 아니면 거부된다.
- Strix 이미지/CLI의 확인된 고정 버전은 아직 없다. `latest` 금지이며 실제 실행은 MVP 잔여 작업이다.
- 컨테이너 대상 주소는 같은 `targets-net` 안의 `juice-shop:3000`이다. `127.0.0.1:3000`/`localhost:3000`은 사용자 Ubuntu VM 호스트용이며, 별도 Strix 컨테이너 안에서는 그 컨테이너 자신을 가리킨다. 주소를 자동 치환하지 않는다.
- Compose의 `internal: true`를 유지한다. 외부 LLM 통신 가능 여부는 미확인이고 격리를 완화하지 않는다.
- 대상 작업은 회당 15분(900초), 같은 초기 상태에서 3회가 계약이다. 현재 래퍼에는 시간 제한·반복 관리·UTC/실행시간 기록·JSONL 자동 저장이 없다. 실제 검증은 사용자 Ubuntu VM 단계에 남긴다.
- 완결된 측정만 `logs/` JSONL에 append-only 저장한다. [기록 규칙](../../logs/README.md)과 [지표 양식](../../benchmarks/metrics.form.md)을 따른다. ground-truth 미확정 등 결측치가 있으면 관찰 메모로 남기며 0을 임의 입력하지 않는다.
- WebGoat, 외부 URL 예시는 MVP에서 사용하지 않는다 (Phase 2 이후).
