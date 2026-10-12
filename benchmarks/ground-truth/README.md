# ground-truth (스텁, MVP)

> 정답지 고정용 폴더. MVP에서는 형식만 정의하고 실제 정답 내용은 Phase 2에서 채운다.

현재 `juice-shop-v17.1.1.json`은 Compose의 Juice Shop `v17.1.1`과 버전만 맞춘 `findings: []` 스텁이다. `fixed_at`은 스텁 작성 시각이며 정답 확정·취약점 0건의 증거가 아니다. TP/FP 판정과 완결된 8지표 실측 비교는 차단 상태이고, 정답 내용은 이번 작업에서 추가하지 않는다.

## 형식

- 파일명: `<타겟>-<기준버전>.json` (예: `juice-shop-v17.1.1.json`)
- 스키마(예시):

```json
{
  "target": "juice-shop",
  "version": "v17.1.1",
  "fixed_at": "2026-10-12T00:00:00Z",
  "findings": [
    {"id": "GT-001", "category": "예시", "severity": "low", "check": "확인 방법(로컬)", "notes": "Phase 2에서 확정"}
  ]
}
```

## 규칙

- ground-truth 확정 후에는 수정하지 않는다. 수정 시 버전+날짜를 바꿔 새 파일로 둔다.
- 외부 익스플로잇·페이로드는 기록하지 않는다. 확인 방법만 로컬 재현 절차로 기술한다.
