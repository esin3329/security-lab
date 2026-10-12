# ARTEX-KO 도구 안내 (ARTEX 한국어판)

> 공식 저장소: https://github.com/jiwoochris/artex-ko (AGPL-3.0 License)  
> 역할: 승인된 범위 내 자율 공격 경로(Autonomous Attack Path) 실습 및 방어·탐지 관찰 보조 도구.

---

## 1. 개요 및 역할

- **도구 정의:** ARTEX-KO는 Go 백엔드와 Next.js 인터페이스로 구성된 자율 보안 점검 도구의 한국어 지원 프로젝트입니다.
- **CTF / KoTH 실습 역할:**
  - **자율 공격 경로 분석:** 허용된 로컬 대상에 대해 자율적인 공격 경로를 탐색하고, 시스템 취약점 연계 가능성을 분석합니다.
  - **KoTH 방어 및 탐지 관찰:** Hill 타겟에 대한 공격 시도를 관찰하여 방어팀 입장에서 탐지 로그를 분석하고, 실시간 패치 효과성을 검증하는 데 활용을 검토합니다.
  - **판정 원칙:** 도구가 공격 경로를 발견했다고 해서 깃발 획득이나 점유로 자동 인정되지 않으며, 실제 king marker 갱신과 외부 judge 검증을 거쳐야 합니다.

---

## 2. 현재 상태 및 사용 경계

- **설치/진단/실행 컨트롤러 통합 완료:**
  - `tools/lab/artex_tool.py` (`python3 tools/lab/practice.py --tool artex <install|doctor|run>`)가 ARTEX-KO 공식 GHCR 이미지(digest 고정), PostgreSQL(digest 고정), 격리망(`internal: true` 전 구간 강제), 로컬 관리자/LLM 설정 기반의 설치·기동·scoped task 생성 컨트롤러를 구현한다. 세부 핀은 `tools/artex-ko/pin.json`과 `docker-compose.pinned.yml` 참조.
  - 관리자 설정, DB 패스워드, LLM API 키는 Git 밖의 operator private state 및 환경 변수에만 보관하며 기본 모델/키를 하드코딩하지 않습니다.
- **라이선스 요구사항:**
  - AGPL-3.0의 수정·배포·서비스 제공 관련 의무를 확인합니다. 소유한 환경 또는 서면 허가된 로컬 lab으로 제한하는 것은 본 프로젝트의 사용 정책입니다.
- **실행 환경 및 미설치 상태:**
  - 사용자 선택에 따라 실행 환경은 **기존 Ubuntu VM**으로 확정되었으나, SSH BatchMode timeout으로 인해 현재 접속 준비 상태입니다. `infra/deploy.py`로 코드 배포 전까지 VM에 ARTEX-KO를 설치하지 않습니다.
  - 코드 통합은 완료했으나 실제 VM 환경에서 ARTEX-KO 컨테이너 기동, 공격 경로 탐색 실습은 **미실행** 상태입니다.
- **외부 사이트 공격 절대 금지:**
  - TryHackMe KoTH 등 공용 실습 사이트를 대상으로 한 Strix/ARTEX 자동화 공격은 엄격히 금지됩니다 (TryHackMe Rule 7: 자동 해킹 스크립트 금지 규정 준수).
  - 허용 목록 3개(`juice-shop:3000`, `127.0.0.1:3000`, `localhost:3000`)에 외부 사이트를 추가하지 않습니다.

---

## 3. 보안 및 기록 규칙

- **자율 생성 페이로드 저장 금지:** 도구가 시도한 원시 페이로드, 익스플로잇 코드, 비인가 계정 접근 정보는 저장소나 보고서에 남기지 않습니다.
- **관찰 요약 기록:** 공격 경로 식별 결과, 방어 탐지 로그의 핵심 요약, 패치 전후 상태 변화만을 한국어로 기록합니다.

