# REA 도구 안내 (Reverse Engineer Anything)

> 공식 저장소: https://github.com/morluto/rea (MIT License)  
> 역할: 바이너리 리버싱 엔지니어링 및 MCP(Model Context Protocol) 기반 근거 분석 보조 도구.

---

## 1. 개요 및 역할

- **도구 정의:** REA(Reverse Engineer Anything)는 MCP 인터페이스를 통해 바이너리 분석, 디스어셈블리, 함수 구조 파악 및 리버스 엔지니어링 근거를 제공하는 보조 도구입니다.
- **CTF / KoTH 실습 역할:**
  - **로컬 바이너리 CTF:** 다운로드 및 로컬 실습이 허용된 바이너리 문제의 함수 구조, 보호 기법, 입력 처리 흐름을 분석하여 취약점 지점 파악을 보조합니다.
  - **KoTH 방어/공격 분석:** Hill 타겟 내 서비스 바이너리의 잠재적 결함을 분석하거나 패치 방안 수립의 기술적 근거를 제공합니다.
  - **판정 원칙:** REA의 분석 출력 자체는 깃발 획득이나 점유의 증거가 아니며, 실제 검증된 flag receipt 또는 외부 judge의 점유 확인으로만 결과를 판정합니다.

---

## 2. 현재 상태 및 구현 경계

- **설치/진단/실행 컨트롤러 통합 완료:**
  - `tools/lab/rea_tool.py` (`python3 tools/lab/practice.py --tool rea <install|doctor|run>`)가 REA 공식 release pin(`rea-agents@6.4.0`, commit `a56f7bb668ab23fec8d33f7af353ac7ed2fe1895`, npm tarball sha512/shasum, 선택적 Ghidra 12.1.4 sha256) 기반으로 설치·sha 검증·MCP 실행을 구현한다. 세부 핀은 `tools/rea/pin.json` 참조.
  - REA는 로컬 허가 아티팩트의 디스어셈블리 및 MCP 분석만 지원하며, 외부 임의 시스템에 대한 역공학에는 사용하지 않습니다.
- **실행 환경 및 미설치 상태:**
  - 사용자 선택에 따라 실행 환경은 **기존 Ubuntu VM**으로 확정되었으나, SSH BatchMode timeout으로 인해 연결 준비 상태입니다. `infra/deploy.py`로 코드 배포 전까지 VM에 REA를 설치하지 않습니다.
  - 코드 통합은 완료했으나 실제 VM 환경에 REA는 **미설치** 상태이며, 설치·진단·실행 명령을 실제로 수행하지 않았습니다.

---

## 3. 보안 및 기록 규칙

- **원시 도구 출력 보관 금지:** REA의 대량 디스어셈블리 덤프나 원시 모델 대화 로그를 저장소에 기록하지 않습니다.
- **풀이(writeup) 및 페이로드 배제:** 분석을 통해 도출된 핵심 오프셋이나 로직 요약만 한국어 관찰 메모로 남기며, 완성된 익스플로잇이나 문제별 풀이 전체를 Git에 보관하지 않습니다.

