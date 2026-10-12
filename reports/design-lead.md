# security-lab — 도구 중심 CTF·King of the Hill 작업계획

- 방향 변경: 2026-10-12. 사용자의 요청에 따라 **각 도구를 활용한 깃발 획득(CTF)과 King of the Hill(KoTH) 실습을 주 목표**로 한다.
- 실습 사이트는 학습·문제 선택·힌트·규칙·허가된 수동 실습을 보조한다. 사이트 링크를 추가한다고 외부 자동 스캔을 허가하지 않는다.
- 기존 8지표 벤치마킹은 완결된 관찰 자료가 있을 때 사용하는 보조 기능이다. 벤치마킹 완료나 ground-truth 확정을 새 실습의 선행조건으로 삼지 않는다.
- 이번 변경은 실습 모델·문서·후속 작업 경계를 정하는 작업이다. 실제 CTF/KoTH 게임, 판정기, REA/ARTEX 연동을 구현·실행했다고 주장하지 않는다.
- 기존 배정 및 통합 이력은 [최종 통합 보고서](final-integration.md), 검증 증거는 [검증 메모](../logs/validation-2026-10-12.md)에 보존한다.

## 1. 현재 산출물과 재사용 경계

| 영역 | 실제 있는 것 | 현재 한계 |
|---|---|---|
| 실습 기반 | Juice Shop `v17.1.1`, `targets-net`의 `internal: true`, loopback 바인딩, named volume | 컨테이너 기동/연결 미실행. 현재 Compose에 CTF mode와 event별 `CTF_KEY` 설정이 없다. |
| pwn 환경 | Ubuntu `24.04`, `pwntools==4.14.0`, pwndbg `55596aa676a2756efb8d67034f31675170eabe48` 고정 및 설치 실패 전파 | Docker 빌드와 GDB/pwndbg/pwntools 동작은 사용자 VM에서 미검증. Phoenix Stack Zero는 기초 실습이며 실제 flag-bearing 문제로 가장하지 않는다. |
| Strix | 기존 원본 입력 검사/dry-run, 별도 worktree의 실행·격리·기록 수정 | 실제 binary 미설치. worktree 수정은 안전 체크포인트에서 중지했고 원본 미통합·미검증이다. 임시 경로 소유권 및 sidecar 오류 정합 등 잔여가 있다. |
| REA / ARTEX-KO | 도입 안내 및 확인한 공식 프로젝트 | 실제 설치·핀·wrapper·연동 미구현. 도구별 실습 성공을 주장하지 않는다. |
| 보조 벤치마킹 | `metrics.schema.json`, `metrics.py`, `requirements.txt`와 회귀 테스트 | CLI append·정책 거부·바이트 보존·동시 중복 스모크 및 3개 회귀 테스트 통과. 합성 임시 자료이며 실측/플래그 획득이 아니다. |
| KoTH | 이 문서의 점유·판정·방어·초기화 계약 | 별도 hill VM, 참가자 격리, 보호된 판정기·점수 수집은 아직 구성/구현하지 않았다. |

현재 CLI 경로 확인에서는 `rea`, `artex-ko`, `artex`, `strix`, `gdb` 실행 파일이 없고 `python3`만 확인됐다. 설치된 이미지나 작동한 도구를 추정하지 않는다.

## 2. CTF: 실제 깃발 획득 흐름

1. **문제와 허가 범위 선택:** 로컬 소유 환경과 고정 버전, 문제/라운드 식별자, 초기 상태를 확인한다. 사이트 자료를 가져오려면 다운로드·로컬 재현이 허용된 문제만 사용한다.
2. **도구 활용:** 웹은 Strix/ARTEX-KO의 분석·승인 범위 내 시도, 바이너리는 REA/GDB/pwndbg의 근거 분석과 pwntools의 로컬 입출력·재현 보조를 이용한다. 도구의 추측이나 취약점 보고 자체는 깃발 획득 증거가 아니다.
3. **실제 flag 확인:** 문제의 실제 flag code/validator와 대조한다. 성공 메시지나 임의로 만든 토큰을 실제 플래그라고 부르지 않는다.
4. **판정 확인:** 로컬 판정 결과 또는 사용자가 플랫폼에서 직접 제출한 receipt로 정답 여부를 확인한다. 실제 flag/secret은 판정 환경에서만 다루고 공개 기록에 넣지 않는다.
5. **안전한 기록과 reset:** 도구·버전·문제/라운드·수행 단계·판정 receipt·한계를 남기고 다음 시도 전에 초기 상태로 복구한다.

### 첫 웹 실습 기준

기존 Juice Shop을 재사용한다. 공식 문서의 `NODE_ENV=ctf`와 event별 비공개 `CTF_KEY` 구성이 필요하며, 고정 `v17.1.1/config/ctf.yml`의 `ctf.showFlagsInNotifications: true`를 직접 확인했다. 현재 이 설정을 배포하거나 flag를 획득하지는 않았다.

처음은 솔로 1개 인스턴스로 시작한다. 공식 문서는 Juice Shop을 single-user application으로 설명하고 참가자별 인스턴스를 권고하므로, 여러 참가자가 동일 인스턴스를 공유하는 경쟁 환경으로 자동 확장하지 않는다. CTFd와 추가 인스턴스는 후속 필요·버전·허가를 확인해 구성한다. 공개 기본 CTF key와 upstream의 미고정 이미지/외부 기본 URL은 복사하지 않는다.

### 바이너리 실습 기준

Phoenix Stack Zero는 메모리·디버깅 기초를 배우는 보조 문제로 유지한다. 실제 CTF 깃발 실습은 허가된 flag-bearing 문제와 그 판정 조건을 선정한 뒤 별도 배정한다. 문제 바이너리·정답·완성 공격 코드·쉘코드를 저장소에 포함하지 않는다.

## 3. KoTH: 점유와 방어를 실제로 확인하는 실습

### 환경과 신뢰 경계

- Hill은 **별도의 소유·허가된, snapshot/reset 가능한 VM**이다. Juice Shop을 다중 참가자 공유 hill로 그대로 사용하지 않는다.
- 첫 훈련은 한 운영자가 공격/방어 두 역할을 교대로 실습한다. 이후 같은 허가 범위에서 두 팀/도구 프로필로 확장한다.
- 개발용 Git worktree와 Herdr pane은 파일 수정 격리일 뿐 참가자·타겟의 보안 격리가 아니다.
- 판정기·점수 DB·clock·라운드 reset 제어는 contest VM 밖의 보호된 관리 영역에 둔다. 타겟을 점유해도 판정기/관리망을 공격하거나 점수를 임의로 바꾸지 못하도록 분리한다.

### 실제 점유와 점수

- 승인된 참가자 ID를 lab의 보호된 king marker에 기록할 권한을 얻고, 외부 판정기가 이를 읽어 확인해야 점유로 인정한다. 모델의 성공 주장이나 score API의 임의 요청은 점유가 아니다.
- 다른 유효 참가자 ID로 marker가 바뀌고 판정기가 확인한 경우를 점유 전환으로 기록한다. 비어 있거나 알 수 없는 ID, 판정 실패는 점수를 주지 않는다.
- 기본안은 로컬 훈련 15분, 판정 5초 tick이다. 유효 ID와 필수 서비스 가용성을 확인한 tick만 점수로 집계한다. 관측된 tick을 실제 연속 점유 시간의 완전한 증거로 주장하지 않는다. 이 값은 후속 구현에서 명시적 라운드 설정으로 고정·기록한다.
- 준비/허가 확인 → 접근 획득 → 점유 확인 → 허용된 패치·방어로 유지 → 상대 역할의 재점유 시도 → 종료 집계 → snapshot reset의 순서를 따른다.

### 훈련 규칙

로컬 훈련의 자동 도구 사용 범위와 시간창을 사전에 정한다. 타겟 외 공격, 판정기/관리망/참가자 기기 공격, DoS·shutdown·서비스 전체 차단, 플래그/판정 변조, 실습 이후의 지속성 확보는 금지한다. 방어는 필수 서비스를 유지하는 범위에서 수행하고 변경과 복구 방법을 기록한다.

TryHackMe 공식 KoTH는 60분 등 자체 운영·채점 규칙을 갖는다. 로컬 훈련 기본안과 동일한 경기나 점수라고 하지 않으며, 특히 공식 rule 7의 자동 hacking/hardening script 금지를 우선한다.

## 4. 도구별 실습 역할

| 도구 | 실습에서 맡을 일 | 도입/운영 조건 |
|---|---|---|
| Strix | 로컬 웹 표면 탐색·검증, CTF 시도 근거 수집 | 기존 수정 재사용 여부와 안전 경계를 새 목표에 맞춰 검증. 실제 flag 판정과 분리. |
| ARTEX-KO | 허가된 로컬 범위의 자율 공격 경로 실습과 방어·탐지 관찰 | [jiwoochris/artex-ko](https://github.com/jiwoochris/artex-ko), AGPL-3.0. 버전·설정·외부 모델/통신·배포 의무 확인 후 연동. |
| REA | 리버싱·바이너리/런타임 근거 분석 | 문서 기준은 [morluto/rea](https://github.com/morluto/rea), REA: Reverse Engineer Anything/MCP, MIT. 실제 host/toolchain과 고정 버전 확인 후 연동. 아직 설치하지 않음. |
| GDB / pwndbg | 실행·메모리·분기 관찰, 실제 판정 조건 확인 | 기존 고정 환경을 사용자 VM에서 빌드/검증. |
| pwntools | 허가된 로컬 문제의 입출력·재현 보조 | 실제 flag-bearing 문제 선정·허가 확인. 공개 완성 공격 코드는 보관하지 않음. |

도구가 도움을 준 것, 취약점을 주장한 것, 실제 flag가 판정된 것을 각각 구분한다. REA와 ARTEX-KO를 이미 구현된 wrapper나 실행 가능한 인터페이스로 표시하지 않는다.

## 5. 보조 실습 사이트

| 사이트 | 보조 용도 | 우선할 제약 |
|---|---|---|
| [Dreamhack 워게임](https://dreamhack.io/wargame/) | 한국어 학습, 웹/pwnable/reversing 문제 선택과 허가된 수동 실습 | 문제/계정/다운로드의 허가 범위 확인. 링크를 자동 스캔 대상으로 등록하지 않음. |
| [pwn.college](https://pwn.college/) | 시스템·바이너리 실습과 기초 학습 | 공식 rules의 공개 writeup·문제 솔루션 영상 제한을 지킴. 정답/flag를 저장소에 공개하지 않음. |
| [TryHackMe KoTH 규칙](https://help.tryhackme.com/en/articles/6498315-king-of-the-hill-overview) | 점유·방어·점수 규칙 참고와 플랫폼에서 허가된 수동 실습 | 자동 hacking/hardening scripts 금지. Strix/ARTEX 자동화 대상이 아님. |

사이트 이용 자체, 로그인, 규칙 동의, 플래그 제출은 이번 작업에서 수행하지 않았다. 새 링크를 기존 `targets.allow`에 추가하지 않는다.

## 6. 작업 분담과 후속 배정

고정 설계자/구현자/검토자 대신 **작업마다 하나의 수정 소유자와 완료 기준**을 둔다. 가용 에이전트·실제 pane·checkout을 확인해 배정하며 완료 후 다음 작업을 새로 맡긴다. agy는 문서·잡무를 유지한다.

이번 방향 전환은 병렬로 분담한다.

- **KoTH 타겟 기술 계약:** opencode가 `.worktrees/pwn-environment`의 `targets/README.md`만 수정한다.
- **진입·도구·보조 사이트·기록 안내:** agy가 `.worktrees/docs`의 지정 README/양식만 수정한다. `targets/README.md`와 기술 파일·코디네이터 보고서는 제외한다.
- **코디네이터:** 원본 작업계획·과거/현재 결과의 구분, 소유 경로 검수·통합·상태 보고.
- **기존 Strix 수정:** `.worktrees/strix-runtime`에 보존하고 현재 구현 작업은 중지한다. 새로운 CTF/KoTH 기능 완료로 통합하지 않는다.

새 구현 배정은 다음과 같이 나누며, 기존 파일의 동시 수정은 금지한다.

| 작업 묶음 | 범위와 의존 | 관찰 가능한 완료 기준 |
|---|---|---|
| 로컬 CTF 기반 | Juice Shop CTF mode, 비공개 event key, 실제 판정/초기화 | 사용자 VM에서 실제 flag code와 판정 receipt 확인, 다음 시도의 초기 상태 복구 |
| 도구 연동·실습 절차 | Strix 수정 검증 및 REA/ARTEX 실제 고정 버전·입력/출력·허가 경계 확인 | 설치된 실제 도구로 승인 target/문제만 처리하고 flag 판정과 안전한 기록을 연결 |
| KoTH 기반 | 별도 owned VM, marker 권한, 외부 판정/tick/서비스 확인, 라운드 reset | 실제 점유·재점유와 서비스 상태를 확인하고 보호된 점수 집계 및 reset 검증 |
| 문서·보조 자료 | 확정 인터페이스 인계 후 agy가 안내/사이트/기록 정합 | 구현과 일치하고 미실행·미측정·판정 유보를 숨기지 않는 사용 안내 |

현재 파일이 제공하는 사실로 결정할 수 없는 VM target/image·snapshot 운영·새 도구 설치/모델 설정은 해당 구현 작업의 선행조건이다. 이번 문서 변경으로 실제 VM 실행이나 외부 대상 자동화를 승인한 것으로 해석하지 않는다.

## 7. 기록과 보존

CTF/KoTH 주 기록은 문제·라운드·도구/버전·판정 receipt·검증된 점유 tick/전환·서비스 상태·방어/복구 요약이다. 실제 flag/key/credential은 공개 기록에서 제외한다.

기존 `benchmarks/metrics.schema.json`과 `tools/strix/metrics.py`는 완결된 별도 벤치마크의 기존 계약(8지표·15분·반복 1~3)을 유지한다. 새 실습 기록을 그 스키마에 억지로 넣거나 결측치를 0/null로 채우지 않는다. TP/FP 비교는 기존 ground-truth 미확정으로 여전히 차단이지만, 이 상태를 CTF/KoTH 자체의 불가능 판정으로 확대하지 않는다.

현재 원본의 검증된 보조 기록기와 pwn 수정, 과거 통합 이력 및 worktree의 중지된 변경을 보존한다. 검증하지 않은 코드·빌드·게임·실제 플래그 성공을 완료라고 하지 않는다.

## 공식 근거

- [Juice Shop CTF 운영 문서](https://pwning.owasp-juice.shop/companion-guide/latest/part4/ctf.html): 실제 flag code, `NODE_ENV=ctf`, `CTF_KEY`, 참가자별 인스턴스/score server.
- [고정 v17.1.1 CTF 설정](https://raw.githubusercontent.com/juice-shop/juice-shop/v17.1.1/config/ctf.yml): flag notification 설정 확인.
- [TryHackMe KoTH 공식 개요/규칙](https://help.tryhackme.com/en/articles/6498315-king-of-the-hill-overview): 점유·방어·플래그·자동화 제한.
- [pwn.college 공식 rules](https://pwn.college/): 공개 풀이 제한.
- [Phoenix Stack Zero](https://exploit.education/phoenix/stack-zero/): 기초 로컬 pwn 학습.
