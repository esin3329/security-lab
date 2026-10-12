# Targets (CTF·KoTH 실습 대상 기술 계약)

> 주 목표: 각 도구를 활용한 깃발 획득 CTF와 King of the Hill(KoTH) 실습.
> 실습 사이트는 문제 선택·기초 학습·힌트·규칙 참고와 허가받은 수동 실습의 보조 수단이다.
> 이 문서는 경계·판정·타이밍·운영 계약만 정의한다. flags/scoreboard/game/VM/도구 설치와
> 실행은 구현·실행되지 않았다고 기록한다.

## 1. 목표 전환과 이 파일의 범위

- 이전 benchmark-primary 안내에서 CTF/KoTH-primary·사이트 auxiliary로 전환한다.
- `benchmarks/metrics.schema.json`·`metrics.py`는 완결된 벤치마크 기록만 처리하는 별도
  기능으로 보존한다. CTF/KoTH 기록을 8지표에 억지로 넣지 않으며, 8지표나
  ground-truth 미확정을 CTF/KoTH의 선행 차단 조건으로 안내하지 않는다.
- 기존 Strix 수정은 미통합·미검증 중지 상태이며, REA/ARTEX-KO/pwn도 실제 설치·실행이 없다.
  어떤 도구·게임도 실행 가능한 완성 상태로 광고하지 않는다.
- 실제 플래그·CTF_KEY·API key·비밀번호·원시 도구 출력·완성 공격 코드/쉘코드/문제별 풀이를
  문서·Git에 보관하지 않는다. 안전 기록은 round/challenge 식별자, 도구와 버전, 수행 단계,
  판정 결과·확인 receipt, 검증된 점유 tick/시간, 방어 변경 요약과 한계뿐이다.

## 2. CTF 주 흐름: 버전 고정 Juice Shop의 flag mode (현재/후속 구분)

- 현재 `infra/compose.targets.yml`의 Juice Shop `v17.1.1`에는 `NODE_ENV=ctf`와
  event별 private `CTF_KEY` 설정이 없다. 현 구성을 이미 CTF flag mode로 실행한 것으로
  쓰지 않는다.
- 후속 작업에서 로컬 VM에 CTF mode를 구성한다. 공식 근거:
  `NODE_ENV=ctf` + `config/ctf.yml`, `CTF_KEY` 환경 변수로 기본 `ctf.key` 재정의 —
  https://pwning.owasp-juice.shop/companion-guide/latest/part4/ctf.html
- 고정 버전 확인값: `config/ctf.yml`의 `ctf.showFlagsInNotifications: true` —
  https://raw.githubusercontent.com/juice-shop/juice-shop/v17.1.1/config/ctf.yml
- 한 참가자/인스턴스 원칙을 지킨다. Juice Shop은 공식 문서에서 single-user
  application으로 명시되므로, 팀·참가자 간 공유 인스턴스를 쓰지 않는다. 중앙 호스팅이
  필요하면 공식 Multi Juicer 계열을 별도 승인 후 검토한다.
- 실제 flag code는 해당 버전 애플리케이션이 생성하고 실제 판정 결과로 확인한다.
  같은 event의 참가 인스턴스와 score server는 같은 비밀 키를 사용하며 키를 공개하지 않는다.
- 판정은 실제 flag/receipt로만 한다. 순서: 도구 정찰/분석 → 승인된 로컬 문제 해결 →
  실제 flag code 확인 → 로컬 판정/플랫폼 수동 제출 receipt 확인 → 안전한 관찰 기록/초기화.
  도구가 보조했다는 이유만으로 flag 획득 성공 판정을 하지 않는다.
- Scoreboard는 CTFd 등 후속 승인 시 `juice-shop-ctf-cli` 계열로 구성하며, 아직
  scoreboard/flag judge를 구현했다고 쓰지 않는다. 참가자는 score server UI에 flag를
  직접 입력한다(런타임 의존성 없음).
- Phoenix Stack Zero 성공 메시지는 실제 CTF flag가 아니다. 임의 플래그로 바꾸거나
  획득했다고 주장하지 않으며, 기초 pwn 학습용 보조 문제로 유지한다.
- 처음은 로컬 솔로 CTF 1개 → 도구별 근거와 flag 판정 → 반복 가능한 reset.
  CTFd/추가 인스턴스/공동 대회는 필요와 명시 승인 기준 후 구성한다.

## 3. KoTH 기술 계약: ownership / judge / timing / service / rules / reset

- Hill은 Juice Shop이 아니라 별도 소유·허가된 재설정 가능 VM이다. Juice Shop을 다중
  참가자 공유 hill로 그대로 쓰지 않는다.
- 처음은 한 운영자가 공격/방어 두 역할을 교대로 실습하고, 이후 같은 허가 로컬 범위에서
  두 팀/도구 프로필로 확장한다. 개발 에이전트 이름을 참가자 권한·격리로 쓰지 않는다.
- 실제 점유 조건: lab의 보호된 king marker에 사전 승인 participant ID를 기록할 권한을
  획득하고, target 밖 보호된 외부 판정기가 읽어 확인하는 것이다. 모델의 성공 주장이나
  score API 임의 POST를 실제 점유로 인정하지 않는다. 재점유는 marker 변경을 외부
  판정기가 확인한 전환이다.
- 판정/기록/라운드 제어는 contest VM 밖 보호된 관리 영역에 둔다. target을 획득해도
  score DB·clock·reset 권한을 획득하지 않도록 분리한다. 참가자는 타겟만 공격하며
  판정기·관리망·다른 참가자 기기는 공격하지 않는다.
- 타이밍: 기본 로컬 훈련 라운드는 15분이며, 판정기는 예컨대 5초마다 유효 participant
  marker와 필수 서비스 상태를 함께 관측하고 검증된 tick만 점수에 반영한다.
  15분 round와 예시 5초 tick은 scanner 900초와 별개 개념이다. 실제 tick/round 값은
  후속 구현에서 명시적 고정 설정으로 기록해야 하며, 이 문서의 수치는 예시로서 고정값이 아니다.
- sampling 관측을 연속 점유 시간의 완전한 증거로 광고하지 않는다. invalid/missing
  marker, 서비스 실패, 판정 관측 오류를 실제 성공·연속 시간으로 메우지 않고 안전한
  상태·근거로 구별해 기록한다.
- 운영 단계: 참가/허가 준비 → 접근 획득 → marker 점유 확인 → 허용 방어·패치로 유지 →
  상대 역할 재점유 시도 → 종료 집계 → snapshot reset. 일시적 실습 범위 내에서만 수행하며
  외부 지속성·계정 탈취·파괴·DoS·모든 통신 차단·flag/판정기 변조는 금지한다.
- 역할 경계: 운영자는 범위·참가자 승인·clock/score/reset 권한을 쥐고, 참가자는 타겟 내
  허용 행위만 하며, 판정기는 독립 관측·판정만 한다. 서비스/통신 유지는 참가자의 방어
  의무이며, 라운드 종료·reset 선언은 운영자·판정기 권한이다.
- 결과물은 실제 검증된 flag, 점유 tick/점유 전환, 서비스 유지 여부, 방어 변경 및
  재현·초기화 근거다. 불완전/미검증은 그 상태 그대로 기록한다.

## 4. 허용 범위와 금지 행위

- 허용 범위는 소유한 로컬 격리 lab뿐이다.
- 금지: 공용 사이트 자동화/스캔, 판정/관리 영역·타 참가자 기기 공격,
  DoS/파괴/모든 통신 차단/외부 지속성/계정 탈취/flag 또는 판정 조작.
- 기존 allowlist 3개(`juice-shop:3000`, `127.0.0.1:3000`, `localhost:3000`)와
  targets-net `internal: true`/loopback 바인딩을 변경하지 않는다. 새 hill이 이미 그
  allowlist에 승인됐다고 하지 않으며, 어떤 사이트 링크도 allowlist에 추가하지 않는다.
- 개발 worktree는 파일 충돌을 줄이는 작업 공간이며 공격/방어 역할의 보안 격리 수단이
  아니다. 실제 참가자/타겟/판정기는 VM/실습망으로 별도 격리한다.

## 5. 보조 사이트 경계 (사이트 제약을 로컬 규칙보다 우선)

- Dreamhack https://dreamhack.io/wargame/ — 웹/pwnable/reversing 교육 문제와 기본 학습.
  명시된 문제·계정·규칙 범위의 수동 실습/허용된 다운로드만 보조한다.
- pwn.college https://pwn.college/ — 시스템/바이너리 실습. 공식 규칙은 문제 해설·
  writeup·솔루션 영상의 인터넷 공개를 하지 말라고 요청한다. 저장소에 문제별 정답·
  플래그·공개 풀이를 추가하지 않는다.
- TryHackMe KoTH https://help.tryhackme.com/en/articles/6498315-king-of-the-hill-overview —
  KoTH 규칙·수동 실습 참고. 공식 rule 7은 자동 hacking/hardening scripts 금지이므로
  Strix/ARTEX 자동화 대상으로 안내하지 않는다. 공식 게임 60분/분당 점수 등은 별도
  규칙이며 로컬 15분 예시와 동일한 운영/점수를 주장하지 않는다.
- 사이트 자체·공용 infrastructure·다른 플레이어 공격은 금지다. 사이트 제약이 로컬 실습
  규칙과 다르면 사이트 제약을 우선한다.

## 6. 공식 출처 및 실행 환경 준비 상태

- CTF 구성·single-user 제한·flag/score server 근거:
  https://pwning.owasp-juice.shop/companion-guide/latest/part4/ctf.html
- 고정 버전 ctf.yml 확인값:
  https://raw.githubusercontent.com/juice-shop/juice-shop/v17.1.1/config/ctf.yml
- KoTH 규칙 참고:
  https://help.tryhackme.com/en/articles/6498315-king-of-the-hill-overview
- **실행 환경 및 연결 상태 (확인된 사실):**
  - 사용자 선택에 따라 실제 Docker/도구/게임 실행 환경은 **기존 Ubuntu VM**(Tailscale 노드명 `<operator-vm>`)으로 결정되었습니다.
  - 일반 OpenSSH(Windows SSH config, BatchMode)는 `authorized_keys` 미등록으로 거부되었으나, 그 VM에서 Tailscale SSH(`sudo tailscale up --ssh`)를 켠 뒤 `infra/ssh-tailscale.sh` 어댑터로 `infra/deploy.py check`가 **실제로 성공**했습니다 (Ubuntu 26.04, Python 3.14.4 확인).
  - 이는 연결·인증 확인일 뿐입니다. 실제 대상 실행, 도구 설치, 스캔, 플래그 제출, `infra/deploy.py deploy`는 아직 수행하지 않았으며, 실제 VM 설치·flag·게임 성공을 주장하지 않습니다.
- **Secret 및 State 격리 정책:**
  - `CTF_KEY`, event ID, SSH credentials, KoTH judge state(sqlite/json)는 Git 밖의 operator 전용 runtime 디렉터리에 `0700`/`0600` 권한으로 보관하며, Git 저장소나 stdout에 노출하지 않습니다.
- **현재 구현 및 실행 상태:**
  - `practice/ctf-runtime`, `practice/koth-runtime`, `practice/tool-integration`의 컨트롤러 코드(`tools/ctf/`, `tools/koth/`, `tools/lab/`)와 `infra/deploy.py` 배포 경로를 코디네이터가 `main`에 통합했습니다. 컴파일·`--help`·기존 단위 테스트·`deploy.py plan`은 통과했습니다.
  - `infra/deploy.py`의 실제 `--target` SSH `check`는 `infra/ssh-tailscale.sh` 어댑터로 성공했습니다(위 항목 참조). 그 외 실제 VM 내 CTF mode 기동, per-event CTF_KEY 주입, scoreboard/judge 운영, hill VM 기동, 외부 판정기 tick 실행, snapshot reset, 모든 도구 설치·실행·flag 제출, `infra/deploy.py deploy`(실제 소스 전송)는 여전히 미구현·미실행입니다.
  - 본 문서 정합 작업에서 VM/Docker/Strix/ARTEX/REA/pwn의 실제 실행과 git 커밋 외의 범위(새 기능 구현)는 수행하지 않았습니다.
