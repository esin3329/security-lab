# pwn 실습 컨테이너 (MVP)
# GDB + pwndbg + pwntools 로컬 재현용. 원격 익스플로잇 금지.
# 빌드·실행은 사용자가 직접: docker build -t pwn-lab:fixed -f pwn/Dockerfile pwn/
FROM ubuntu:24.04

# 한국어 주석: 기본 패키지 + 디버깅 도구
# 외부 네트워크 작업은 빌드 시점에만 허용, 실습 시에는 로컬 실행 원칙
ENV DEBIAN_FRONTEND=noninteractive
ENV LC_ALL=C.UTF-8

RUN apt-get update && apt-get install -y --no-install-recommends \
    gdb \
    python3 \
    python3-pip \
    python3-dev \
    git \
    file \
    checksec \
    socat \
    vim-tiny \
  && rm -rf /var/lib/apt/lists/*

# pwndbg 설치 (immutable release 2026.09.15 고정, 설치 실패 전파)
# 공식 근거:
# - release/tag 2026.09.15 (Immutable release): https://github.com/pwndbg/pwndbg/releases/tag/2026.09.15
# - commit 55596aa676a2756efb8d67034f31675170eabe48: https://github.com/pwndbg/pwndbg/commit/55596aa676a2756efb8d67034f31675170eabe48
# - tag->commit 메타데이터: https://api.github.com/repos/pwndbg/pwndbg/tags (2026.09.15 -> 위 SHA)
# - 설치법(인자 없는 ./setup.sh, legacy): https://pwndbg.re/stable/setup/
# - 지원 옵션 근거(--update/--help만 지원, --yes 미지원): https://raw.githubusercontent.com/pwndbg/pwndbg/2026.09.15/setup.sh
# - upstream Dockerfile 동일 호출: https://raw.githubusercontent.com/pwndbg/pwndbg/2026.09.15/Dockerfile (`DEBIAN_FRONTEND=noninteractive ./setup.sh`)
RUN git clone https://github.com/pwndbg/pwndbg.git /opt/pwndbg \
  && cd /opt/pwndbg \
  && git checkout 55596aa676a2756efb8d67034f31675170eabe48 \
  && test "$(git rev-parse HEAD)" = "55596aa676a2756efb8d67034f31675170eabe48" \
  && ./setup.sh

# pwntools 설치 (버전 고정 권장)
RUN pip3 install --no-cache-dir --break-system-packages "pwntools==4.14.0"

# 실습 작업 디렉터리
WORKDIR /pwn
COPY challenges/ /pwn/challenges/
COPY exploits/ /pwn/exploits/

# 최소 권한 원칙: SYS_PTRACE만 부여해 실행
# 예: docker run --rm -it --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v ./pwn:/pwn pwn-lab:fixed
CMD ["/bin/bash"]
