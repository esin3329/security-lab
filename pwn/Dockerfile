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

# pwndbg 설치 (고정 커밋 권장: latest 추적 금지)
# 실제 커밋 해시는 사용자가 코드리뷰 후 고정할 것
# 예: git checkout <핀된-커밋-해시>
RUN git clone --depth 1 https://github.com/pwndbg/pwndbg.git /opt/pwndbg \
  && /opt/pwndbg/setup.sh --yes || true

# pwntools 설치 (버전 고정 권장)
RUN pip3 install --no-cache-dir --break-system-packages "pwntools==4.14.0"

# 실습 작업 디렉터리
WORKDIR /pwn
COPY challenges/ /pwn/challenges/
COPY exploits/ /pwn/exploits/

# 최소 권한 원칙: SYS_PTRACE만 부여해 실행
# 예: docker run --rm -it --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v ./pwn:/pwn pwn-lab:fixed
CMD ["/bin/bash"]
