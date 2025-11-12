FROM ubuntu:22.04 AS build

RUN apt-get update && apt-get install -y \
    clang llvm gcc make git libbpf-dev libelf-dev libz-dev pkg-config

WORKDIR /app

# 정책 및 커널 BTF 헤더
COPY policy.c .
COPY vmlinux.h .

# eBPF CO-RE 오브젝트 빌드
RUN clang -O2 -g -Wall \
    -target bpf \
    -D__TARGET_ARCH_x86 \
    -c policy.c -o policy.o

# userspace loader
COPY loader.c .
RUN gcc -O2 -Wall loader.c -o loader $(pkg-config --cflags --libs libbpf) -lelf -lz

# --- Runtime Stage ---
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    python3 python3-pip iproute2 libelf1 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=build /app/policy.o /app/policy.o
COPY --from=build /app/loader   /app/loader
COPY controller.py /app/controller.py

# 먼저 LSM attach, 이후 컨트롤러 실행(필요시)
CMD ["/bin/bash","-c", "\
  echo '[+] Attaching LSM via libbpf loader' && \
  /app/loader & \
  echo '[+] Running controller' && \
  python3 /app/controller.py \
"]
