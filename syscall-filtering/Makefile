BPF_CLANG  ?= clang
BPF_CFLAGS ?= -O2 -g -Wall -target bpf \
              -D__TARGET_ARCH_x86 \
              -I/usr/include \
              -I/usr/include/x86_64-linux-gnu

all: filter_connect_cgroup.o

filter_connect_cgroup.o: filter_connect_cgroup.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f *.o
