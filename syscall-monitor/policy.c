// policy.c

#include "vmlinux.h"            // 커널 타입 정의 (CO-RE)
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>    // ✅ LSM / BPF_PROG 매크로 정의
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

// AF_INET = 2
#define AF_INET 2
// EACCES = 13
#define EACCES 13

SEC("lsm/security_socket_connect")
int BPF_PROG(check_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    struct sockaddr_in *addr = (struct sockaddr_in *)address;

    if (!addr)
        return 0;

    if (addr->sin_family != AF_INET)
        return 0;

    __u16 port = bpf_ntohs(addr->sin_port);

    // TEST: port 80 block
    if (port == 80)
        return -EACCES;  // block

    return 0; // allow
}
