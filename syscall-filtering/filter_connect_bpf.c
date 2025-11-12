// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

/* cgroup_id → 1(deny) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, __u8);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} denylist SEC(".maps");

/* LSM connect filter */
SEC("lsm/socket_connect")
int BPF_PROG(block_connect, struct socket *sock, struct sockaddr *addr, int addrlen)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    __u8 *deny = bpf_map_lookup_elem(&denylist, &cgid);

    if (deny)
        return -1;  // ✅ = -EPERM, no headers required, always correct

    return 0;
}
