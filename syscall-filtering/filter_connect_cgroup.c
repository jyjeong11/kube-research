// filter_connect_cgroup.c
// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// cgroup_id -> 1
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, __u8);
} denylist SEC(".maps");

// IPv4 connect 훅
SEC("cgroup/connect4")
int block_connect4(struct bpf_sock_addr *ctx)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    __u8 *deny = bpf_map_lookup_elem(&denylist, &cgid);
    if (deny) {
        // cgroup sock_addr 훅은 0을 리턴하면 connect()가 EPERM로 거절됨
        return 0;   // deny
    }
    return 1;       // allow
}

// IPv6 connect 훅
SEC("cgroup/connect6")
int block_connect6(struct bpf_sock_addr *ctx)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    __u8 *deny = bpf_map_lookup_elem(&denylist, &cgid);
    if (deny) {
        return 0;   // deny
    }
    return 1;       // allow
}

char _license[] SEC("license") = "GPL";
