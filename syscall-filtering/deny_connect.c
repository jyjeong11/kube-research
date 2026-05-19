#include <uapi/linux/bpf.h>
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_HASH(blocked_cgroups, u64, u8);

// IPv4 connect hook
int deny_connect4(struct bpf_sock_addr *ctx)
{
    u64 cg = bpf_get_current_cgroup_id();
    u8 *val = blocked_cgroups.lookup(&cg);
    if (val)
        return -1;  // EPERM
    return 1;
}

// IPv6 connect hook
int deny_connect6(struct bpf_sock_addr *ctx)
{
    u64 cg = bpf_get_current_cgroup_id();
    u8 *val = blocked_cgroups.lookup(&cg);
    if (val)
        return -1;
    return 1;
}
