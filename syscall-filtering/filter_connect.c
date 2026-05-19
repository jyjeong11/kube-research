#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_HASH(blocked_cgroups, u64, u8);

int kprobe__sys_connect(struct pt_regs *ctx, int fd, struct sockaddr *uservaddr, int addrlen) {
    u64 cgroup_id = bpf_get_current_cgroup_id();

    u8 *flag = blocked_cgroups.lookup(&cgroup_id);
    if (flag) {
        bpf_trace_printk("Blocked cgroup_id: %llu\\n", cgroup_id);
        return -1;  // EPERM
    }
    return 0;
}
