from bcc import BPF
import subprocess
import os
import time

bpf_src = r"""
#include <uapi/linux/ptrace.h>
#include <linux/socket.h>

BPF_HASH(denylist, u64, u8);

int on_sys_enter_connect(struct pt_regs *ctx)
{
    u64 cg = bpf_get_current_cgroup_id();
    u8 *deny = denylist.lookup(&cg);
    if (deny) {
        bpf_override_return(ctx, -1);
    }
    return 0;
}
"""

# Load BPF
b = BPF(text=bpf_src)
b.attach_tracepoint(tp="syscalls:sys_enter_connect", fn_name="on_sys_enter_connect")

denylist = b.get_table("denylist")

def get_cgroup_id_by_pid(pid):
    with open(f"/proc/{pid}/cgroup") as f:
        for line in f:
            # cgroup v2 line format: 0::/kubepods.slice/.../docker-<container>.scope
            parts = line.strip().split(":")
            if len(parts) >= 3:
                path = parts[2]
                full = "/sys/fs/cgroup" + path
                st = os.stat(full)
                return st.st_ino   # inode == cgroup id

def add_block_pid(pid):
    cgid = get_cgroup_id_by_pid(pid)
    print(f"[+] BLOCK pid={pid}, cgroup={cgid}")
    denylist[cgid] = b"\x01"

def remove_all():
    for k, v in denylist.items():
        del denylist[k]

print("[*] syscall filter running... press Ctrl+C to stop")

# 예시 테스트: busybox pod PID 찾아 차단해보기
# 실제 K8s 연동은 아래 2단계에서

test_pid = subprocess.check_output("pidof nginx", shell=True).decode().strip().split()[0]
add_block_pid(int(test_pid))

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    remove_all()
