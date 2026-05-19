from bcc import BPF
import socket
import struct
import os

# 차단할 대상 IP (nginx pod IP)
BLOCK_IP = "172.16.103.183"  # 예시, 실제 nginx pod IP로 교체 필요
BLOCK_HEX = struct.unpack("!I", socket.inet_aton(BLOCK_IP))[0]

# eBPF 프로그램 정의
bpf_text = f"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/in.h>
#include <linux/net.h>

int kprobe__sys_connect(struct pt_regs *ctx, int fd, struct sockaddr __user *uservaddr, int addrlen)
{{
    struct sockaddr_in sa = {{}};
    bpf_probe_read_user(&sa, sizeof(sa), uservaddr);

    u32 dst_ip = sa.sin_addr.s_addr;

    // 블록 대상 IP 비교
    if (dst_ip == {BLOCK_HEX})
    {{
        bpf_trace_printk("Blocked connection to {BLOCK_IP}\\n");
        // errno 설정 (연결 실패)
        return -1;
    }}

    return 0;
}}
"""

print("[+] Loading eBPF program...")
b = BPF(text=bpf_text)
print("[+] eBPF program loaded. Monitoring connect() calls...")

while True:
    try:
        (_, _, _, _, msg, _) = b.trace_fields(nonblocking=True)
        if msg:
            print(msg)
    except KeyboardInterrupt:
        exit()
