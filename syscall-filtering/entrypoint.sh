#!/bin/bash
set -e

if ! mount | grep -q '/sys/fs/bpf type bpf'; then
    mount -t bpf bpf /sys/fs/bpf
fi

mkdir -p /sys/fs/bpf/connect_filter

echo "[*] loading eBPF program..."
bpftool prog loadall /app/filter_connect_cgroup.o /sys/fs/bpf/connect_filter

CGROOT=/sys/fs/cgroup
echo "[*] attaching to root cgroup..."
bpftool cgroup attach $CGROOT connect4 pinned /sys/fs/bpf/connect_filter/block_connect4 || true
bpftool cgroup attach $CGROOT connect6 pinned /sys/fs/bpf/connect_filter/block_connect6 || true

echo "[+] connect filter active. starting controller..."
exec python3 /app/controller.py
