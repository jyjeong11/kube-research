#!/usr/bin/env python3
from bcc import BPF
from kubernetes import client, config
import ctypes as ct
import os
import time

LABEL_SELECTOR = "app=busybox"
POLL_INTERVAL = 5

print("[+] Loading eBPF program...")
b = BPF(src_file="deny_connect.c")
print("[+] eBPF program loaded successfully")

# 1) 프로그램 타입: CGROUP_SOCK_ADDR
fn4 = b.load_func("deny_connect4", BPF.CGROUP_SOCK_ADDR)
fn6 = b.load_func("deny_connect6", BPF.CGROUP_SOCK_ADDR)

# 2) attach 타입: enum 값 직접 사용 (10/11)
BPF_CGROUP_INET4_CONNECT = 10
BPF_CGROUP_INET6_CONNECT = 11

b.attach_cgroup(fn4, "/sys/fs/cgroup", attach_type=BPF_CGROUP_INET4_CONNECT)
b.attach_cgroup(fn6, "/sys/fs/cgroup", attach_type=BPF_CGROUP_INET6_CONNECT)

print("[+] Attached deny_connect4/6 to cgroup connect hooks")

blocked_map = b.get_table("blocked_cgroups")

def kube_client():
    if os.getenv("KUBERNETES_SERVICE_HOST"):
        config.load_incluster_config()
    else:
        config.load_kube_config()
    return client.CoreV1Api()

def get_local_node_name():
    return os.environ.get("NODE_NAME") or os.uname().nodename

def list_target_pods_on_node(k8s, node_name):
    pods = k8s.list_pod_for_all_namespaces(label_selector=LABEL_SELECTOR)
    return [p for p in pods.items if p.spec.node_name == node_name]

def container_id_from_status(status):
    cid = status.container_id
    return cid.split("://", 1)[1] if cid and "://" in cid else cid

def find_cgroup_path_for_container(container_id):
    for root, dirs, _ in os.walk("/sys/fs/cgroup"):
        for d in dirs:
            if container_id in d:
                return os.path.join(root, d)
        if container_id in root:
            return root
    return None

def inode_of_path(path):
    return os.stat(path).st_ino

def sync_blocked_pods():
    k8s = kube_client()
    node_name = get_local_node_name()
    print(f"[*] Running on node: {node_name}")

    while True:
        blocked_map.clear()
        pods = list_target_pods_on_node(k8s, node_name)

        for p in pods:
            statuses = p.status.container_statuses or []
            for st in statuses:
                cid = container_id_from_status(st)
                if not cid:
                    continue
                cpath = find_cgroup_path_for_container(cid)
                if not cpath:
                    continue
                try:
                    ino = inode_of_path(cpath)
                    blocked_map[ctypes.c_ulonglong(ino)] = ctypes.c_ubyte(1)
                    print(f"[+] Blocked Pod: {p.metadata.namespace}/{p.metadata.name} (inode={ino})")
                except Exception as e:
                    print(f"[!] Failed to block {p.metadata.namespace}/{p.metadata.name}: {e}")

        print(f"[*] Updated blocked_cgroups map ({len(blocked_map)} entries)")
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    import ctypes
    sync_blocked_pods()
