# controller.py
from kubernetes import client, config, watch
import os, subprocess

DENYLIST_MAP = "/sys/fs/bpf/connect_filter/denylist"

def put_cgroup(cgid):
    key_hex = cgid.to_bytes(8, "little").hex()
    val_hex = (1).to_bytes(1, "little").hex()
    subprocess.run([
        "bpftool", "map", "update", "pinned", DENYLIST_MAP,
        "key", "hex", key_hex, "value", "hex", val_hex
    ], check=True)

def clear_all():
    subprocess.run([
        "bpftool", "map", "delete", "pinned", DENYLIST_MAP, "key", "all"
    ], check=False)

def get_pids_on_node(pod):
    pids = []
    for pid in os.listdir("/proc"):
        if pid.isdigit():
            try:
                with open(f"/proc/{pid}/cgroup") as f:
                    if pod.metadata.uid in f.read():
                        pids.append(int(pid))
            except:
                pass
    return pids

def cgroup_id(pid):
    with open(f"/proc/{pid}/cgroup") as f:
        for line in f:
            parts = line.strip().split(":")
            if len(parts) >= 3:
                full = "/sys/fs/cgroup" + parts[2]
                return os.stat(full).st_ino

config.load_incluster_config()
v1 = client.CoreV1Api()
w = watch.Watch()
node = os.environ["MY_NODE_NAME"]

print("[*] watching pods...")

for event in w.stream(v1.list_pod_for_all_namespaces):
    pod = event["object"]
    if pod.spec.node_name != node:
        continue

    labels = pod.metadata.labels or {}
    blocked = labels.get("app") == "busybox"  # 원하는 라벨 조건

    pids = get_pids_on_node(pod)
    if blocked:
        for pid in pids:
            cg = cgroup_id(pid)
            if cg:
                print(f"[+] BLOCK pod={pod.metadata.name}, pid={pid}, cgroup={cg}")
                put_cgroup(cg)
    else:
        clear_all()
