# controller.py
from kubernetes import client, config, watch
import subprocess
import bpf
import re

def get_cgroup_id(pid):
    with open(f"/proc/{pid}/cgroup") as f:
        for line in f:
            m = re.search(r"0::/kubepods.*pod([^/]+)", line)
            if m:
                pod_uid = m.group(1)
                return pod_uid
    return None

def main():
    config.load_incluster_config()
    v1 = client.CoreV1Api()

    while True:
        pods = v1.list_pod_for_all_namespaces(label_selector="app=server").items
        for pod in pods:
            # find process running in this pod via container runtime
            # simplest: find cgroup_id via cgroupfs
            # assumption: using containerd
            pod_uid = pod.metadata.uid

            # lookup kernel cgroup_id via bpftool
            cmd = f"bpftool cgroup show /sys/fs/cgroup/kubepods.slice/*{pod_uid}*"
            out = subprocess.getoutput(cmd)
            for line in out.splitlines():
                if "cgroup" in line:
                    cg_id = int(line.split()[0])
                    bpf.map_update("allowed_cgroups", cg_id, 1)

            print(f"[+] Allowed pod {pod.metadata.name} (app=server)")

if __name__ == "__main__":
    main()
