// loader.c : libbpf로 LSM(eBPF) 오브젝트 로드 & attach
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>

int main(void) {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    int err;

    // CO-RE strict mode 활성화 (이 API는 0.6 이후에서도 안정)
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    obj = bpf_object__open_file("/app/policy.o", NULL);
    if (!obj) { perror("bpf_object__open_file"); return 1; }

    err = bpf_object__load(obj);
    if (err) { fprintf(stderr, "bpf_object__load: %d\n", err); return 1; }

    prog = bpf_object__find_program_by_title(obj, "lsm/security_socket_connect");
    if (!prog) { fprintf(stderr, "program not found\n"); return 1; }

    link = bpf_program__attach_lsm(prog);
    if (!link) { fprintf(stderr, "bpf_program__attach_lsm failed\n"); return 1; }

    printf("[loader] ✅ LSM attached: security_socket_connect\n");
    for (;;) sleep(3600);
    return 0;
}
