//go:build with_ebpf && (linux || android) && cgo

#include "native/singbox_ebpf.h"

#include <errno.h>

int bpf2socks_interface_policy_start(
    const struct bpf2socks_policy_config *policy,
    struct bpf2socks_bpf_runtime *runtime) {
    (void)policy;
    (void)runtime;
    return 0;
}

void bpf2socks_interface_policy_stop(struct bpf2socks_bpf_runtime *runtime) {
    (void)runtime;
}

int bpf2socks_sk_lookup_probe(bool enable_ipv6, char *message, size_t message_size) {
    (void)enable_ipv6;
    (void)message;
    (void)message_size;
    errno = ENOTSUP;
    return -1;
}

int bpf2socks_sk_lookup_start(
    const struct bpf2socks_policy_config *policy,
    const struct bpf2socks_runtime_config *config,
    struct bpf2socks_bpf_runtime *runtime) {
    (void)policy;
    (void)config;
    (void)runtime;
    return 0;
}

int bpf2socks_splice_probe(char *message, size_t message_size) {
    (void)message;
    (void)message_size;
    errno = ENOTSUP;
    return -1;
}

int bpf2socks_prerouting_policy_probe(
    const struct bpf2socks_runtime_config *config,
    bool enable_ipv6,
    char *message,
    size_t message_size) {
    (void)config;
    (void)enable_ipv6;
    (void)message;
    (void)message_size;
    errno = ENOTSUP;
    return -1;
}
