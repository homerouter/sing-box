---
icon: material/lan-connect
---

# eBPF

The eBPF inbound intercepts locally generated TCP and UDP traffic with cgroup
socket-address programs. It does not use a TUN device, TProxy, TC, iptables, or
a SOCKS bridge.

This inbound is intended for a rooted Android or Linux native sing-box binary.
It is included only in builds made with the `with_ebpf` build tag and cgo.

## Structure

```json
{
  "type": "ebpf",
  "tag": "ebpf-in"
}
```

There are no UID, CIDR, private-network, interface, or DNS policy fields. The
programs attach to the root cgroup2 mount discovered from
`/proc/self/mountinfo`, so all local application sockets in that hierarchy are
intercepted. Loopback traffic is left local.

sing-box registers the `SO_COOKIE` value of each socket it creates in an eBPF
LRU map. The cgroup programs consult this map before redirecting traffic, which
prevents sing-box outbound connections and UDP listeners from being captured
again.

## Android build

Run the build from the sing-box source directory with an Android NDK installed:

```sh
make build_android_ebpf \
  ANDROID_CC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android28-clang"
```

The output defaults to `sing-box-android-arm64`. The build uses Android PIE and
cgo, and adds `with_ebpf` to the standard sing-box build tags.

The device kernel must provide cgroup2 and the cgroup connect4/connect6,
UDP4/UDP6 sendmsg, and UDP4/UDP6 recvmsg BPF attach types. The process needs
permission to create BPF maps/programs and attach them to the root cgroup.

The current Android path intercepts IPv4 and IPv4-mapped IPv6 sockets. Native
IPv6 attempts are rejected by the eBPF program so they cannot bypass routing;
applications with Happy Eyeballs normally fall back to intercepted IPv4.
