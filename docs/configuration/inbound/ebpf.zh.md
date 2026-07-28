---
icon: material/lan-connect
---

# eBPF

eBPF 入站通过 cgroup socket-address 程序拦截本机产生的 TCP 和 UDP 流量，
不使用 TUN、TProxy、TC、iptables 或 SOCKS 中间层。

此入站用于以 root 权限直接运行 Android 或 Linux 原生 sing-box 二进制的场景。
构建时必须启用 cgo 和 `with_ebpf` 构建标签。

## 结构

```json
{
  "type": "ebpf",
  "tag": "ebpf-in"
}
```

配置不包含 UID、CIDR、私网、网卡或 DNS 策略。sing-box 从
`/proc/self/mountinfo` 自动找到 cgroup2 根挂载点，并在该层拦截本机应用流量；
回环流量保持本地直连。

sing-box 会把自身创建的 socket 的 `SO_COOKIE` 登记到 eBPF LRU map。cgroup
程序在重定向前查询此 map，从而避免 sing-box 的出站连接和 UDP listener
再次被捕获。

## Android 构建

在 sing-box 项目根目录中，安装 Android NDK 后执行：

```sh
make build_android_ebpf \
  ANDROID_CC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android28-clang"
```

默认输出为 `sing-box-android-arm64`，构建方式为 Android PIE 和 cgo，并在
sing-box 标准构建标签的基础上加入 `with_ebpf`。

设备内核必须提供 cgroup2，以及 cgroup connect4/connect6、UDP4/UDP6
sendmsg 和 UDP4/UDP6 recvmsg BPF attach type。进程还需要创建 BPF
map/program 并将其挂载到 cgroup 根节点的权限。

当前 Android 路径拦截 IPv4 和 IPv4-mapped IPv6 socket。eBPF 程序会拒绝
原生 IPv6 连接以避免绕过路由；支持 Happy Eyeballs 的应用通常会回退到已拦截的
IPv4。
