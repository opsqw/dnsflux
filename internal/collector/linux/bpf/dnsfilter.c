#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// 定义事件结构体，增加更多信息
struct dns_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __u32 ifindex;
    char comm[64];
    __u16 sport;
    __u16 dport;
    __u32 saddr;
    __u32 daddr;
    __u16 protocol;
    __u16 pkt_len;
    __u8 pkt_data[512];
};

// 定义 ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// 处理 DNS 请求的通用函数
static __always_inline int process_dns(struct pt_regs *ctx, struct sock *sk, __u16 protocol) {
    if (!sk)
        return 0;

    // 检查是否是 DNS 端口（源端口或目标端口为53）
    __u16 sport, dport;
    BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);

    if (bpf_ntohs(dport) != 53 && sport != 53)
        return 0;

    // 分配事件结构体
    struct dns_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    // 获取基本信息
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid_tgid >> 32;
    event->tgid = pid_tgid & 0xFFFFFFFF;
    event->uid = uid_gid & 0xFFFFFFFF;
    event->gid = uid_gid >> 32;

    // 获取进程名
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // 获取网络信息
    event->sport = sport;
    event->dport = dport;
    BPF_CORE_READ_INTO(&event->saddr, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&event->daddr, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&event->ifindex, sk, __sk_common.skc_bound_dev_if);
    event->protocol = protocol;

    // 获取数据包内容
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    if (msg) {
        struct iovec *iov;
        BPF_CORE_READ_INTO(&iov, msg, msg_iter.iov);
        if (iov) {
            void *base;
            size_t len;
            BPF_CORE_READ_INTO(&base, iov, iov_base);
            BPF_CORE_READ_INTO(&len, iov, iov_len);

            if (base && len <= sizeof(event->pkt_data)) {
                bpf_probe_read_user(event->pkt_data, len, base);
                event->pkt_len = len;
            }
        }
    }

    // 转换地址为网络字节序
    event->saddr = bpf_htonl(event->saddr);
    event->daddr = bpf_htonl(event->daddr);
    event->sport = bpf_htons(event->sport);
    event->dport = bpf_htons(event->dport);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// 跟踪UDP数据包
SEC("kprobe/udp_sendmsg")
int trace_udp_sendmsg(struct pt_regs *ctx) {
    return process_dns(ctx, (struct sock *)PT_REGS_PARM1(ctx), 17); // UDP
}

// 跟踪TCP数据包
SEC("kprobe/tcp_sendmsg")
int trace_tcp_sendmsg(struct pt_regs *ctx) {
    return process_dns(ctx, (struct sock *)PT_REGS_PARM1(ctx), 6);  // TCP
}

char LICENSE[] SEC("license") = "GPL";