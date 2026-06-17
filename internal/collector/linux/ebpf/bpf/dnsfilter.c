#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// ==============================================================================
// 跨架构寄存器访问兼容层
// ==============================================================================
#if defined(__TARGET_ARCH_x86)
    #define PARAM_SK(ctx) (((struct pt_regs *)(ctx))->di)
    #define PT_REGS_RC(ctx) (((struct pt_regs *)(ctx))->ax)
#elif defined(__TARGET_ARCH_arm64)
    struct pt_regs_arm64_compat {
        unsigned long regs[31];
    };
    #define PARAM_SK(ctx) (((struct pt_regs_arm64_compat *)(ctx))->regs[0])
    #define PT_REGS_RC(ctx) (((struct pt_regs_arm64_compat *)(ctx))->regs[0])
#else
    #define PARAM_SK(ctx) 0
    #define PT_REGS_RC(ctx) 0
#endif

// ==============================================================================
// 数据结构定义
// ==============================================================================

struct flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  proto;
    __u8  pad[3];
};

struct proc_info {
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    char comm[64];
};

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

// ==============================================================================
// BPF Maps
// ==============================================================================

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct flow_key);
    __type(value, struct proc_info);
} flow_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64); // pid_tgid
    __type(value, struct sock *); // sk pointer
} pending_sockets SEC(".maps");

// ==============================================================================
// Kprobes
// ==============================================================================

static __always_inline int trace_sendmsg_with_sk(struct sock *sk, __u8 proto) {
    if (!sk) return 0;

    struct flow_key key = {};
    key.proto = proto;

    BPF_CORE_READ_INTO(&key.saddr, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&key.daddr, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&key.sport, sk, __sk_common.skc_num);
    BPF_CORE_READ_INTO(&key.dport, sk, __sk_common.skc_dport);

    key.sport = bpf_htons(key.sport);

    struct proc_info info = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    
    info.pid = pid_tgid >> 32;
    info.tgid = pid_tgid & 0xFFFFFFFF;
    info.uid = uid_gid & 0xFFFFFFFF;
    info.gid = uid_gid >> 32;
    bpf_get_current_comm(&info.comm, sizeof(info.comm));

    bpf_map_update_elem(&flow_map, &key, &info, BPF_ANY);
    return 0;
}

static __always_inline int trace_sendmsg(void *ctx, __u8 proto) {
    struct sock *sk = (struct sock *)PARAM_SK(ctx);
    return trace_sendmsg_with_sk(sk, proto);
}

SEC("kprobe/udp_sendmsg")
int kprobe_udp_sendmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PARAM_SK(ctx);
    if (!sk) return 0;

    __u16 sport;
    BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
    if (sport != 0) {
        return trace_sendmsg_with_sk(sk, 17);
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&pending_sockets, &pid_tgid, &sk, BPF_ANY);
    return 0;
}

SEC("kretprobe/udp_sendmsg")
int kretprobe_udp_sendmsg(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock **sk_pp = bpf_map_lookup_elem(&pending_sockets, &pid_tgid);
    if (!sk_pp) return 0;

    struct sock *sk = *sk_pp;
    bpf_map_delete_elem(&pending_sockets, &pid_tgid);

    int ret = PT_REGS_RC(ctx);
    if (ret <= 0) return 0;

    return trace_sendmsg_with_sk(sk, 17);
}

SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg(struct pt_regs *ctx) {
    return trace_sendmsg(ctx, 6);
}

// ==============================================================================
// Socket Filter
// ==============================================================================

#define ETH_HLEN 14
#define IP_PROTO_OFF 23
#define IP_SADDR_OFF 26
#define IP_DADDR_OFF 30
#define IP_HLEN_OFF 14

SEC("socket")
int socket_dns_filter(struct __sk_buff *skb) {
    __u16 eth_proto;
    if (bpf_skb_load_bytes(skb, 12, &eth_proto, 2) < 0) return 0;
    if (eth_proto != bpf_htons(0x0800)) return 0;

    __u8 proto;
    __u32 saddr, daddr;
    if (bpf_skb_load_bytes(skb, IP_PROTO_OFF, &proto, 1) < 0) return 0;
    if (bpf_skb_load_bytes(skb, IP_SADDR_OFF, &saddr, 4) < 0) return 0;
    if (bpf_skb_load_bytes(skb, IP_DADDR_OFF, &daddr, 4) < 0) return 0;

    if (proto != 17 && proto != 6) return 0;

    __u8 ihl_byte;
    if (bpf_skb_load_bytes(skb, IP_HLEN_OFF, &ihl_byte, 1) < 0) return 0;
    __u32 ip_hlen = (ihl_byte & 0x0F) * 4;
    __u32 transport_offset = ETH_HLEN + ip_hlen;

    __u16 sport, dport;
    if (bpf_skb_load_bytes(skb, transport_offset, &sport, 2) < 0) return 0;
    if (bpf_skb_load_bytes(skb, transport_offset + 2, &dport, 2) < 0) return 0;

    if (dport != bpf_htons(53) && sport != bpf_htons(53)) return 0;

    struct flow_key key = {};
    if (sport == bpf_htons(53)) {
        // 响应包：交换源/目的 IP 和源/目的端口以匹配请求流
        key.saddr = daddr;
        key.daddr = saddr;
        key.sport = dport;
        key.dport = sport;
    } else {
        // 查询包：正常匹配
        key.saddr = saddr;
        key.daddr = daddr;
        key.sport = sport;
        key.dport = dport;
    }
    key.proto = proto;
    struct proc_info *pinfo = bpf_map_lookup_elem(&flow_map, &key);

    struct dns_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) return 0;

    event->timestamp = bpf_ktime_get_ns();
    event->ifindex = skb->ifindex;
    
    if (pinfo) {
        event->pid = pinfo->pid;
        event->tgid = pinfo->tgid;
        event->uid = pinfo->uid;
        event->gid = pinfo->gid;
        __builtin_memcpy(event->comm, pinfo->comm, 64);
    } else {
        event->pid = 0;
        event->comm[0] = 0;
    }

    event->saddr = saddr;
    event->daddr = daddr;
    event->sport = sport;
    event->dport = dport;
    event->protocol = proto;

    __u32 trans_hlen = 8;
    if (proto == 6) {
        __u8 doff;
        if (bpf_skb_load_bytes(skb, transport_offset + 12, &doff, 1) >= 0)
            trans_hlen = (doff >> 4) * 4;
    }
    __u32 payload_offset = transport_offset + trans_hlen;

    __u32 total_len = skb->len;
    // 确保 payload_offset 在合理范围内
    if (total_len > payload_offset) {
        __u32 len = total_len - payload_offset;
        
        // 使用位与操作限制范围到 [0, 511]，确保满足 Verifier 边界检测
        len &= 0x1FF;
        
        if (len > 0) {
            bpf_skb_load_bytes(skb, payload_offset, event->pkt_data, len);
            event->pkt_len = (__u16)len;
        } else {
            event->pkt_len = 0;
        }
    } else {
        event->pkt_len = 0;
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
