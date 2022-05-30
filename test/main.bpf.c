#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "common.h"

// separate data structs for ipv4 and ipv6


/* BPF ringbuf map */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 /* 16 KB */);
} events SEC(".maps");


SEC("tracepoint/tcp/tcp_retransmit_skb")
int tracepoint__tcp__tcp_retransmit_skb(struct trace_event_raw_tcp_event_sk_skb *ctx)
{		
		
        /**
         * @brief 
         * struct trace_event_raw_tcp_event_sk_skb {
                struct trace_entry ent;
                const void *skbaddr;
                const void *skaddr;
                int state;
                __u16 sport;
                __u16 dport;
                __u16 family;
                __u8 saddr[4];
                __u8 daddr[4];
                __u8 saddr_v6[16];
                __u8 daddr_v6[16];
                char __data[0];
            };
         */
		struct event_t *event;
		event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
		if (!event) {
			return 0;
		}

        struct task_struct *task = (struct task_struct *)
        bpf_get_current_task();

		event->host_pid = bpf_get_current_pid_tgid() >> 32;
		event->host_ppid = BPF_CORE_READ(task, real_parent, tgid);
        event->sport = BPF_CORE_READ(ctx, sport);
        event->dport = BPF_CORE_READ(ctx, dport);

        event->saddr[0] =  BPF_CORE_READ(ctx, saddr[0]);
        event->saddr[1] =  BPF_CORE_READ(ctx, saddr[1]);
        event->saddr[2] =  BPF_CORE_READ(ctx, saddr[2]);
        event->saddr[3] =  BPF_CORE_READ(ctx, saddr[3]);

        event->daddr[0] =  BPF_CORE_READ(ctx, daddr[0]);
        event->daddr[1] =  BPF_CORE_READ(ctx, daddr[1]);
        event->daddr[2] =  BPF_CORE_READ(ctx, daddr[2]);
        event->daddr[3] =  BPF_CORE_READ(ctx, daddr[3]);
    

		bpf_ringbuf_submit(event, 0);
		return 0;
}

char _license[] SEC("license") = "GPL";
