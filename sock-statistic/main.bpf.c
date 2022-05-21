#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

/* BPF ringbuf map */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct sock *);
	__uint(max_entries, 1024);   
} current_sock SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int kprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	struct sock *sk = PT_REGS_PARM1(ctx);
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_update_elem(&current_sock, &pid, &sk, 0);

	return 0;
};

SEC("kretprobe/tcp_v4_connect")
int kretprobe__tcp_v4_connect(struct pt_regs *ctx) 
{
	int ret = PT_REGS_RC(ctx);
	u32 pid = bpf_get_current_pid_tgid() >> 32;

	struct sock *skpp; 
	skpp = bpf_map_lookup_elem(&current_sock, &pid);
	if (skpp == 0) 
	{
		return 0;
	}

	if (ret != 0) 
	{
		bpf_map_delete_elem(&current_sock, &pid);
		return 0;
	}


	struct sock *skp = skpp;
	if (skp == 0){
		return 0;
	}
	u32 saddr = skp->__sk_common.skc_rcv_saddr;
	u32 daddr = skp->__sk_common.skc_daddr;

	// bpf_trace_printk("trace_tcp4connect %x %x\\n", saddr, daddr);

	struct session *s;
	s = bpf_ringbuf_reserve(&events, sizeof(*s), 0);
	if (!s) {
		return 0;
	}

	s->saddr = saddr;
	s->daddr = daddr;

	bpf_ringbuf_submit(s, 0);
	bpf_map_delete_elem(&current_sock, &pid);

	return 0;
}

char _license[] SEC("license") = "GPL";
