#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
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
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
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

	// struct session *s;
	// s = bpf_ringbuf_reserve(&events, sizeof(*s), 0);
	// if (!s) {
	// 	return 0;
	// }

	// s->saddr = saddr;
	// s->daddr = daddr;

	// bpf_ringbuf_submit(s, 0);
	//
	struct event_t *event;
	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		return 0;
	}

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent_task = BPF_CORE_READ(task, real_parent);
	u64 tgid = bpf_get_current_pid_tgid();
	u64 ugid = bpf_get_current_uid_gid();

	event->saddr = saddr;
	event->daddr = daddr;

	event->cgroup_id = bpf_get_current_cgroup_id();
	event->host_tid = tgid;
	event->host_pid = tgid >> 32;
	event->host_ppid = BPF_CORE_READ(parent_task, tgid);

	struct nsproxy *namespaceproxy = BPF_CORE_READ(task, nsproxy);
	struct pid_namespace *pid_ns_children = BPF_CORE_READ(namespaceproxy, pid_ns_for_children);
	unsigned int level = BPF_CORE_READ(pid_ns_children, level);
	event->tid = BPF_CORE_READ(task, thread_pid, numbers[level].nr);
	event->pid = BPF_CORE_READ(task, group_leader, thread_pid, numbers[level].nr);

	struct nsproxy *parent_namespaceproxy = BPF_CORE_READ(parent_task, nsproxy);
	struct pid_namespace *parent_pid_ns_children = BPF_CORE_READ(parent_namespaceproxy, pid_ns_for_children);
	unsigned int parent_level = BPF_CORE_READ(parent_pid_ns_children, level);
	event->ppid = BPF_CORE_READ(parent_task, group_leader, thread_pid, numbers[parent_level].nr);

	event->uid = ugid;
	event->gid = ugid >> 32;

	event->cgroup_ns_id = BPF_CORE_READ(namespaceproxy, cgroup_ns, ns.inum);
	event->ipc_ns_id = BPF_CORE_READ(namespaceproxy, ipc_ns, ns.inum);
	event->net_ns_id = BPF_CORE_READ(namespaceproxy, net_ns, ns.inum);
	event->mount_ns_id = BPF_CORE_READ(namespaceproxy, mnt_ns, ns.inum);
	event->pid_ns_id = BPF_CORE_READ(namespaceproxy, pid_ns_for_children, ns.inum);
	event->time_ns_id = BPF_CORE_READ(namespaceproxy, time_ns, ns.inum);
	event->user_ns_id = BPF_CORE_READ(namespaceproxy, cgroup_ns, ns.inum);
	event->uts_ns_id = BPF_CORE_READ(namespaceproxy, cgroup_ns, ns.inum);

	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	bpf_ringbuf_submit(event, 0);
	//
	bpf_map_delete_elem(&current_sock, &pid);

	return 0;
}

char _license[] SEC("license") = "GPL";
