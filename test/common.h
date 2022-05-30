// https://elixir.bootlin.com/linux/v5.13/source/include/linux/sched.h#L215
#define TASK_COMM_LEN			16

struct event_t {
    u32 host_pid;                  // pid in host pid namespace
    u32 host_ppid; 
    u16 sport;
    u16 dport;
    u8 saddr[4];
    u8 daddr[4];
};
