#define TASK_COMM_LEN			16

struct event_t {
    u32 saddr;
    u32 daddr;

    u64 cgroup_id;                
    u32 host_tid;                  
    u32 host_pid;                  
    u32 host_ppid;                 

    u32 tid;                       
    u32 pid;                       
    u32 ppid;                      
    u32 uid;
    u32 gid;

    u32 cgroup_ns_id;
    u32 ipc_ns_id;
    u32 net_ns_id;
    u32 mount_ns_id;
    u32 pid_ns_id;
    u32 time_ns_id;
    u32 user_ns_id;
    u32 uts_ns_id;

    char comm[TASK_COMM_LEN];      
};
