#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct event {
    __u64 duration_ns;
    __u32 pid;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} start_times SEC(".maps");

SEC("uprobe")
int trace_enter(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 ts = bpf_ktime_get_ns();
    
    bpf_map_update_elem(&start_times, &pid, &ts, BPF_ANY);
    bpf_printk("Function entered: pid=%d", pid);
    return 0;
}

SEC("uretprobe")
int trace_exit(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 *start_ts = bpf_map_lookup_elem(&start_times, &pid);
    
    if (start_ts) {
        __u64 duration = bpf_ktime_get_ns() - *start_ts;
        bpf_printk("Function exited: pid=%d duration=%llu ns", pid, duration);
        bpf_map_delete_elem(&start_times, &pid);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";