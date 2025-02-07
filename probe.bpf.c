#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>

struct event_t {
    __u64 timestamp_start;
    __u64 timestamp_end;
    __u32 pid;
    char comm[16];
};

SEC("uprobe")
int trace_enter(struct pt_regs *ctx) {
    struct event_t event = {};
    event.timestamp_start = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_printk("Enter: %s", event.comm);
    return 0;
}

SEC("uretprobe")
int trace_exit(struct pt_regs *ctx) {
    struct event_t event = {};
    event.timestamp_end = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_printk("Exit: %s", event.comm);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
