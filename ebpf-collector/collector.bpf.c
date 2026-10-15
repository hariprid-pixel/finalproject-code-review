// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../include/collector.h"

char LICENSE[] SEC("license") = "GPL";

/* Ring buffer shared with userspace daemon. 16MB — bump if you see drops
 * once EVENT_READ/EVENT_WRITE are enabled at full volume. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024);
} events SEC(".maps");

/* pid -> uid at time of process start, so we can detect uid *changes*
 * (the "elevate" step) rather than just sampling current uid per event. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u32);
} pid_start_uid SEC(".maps");

static __always_inline struct event *reserve_event(void)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    return e;
}

static __always_inline void fill_common(struct event *e, __u32 type)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type   = type;
    e->pid          = pid_tgid >> 32;
    e->tid          = (__u32)pid_tgid;
    e->ppid         = BPF_CORE_READ(task, real_parent, tgid);

    __u64 uid_gid = bpf_get_current_uid_gid();
    e->uid  = uid_gid & 0xffffffff;
    e->euid = uid_gid & 0xffffffff; /* refined via cred below when needed */
    e->gid  = uid_gid >> 32;
    e->egid = uid_gid >> 32;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

/* ---------------------------------------------------------------------
 * EVENT_EXECUTE — new process image
 * ------------------------------------------------------------------- */
SEC("tp/sched/sched_process_exec")
int on_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct event *e = reserve_event();
    if (!e)
        return 0;

    fill_common(e, EVENT_EXECUTE);

    /* filename offset is provided by the tracepoint format */
    unsigned fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(e->data.exec.argv, sizeof(e->data.exec.argv),
                        (void *)ctx + fname_off);

    /* seed the uid baseline for this pid so later setuid calls can diff */
    __u32 pid = e->pid;
    __u32 uid = e->uid;
    bpf_map_update_elem(&pid_start_uid, &pid, &uid, BPF_ANY);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---------------------------------------------------------------------
 * EVENT_CLONE — fork/thread creation (subject lineage edge)
 * ------------------------------------------------------------------- */
SEC("tp/sched/sched_process_fork")
int on_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    struct event *e = reserve_event();
    if (!e)
        return 0;

    fill_common(e, EVENT_CLONE);
    e->pid  = ctx->parent_pid;               /* subject = parent  */
    e->data.inject.target_pid = ctx->child_pid; /* new child pid  */

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---------------------------------------------------------------------
 * EVENT_EXIT
 * ------------------------------------------------------------------- */
SEC("tp/sched/sched_process_exit")
int on_exit(struct trace_event_raw_sched_process_template *ctx)
{
    struct event *e = reserve_event();
    if (!e)
        return 0;

    fill_common(e, EVENT_EXIT);

    __u32 pid = e->pid;
    bpf_map_delete_elem(&pid_start_uid, &pid);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---------------------------------------------------------------------
 * EVENT_OPEN — file open (path resolved fully in userspace via /proc,
 * we just pass the raw filename argument here)
 * ------------------------------------------------------------------- */
SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(on_openat2, int dfd, const char *filename)
{
    struct event *e = reserve_event();
    if (!e)
        return 0;

    fill_common(e, EVENT_OPEN);
    bpf_probe_read_user_str(e->data.file.path, sizeof(e->data.file.path),
                             filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---------------------------------------------------------------------
 * EVENT_CONNECT — outbound TCP connect (NetFlow object creation)
 * ------------------------------------------------------------------- */
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(on_tcp_connect, struct sock *sk)
{
    struct event *e = reserve_event();
    if (!e)
        return 0;

    fill_common(e, EVENT_CONNECT);

    __u16 sport, dport;
    __u32 saddr, daddr;

    BPF_CORE_READ_INTO(&saddr, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&daddr, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);

    e->data.net.saddr    = saddr;
    e->data.net.daddr     = daddr;
    e->data.net.sport     = sport;
    e->data.net.dport     = bpf_ntohs(dport);
    e->data.net.protocol  = 6; /* TCP */

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---------------------------------------------------------------------
 * EVENT_MPROTECT — permission changes on mapped memory. High signal
 * around shellcode staging (RW -> RX transitions).
 * ------------------------------------------------------------------- */
SEC("lsm/file_mprotect")
int BPF_PROG(on_file_mprotect, struct vm_area_struct *vma,
             unsigned long reqprot, unsigned long prot)
{
    struct event *e = reserve_event();
    if (!e)
        return 0;

    fill_common(e, EVENT_MPROTECT);
    e->data.mem.addr = vma->vm_start;
    e->data.mem.len  = vma->vm_end - vma->vm_start;
    e->data.mem.prot = (__u32)prot;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---------------------------------------------------------------------
 * EVENT_CHANGE_PRINCIPAL — setuid transitions (catches "elevate")
 * ------------------------------------------------------------------- */
SEC("lsm/task_fix_setuid")
int BPF_PROG(on_setuid, struct cred *new, const struct cred *old, int flags)
{
    struct event *e = reserve_event();
    if (!e)
        return 0;

    fill_common(e, EVENT_CHANGE_PRINCIPAL);

    e->data.principal.old_uid = BPF_CORE_READ(old, uid.val);
    e->data.principal.new_uid = BPF_CORE_READ(new, uid.val);
    e->data.principal.old_gid = BPF_CORE_READ(old, gid.val);
    e->data.principal.new_gid = BPF_CORE_READ(new, gid.val);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---------------------------------------------------------------------
 * EVENT_INJECT_PTRACE — cross-process ptrace (attach/poketext/setregs)
 * ------------------------------------------------------------------- */
SEC("tp/syscalls/sys_enter_ptrace")
int on_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    long request = ctx->args[0];
    long target_tid = ctx->args[1];

    /* only care about attach + write-style requests, not routine peeks */
    if (request != 16 /* PTRACE_ATTACH */ &&
        request != 0x4206 /* PTRACE_SEIZE */ &&
        request != 4 /* PTRACE_POKETEXT */ &&
        request != 5 /* PTRACE_POKEDATA */ &&
        request != 13 /* PTRACE_SETREGS */)
        return 0;

    struct event *e = reserve_event();
    if (!e)
        return 0;

    fill_common(e, EVENT_INJECT_PTRACE);
    e->data.inject.target_pid = (__u32)target_tid;
    e->data.inject.request    = (__u32)request;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---------------------------------------------------------------------
 * EVENT_INJECT_VM_WRITE — direct cross-process memory write
 * ------------------------------------------------------------------- */
SEC("tp/syscalls/sys_enter_process_vm_writev")
int on_vm_writev(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e = reserve_event();
    if (!e)
        return 0;

    fill_common(e, EVENT_INJECT_VM_WRITE);
    e->data.inject.target_pid = (__u32)ctx->args[0]; /* pid arg */
    e->data.inject.request    = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---------------------------------------------------------------------
 * EVENT_UNLINK
 * ------------------------------------------------------------------- */
SEC("lsm/path_unlink")
int BPF_PROG(on_unlink, const struct path *dir, struct dentry *dentry)
{
    struct event *e = reserve_event();
    if (!e)
        return 0;

    fill_common(e, EVENT_UNLINK);
    bpf_probe_read_kernel_str(e->data.file.path, sizeof(e->data.file.path),
                               BPF_CORE_READ(dentry, d_name.name));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
