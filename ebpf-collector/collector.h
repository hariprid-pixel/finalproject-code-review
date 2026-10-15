#ifndef __COLLECTOR_H
#define __COLLECTOR_H

/*
 * Shared event schema between kernel-side BPF programs and the userspace
 * daemon. This mirrors DARPA TC CDM20's Subject/Object/Event model so the
 * JSONL this daemon emits is structurally compatible with the CDM-derived
 * graph pipeline (same downstream parser, same node/edge types).
 */

#define TASK_COMM_LEN   16
#define MAX_PATH_LEN    256
#define MAX_ARGV_LEN    256

enum event_type {
    EVENT_EXECUTE = 1,
    EVENT_CLONE,
    EVENT_EXIT,
    EVENT_OPEN,
    EVENT_READ,
    EVENT_WRITE,
    EVENT_MMAP,
    EVENT_MPROTECT,
    EVENT_CONNECT,
    EVENT_SENDTO,
    EVENT_RECVFROM,
    EVENT_CHANGE_PRINCIPAL,   /* setuid / privilege change */
    EVENT_UNLINK,
    EVENT_INJECT_PTRACE,      /* non-CDM: process injection via ptrace */
    EVENT_INJECT_VM_WRITE,    /* non-CDM: process_vm_writev */
};

/*
 * A single tagged-union record. Kept fixed-size and flat so it can be
 * pushed through a BPF ring buffer without per-type layouts.
 */
struct event {
    __u64 timestamp_ns;
    __u32 event_type;

    __u32 pid;      /* tgid, i.e. the "process" id userspace expects */
    __u32 ppid;
    __u32 tid;      /* actual thread id, for injection correlation   */

    __u32 uid;
    __u32 euid;
    __u32 gid;
    __u32 egid;

    char  comm[TASK_COMM_LEN];

    union {
        struct {
            __u32 saddr;
            __u32 daddr;
            __u16 sport;
            __u16 dport;
            __u8  protocol; /* 6 = TCP, 17 = UDP */
        } net;

        struct {
            char  path[MAX_PATH_LEN];
            __u32 flags;
            __u64 inode;
            __u32 dev;
        } file;

        struct {
            __u64 addr;
            __u64 len;
            __u32 prot;
        } mem;

        struct {
            __u32 target_pid;
            __u32 request;   /* PTRACE_* request code, or 0 for vm_writev */
        } inject;

        struct {
            __u32 old_uid;
            __u32 new_uid;
            __u32 old_gid;
            __u32 new_gid;
        } principal;

        struct {
            char argv[MAX_ARGV_LEN];
        } exec;
    } data;
};

#endif /* __COLLECTOR_H */
