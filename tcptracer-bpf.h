#ifndef __TCPTRACER_BPF_H
#define __TCPTRACER_BPF_H

#include <linux/types.h>

#define TCP_EVENT_TYPE_CONNECT          1
#define TCP_EVENT_TYPE_ACCEPT           2
#define TCP_EVENT_TYPE_CLOSE            3
#define TCP_EVENT_TYPE_FD_INSTALL       4
#define TCP_EVENT_TYPE_SEND             5

#define GUESS_SADDR      0
#define GUESS_DADDR      1
#define GUESS_FAMILY     2
#define GUESS_SPORT      3
#define GUESS_DPORT      4
#define GUESS_NETNS      5
#define GUESS_DADDR_IPV6 6

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

//BPF_HASH(ipv4_send_bytes, u32);

struct tcp_ipv4_event_t {
	__u64 timestamp;
	__u64 cpu;
	__u32 type;
	__u32 pid;
	char comm[TASK_COMM_LEN];
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u32 netns;
	__u32 fd;
	__u32 dummy;
};

struct tcp_traffic_event_t {
	__u64 timestamp;
    __u64 cpu;
    __u32 type;
    __u32 pid;
    char comm[TASK_COMM_LEN];
//    __u32 saddr;
//    __u32 daddr;
//    __u16 sport;
//    __u16 dport;

//    __u64 size;

};

struct ipv6_key_t {
    __u32 type;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    __u32 pid;
    __u16 lport;
    __u16 dport;
    __u64 __pad__;
    __u64 size;
};

struct tcp_ipv6_event_t {
	__u64 timestamp;
	__u64 cpu;
	__u32 type;
	__u32 pid;
	char comm[TASK_COMM_LEN];
	/* Using the type unsigned __int128 generates an error in the ebpf verifier */
	__u64 saddr_h;
	__u64 saddr_l;
	__u64 daddr_h;
	__u64 daddr_l;
	__u16 sport;
	__u16 dport;
	__u32 netns;
	__u32 fd;
	__u32 dummy;
};

// tcp_set_state doesn't run in the context of the process that initiated the
// connection so we need to store a map TUPLE -> PID to send the right PID on
// the event
struct ipv4_tuple_t {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u32 netns;
};

struct ipv6_tuple_t {
	/* Using the type unsigned __int128 generates an error in the ebpf verifier */
	__u64 saddr_h;
	__u64 saddr_l;
	__u64 daddr_h;
	__u64 daddr_l;
	__u16 sport;
	__u16 dport;
	__u32 netns;
};

struct pid_comm_t {
	__u64 pid;
	char comm[TASK_COMM_LEN];
};

#define TCPTRACER_STATE_UNINITIALIZED 0
#define TCPTRACER_STATE_CHECKING      1
#define TCPTRACER_STATE_CHECKED       2
#define TCPTRACER_STATE_READY         3
struct tcptracer_status_t {
	__u64 state;

	/* checking */
	__u64 pid_tgid;
	__u64 what;
	__u64 offset_saddr;
	__u64 offset_daddr;
	__u64 offset_sport;
	__u64 offset_dport;
	__u64 offset_netns;
	__u64 offset_ino;
	__u64 offset_family;
	__u64 offset_daddr_ipv6;

	__u64 err;

	__u32 daddr_ipv6[4];
	__u32 netns;
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 padding;
};

#endif

//// Changes to the macro require changes in BFrontendAction classes
//#define BPF_F_TABLE(_table_type, _key_type, _leaf_type, _name, _max_entries, _flags) \
//struct _name##_table_t { \
//  _key_type key; \
//  _leaf_type leaf; \
//  _leaf_type * (*lookup) (_key_type *); \
//  _leaf_type * (*lookup_or_init) (_key_type *, _leaf_type *); \
//  _leaf_type * (*lookup_or_try_init) (_key_type *, _leaf_type *); \
//  int (*update) (_key_type *, _leaf_type *); \
//  int (*insert) (_key_type *, _leaf_type *); \
//  int (*delete) (_key_type *); \
//  void (*call) (void *, int index); \
//  void (*increment) (_key_type, ...); \
//  int (*get_stackid) (void *, u64); \
//  u32 max_entries; \
//  int flags; \
//}; \
//__attribute__((section("maps/" _table_type))) \
//struct _name##_table_t _name = { .flags = (_flags), .max_entries = (_max_entries) }; \
//BPF_ANNOTATE_KV_PAIR(_name, _key_type, _leaf_type)
//// Changes to the macro require changes in BFrontendAction classes
//#define BPF_QUEUESTACK(_table_type, _name, _leaf_type, _max_entries, _flags) \
//struct _name##_table_t { \
//  _leaf_type leaf; \
//  int * (*peek) (_leaf_type *); \
//  int * (*pop) (_leaf_type *); \
//  int * (*push) (_leaf_type *, u64); \
//  u32 max_entries; \
//  int flags; \
//}; \
//__attribute__((section("maps/" _table_type))) \
//struct _name##_table_t _name = { .flags = (_flags), .max_entries = (_max_entries) }; \
//BPF_ANNOTATE_KV_PAIR_QUEUESTACK(_name, _leaf_type)
//// define queue with 3 parameters (_type=queue/stack automatically) and default flags to 0
//#define BPF_QUEUE_STACK3(_type, _name, _leaf_type, _max_entries) \
//  BPF_QUEUESTACK(_type, _name, _leaf_type, _max_entries, 0)
//// define queue with 4 parameters (_type=queue/stack automatically)
//#define BPF_QUEUE_STACK4(_type, _name, _leaf_type, _max_entries, _flags) \
//  BPF_QUEUESTACK(_type, _name, _leaf_type, _max_entries, _flags)
//// helper for default-variable macro function
//#define BPF_QUEUE_STACKX(_1, _2, _3, _4, NAME, ...) NAME
//#define BPF_QUEUE(...) \
//  BPF_QUEUE_STACKX(__VA_ARGS__, BPF_QUEUE_STACK4, BPF_QUEUE_STACK3)("queue", __VA_ARGS__)
//#define BPF_STACK(...) \
//  BPF_QUEUE_STACKX(__VA_ARGS__, BPF_QUEUE_STACK4, BPF_QUEUE_STACK3)("stack", __VA_ARGS__)
//#define BPF_QUEUESTACK_PINNED(_table_type, _name, _leaf_type, _max_entries, _flags, _pinned) \
//BPF_QUEUESTACK(_table_type ":" _pinned, _name, _leaf_type, _max_entries, _flags)
//#define BPF_QUEUESTACK_PUBLIC(_table_type, _name, _leaf_type, _max_entries, _flags) \
//BPF_QUEUESTACK(_table_type, _name, _leaf_type, _max_entries, _flags); \
//__attribute__((section("maps/export"))) \
//struct _name##_table_t __##_name
//#define BPF_QUEUESTACK_SHARED(_table_type, _name, _leaf_type, _max_entries, _flags) \
//BPF_QUEUESTACK(_table_type, _name, _leaf_type, _max_entries, _flags); \
//__attribute__((section("maps/shared"))) \
//struct _name##_table_t __##_name
//#define BPF_TABLE(_table_type, _key_type, _leaf_type, _name, _max_entries) \
//BPF_F_TABLE(_table_type, _key_type, _leaf_type, _name, _max_entries, 0)
//#define BPF_TABLE_PINNED(_table_type, _key_type, _leaf_type, _name, _max_entries, _pinned) \
//BPF_TABLE(_table_type ":" _pinned, _key_type, _leaf_type, _name, _max_entries)
//// define a table same as above but allow it to be referenced by other modules
//#define BPF_TABLE_PUBLIC(_table_type, _key_type, _leaf_type, _name, _max_entries) \
//BPF_TABLE(_table_type, _key_type, _leaf_type, _name, _max_entries); \
//__attribute__((section("maps/export"))) \
//struct _name##_table_t __##_name
//// define a table that is shared across the programs in the same namespace
//#define BPF_TABLE_SHARED(_table_type, _key_type, _leaf_type, _name, _max_entries) \
//BPF_TABLE(_table_type, _key_type, _leaf_type, _name, _max_entries); \
//__attribute__((section("maps/shared"))) \
//struct _name##_table_t __##_name
//// Identifier for current CPU used in perf_submit and perf_read
//// Prefer BPF_F_CURRENT_CPU flag, falls back to call helper for older kernel
//// Can be overridden from BCC
//#ifndef CUR_CPU_IDENTIFIER
//#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
//#define CUR_CPU_IDENTIFIER BPF_F_CURRENT_CPU
//#else
//#define CUR_CPU_IDENTIFIER bpf_get_smp_processor_id()
//#endif
//#endif
//// Table for pushing custom events to userspace via perf ring buffer
//#define BPF_PERF_OUTPUT(_name) \
//struct _name##_table_t { \
//  int key; \
//  u32 leaf; \
//  /* map.perf_submit(ctx, data, data_size) */ \
//  int (*perf_submit) (void *, void *, u32); \
//  int (*perf_submit_skb) (void *, u32, void *, u32); \
//  u32 max_entries; \
//}; \
//__attribute__((section("maps/perf_output"))) \
//struct _name##_table_t _name = { .max_entries = 0 }
//// Table for pushing custom events to userspace via ring buffer
//#define BPF_RINGBUF_OUTPUT(_name, _num_pages) \
//struct _name##_table_t { \
//  int key; \
//  u32 leaf; \
//  /* map.ringbuf_output(data, data_size, flags) */ \
//  int (*ringbuf_output) (void *, u64, u64); \
//  /* map.ringbuf_reserve(data_size) */ \
//  void* (*ringbuf_reserve) (u64); \
//  /* map.ringbuf_discard(data, flags) */ \
//  void (*ringbuf_discard) (void *, u64); \
//  /* map.ringbuf_submit(data, flags) */ \
//  void (*ringbuf_submit) (void *, u64); \
//  u32 max_entries; \
//}; \
//__attribute__((section("maps/ringbuf"))) \
//struct _name##_table_t _name = { .max_entries = ((_num_pages) * PAGE_SIZE) }
//// Table for reading hw perf cpu counters
//#define BPF_PERF_ARRAY(_name, _max_entries) \
//struct _name##_table_t { \
//  int key; \
//  u32 leaf; \
//  /* counter = map.perf_read(index) */ \
//  u64 (*perf_read) (int); \
//  int (*perf_counter_value) (int, void *, u32); \
//  u32 max_entries; \
//}; \
//__attribute__((section("maps/perf_array"))) \
//struct _name##_table_t _name = { .max_entries = (_max_entries) }
//// Table for cgroup file descriptors
//#define BPF_CGROUP_ARRAY(_name, _max_entries) \
//struct _name##_table_t { \
//  int key; \
//  u32 leaf; \
//  int (*check_current_task) (int); \
//  u32 max_entries; \
//}; \
//__attribute__((section("maps/cgroup_array"))) \
//struct _name##_table_t _name = { .max_entries = (_max_entries) }
//#define BPF_HASH1(_name) \
//  BPF_TABLE("hash", u64, u64, _name, 10240)
//#define BPF_HASH2(_name, _key_type) \
//  BPF_TABLE("hash", _key_type, u64, _name, 10240)
//#define BPF_HASH3(_name, _key_type, _leaf_type) \
//  BPF_TABLE("hash", _key_type, _leaf_type, _name, 10240)
//#define BPF_HASH4(_name, _key_type, _leaf_type, _size) \
//  BPF_TABLE("hash", _key_type, _leaf_type, _name, _size)
//// helper for default-variable macro function
//#define BPF_HASHX(_1, _2, _3, _4, NAME, ...) NAME
//// Define a hash function, some arguments optional
//// BPF_HASH(name, key_type=u64, leaf_type=u64, size=10240)
//#define BPF_HASH(...) \
//  BPF_HASHX(__VA_ARGS__, BPF_HASH4, BPF_HASH3, BPF_HASH2, BPF_HASH1)(__VA_ARGS__)

#define BUFSIZE_PADDED (2 << 13)
#define BUFSIZE ((BUFSIZE_PADDED - 1) >> 1)

typedef struct buf {
  __u32 off;
  __u8 data[BUFSIZE_PADDED];
} buf_t;
