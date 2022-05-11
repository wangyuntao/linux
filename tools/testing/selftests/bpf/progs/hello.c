#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MY_TV_NSEC 1337

bool fentry_called = false;

SEC("fentry/hrtimer_start_range_ns")
int BPF_PROG(handle__fentry, struct hrtimer *timer, ktime_t tim, u64 delta_ns,
	     const enum hrtimer_mode mode)
{
	if (tim == MY_TV_NSEC)
		fentry_called = true;
	return 0;
}

char _license[] SEC("license") = "GPL";
