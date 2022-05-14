// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020 Facebook */

#include <test_progs.h>
#include <time.h>
#include "test_vmlinux.skel.h"

#define MY_TV_NSEC 1337

static void nsleep()
{
	struct timespec ts = { .tv_nsec = MY_TV_NSEC };

	(void)syscall(__NR_nanosleep, &ts, NULL);
}

void test_vmlinux(void)
{
	int duration = 0, err;
	struct test_vmlinux* skel;
	struct test_vmlinux__bss *bss;

	LIBBPF_OPTS(bpf_object_open_opts, opts,
		    .kernel_log_level = 7,
	);

	skel = test_vmlinux__open_opts(&opts);
	if (CHECK(!skel, "skel_open", "failed to open skeleton\n"))
		return;

	err = test_vmlinux__load(skel);
	if (CHECK(err, "load", "failed to load skeleton\n"))
		goto cleanup;

	bss = skel->bss;

	err = test_vmlinux__attach(skel);
	if (CHECK(err, "skel_attach", "skeleton attach failed: %d\n", err))
		goto cleanup;

	/* trigger everything */
	nsleep();

	CHECK(!bss->tp_called, "tp", "not called\n");
	CHECK(!bss->raw_tp_called, "raw_tp", "not called\n");
	CHECK(!bss->tp_btf_called, "tp_btf", "not called\n");
	CHECK(!bss->kprobe_called, "kprobe", "not called\n");
	CHECK(!bss->fentry_called, "fentry", "not called\n");

	sleep(10000000);

cleanup:
	test_vmlinux__destroy(skel);
}
