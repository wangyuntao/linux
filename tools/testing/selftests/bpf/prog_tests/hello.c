#include <test_progs.h>
#include "hello.skel.h"

#define MY_TV_NSEC 1337

static void nsleep()
{
	struct timespec ts = { .tv_nsec = MY_TV_NSEC };

	(void)syscall(__NR_nanosleep, &ts, NULL);
}

void test_hello(void)
{
	int duration = 0, err;
	struct hello* skel;

	skel = hello__open_and_load();
	if (CHECK(!skel, "skel_open", "failed to open skeleton\n"))
		return;

	err = hello__attach(skel);
	if (CHECK(err, "skel_attach", "skeleton attach failed: %d\n", err))
		goto cleanup;

	/* trigger everything */
	nsleep();

	CHECK(!skel->bss->fentry_called, "fentry", "not called\n");

cleanup:
	hello__destroy(skel);
}
