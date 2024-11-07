#define _GNU_SOURCE
#include "tester.h"
#include "result.h"
#include "signal.h"
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include <execinfo.h>
#include <unistd.h>
#include <pthread.h>

static struct ctest_result *_G_result;
static void sighandler(int signum)
{
	printf("TID=%d\n", gettid());
	__ctest_signal_handler(_G_result, signum);
}

static void *thread_start(void *data)
{
	const struct ctest_unit *unit = data;
	
	struct ctest_result result = __ctest_result_new();
	_G_result = &result;
	// Run unit
	if (!setjmp(result.jmp_end))
	{
		unit->fn(&result);
	}
	_G_result = NULL;
	__ctest_result_print(&result);
	__ctest_result_free(&result);
	return NULL;
}

void	run_test(struct ctest_data *data, const struct ctest_unit *unit)
{
	printf("TID=%d\n", gettid());
	// Set sighandlers
	for (int i = 0; i < 32; ++i)
	{
		struct sigaction act;
		act.sa_handler = sighandler;
		// https://www.gnu.org/software/libc/manual/html_node/Blocking-for-Handler.html
		sigset_t block_mask;

		sigemptyset (&block_mask);
		sigaddset (&block_mask, i);
		act.sa_mask = block_mask;
		act.sa_flags = 0;
		if (i != 0 && i != 9 && i != 19 && sigaction(i, &act, NULL) == -1)
		{
			int errsv = errno;
			fprintf(stderr, "Failed to set signal handler for signal %d: %s\n", i, strerror(errsv));
		}
	}

	// TODO REDIR
 	pthread_t tid;
	pthread_create(&tid, NULL, thread_start, (void*)unit);
	pthread_join(tid, NULL);
}
