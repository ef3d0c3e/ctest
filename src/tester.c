#include <sys/mman.h>
#define _GNU_SOURCE
#include "tester.h"
#include "tracer.h"
#include "result.h"
#include "signal.h"
#include <errno.h>
#include <execinfo.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <linux/ptrace.h>
#include <threads.h>
#include <unistd.h>

/* Signals handler for non ptraced runtime */
static struct ctest_result* _G_result;
static void
sighandler(int signum)
{
	__ctest_signal_handler(sighandler, _G_result, signum);
}

static void*
child_start(const struct ctest_unit* unit)
{
	if (!(unit->flags & CTEST_DISABLE_PTRACE))
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
	else
	{
		// Set sighandlers
		for (int i = 0; i < 32; ++i)
		{
			// https://www.gnu.org/software/libc/manual/html_node/Blocking-for-Handler.html
			struct sigaction act;
			act.sa_handler = sighandler;
			sigemptyset (&act.sa_mask);
			act.sa_flags = SA_RESETHAND | SA_NODEFER;
			if (i != 0 && i != 9 && i != 19 && sigaction(i, &act, NULL) == -1)
			{
				int errsv = errno;
				fprintf(stderr, "Failed to set signal handler for signal %d: %s\n", i,
						strerror(errsv));
			}
		}
	}

	struct ctest_result result = __ctest_result_new();
	_G_result = &result;
	// Run unit
	if (!setjmp(result.jmp_end)) {
		unit->fn(&result);
	}
	_G_result = NULL;
	// TODO: Raise errors on unhandled stdout/stderr content
	__ctest_result_print(&result);
	__ctest_result_free(&result);
	exit(1);
	return NULL;
}

void
run_test(struct ctest_data* data, const struct ctest_unit* unit)
{
	// TODO REDIR
	pid_t pid = fork();
	if (pid > 0) {
		if (!(unit->flags & CTEST_DISABLE_PTRACE))
			__ctest_tracer_start(pid);
	} else {
		child_start(unit);
	}
}
