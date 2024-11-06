#include "tester.h"
#include "result.h"
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>

static struct ctest_result *_G_result;
static void sighandler(int signum)
{
	_G_result->sigdata.signum = signum;
	if (_G_result->sigdata.handling)
		siglongjmp(_G_result->jmp_recover, 1);
	else
	{
		// TODO: Backtrace
		dprintf(_G_result->messages, "Program crashed unexpectedly: %d\n", signum);
		siglongjmp(_G_result->jmp_end, 1);
	}
}

void	run_test(struct ctest_data *data, const struct ctest_unit *unit)
{
	// Set sighandlers
	for (int i = 0; i < 32; ++i)
	{
		if (i != 0 && i != 9 && i != 19 && signal(i, sighandler) == SIG_ERR)
		{
			int errsv = errno;
			fprintf(stderr, "Failed to set signal handler for signal %d: %s\n", i, strerror(errsv));
		}
	}

	// TODO REDIR
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
}
