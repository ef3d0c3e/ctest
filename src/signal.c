#include "signal.h"
#include "result.h"
#include <errno.h>
#include <execinfo.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct ctest_signal_data __ctest_signal_new()
{
	return (struct ctest_signal_data) {
		.signum = -1,
		.handling = 0,
	};
}
void __ctest_signal_free(struct ctest_signal_data *sigdata)
{
	(void)sigdata;
}

void __ctest_signal_reset(struct ctest_signal_data *sigdata)
{
	sigdata->signum = -1;
}

int __ctest_signal_crash(struct ctest_signal_data *sigdata)
{
	return sigdata->signum != -1;
}

void __ctest_signal_handler(void (*handler)(int), struct ctest_result *result, int signum)
{
	if (signum == SIGINT)
	{
		dprintf(result->messages, "WARN: Program halted unexpectedly with signal=%d\n", signum);
		siglongjmp(result->jmp_end, 1);
		// TODO: This does not gracefully shuts down the program, testers are still running
	}

	result->sigdata.signum = signum;
	if (result->sigdata.handling)
	{
		// Reinstall handler
		struct sigaction sa;
		sa.sa_handler = handler;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = SA_RESETHAND | SA_NODEFER;
		if (sigaction(signum, &sa, NULL) == -1) {
			int errsv = errno;
			dprintf(result->messages, "CRITICAL: Failed to reinstall signal handler after recoverable signal %d: %s\n", signum, strerror(errsv));
			longjmp(result->jmp_end, 1);
		}
		longjmp(result->jmp_recover, 1);
	}
	else
	{
		dprintf(result->messages, "Program crashed unexpectedly: SIGNAL=%d, Backtrace:\n", signum);
		void *buffer[64];
		int size = backtrace(buffer, sizeof(buffer) / sizeof(buffer[0]));
		char **bt = backtrace_symbols(buffer, size);
		for (int i = 0; i < size; ++i)
		{
			dprintf(result->messages, " #%d: %s\n", i, bt[i]);
		}
		free(bt);
		longjmp(result->jmp_end, 1);
	}
}
