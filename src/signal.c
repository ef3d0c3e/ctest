#include "signal.h"
#include "result.h"
#include <execinfo.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>

struct ctest_signal_data __ctest_signal_new()
{
	return (struct ctest_signal_data) {
		.signum = -1,
		.handling = 0,
	};
}
void __ctest_signal_free(struct ctest_signal_data *sigdata)
{

}

void __ctest_signal_reset(struct ctest_signal_data *sigdata)
{
	sigdata->signum = -1;
}

int __ctest_signal_crash(struct ctest_signal_data *sigdata)
{
	return sigdata->signum != -1;
}

void __ctest_signal_handler(struct ctest_result *result, int signum)
{
	result->sigdata.signum = signum;
	if (result->sigdata.handling)
	{
		siglongjmp(result->jmp_recover, 1);
	}
	else
	{
		dprintf(result->messages, "Program crashed unexpectedly: SIGNAL=%d, Backtrace:\n", signum);
		void *buffer[64];
		int size = backtrace(buffer, sizeof(buffer) / sizeof(buffer[0]));
		char **bt = backtrace_symbols(buffer, size);
		for (size_t i = 0; i < size; ++i)
		{
			dprintf(result->messages, " #%zu: %s\n", i, bt[i]);
		}
		free(bt);
		siglongjmp(result->jmp_end, 1);
	}
}
