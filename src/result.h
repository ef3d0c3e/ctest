#ifndef CTEST_RESULT_H
#define CTEST_RESULT_H

#include "signal.h"
#include <setjmp.h>

struct ctest_result
{
	int	messages;
	int stdout;
	int	stderr;
	struct ctest_signal_data sigdata;
	jmp_buf jmp_recover;
	jmp_buf jmp_end;
};

struct ctest_result __ctest_result_new();
void __ctest_result_free(struct ctest_result *res);

void __ctest_result_print(struct ctest_result *res);

#endif // CTEST_RESULT_H
