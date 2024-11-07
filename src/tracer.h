#ifndef CTEST_TRACER_H
#define CTEST_TRACER_H

#include "result.h"
#include <sys/types.h>

struct ctest_result;
void __ctest_tracer_start(pid_t pid, struct ctest_result *result);

#endif // CTEST_TRACER_H
