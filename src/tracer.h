#ifndef CTEST_TRACER_H
#define CTEST_TRACER_H

#include "result.h"
#include <sys/types.h>

struct ctest_result;

/**
 * @brief Shutdown function to be called by the child when in need of graceful shutdown
 *
 * @param result (RDI) The result structure
 */
void __ctest_tracer_shutdown(struct ctest_result* result);

/**
 * @brief Starts tracing the child
 */
void __ctest_tracer_start(struct ctest_result *result);

#endif // CTEST_TRACER_H
