#ifndef CTEST_BUFFER_H
#define CTEST_BUFFER_H

#include <stdint.h>
#include <sys/user.h>
#include <unistd.h>
struct ctest_result;

/**
 * @brief Checks that the buffer at `addr` can hold `size` bytes
 *
 * This function will raise an error in case the buffer is unable to hold size.
 *
 * @param result The result structure
 * @param regs The traced program's registers
 * @param addr Start address in a buffer
 * @param size The size to check
 * @param action The action message, e.g `read` or `read+write`
 *
 * @returns 0 If an error happened
 */
int
__ctest_buffer_at_least(struct ctest_result* result, struct user_regs_struct* regs, uintptr_t addr, size_t size, const char* action);

#endif // CTEST_BUFFER_H
