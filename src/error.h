#ifndef CTEST_ERROR_H
#define CTEST_ERROR_H

#include <sys/user.h>
struct ctest_result;

/**
 * @brief Raises an error from the parent
 */
void __ctest_raise_parent_error(struct ctest_result *result, struct user_regs_struct *regs, const char *fmt, ...);

#endif // CTEST_ERROR_H
