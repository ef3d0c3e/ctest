#ifndef CTEST_CALLS_H
#define CTEST_CALLS_H

#include <capstone/capstone.h>
#include <sys/user.h>
struct ctest_result;

/**
 * @brief Process call insn
 *
 * @param result The result structure
 * @param regs The registers
 * @param insn The call insn
 *
 * @returns 1 on success, 0 on failure
 */
int
__ctest_calls_insn_hook(struct ctest_result* result,
                        struct user_regs_struct* regs,
                        cs_insn* insn);

#endif // CTEST_CALLS_H
