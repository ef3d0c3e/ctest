#ifndef CTEST_INSN_H
#define CTEST_INSN_H

#include <capstone/capstone.h>
#include <sys/user.h>

struct ctest_result;

/**
 * @brief Runs a hook on decoded instructions
 *
 * @param result The result structure
 * @param regs The process's register state
 * @param insn_hook The hook that will be called once instructions are decoded
 *
 * @note This function will crash the program on failure to decode instructions
 */
void
__ctest_insn_hook(struct ctest_result* result,
                  struct user_regs_struct* regs,
                  void (*insn_hook)(struct ctest_result*, struct user_regs_struct*, cs_insn*));

#endif // CTEST_INSN_H
