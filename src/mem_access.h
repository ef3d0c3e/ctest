#ifndef CTEST_MEM_ACCESS_H
#define CTEST_MEM_ACCESS_H

#include <capstone/capstone.h>
#include <sys/user.h>
struct ctest_result;

/**
 * @brief Hook called when a memory access instruction is executed
 *
 * @brief result The result structure
 * @brief regs The registers
 * @brief insi The executed instruction
 */
int __ctest_mem_access_insn_hook(struct ctest_result* result, struct user_regs_struct* regs, cs_insn* insn);

/**
 * @brief Hooks called when a memory management function is called
 *
 * Currently this is called for malloc/realloc and free
 *
 * @returns 1 If message_in needs to be processed for the next steps
 */
int
__ctest_mem_memman_hook(struct ctest_result* result, struct user_regs_struct* regs);

#endif // CTEST_MEM_ACCESS_H
