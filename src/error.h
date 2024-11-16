#ifndef CTEST_ERROR_H
#define CTEST_ERROR_H

#include "arena.h"
#include <stdint.h>
#include <sys/user.h>
struct ctest_result;

/**
 * @brief Handles segfault in ptrace mode
 */
void
__ctest_handle_sigsegv(struct ctest_result* result, struct user_regs_struct* regs);

/**
 * @brief Convenience function to raises an error from the parent
 */
void
__ctest_raise_parent_error(struct ctest_result* result,
                           struct user_regs_struct* regs,
                           const char* fmt,
                           ...);

/**
 * @brief Prints information related to an allocation
 *
 * @param result The result structure
 * @param alloc The allocation
 */
void
__ctest_print_alloc_info(struct ctest_result* result, struct ctest_mem_allocation* alloc);

/**
 * @brief Prints the values in the registers
 *
 * @param fd The file descriptor to print to
 * @param regs The registers state
 */
void
__ctest_print_registers(int fd, struct user_regs_struct* regs);

/**
 * @brief Prints the source line information
 *
 * This will only work if the tested binary was compiled with debug informations, e.g `-g` on gcc
 *
 * @param result The result structure
 * @param fd The file descriptor to print to
 * @param rip Instruction to print the line of
 *
 * @returns 1 If getting the line info succeeded, 0 otherwise
 */
int
__ctest_print_source_line(struct ctest_result* result, int fd, uintptr_t rip);

/**
 * @brief Prints a stacktrace of the traced process
 *
 * This function will walk the stack and try to retrieve symbols informations
 *
 * @param result The result structure
 * @param fd The file descriptor to print to
 * @param regs Registers state
 */
void
__ctest_print_stack_trace(struct ctest_result* result, int fd, struct user_regs_struct* regs);

#endif // CTEST_ERROR_H
