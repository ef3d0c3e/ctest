#ifndef CTEST_REPORTING_REPORT_HPP
#define CTEST_REPORTING_REPORT_HPP

#include <cstdint>
#include "../memory/heap.hpp"
#include <sys/user.h>

namespace ctest {
struct session;
} // namespaace ctest

namespace ctest::report {
/**
 * @brief Prints registers to stderr
 *
 * @param regs Registers to print
 */
void
registers(const struct user_regs_struct& regs);

/**
 * @brief Prints a stacktrace to stderr
 *
 * @param session The debugging session
 * @param pc The program counter
 * @param limit Stack trace limit
 */
void
stack_trace(const session& session, uintptr_t pc, size_t limit = 16);

/**
 * @brief Prints source line information for a given program counter to stderr
 *
 * @param session The debugging session
 * @param pc The program counter
 */
void source_line(const session& session, uintptr_t pc);

/**
 * @brief Prints information about an allocation to stderr
 *
 * @param session The debugging session
 * @param block The heap block to display information about
 */
void allocation(const session& session, const mem::heap_block& block);
} // namespace ctest::report

#endif // CTEST_REPORTING_REPORT_HPP
