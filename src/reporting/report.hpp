#ifndef CTEST_REPORTING_REPORT_HPP
#define CTEST_REPORTING_REPORT_HPP

#include "../memory/heap.hpp"
#include "../memory/maps.hpp"
#include <cstdint>
#include <string>
#include <sys/user.h>

namespace ctest {
struct session;
} // namespaace ctest

// TODO: The methods used to get informations should be split to be made
// available to other modules.
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
void
source_line(const session& session, uintptr_t pc);

/**
 * @brief Prints information about an allocation to stderr
 *
 * @param session The debugging session
 * @param block The heap block to display information about
 */
void
allocation(const session& session, const mem::heap_block& block);

/**
 * @brief Prints informations about memory map
 */
void
map(const session& session, const mem::map_entry& entry);

/**
 * @brief Prints an error message to stderr
 *
 * @param The debug session
 * @param regs The registers of the program when the error is created
 * @param what The formatted error message
 */
void
error_message(const session& session,
              const user_regs_struct& regs,
              std::string what);

/**
 * @brief Prints an information message to stderr
 *
 * @param The debug session
 * @param regs The registers of the program when the error is created
 * @param what The formatted information message
 */
void
info_message(const session& session,
              const user_regs_struct& regs,
              std::string what);
} // namespace ctest::report

#endif // CTEST_REPORTING_REPORT_HPP
