#ifndef CTEST_HOOKS_INSN_HPP
#define CTEST_HOOKS_INSN_HPP

#include "../memory/memory.hpp"
#include <capstone/capstone.h>
#include <functional>
#include <optional>
#include <sys/user.h>
#include <vector>

namespace ctest {
struct session;
} // namespace ctest

namespace ctest::hooks {

using insn_hook_t = std::function<
  bool(session& session, const user_regs_struct& regs, const cs_insn* insn)>;

class insn
{
	/**
	 * @brief Stores registered hooks
	 */
	std::vector<insn_hook_t> hooks;

public:
	/**
	 * @brief Registers a new hook to the list
	 *
	 * @param hook New hook to register
	 */
	void add(insn_hook_t&& hook);

	/**
	 * @brief Process instruction hooks
	 *
	 * @param session The debugging session
	 * @param regs Registers of the program
	 *
	 * @note As soon as a hook fails, the function returns false and does not
	 * run the next hooks
	 *
	 * @returns true on success, false on failure
	 */
	[[nodiscard]] bool process(session& session,
	                           const user_regs_struct& regs) const;
}; // class insn_hook

/**
 * @brief Utility for @ref mem::memory::process_access
 *
 * @param regs The program registers
 * @param insn The decoded instruction at RIP
 *
 * @returns The memory access the instruction is trying to achieve
 */
std::vector<mem::mem_access>
get_memory_access(const user_regs_struct& regs, const cs_insn* insn);
} // namespace ctest::hooks

#endif // CTEST_HOOKS_INSN_HPP
