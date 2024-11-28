#ifndef CTEST_CALLS_SYSCALLS_HPP
#define CTEST_CALLS_SYSCALLS_HPP

#include "../exceptions.hpp"
#include "calls.hpp"
#include <cstdint>
#include <sys/types.h>
#include <sys/user.h>

namespace ctest {
struct session;
} // namespace ctest

namespace ctest::calls {

namespace detail {

/* Get systen call parameter from registers following linux syscall abi */
template<std::size_t I, typename T>
T
get_syscall_parameter_value(const user_regs_struct& regs)
{
	unsigned long value;
	switch (I) {
		case 0:
			value = regs.rdi;
			break;
		case 1:
			value = regs.rsi;
			break;
		case 2:
			value = regs.rdx;
			break;
		case 3:
			value = regs.r10;
			break;
		case 4:
			value = regs.r8;
			break;
		case 5:
			value = regs.r9;
			break;
		default:
			throw ctest::exception("Unsupported syscall parameters");
	}
	if constexpr (std::is_pointer_v<T>)
		return reinterpret_cast<T>(value);
	else
		return static_cast<T>(value);
}

template<typename Tuple, std::size_t... Is>
Tuple
get_syscall_parameters_impl(const user_regs_struct& regs,
                            std::index_sequence<Is...>)
{
	return std::make_tuple(
	  get_syscall_parameter_value<Is, std::tuple_element_t<Is, Tuple>>(
	    regs)...);
}
} // namespace detail

/**
 * @brief Represents a function call
 */
struct system_call
{
	/**
	 * @brief Syscall id
	 */
	long id;
}; // struct function_call

/**
 * @brief Messages to the child
 */
union syscall_message_in
{
	struct
	{
		int fd;
		uintptr_t buffer;
		size_t count;
	} read;
}; // union syscall_message_in

/**
 * @brief Messages from the child
 */
union syscall_message_out
{
	struct
	{
		ssize_t nread;
	} read;
}; // union syscall_message_out

class syscalls
{
	/**
	 * @brief Indicates that the program is running a syscall hook, no other
	 * call hooks should be triggered during that time
	 */
	bool in_hook = false;
	/**
	 * @brief Keeps track of the last hook that ran, only valid if @ref in_hook
	 * was set previous step
	 */
	uintptr_t current_hook = 0;
	/**
	 * @brief Value of RIP before a call hook. Only valid if @ref in_hook was
	 * set previously
	 */
	uintptr_t pc_before_hook;
	/**
	 * @brief Keeps the value of RDI before detouriung the syscall. This is done
	 * because syscalls are supposed to preserve registers.
	 */
	uintptr_t saved_rdi;
	/**
	 * @brief Message from the parent to the child
	 *
	 * This is set when the child is entering a syscall hook
	 */
	syscall_message_in msg_in;
	/**
	 * @brief Message from the child to the parent
	 *
	 * This is read by the parent when a child finishes a syscall hook
	 */
	syscall_message_out msg_out;

	static ssize_t read_hook(ctest::session& session);

public:
	template<typename F>
	static auto get_syscall_parameter(const user_regs_struct& regs,
	                                  [[maybe_unused]] F&& f)
	{
		using traits = detail::function_traits<std::remove_reference_t<F>>;
		using args_tuple = typename traits::args_tuple;

		return detail::get_syscall_parameters_impl<args_tuple>(
		  regs, std::make_index_sequence<traits::arg_count>{});
	}

	template<typename F, typename T>
	void syscall_detour(pid_t pid,
	            user_regs_struct& regs,
	            F&& f,
	            T t)
	{
		using traits = detail::function_traits<std::remove_reference_t<F>>;

		static_assert(traits::arg_count == 1);

		pc_before_hook = regs.rip;
		current_hook = (uintptr_t)f;
		in_hook = true;
		saved_rdi = regs.rdi;

		// Prepare call
		const uintptr_t original_rip = regs.rip + 2; // Syscall is 0F 05
		regs.rsp -= sizeof(uintptr_t);
		ptrace(PTRACE_POKEDATA, pid, (void*)regs.rsp, original_rip);

		// Set parameters via the registers & stack
		regs.rdi = t;

		regs.rip = current_hook;
		if (ptrace(PTRACE_SETREGS, pid, 0, &regs) < 0)
			throw ctest::exception("Failed to set registers");
	}

	/**
	 * @brief Method to checks whether the child is currently running a syscall hook
	 *
	 * @returns true If the child is currently in a hook
	 */
	bool hooked() const { return in_hook; }

	/**
	 * @brief Process syscalls hooks
	 *
	 * @param session The debugging session
	 * @param regs Program registers
	 * @param system_call The syscall
	 *
	 * @return true On success, false on failure
	 */
	[[nodiscard]] bool process_syscalls(ctest::session& session,
	                                    user_regs_struct& regs,
	                                    system_call&& call);

	[[nodiscard]]
	bool process_messages(ctest::session& session,
	                      user_regs_struct& regs);
}; // class syscalls
} // namespace ctest::calls

#endif // CTEST_CALLS_SYSCALLS_HPP
