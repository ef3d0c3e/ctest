#ifndef CTEST_CALLS_CALLS_HPP
#define CTEST_CALLS_CALLS_HPP

#include "../exceptions.hpp"
#include <cstdint>
#include <set>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <tuple>
#include <type_traits>
#include <utility>

namespace ctest {
struct session;
} // namespace ctest

namespace ctest::calls {

/**
 * @brief Boilerplate code for function_traits, should cover most cases
 */
namespace detail {
template<typename T>
struct function_traits;

/* Regular function pointer with noexcept */
template<typename R, typename... Args>
struct function_traits<R (*)(Args...) noexcept>
{
	using return_type = R;
	static constexpr size_t arg_count = sizeof...(Args);
	using args_tuple =
	  std::tuple<std::remove_cv_t<std::remove_reference_t<Args>>...>;
};

/* Regular function pointer */
template<typename R, typename... Args>
struct function_traits<R (*)(Args...)>
{
	using return_type = R;
	static constexpr size_t arg_count = sizeof...(Args);
	using args_tuple =
	  std::tuple<std::remove_cv_t<std::remove_reference_t<Args>>...>;
};

/* C-style function with noexcept */
template<typename R, typename... Args>
struct function_traits<R(Args...) noexcept>
{
	using return_type = R;
	static constexpr size_t arg_count = sizeof...(Args);
	using args_tuple =
	  std::tuple<std::remove_cv_t<std::remove_reference_t<Args>>...>;
};

/* C-style function */
template<typename R, typename... Args>
struct function_traits<R(Args...)>
{
	using return_type = R;
	static constexpr size_t arg_count = sizeof...(Args);
	using args_tuple =
	  std::tuple<std::remove_cv_t<std::remove_reference_t<Args>>...>;
};

/* Member function pointer with noexcept */
template<typename C, typename R, typename... Args>
struct function_traits<R (C::*)(Args...) noexcept>
{
	using return_type = R;
	static constexpr size_t arg_count = sizeof...(Args);
	using args_tuple =
	  std::tuple<std::remove_cv_t<std::remove_reference_t<Args>>...>;
};

/* Member function pointer */
template<typename C, typename R, typename... Args>
struct function_traits<R (C::*)(Args...)>
{
	using return_type = R;
	static constexpr size_t arg_count = sizeof...(Args);
	using args_tuple =
	  std::tuple<std::remove_cv_t<std::remove_reference_t<Args>>...>;
};

/* Const member function pointer with noexcept */
template<typename C, typename R, typename... Args>
struct function_traits<R (C::*)(Args...) const noexcept>
{
	using return_type = R;
	static constexpr size_t arg_count = sizeof...(Args);
	using args_tuple =
	  std::tuple<std::remove_cv_t<std::remove_reference_t<Args>>...>;
};

/* Const member function pointer */
template<typename C, typename R, typename... Args>
struct function_traits<R (C::*)(Args...) const>
{
	using return_type = R;
	static constexpr size_t arg_count = sizeof...(Args);
	using args_tuple =
	  std::tuple<std::remove_cv_t<std::remove_reference_t<Args>>...>;
};

/* Function reference with noexcept */
template<typename R, typename... Args>
struct function_traits<R (&)(Args...) noexcept>
{
	using return_type = R;
	static constexpr size_t arg_count = sizeof...(Args);
	using args_tuple =
	  std::tuple<std::remove_cv_t<std::remove_reference_t<Args>>...>;
};

/* Function reference */
template<typename R, typename... Args>
struct function_traits<R (&)(Args...)>
{
	using return_type = R;
	static constexpr size_t arg_count = sizeof...(Args);
	using args_tuple =
	  std::tuple<std::remove_cv_t<std::remove_reference_t<Args>>...>;
};

/* Helper to get function traits from any callable type */
template<typename T>
struct get_function_traits
{
	using type = function_traits<std::remove_cv_t<std::remove_reference_t<T>>>;
};

/* Specialization for function pointers with noexcept */
template<typename R, typename... Args>
struct get_function_traits<R (*)(Args...) noexcept>
{
	using type = function_traits<R (*)(Args...) noexcept>;
};

/* Specialization for function pointers */
template<typename R, typename... Args>
struct get_function_traits<R (*)(Args...)>
{
	using type = function_traits<R (*)(Args...)>;
};

/* Helper type alias */
template<typename T>
using get_function_traits_t = typename get_function_traits<T>::type;

/* Helper to check if type should be passed in XMM registers */
template<typename T>
constexpr bool
is_xmm_type()
{
	return std::is_same_v<T, float> || std::is_same_v<T, double>;
}

/* Get parameter from registers following x86_64 System V ABI */
template<std::size_t I, typename T>
T
get_parameter_value(pid_t pid,
                    const user_regs_struct& regs,
                    const user_fpregs_struct& fpregs)
{
	if constexpr (is_xmm_type<T>()) {
		// Handle XMM registers (float/double)
		if constexpr (I < 8) { // XMM0-XMM7 for floating point
			const auto* xmm_ptr =
			  reinterpret_cast<const T*>(&fpregs.xmm_space[I * 16]);
			return *xmm_ptr;
		}
	} else {
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
				value = regs.rcx;
				break;
			case 4:
				value = regs.r8;
				break;
			case 5:
				value = regs.r9;
				break;
			default: {
				// TODO: Verify it's working
				unsigned long stack_addr =
				  regs.rsp + sizeof(uintptr_t) * (I - 6 + 1);
				value = ptrace(PTRACE_PEEKDATA, pid, stack_addr, nullptr);
			}
		}
		if constexpr (std::is_pointer_v<T>)
			return reinterpret_cast<T>(value);
		else
			return static_cast<T>(value);
	}
}

/* Set parameter in registers or stack following x86_64 System V ABI */
template<std::size_t I, typename T>
void
set_parameter_value(pid_t pid,
                    user_regs_struct& regs,
                    user_fpregs_struct& fpregs,
                    T&& t)
{
	if constexpr (is_xmm_type<T>()) {
		// Handle XMM registers (float/double)
		if constexpr (I < 8) { // XMM0-XMM7 for floating point
			const auto* xmm_ptr =
			  reinterpret_cast<const T*>(&fpregs.xmm_space[I * 16]);
			return *xmm_ptr;
		}
	} else {
		unsigned long long* value;
		switch (I) {
			case 0:
				value = &regs.rdi;
				break;
			case 1:
				value = &regs.rsi;
				break;
			case 2:
				value = &regs.rdx;
				break;
			case 3:
				value = &regs.rcx;
				break;
			case 4:
				value = &regs.r8;
				break;
			case 5:
				value = &regs.r9;
				break;
			default: {
				// TODO: Verify it's working
				unsigned long stack_addr =
				  regs.rsp + sizeof(uintptr_t) * (I - 6 + 1);
				if constexpr (std::is_pointer_v<T>)
					ptrace(
					  PTRACE_POKEDATA, pid, stack_addr, reinterpret_cast<T>(t));
				else
					ptrace(PTRACE_POKEDATA, pid, stack_addr, static_cast<T>(t));
				return;
			}
		}
		if constexpr (std::is_pointer_v<T>)
			*value = reinterpret_cast<T>(t);
		else
			*value = static_cast<T>(t);
	}
}

template<typename Tuple, std::size_t... Is>
Tuple
get_parameters_impl(pid_t pid,
                    const user_regs_struct& regs,
                    std::index_sequence<Is...>)
{
	// TODO: Only evaluate if required
	user_fpregs_struct fpregs;
	if (ptrace(PTRACE_GETFPREGS, pid, nullptr, &fpregs) < 0)
		throw ctest::exception("Failed to get floating point registers");

	return std::make_tuple(
	  get_parameter_value<Is, std::tuple_element_t<Is, Tuple>>(
	    pid, regs, fpregs)...);
}

template<typename Tuple>
void
make_call_impl(pid_t pid,
               user_regs_struct& regs,
               user_fpregs_struct& fpregs,
               Tuple&& t)
{
	[&]<auto... i>(std::index_sequence<i...>) {
		(set_parameter_value<i>(pid, regs, fpregs, std::get<i>(t)), ...);
	}(std::make_index_sequence<std::tuple_size_v<Tuple>>{});
}

} // namespace detail

/**
 * @brief Represents a function call
 */
struct function_call
{
	/**
	 * @brief Base address of the call, e.g `call 0x74f74`
	 */
	uintptr_t addr;
	/**
	 * @brief Resolved address of the call
	 */
	uintptr_t resolved;

	/**
	 * @brief Length in bytes of the call insruction
	 */
	uint16_t call_length;

	/**
	 * @brief Whether the called function is already being executed
	 */
	bool inside;
}; // struct function_call

/**
 * @brief Messages to the child
 */
union call_message_in
{
	struct
	{
		size_t size;
	} malloc;

	struct
	{
		size_t size;
	} calloc;

	struct
	{
		uintptr_t ptr;
	} free;
}; // union call_message_in

/**
 * @brief Messages from the child
 */
union call_message_out
{
	struct
	{
		uintptr_t ptr;
	} malloc;

	struct
	{
		uintptr_t ptr;
	} calloc;
}; // union call_message_out

/**
 * @brief Class that handles function calls
 */
class calls
{
	/**
	 * @brief Set containing all functions that are hooked
	 */
	std::set<uintptr_t> pc_hooks;
	/**
	 * @brief Indicates that the program is running a call hook, no other call
	 * hooks should be triggered during that time
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
	 * @brief Message from the parent to the child
	 *
	 * This is set when the child is entering a call hook
	 */
	call_message_in msg_in;
	/**
	 * @brief Message from the child to the parent
	 *
	 * This is read by the parent when a child finishes a call hook
	 */
	call_message_out msg_out;

	static void* malloc_hook(ctest::session& session);
	static void* calloc_hook(ctest::session& session);
	static void free_hook(ctest::session& session);

public:
	/**
	 * @brief Gets the value of a call parameter by it's number
	 *
	 * # Example
	 *
	 * @code cpp
	 * The call:
	 * ptr = realloc(optr, size);
	 * Will give:
	 * auto&& [_optr, _size] = get_call_parameter(realloc, regs, fpregs);
	 * assert(optr == optr);
	 * assert(_size == size);
	 * @encode
	 *
	 * @note This method requires ptrace to get stack values or floating-point
	 * registers in some cases
	 *
	 * @param pid The pid of the traced program
	 * @param regs The base registers
	 * @param f The function to get parameters of
	 *
	 * @returns The parameters passed to f as a tuple, in order
	 */
	template<typename F>
	static auto get_call_parameter(pid_t pid,
	                               const user_regs_struct& regs,
	                               [[maybe_unused]] F&& f)
	{
		using traits = detail::function_traits<std::remove_reference_t<F>>;
		using args_tuple = typename traits::args_tuple;

		return detail::get_parameters_impl<args_tuple>(
		  pid, regs, std::make_index_sequence<traits::arg_count>{});
	}
	/**
	 * @brief Makes the child process call a specific function
	 *
	 * Makes the child call to a custom function `f` and return to it's current
	 * RIP + call_length. This method is to be used when the child makes a call
	 * to a function and you want it to call another function instead (hooking)
	 *
	 * This method also updates the @ref pc_before_hook, @ref current_hook and
	 * @ref in_hook variables.
	 *
	 * @param pid Pid of the child
	 * @param regs Registers of the child (will be modified)
	 * @param f Function to call
	 * @param ts Parameters, must match the function's parameters
	 */
	template<typename F, typename... Ts>
	void make_call(pid_t pid,
	               user_regs_struct& regs,
	               F&& f,
	               const function_call& call,
	               Ts&&... ts)
	{
		using traits = detail::function_traits<std::remove_reference_t<F>>;

		static_assert(traits::arg_count == sizeof...(Ts));

		pc_before_hook = regs.rip;
		current_hook = (uintptr_t)f;
		in_hook = true;

		// Get fpregs
		user_fpregs_struct fpregs;
		if (ptrace(PTRACE_GETFPREGS, pid, nullptr, &fpregs) < 0)
			throw ctest::exception("Failed to get floating point registers");

		// Prepare call
		if (call.inside == 0) {
			const uintptr_t original_rip = regs.rip + call.call_length;
			regs.rsp -= sizeof(uintptr_t);
			ptrace(PTRACE_POKEDATA, pid, (void*)regs.rsp, original_rip);
		}

		// Set parameters via the registers & stack
		detail::make_call_impl(
		  pid, regs, fpregs, std::make_tuple(std::forward<Ts>(ts)...));

		regs.rip = current_hook;
		if (ptrace(PTRACE_SETREGS, pid, 0, &regs) < 0)
			throw ctest::exception("Failed to set registers");
		if (ptrace(PTRACE_SETFPREGS, pid, 0, &fpregs) < 0)
			throw ctest::exception("Failed to set floating-point registers");
	}

	/**
	 * @brief Constructor
	 *
	 * Initializes the hooks tables
	 */
	calls();

	/**
	 * @brief Method to checks whether the child is currently running a hook
	 *
	 * @returns true If the child is currently in a hook
	 */
	bool hooked() const { return in_hook; }

	/**
	 * @brief Process function hooks
	 *
	 * @param session The debugging session
	 * @param regs Program registers
	 * @param call The call
	 *
	 * @return true On success, false on failure
	 */
	[[nodiscard]] bool process_calls(ctest::session& session,
	                                 user_regs_struct& regs,
	                                 function_call&& call);

	/**
	 * @brief Process function hooks from the RIP
	 *
	 * Whenever a function is called directly, this method will check the RIP in
	 * order to call a hooked version. It will call @ref process_calls in order
	 * to achieve this.
	 *
	 * @param session The debugging session
	 * @param regs Program registers
	 *
	 * @return 1 On success, 0 on failure
	 */
	[[nodiscard]] bool process_from_pc(ctest::session& session,
	                                   user_regs_struct& regs);

	[[nodiscard]]
	bool process_messages(ctest::session& session,
	                      const user_regs_struct& regs);
}; // class calls
} // namespace ctest::calls

#endif // CTEST_CALLS_CALLS_HPP
