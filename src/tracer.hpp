#ifndef CTEST_TRACER_HPP
#define CTEST_TRACER_HPP

#include "hooks/insn.hpp"

namespace ctest {

struct session;
/**
 * The class responsible for ptracing the program
 */
class tracer
{
	/**
	 * @brief The debug session
	 */
	ctest::session& session;

	/**
	 * @brief The instruction hooks
	 */
	hooks::insn insn_hooks;

	/**
	 * @brief Recovery function for the child
	 *
	 * @param session (RDI)
	 */
	static void recover(ctest::session& session);

	/**
	 * @brief Handles sigsegv, based on whether the tracer should make the child
	 * recover or not
	 *
	 * @returns true If tracing should continue, false otherwise.
	 */
	bool handle_sigsegv();

public:
	/**
	 * @brief Constructor
	 *
	 * @params session A @ref session that where ptrace has already been
	 * initialized
	 */
	tracer(ctest::session& session);

	void trace();
}; // class tracer
} // namespace ctest

#endif // CTEST_TRACER_HPP
