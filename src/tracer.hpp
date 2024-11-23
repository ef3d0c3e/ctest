#ifndef CTEST_TRACER_HPP
#define CTEST_TRACER_HPP

#include "insn.hpp"

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
	insn_hook insn_hooks;

	/**
	 * @brief Handles sigsegv, based on whether the tracer should make the child recover or not
	 *
	 * @returns true If tracing should continue, false otherwise.
	 */
	bool handle_sigsegv();
public:
	/**
	 * @brief Constructor
	 *
	 * @params session A @ref session that where ptrace has already been initialized
	 */
	tracer(ctest::session& session);

	void trace();
}; // class tracer
} // namespace ctest

#endif // CTEST_TRACER_HPP
