#ifndef CTEST_SESSION_H
#define CTEST_SESSION_H

#include "ctest.h"
#include "memory/memory.hpp"
#include "calls/calls.hpp"
#include <capstone/capstone.h>
#include <condition_variable>
#include <csetjmp>
#include <elfutils/libdwfl.h>

namespace ctest {
/**
 * @brief The session is what manages the traced program via ptrace
 */
struct session
{
	/**
	 * @brief Atomic variable to indicate tracing can start
	 */
	std::atomic<int> trace_status = 0;

	/**
	 * @brief The memory system
	 */
	mem::memory memory;

	/**
	 * @brief The calls system
	 */
	calls::calls calls;
	

	/**
	 * @brief The unit for this session
	 */
	const ctest_unit* unit;
	/**
	 * @brief The test data shared with the child
	 */
	ctest_data test_data;
	/**
	 * @brief Handle of the capstone engine
	 */
	csh capstone_handle;
	/**
	 * @brief Handle for dwfl
	 */
	Dwfl* dwfl_handle;
	/**
	 * @brief The child's pid
	 */
	pid_t child;
	/**
	 * @brief thisptr in the child's virtual memory
	 */
	uintptr_t child_session;

	/**
	 * @brief The child's standard output/error file descriptor
	 */
	int stdout, stderr;
	/**
	 * @brief The exit jump address
	 *
	 * The child should go this address when graceful shutdown is needed, e.g
	 * after an unrecoverable crash
	 */
	jmp_buf jmp_exit;

	/**
	 * @brief The tracer's entry point
	 */
	void tracer_start();
	/**
	 * @brief The child's entry point
	 */
	void child_start();

	session() = delete;
	session(const session&) = delete;

	session(const ctest_unit* unit);
	~session();

	/**
	 * @brief Starts the debugging session
	 *
	 * @returns true When the parent returns, false when the child returns
	 */
	bool start();
}; // struct session
} // namespace ctest

#endif // CTEST_SESSION_H
