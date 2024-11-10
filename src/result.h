#ifndef CTEST_RESULT_H
#define CTEST_RESULT_H

#include "memory.h"
#include "signal.h"
#include <capstone/capstone.h>
#include <setjmp.h>

/**
 * @brief Structure to hold the result of a test
 */
struct ctest_result
{
	/**
	 * @brief The unit being tested
	 */
	const struct ctest_unit *unit;
	/**
	 * @brief The internal message channel
	 *
	 * Stores error and debug messages.
	 * This channel is printed at the end of the test.
	 * If empty consider the test as successful.
	 */
	int messages;
	/**
	 * @brief The stdout redirect
	 */
	int stdout;
	/**
	 * @brief The stderr redirect
	 */
	int stderr;
	/**
	 * @brief The signal data
	 */
	struct ctest_signal_data sigdata;
	/**
	 * @brief Memory data
	 */
	struct ctest_mem mem;
	/**
	 * @brief longjmp address to recover from an intentional crash
	 *
	 * Should not be used if @ref sigdata.handling is 0
	 */
	jmp_buf jmp_recover;
	/**
	 * @brief longjmp address to terminate the test
	 *
	 * This is used when the test crashes unexpectedly
	 */
	jmp_buf jmp_end;

	/**
	 * @brief The child's pid in ptrace mpde
	 */
	pid_t child;
	/**
	 * @brief Address of this struct in the child process
	 */
	uintptr_t child_result;
	/**
	 * @brief Flag set to 1 when the child is in the testing function
	 */
	int in_function;

	/**
	 * @brief Handle of the capstone engine
	 */
	csh capstone_handle;

	/**
	 * @brief Messages parent -> child
	 *
	 * Used to send custom commands to hooks
	 */
	union
	{
		union ctest_mem_msg_out mem;
	} message_out;

	/**
	 * @brief Messages child -> parent
	 *
	 * Used to receive custom commands from hooks
	 */
	union
	{
		union ctest_mem_msg_in mem;
	} message_in;
};

/**
 * @brief Initializes a new result into mmaped memory
 *
 * @returns A new mmap buffer containing a result
 */
struct ctest_result*
__ctest_result_new(const struct ctest_unit* unit);
/**
 * @brief Deletes a test result structure
 */
void
__ctest_result_free(struct ctest_result* res);

/**
 * @brief Prints the content of the internal logging channel
 */
void
__ctest_result_print(struct ctest_result* res);

#endif // CTEST_RESULT_H
