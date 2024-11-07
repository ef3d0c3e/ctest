#ifndef CTEST_RESULT_H
#define CTEST_RESULT_H

#include "signal.h"
#include <setjmp.h>

/**
 * @brief Structure to hold the result of a test
 */
struct ctest_result
{
	/**
	 * @brief The internal message channel
	 *
	 * Stores error and debug messages.
	 * This channel is printed at the end of the test.
	 * If empty consider the test as successful.
	 */
	int	messages;
	/**
	 * @brief The stdout redirect
	 */
	int stdout;
	/**
	 * @brief The stderr redirect
	 */
	int	stderr;
	/**
	 * @brief The signal data
	 */
	struct ctest_signal_data sigdata;
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
};

/**
 * @brief Creates a new test result structure
 */
struct ctest_result __ctest_result_new();
/**
 * @brief Deletes a test result structure
 */
void __ctest_result_free(struct ctest_result *res);

/**
 * @brief Prints the content of the internal logging channel
 */
void __ctest_result_print(struct ctest_result *res);

#endif // CTEST_RESULT_H
