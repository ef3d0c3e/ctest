#ifndef CTEST_RESULT_H
#define CTEST_RESULT_H

#include <setjmp.h>

#ifdef __cplusplus
extern "C"
{
#endif // __cplusplus

struct ctest_signal_status
{
	/**
	 * @brief The last signal emitted by the child, 0 for none
	 */
	int signum;
	/**
	 * @brief Whether the tracer program should make the child recover on SIGSEGV
	 */
	int recover;
	/**
	 * @brief Where the program should attempt to recover
	 */
	jmp_buf recovery_point;
}; // struct signal_status

/**
 * @brief Data accessible to the running test
 */
struct ctest_data
{
	/**
	 * @brief Flag set to 1 when the tested function is running
	 */
	int in_function;

	/**
	 * @brief The message file descriptor
	 *
	 * This is an in-memory file descriptor to report to the parent
	 */
	int message_fd;

	/**
	 * @brief How the tracing program should handle signals from the child
	 */
	struct ctest_signal_status sigstatus;
}; // struct ctest_data

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // CTEST_RESULT_H
