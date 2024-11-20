#ifndef CTEST_RESULT_H
#define CTEST_RESULT_H

#ifdef __cplusplus
extern "C"
{
#endif // __cplusplus

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
}; // struct ctest_data

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // CTEST_RESULT_H
