#ifndef CTEST_SIGNAL_H
#define CTEST_SIGNAL_H

struct ctest_result;

/**
 * @brief Stores signal data
 */
struct ctest_signal_data
{
	/**
	 * @brief Whether signals should be handled in a recoverable manner (e.g jumping to the @ref
	 * ctest_result.jmp_recover) Otherwise, the handler should jump to @ref ctest_result.jmp_end
	 */
	int handling;
	/**
	 * @brief The last signal received
	 *
	 * Set to -1 when nothing has happened, @see __ctest_signal_reset and @see
	 * __ctest_signal_crash
	 */
	int signum;
};

/**
 * @brief Creates a new signal data structure
 */
struct ctest_signal_data
__ctest_signal_new();
/**
 * @brief Destroys a signal data structure
 */
void
__ctest_signal_free(struct ctest_signal_data* sigdata);

/**
 * @brief Resets the signal data
 *
 * This function should be used after a crash
 *
 * @param sigdata The signal data
 */
void
__ctest_signal_reset(struct ctest_signal_data* sigdata);
/**
 * @brief Checks if a crash has happened
 *
 * @param sigdata The signal data
 */
int
__ctest_signal_crash(struct ctest_signal_data* sigdata);

/**
 * @brief The signal handler
 *
 * Handles signals and attempts to recover if @ref ctest_signal_data.handling is true,
 * otherwise terminates the current test.
 *
 * @param handler The original signal handler, so it can be properly reinstalled on recoverable
 * signals
 * @param result The @ref ctest_result data
 * @param signum The signal number
 */
void
__ctest_signal_handler(void (*handler)(int), struct ctest_result* result, int signum);

#endif // CTEST_SIGNAL_H
