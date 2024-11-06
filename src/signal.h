#ifndef CTEST_SIGNAL_H
#define CTEST_SIGNAL_H

struct ctest_signal_data
{
	/**
	 * @brief Whether signals should be handled in a recoverable manner (e.g jumping to the @ref ctest_result.jmp_recover)
	 * Otherwise, the handler should jump to @ref ctest_result.jmp_end
	 */
	int handling;
	int signum;
};

struct ctest_signal_data __ctest_signal_new();
void __ctest_signal_free(struct ctest_signal_data *sigdata);

void __ctest_signal_reset(struct ctest_signal_data *sigdata);
int __ctest_signal_crash(struct ctest_signal_data *sigdata);

#endif // CTEST_SIGNAL_H
