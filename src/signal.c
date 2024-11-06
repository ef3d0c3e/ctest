#include "signal.h"

struct ctest_signal_data __ctest_signal_new()
{
	return (struct ctest_signal_data) {
		.signum = -1,
		.handling = 0,
	};
}
void __ctest_signal_free(struct ctest_signal_data *sigdata)
{

}

void __ctest_signal_reset(struct ctest_signal_data *sigdata)
{
	sigdata->signum = -1;
}

int __ctest_signal_crash(struct ctest_signal_data *sigdata)
{
	return sigdata->signum != -1;
}
