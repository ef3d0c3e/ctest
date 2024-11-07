#ifndef CTEST_TESTER_H
#define CTEST_TESTER_H

#include "test.h"

struct ctest_data
{
	const char* filter;
	size_t successes;
	size_t failures;
};

void
run_test(struct ctest_data* data, const struct ctest_unit* unit);

#endif // CTEST_TESTER_H
