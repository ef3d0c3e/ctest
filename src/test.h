#ifndef CTEST_H
#define CTEST_H

#include "result.h"
#include <stdint.h>
#include <stdio.h>

typedef int (*ctest_unit_fn)(struct ctest_result *);

enum ctest_unit_flags : uint8_t
{
	CTEST_FLAG_DEFAULT = 0,
	CTEST_FLAG_REAL_MALLOC = 0b00000001,
};

struct ctest_unit
{
	const char *file;
	const size_t id;
	const ctest_unit_fn fn;
	const uint8_t flags;
};


#define __CTEST_CONCAT(__X, __Y) __X##__Y
#define CTEST_CONCAT(__X, __Y) __CTEST_CONCAT(__X, __Y)

#define __CTEST_UNIT(__NAME, __ID, ...) \
int CTEST_CONCAT(CTEST_CONCAT(__ctest_function_, __NAME), __ID)(struct ctest_result *__ctest_result) { \
	__VA_ARGS__; \
	return 1; \
} \
struct ctest_unit CTEST_CONCAT(CTEST_CONCAT(__ctest_unit_, __NAME), __ID) = { \
	.file = __FILE__, \
	.id = __ID, \
	.fn = CTEST_CONCAT(CTEST_CONCAT(__ctest_function_, __NAME), __ID), \
	.flags = CTEST_FLAG_DEFAULT, \
};
#define CTEST_UNIT(__NAME, ...) __CTEST_UNIT(__NAME, __COUNTER__, __VA_ARGS__)

#define __CTEST_LOG(__FILE, __LINE, __MSG, ...) dprintf(__ctest_result->messages, \
		"In %s at line %d: %s:\n -- BEGIN CODE --\n%s\n -- END CODE --\n", (__FILE), (__LINE), (__MSG), #__VA_ARGS__);

/**
 * @brief Check if an expression crashes the program
 *
 * A sighandler will check for crash signals and then a condition will
 * be used to test if the program did crash.
 */
#define CTEST_CRASH(__MSG, ...) \
{ \
	__ctest_signal_reset(&__ctest_result->sigdata); \
	const int __ctest_handling = __ctest_result->sigdata.handling; \
	__ctest_result->sigdata.handling = 1; \
	if (!setjmp(__ctest_result->jmp_recover)) \
	{ \
		{ __VA_ARGS__; } \
		if (!__ctest_signal_crash(&__ctest_result->sigdata)) \
		{ \
			__CTEST_LOG(__FILE__, __LINE__, (__MSG), __VA_ARGS__) \
			return 0; \
		} \
	} \
	__ctest_result->sigdata.handling = __ctest_handling; \
	__ctest_signal_reset(&__ctest_result->sigdata); \
}


#endif // CTEST_H
