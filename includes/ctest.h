#ifndef CTEST_H
#define CTEST_H

#include "result.h"
#include <signal.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C"
{
#endif // __cplusplus

typedef int (*ctest_unit_fn)(struct ctest_data*);

enum ctest_unit_flags
{
	CTEST_FLAG_DEFAULT = 0,
	CTEST_DISABLE_PTRACE = 0b00000001,
};

/**
 * @brief Test unit data structure
 */
struct ctest_unit
{
	/**
	 * @brief Source file of the test
	 *
	 * Shoule be populated by the __FILE__ macro
	 */
	const char* file;
	/**
	 * @brief File-unique id
	 *
	 * Should be populated by the (non-standard) __COUNTER__ macro
	 */
	const size_t id;
	/**
	 * @brief The test function
	 *
	 * Not strictly necessary to store here as the function is a linkable
	 * symbol, but it makes for easier access
	 */
	const ctest_unit_fn fn;
	/**
	 * @brief Flags for the test @see ctest_unit_flags
	 */
	const uint8_t flags;
};

#define __CTEST_CONCAT(__X, __Y) __X##__Y
#define CTEST_CONCAT(__X, __Y) __CTEST_CONCAT(__X, __Y)

#define __CTEST_UNIT(__NAME, __ID, ...)                                        \
	int CTEST_CONCAT(CTEST_CONCAT(__ctest_function_, __NAME),                  \
	                 __ID)(struct ctest_data * __ctest_data)                   \
	{                                                                          \
		__ctest_data->in_function = 1;                                         \
		{                                                                      \
			__VA_ARGS__;                                                       \
		}                                                                      \
		return 1;                                                              \
	}                                                                          \
	struct ctest_unit CTEST_CONCAT(CTEST_CONCAT(__ctest_unit_, __NAME),        \
	                               __ID) = {                                   \
		.file = __FILE__,                                                      \
		.id = __ID,                                                            \
		.fn = CTEST_CONCAT(CTEST_CONCAT(__ctest_function_, __NAME), __ID),     \
		.flags = CTEST_FLAG_DEFAULT,                                           \
	};
/**
 * @brief Creates a new test unit
 *
 * The unit is stored as a linkable symbol, so reading the .symtab section
 * allows ctest to read it.
 *
 * @param __NAME Name (identifier) of the test to create (used for logging)
 * @param ... Content of the test, a scope of C code
 *
 * @note The test name should be a file-unique identifier, expect unreadable
 * error messages otherwise
 */
#ifdef CTEST_UNITS_ENABLED
#define CTEST_UNIT(__NAME, ...) __CTEST_UNIT(__NAME, __COUNTER__, __VA_ARGS__)
#else
#define CTEST_UNIT(__NAME, ...)
#endif // CTEST_UNITS_ENABLED

// TODO: Prettify code
#define __CTEST_LOG(__FILE, __LINE, __MSG, ...)                                \
	dprintf(__ctest_data->message_fd,                                          \
	        "In %s at line %d: %s:\n -- BEGIN CODE --\n%s\n -- END CODE --\n", \
	        (__FILE),                                                          \
	        (__LINE),                                                          \
	        (__MSG),                                                           \
	        #__VA_ARGS__);

/**
 * @brief Check if an expression crashes the program
 *
 * A sighandler will check for crash signals and then a condition will
 * be used to test if the program did crash.
 */
#define CTEST_CRASH(__MSG, ...)                                                \
	{                                                                          \
		__ctest_data->sigstatus.signum = 0;                                    \
		const int __ctest_recover = __ctest_data->sigstatus.recover;           \
		__ctest_data->sigstatus.recover = 1;                                   \
		if (!setjmp(__ctest_data->sigstatus.recovery_point)) {                 \
			{                                                                  \
				__VA_ARGS__;                                                   \
			}                                                                  \
			if (__ctest_data->sigstatus.signum != SIGSEGV) {                   \
				dprintf(__ctest_data->message_fd,                              \
				        "CTEST_CRASH(...) assertion failed:\n");               \
				__CTEST_LOG(__FILE__, __LINE__, (__MSG), __VA_ARGS__)          \
				return 0;                                                      \
			}                                                                  \
		}                                                                      \
		__ctest_data->sigstatus.recover = __ctest_recover;                     \
	}

/**
 * @brief Check for an expression value
 *
 * @param __EXPR The expression to check for
 */
#define CTEST_ASSERT(__EXPR)                                                   \
	{                                                                          \
		if (!(__EXPR)) {                                                       \
			__CTEST_LOG(__FILE__, __LINE__, "Assertion failed", (__EXPR))      \
			return 0;                                                          \
		}                                                                      \
	}

/**
 * @brief Check for an expression value with custom failure message
 *
 * @param __MSG Custom assertion message
 * @param __EXPR The expression to check for
 */
#define CTEST_ASSERT_MSG(__MSG, __EXPR)                                        \
	{                                                                          \
		if (!(__EXPR)) {                                                       \
			__CTEST_LOG(__FILE__, __LINE__, (__MSG), (__EXPR))                 \
			return 0;                                                          \
		}                                                                      \
	}

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

#endif // CTEST_H
