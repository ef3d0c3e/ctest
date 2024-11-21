#ifndef CTEST_SESSION_H
#define CTEST_SESSION_H

#include "ctest.h"
#include <capstone/capstone.h>
#include <elfutils/libdwfl.h>

namespace ctest {
class session
{
	/**
	 * @brief The unit for this session
	 */
	const ctest_unit* unit;
	/**
	 * @brief Handle of the capstone engine
	 */
	csh capstone_handle;
	/**
	 * @brief Handle for dwfl
	 */
	Dwfl* dwfl_handle;

public:
	session(const ctest_unit* unit);
	~session();

	void start();
}; // class session
} // namespace ctest

#endif // CTEST_SESSION_H
