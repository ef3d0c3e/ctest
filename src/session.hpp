#ifndef CTEST_SESSION_H
#define CTEST_SESSION_H

#include <capstone/capstone.h>
#include <elfutils/libdwfl.h>

namespace ctest {
class session
{
	/**
	 * @brief Handle of the capstone engine
	 */
	csh capstone_handle;

	public:
	session();
	~session();
}; // class session
} // namespace ctest

#endif // CTEST_SESSION_H
