#ifndef CTEST_CALLS_CALLS_HPP
#define CTEST_CALLS_CALLS_HPP

#include <cstdint>
namespace ctest::calls
{
/**
 * @brief Represents a function call
 */
struct function_call
{
	/**
	 * @brief Base address of the call, e.g `call 0x74f74`
	 */
	uintptr_t addr;
	/**
	 * @brief Resolved address of the call
	 */
	uintptr_t resolved;
};

} // namespace ctest::calls

#endif // CTEST_CALLS_CALLS_HPP
