#ifndef CTEST_MEMORY_RANGE_HPP
#define CTEST_MEMORY_RANGE_HPP

#include <compare>
#include <cstdint>

namespace ctest::mem {
/**
 * @brief Represents an address range
 */
struct range
{
	/**
	 * @brief The addresses
	 */
	uintptr_t start, end;

	auto operator<=>(const range& other) const = default;
}; // struct range
} // namespace ctest::mem

#endif // CTEST_MEMORY_RANGE_HPP
