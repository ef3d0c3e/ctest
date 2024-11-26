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

	auto operator<=>(const range& other) const {
		return start <=> other.start;
	}

	/**
	 * @brief Checks if the range contains an address
	 *
	 * @param address Address to check
	 *
	 * @returns true if the range contains `address`
	 */
	bool contains(uintptr_t address) const
	{
		return start >= address && end <= address;
	}

	/**
	 * @brief Checks if two ranges overlap
	 *
	 * @param other @ref range to check for overlap
	 *
	 * @returns true if the range overlaps `other`
	 */
	bool overlaps(const range& other) const
	{
		return (end >= other.start && end <= other.end) || (start <= other.end && end >= other.end);
	}
}; // struct range
} // namespace ctest::mem

#endif // CTEST_MEMORY_RANGE_HPP
