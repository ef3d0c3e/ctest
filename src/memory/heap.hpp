#ifndef CTEST_MEMORY_HEAP_HPP
#define CTEST_MEMORY_HEAP_HPP

#include "range.hpp"
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <optional>
#include <string_view>
#include <expected>
#include <vector>

namespace ctest::mem {
/**
 * @brief Stores the allocated memory from malloc
 *
 * It it called `heap` but malloc may use mmap for large chunks
 *
 * @note Once deallocated, memory allocations will be kept to detect double free
 */
struct heap_block
{
	/**
	 * @brief Address of the allocator function, i.e malloc, realloc or mmap
	 */
	uintptr_t allocator;
	/**
	 * @brief Address of the deallocator function, i.e free, munmap
	 * Only set if deallocator has been called, otherwise 0
	 */
	uintptr_t deallocator;
	/**
	 * @brief Address returned by the allocator
	 */
	uintptr_t address;
	/**
	 * @brief Requested size of the allocation
	 */
	std::size_t size;
	/**
	 * @brief Stores the initialized bytes
	 *
	 * One bit represent one byte
	 */
	std::vector<bool> initialized;
	/**
	 * @brief RIP before call to the allocator
	 */
	uintptr_t alloc_pc;
	/**
	 * @brief RIP before call to free, set to 0 when not freed
	 */
	uintptr_t free_pc;

	/**
	 * @brief Get the name of the allocator
	 *
	 * @returns The name of the allocator
	 */
	std::string_view allocated_by() const;

	/**
	 * @brief Get the name of the deallocator
	 *
	 * @returns The name of the deallocator
	 *
	 * @note Will throw if not deallocated yet, check that `freed_rip != 0` before calling this method
	 */
	std::string_view deallocated_by() const;

	/**
	 * @brief Check if all bytes over a range are initialized
	 *
	 * @param r The range to check over
	 *
	 * @returns true If all bytes in range `r` are initialized
	 */
	bool is_initialized(const range& r) const;

	/**
	 * @brief Set all bytes over a range as initialized
	 *
	 * @param r The range to set over
	 */
	void set_initialized(const range& r);
}; // struct heap_block

/**
 * @brief Manages the allocated data from malloc or realloc
 *
 * It it called `heap` but malloc may use mmap for large chunks
 */
class heap
{
	std::map<range, heap_block> blocks;

public:
	struct range_error
	{
		/**
		 * @brief The blocks overlapping with address
		 */
		std::vector<std::reference_wrapper<const heap_block>> overlapping;
		/**
		 * @brief Optional previous@ref heap_block
		 */
		std::optional<std::reference_wrapper<const heap_block>> previous;
		/**
		 * @brief Optional next @ref heap_block
		 */
		std::optional<std::reference_wrapper<const heap_block>> next;
	};

	/**
	 * @brief Inserts a new heap block
	 *
	 * @param block @ref heap_block to add
	 *
	 * @note In case the block overlaps with an already existing block, an
	 * exception will be thrown
	 */
	void insert(heap_block&& block);

	/**
	 * @brief Gets an allocation by a range
	 *
	 * @param range The range to get the allocation of
	 *
	 * @returns @ref range_result_ok with the allocation if found, otherwise
	 * return the following
	 *  - @ref range_result_unknown: If no block containing the range was found,
	 * with potential closest blocks
	 *  - @ref range_result_unbounded: If an overflow is detected, with the
	 * overflow and underflow amout
	 */
	std::expected<std::reference_wrapper<heap_block>, range_error>
	get_range(const range& r);
}; // class heap
} // namespace ctest::mem

#endif // CTEST_MEMORY_HEAP_HPP
