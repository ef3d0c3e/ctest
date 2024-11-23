#ifndef CTEST_MEMORY_HEAP_HPP
#define CTEST_MEMORY_HEAP_HPP

#include "range.hpp"
#include <cstdint>
#include <map>
#include <optional>
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
	 * @brief Address of the allocator function, i.e malloc or realloc
	 */
	uintptr_t allocator;
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
	 * @brief Get a @ref heap_block containing a given address
	 *
	 * @param address Address to find the @ref map_entry of
	 *
	 * @returns The @ref heap_block if found
	 */
	std::optional<std::reference_wrapper<heap_block>> get(uintptr_t address);
}; // class heap
} // namespace ctest::mem

#endif // CTEST_MEMORY_HEAP_HPP
