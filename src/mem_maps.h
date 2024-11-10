#ifndef CTEST_MEM_MAP_H
#define CTEST_MEM_MAP_H

#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

enum ctest_map_access
{
	CTEST_MAP_SHARED  = 0b0001,
	CTEST_MAP_EXECUTE = 0b0010,
	CTEST_MAP_WRITE   = 0b0100,
	CTEST_MAP_READ    = 0b1000,
};

/**
 * @brief Structure to represent a memory map
 */
struct ctest_map_entry
{
	/**
	 * @brief Start of address
	 */
	uintptr_t start;
	/**
	 * @brief End of address
	 */
	uintptr_t end;
	/**
	 * @brief Offset of the map
	 */
	uintptr_t offset;
	/**
	 * @brief The map access flags, @see ctest_map_access
	 */
	enum ctest_map_access access_flags;
	/**
	 * @brief Map path, may be null
	 */
	char* pathname;
};

// TODO: Update mechanism
struct ctest_maps
{
	struct ctest_map_entry* data;
	size_t size;
	size_t capacity;
};

/**
 * @brief Parses the /proc/PID/maps entry for the child
 *
 * @returns The parsed /proc/PID/maps entry
 *
 * @note The map entry needs to be updated with subsequent calls to mmap/mremap/munmap or
 * brk/sbrk.
 */
struct ctest_maps
__ctest_mem_maps_parse(pid_t pid);

/**
 * @brief Free the map entries
 *
 * @param maps Map entries to free
 */
void
__ctest_mem_maps_free(struct ctest_maps* maps);

/**
 * @brief Gets the corresponding map that contains @p address
 *
 * @param maps The memory maps
 * @param address The address to find the map of
 *
 * @returns The map if found, NULL if address is not mapped
 */
struct ctest_map_entry* __ctest_mem_maps_get(struct ctest_maps* maps, uintptr_t address);

#endif // CTEST_MEM_MAP_H
