#ifndef CTEST_MEMORY_MAP_H
#define CTEST_MEMORY_MAP_H

#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

enum ctest_map_access
{
	CTEST_MAP_PRESENT = 0b0001,
	CTEST_MAP_EXECUTE = 0b0010,
	CTEST_MAP_WRITE = 0b0100,
	CTEST_MAP_READ = 0b1000,
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
	size_t offset;
	/**
	 * @brief The map access flags, @see ctest_map_access
	 */
	enum ctest_map_access access_flags;
	/**
	 * @brief Map path, may be null
	 */
	char* pathname;
};

struct ctest_map_entry*
__ctest_mem_maps_parse(pid_t pid);

#endif // CTEST_MEMORY_MAP_H
