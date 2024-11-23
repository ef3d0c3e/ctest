#ifndef CTEST_MEMORY_MAPS_H
#define CTEST_MEMORY_MAPS_H

#include "range.hpp"
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <sys/types.h>
#include <vector>
namespace ctest::mem {
/**
 * @brief Access flags for maps
 */
enum class access : uint8_t
{
	SHARED = 0b0001,
	EXECUTE = 0b0010,
	WRITE = 0b0100,
	READ = 0b1000,
};
/**
 * @brief Represents an entry in /proc/PID/maps
 */
struct map_entry
{
	/**
	 * @brief Start address
	 */
	uintptr_t start;
	/**
	 * @brief End address
	 */
	uintptr_t end;
	/**
	 * @brief Offset of the map
	 */
	uintptr_t offset;
	/**
	 * @brief The map access flags, @see ctest_map_access
	 */
	enum access access_flags;
	/**
	 * @brief Map path, may be empty
	 */
	std::string pathname;
}; // struct entry

/**
 * @brief Manages the map @entry
 */
class maps
{
	std::map<range, map_entry> entries;

public:
	/**
	 * @brief Parse maps for a pid
	 */
	void parse(pid_t pid);

	/**
	 * @brief Get a @ref map_entry containing a given address
	 *
	 * @param address Address to find the @ref map_entry of
	 *
	 * @returns The @ref map_entry if found
	 */
	std::optional<std::reference_wrapper<map_entry>> get(uintptr_t address);
}; // class maps
} // namespace ctest::mem

#endif // CTEST_MEMORY_MAPS_H
