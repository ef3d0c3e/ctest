#ifndef CTEST_MEMORY_HPP
#define CTEST_MEMORY_HPP

#include <cstdint>
#include <sys/types.h>
#include <vector>
namespace ctest {
namespace map {
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
struct entry
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
	 * @brief Map path, may be null
	 */
	char* pathname;

	entry()
	  : pathname{ NULL }
	{
	}
	~entry() { delete pathname; }
}; // struct entry

/**
 * @brief Manages the map @entry
 */
class maps
{
	std::vector<entry> entries;

public:
	/**
	 * @brief Parse maps for a pid
	 */
	void parse(pid_t pid);
}; // class maps
} // namespace map

class memory
{
	map::maps maps;

public:
}; // class memory
} // namespace ctest

#endif // CTEST_MEMORY_HPP
