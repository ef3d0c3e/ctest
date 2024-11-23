#ifndef CTEST_MEMORY_HPP
#define CTEST_MEMORY_HPP

#include "maps.hpp"
#include "heap.hpp"
#include <sys/user.h>

namespace ctest
{
	class session;
} // namespace ctest

namespace ctest::mem {
/**
 * @brief The types of memory access
 */
enum class access_type : uint8_t
{
	READ = 0b01,
	WRITE = 0b11,
};

/**
 * @brief An access to memory
 */
struct mem_access
{
	/**
	 * @brief The accessed address
	 */
	uintptr_t address;
	/**
	 * @brief The access size in bytes
	 */
	uint8_t size;
	/**
	 * @brief The type of access
	 */
	access_type access;
	/**
	 * @brief Registers during access
	 */
	const user_regs_struct& regs;
};

class memory
{
	friend ctest::session;

	mem::maps maps;
	mem::heap heap;
public:
	void process_access(class ctest::session& session, mem_access&& access);
}; // class memory
} // namespace ctest::mem

#endif // CTEST_MEMORY_HPP
