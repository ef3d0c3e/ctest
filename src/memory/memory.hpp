#ifndef CTEST_MEMORY_HPP
#define CTEST_MEMORY_HPP

#include "maps.hpp"
#include "heap.hpp"
#include <sys/user.h>

namespace ctest
{
	struct session;
	namespace calls
	{
		class calls;
	} // namespace calls
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
	 * @brief Returns the access name
	 */
	std::string_view access_name() const;
};

class memory
{
	friend session;
	friend calls::calls;

	mem::maps maps;
	mem::heap heap;
public:
	/**
	 * @brief Process memory access hooks
	 *
	 * @param session The debugging session
	 * @param regs Program registers
	 * @param access Memory access
	 *
	 * @return 1 On success, 0 on failure
	 */
	[[nodiscard]] bool process_access(ctest::session& session, const user_regs_struct& regs, mem_access&& access);
}; // class memory
} // namespace ctest::mem

#endif // CTEST_MEMORY_HPP
