#include "report.hpp"
#include "../colors.hpp"
#include <iostream>

using namespace ctest;

/**
 * @brief Prints information about an allocation to stderr
 *
 * @param session The debugging session
 * @param block The heap block to display information about
 */
void
ctest::report::allocation(const session& session, const mem::heap_block& block)
{
	std::cerr << format("{c_bold}Buffer {c_blue}[{0:x}; {1}]{c_reset}{c_bold} allocated by {2}:{c_reset}\n"sv, block.address, block.size, block.allocated_by());
	source_line(session, block.alloc_pc);
	if (block.free_pc != 0)
	{
		std::cerr << format("{c_bold}Freed by {0}:{c_reset}\n"sv, block.deallocated_by());
		source_line(session, block.free_pc);
	}
}
