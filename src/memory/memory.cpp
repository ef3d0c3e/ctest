#include "memory.hpp"
#include "../colors.hpp"
#include "../reporting/report.hpp"
#include "../session.hpp"
#include <sys/user.h>

using namespace ctest::mem;

std::string_view
mem_access::access_name() const
{
	const bool is_read = (uint8_t)access & (uint8_t)access_type::READ;
	const bool is_write = (uint8_t)access & (uint8_t)access_type::WRITE;

	if (is_read && is_write)
		return "READ+WRITE"sv;
	else if (is_read)
		return "READ"sv;
	else if (is_write)
		return "READ"sv;
	else
		return "UNKNOWN ACCESS"sv;
}

bool
memory::process_access(session& session,
                       const user_regs_struct& regs,
                       mem_access&& access)
{
	// Find accessed map
	const auto start_map = maps.get(access.address);
	const auto end_map = maps.get(access.address + access.size);
	if (!start_map) {
		report::error_message(
		  session,
		  regs,
		  format("Attempted to access unmapped memory in {0} instruction: "
		         "{c_blue}[{1:x}; {2}]{c_reset}"sv,
		         access.access_name(),
		         access.address,
		         access.size));
		return false;
	} else if (!end_map) {
		report::error_message(
		  session,
		  regs,
		  format("Attempted to access unmapped memory in {0} instruction: "
		         "{c_blue}[{1:x}; {2}]{c_reset}"sv,
		         access.access_name(),
		         access.address,
		         access.size));
		return false;
	}

	if (start_map->get().pathname == "[heap]") {
	}

	return true;
}
