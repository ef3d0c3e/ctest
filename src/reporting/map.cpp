#include "report.hpp"
#include "../colors.hpp"
#include <iostream>

using namespace ctest;

void
ctest::report::map(const session& session, const mem::map_entry& map)
{
	std::string flags;
	flags.push_back("s-"[((uint8_t)map.access_flags & (uint8_t)mem::access::SHARED) == 0]);
	flags.push_back("r-"[((uint8_t)map.access_flags & (uint8_t)mem::access::READ) == 0]);
	flags.push_back("w-"[((uint8_t)map.access_flags & (uint8_t)mem::access::WRITE) == 0]);
	flags.push_back("x-"[((uint8_t)map.access_flags & (uint8_t)mem::access::EXECUTE) == 0]);


	std::cerr << format("{c_bold}Memory map {c_blue}[{0:x}-{1:x}]{c_reset} path={c_red}'{2}' {3}{c_reset}\n"sv, map.start, map.end, map.pathname, flags);
}
