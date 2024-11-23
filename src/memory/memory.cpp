#include "memory.hpp"
#include "../session.hpp"

using namespace ctest::mem;

void
memory::process_access(session& session, mem_access&& access)
{
	// Find accessed map
	const auto start_map = maps.get(access.address);
	const auto end_map = maps.get(access.address + access.size);
	if (!start_map) {
		// TODO
		return;
	} else if (!end_map) {
		// TODO
		return;
	}

	if (start_map->get().pathname == "[heap]")
	{
	}
}
