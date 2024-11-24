#include "memory.hpp"
#include "../colors.hpp"
#include "../reporting/report.hpp"
#include "../session.hpp"
#include <iostream>
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
		const auto block =
		  heap.get_range(range{ access.address, access.address + access.size });

		if (!std::visit(
		      [&]<class T>(const T& t) {
			      if constexpr (std::is_same_v<heap::range_result_unknown, T>) {
				      report::error_message(
				        session,
				        regs,
				        format(
				          "Unallocated heap memory access in {0} instruction: "
				          "{c_blue}[{1:x}; {2}]{c_reset}"sv,
				          access.access_name(),
				          access.address,
				          access.size));
				      if (t.first.has_value()) {
					      std::cerr << format(" {c_blue}-> Closest previous "
					                          "heap block:{c_reset}\n");
					      report::allocation(session, t.first.value());
				      }
				      if (t.second.has_value()) {
					      std::cerr << format(
					        " {c_blue}-> Closest next heap block:{c_reset}\n");
					      report::allocation(session, t.second.value());
				      }
				      return false;
			      } else if constexpr (std::is_same_v<
			                             heap::range_result_unbounded,
			                             T>) {
				      report::error_message(
				        session,
				        regs,
				        format(
				          "Heap-Buffer {0} of {1} bytes in {2} instruction: "
				          "{c_blue}[{3:x}; {4}]{c_reset}"sv,
				          std::get<1>(t) != 0 ? "overflow" : "underflow",
				          std::get<1>(t) + std::get<2>(t),
				          access.access_name(),
				          access.address,
				          access.size));
				      std::cerr << format(" {c_blue}-> Heap block:{c_reset}\n");
				      report::allocation(session, std::get<0>(t));
				      return false;
			      }
			      return true;
		      },
		      block))
			return false;
	}

	return true;
}
