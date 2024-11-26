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
		const auto result =
		  heap.get_range(range{ access.address, access.address + access.size });

		if (result.has_value()) {
			auto& block{ result.value().get() };
			const range r{ access.address - block.address,
				           access.address + access.size - block.address };
			if ((uint8_t)access.access & (uint8_t)access_type::READ &&
			    !block.is_initialized(r)) {
				report::error_message(
				  session,
				  regs,
				  format("Access to non-initialized memory in {0} instruction: "
				         "{c_blue}[{1:x}; {2}]{c_reset}"sv,
				         access.access_name(),
				         access.address,
				         access.size));
				report::allocation(session, block);
				return false;
			}
			if ((uint8_t)access.access & (uint8_t)access_type::WRITE) {
				block.set_initialized(r);
			}
		} else {
			const auto err = result.error();
			/* No blocks found */
			if (err.overlapping.empty()) {
				report::error_message(
				  session,
				  regs,
				  format("Unallocated heap memory access in {0} instruction: "
				         "{c_blue}[{1:x}; {2}]{c_reset}"sv,
				         access.access_name(),
				         access.address,
				         access.size));
				return false;
			} else if (err.overlapping.size() != 1) {
				report::error_message(
				  session,
				  regs,
				  format("Access over multiple heap blocks in {0} instruction: "
				         "{c_blue}[{1:x}; {2}]{c_reset}"sv,
				         access.access_name(),
				         access.address,
				         access.size));
				std::cerr << format(" {c_blue}-> Concerned blocks:{c_reset}\n");
				for (const auto& block : err.overlapping)
					report::allocation(session, block);
				return false;
			}
			/* Underflow */
			else if (const auto& block = err.overlapping[0].get();
			         block.address > access.address) {
				report::error_message(
				  session,
				  regs,
				  format(
				    "Heap-Buffer underflow of {0} bytes in {1} instruction: "
				    "{c_blue}[{2:x}; {3}]{c_reset}"sv,
				    block.address - access.address,
				    access.access_name(),
				    access.address,
				    access.size));
				std::cerr << format(" {c_blue}-> Heap block:{c_reset}\n");
				report::allocation(session, block);
				return false;
			}
			/* Overflow */
			else if (const auto& block = err.overlapping[0].get();
			         block.address + block.size <
			         access.address + access.size) {
				report::error_message(
				  session,
				  regs,
				  format(
				    "Heap-Buffer overflow of {0} bytes in {1} instruction: "
				    "{c_blue}[{2:x}; {3}]{c_reset}"sv,
				    access.address + access.size - block.address - block.size,
				    access.access_name(),
				    access.address,
				    access.size));
				std::cerr << format(" {c_blue}-> Heap block:{c_reset}\n");
				report::allocation(session, block);
				return false;
			}

			/* Info about neighbor blocks */
			if (err.previous.has_value()) {
				std::cerr << format(" {c_blue}-> Closest previous "
				                    "heap block:{c_reset}\n");
				report::allocation(session, err.previous.value());
			}
			if (err.next.has_value()) {
				std::cerr << format(
				  " {c_blue}-> Closest next heap block:{c_reset}\n");
				report::allocation(session, err.next.value());
			}

			return false;
		}
	}

	return true;
}
