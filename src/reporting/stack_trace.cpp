#include "../colors.hpp"
#include "../exceptions.hpp"
#include "../session.hpp"
#include "report.hpp"
#include <cxxabi.h>
#include <iostream>
#include <libunwind-ptrace.h>
#include <memory>

using namespace ctest;

/* Gets ready-to-print function name, source file and definition line, also
 * tries to demangles C++ function names */
static std::string
get_function_detail(const session& session, Dwarf_Addr pc)
{
	Dwfl_Module* module = dwfl_addrmodule(session.dwfl_handle, pc);
	if (!module)
		return format("{c_italic}<Module not found for address={0:x}>{c_reset}",
		              pc);

	// Retrieve source line information using dwfl_module_getsrc
	Dwfl_Line* line = dwfl_module_getsrc(module, pc);
	const char* file = NULL;
	int line_nr = 0;
	Dwarf_Addr addr;
	if (line) {
		file = dwfl_lineinfo(line, &addr, &line_nr, NULL, NULL, NULL);
	}

	// Get source line information
	std::string result;
	if (file)
		result +=
		  format("{c_blue}{0}{c_reset}:{c_reset}{1}{c_reset} ", file, line_nr);
	else
		result += format("{c_blue}{c_italic}<unknown>{c_reset} ");

	// Get function name using dwfl_addrmodule
	GElf_Sym sym;
	const char* symbol = dwfl_module_addrsym(module, pc, &sym, NULL);
	if (symbol) {
		// Demangle C++ names
		std::unique_ptr<char, void (*)(void*)> own(
				abi::__cxa_demangle(symbol, nullptr, nullptr, nullptr),
				std::free);
		result += format("{c_green}{0}{1}{c_reset}", own ? own.get() : symbol, own ? "" : "()");
	} else
		result += format("{c_green}{c_italic}<unknown>{c_reset}", symbol);

	return result;
}

void
ctest::report::stack_trace(const session& session, uintptr_t pc, size_t limit)
{
	// Setup libunwind
	unw_addr_space_t addr_space = unw_create_addr_space(&_UPT_accessors, 0);
	if (!addr_space)
		throw exception(fmt::format("unw_create_addr_space() failed"));

	unw_set_caching_policy(addr_space, UNW_CACHE_GLOBAL);
	void* upt_info = _UPT_create(session.child);
	if (!upt_info)
		throw exception("_UPT_create() failed");

	unw_cursor_t cursor;
	if (const int code = unw_init_remote(&cursor, addr_space, upt_info);
	    code < 0)
		throw exception(
		  fmt::format("unw_init_remote() failed with code: {0}", code));

	if (const int code = unw_set_reg(&cursor, UNW_REG_IP, pc); code < 0)
		throw exception(
		  fmt::format("unw_set_reg() failed with code: {0}", code));

	size_t i = 0;
	while (unw_step(&cursor) > 0 && i < limit) {
		unw_word_t ip, sp;

		unw_get_reg(&cursor, UNW_REG_IP, &ip);
		unw_get_reg(&cursor, UNW_REG_SP, &sp);

		std::cerr << format(" {c_yellow}#{0}{c_reset} {1}\n",
		                    i,
		                    get_function_detail(session, ip));
		++i;
	}

	_UPT_destroy(upt_info);
	unw_destroy_addr_space(addr_space);
}
