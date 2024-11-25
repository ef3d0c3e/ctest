#include "../session.hpp"
#include "../colors.hpp"
#include "../exceptions.hpp"
#include "report.hpp"
#include <fstream>
#include <iostream>
#include <string>

using namespace ctest;

/* Reads the file to memory and returns formatted lines in a range */
static std::string
lines_from_file(const char* source_file, std::pair<int, int> range, int target)
{
	if (target < range.first || target >= range.second)
		throw exception(fmt::format("Invalid target={}, range=[{}, {}]", target, range.first, range.second));
	std::ifstream in(source_file);
	if (!in.good())
		return format("{c_italic}<Can't open '{0}'>{c_reset}\n", source_file);



	std::string result = format("{c_underline}File '{0}', line {c_yellow}{1}{c_reset}:\n", source_file, target);
	int current_line = 1;
	for (std::string line; std::getline(in, line); ++current_line) {
		if (current_line < range.first)
			continue;
		else if (current_line > range.second)
			break;
		
		if (current_line == target)
			result += format(" {c_green}{0: <4}|{c_reset}{c_red}{1}{c_reset}\n"sv, current_line, line);
		else
			result += format(" {c_green}{0: <4}|{c_reset}{1}\n"sv, current_line, line);
	}
	return result;
}

void ctest::report::source_line(const session &session, uintptr_t pc)
{
	Dwfl_Module* module = dwfl_addrmodule(session.dwfl_handle, pc);
	const char* source_file;
	int line_nr;

	if (!module)
		throw exception(fmt::format("Failed to get module information for address={:x}", pc));

	Dwfl_Line* line = dwfl_module_getsrc(module, pc);
	if (!line)
	{
		std::cerr << format("{c_italic}<Missing line info>{c_reset}\n");
		return;
	}
	source_file = dwfl_lineinfo(line, &pc, &line_nr, NULL, NULL, NULL);
	if (!source_file)
		std::cerr << format("{c_italic}<Unknown file>{c_reset}\n");
	else
		std::cerr << lines_from_file(source_file, {line_nr - 1, line_nr + 1}, line_nr);
}
