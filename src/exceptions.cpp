#include "exceptions.hpp"
#include <execinfo.h>
#include <format>

using namespace ctest;

exception::exception(std::string&& message, std::source_location&& loc)
{
	m_what = std::format("{}#{}@{}:\n{}",
	                     loc.file_name(),
	                     loc.function_name(),
	                     loc.line(),
	                     message);

	void* bt[16];
	int n = backtrace(bt, 16);
	char** syms = backtrace_symbols(bt, n);
	for (int i = 0; i < n; ++i)
		m_trace += std::format(" #{} {}\n", i, syms[i]);
	free(syms);
}

const char*
exception::what() const throw()
{
	return m_what.c_str();
}

const std::string&
exception::trace() const
{
	return m_trace;
}
