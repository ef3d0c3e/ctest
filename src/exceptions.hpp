#ifndef CTEST_EXCEPTIONS_HPP
#define CTEST_EXCEPTIONS_HPP

#include <source_location>
#include <string>

namespace ctest {
class exception : public std::exception
{
	std::string m_what;
	std::string m_trace;

	public:
	exception(std::string&& message,
	          std::source_location&& loc = std::source_location::current());

	virtual const char* what() const throw();

	const std::string& trace() const;
}; // class exception
} // namespace ctest

#endif // CTEST_EXCEPTIONS_HPP
