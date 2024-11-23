#ifndef CTEST_COLORS_HPP
#define CTEST_COLORS_HPP

#include <fmt/core.h>
#include <fmt/format.h>
#include <string_view>

namespace ctest {
using namespace std::literals;

union colors
{
	struct
	{
		const char* reset;
		const char* red;
		const char* green;
		const char* blue;
		const char* yellow;
		const char* bold;
		const char* italic;
		const char* underline;
	} named;
	const char* colors[8];

	/**
	 * @brief Enables/Disables colors
	 *
	 * @param enabled If set to true, colors will be enabled, otherwise they
	 * will not (default)
	 */
	static void intitialize(bool enabled);
}; // struct colors

/**
 * @brief Global color variable
 */
extern colors _g_colors;

/**
 * @brief Ctest formatting function
 *
 * This function performs formatting with colors.
 * To add a colors simply use `{c_red}Colored{c_reset}` in the format string
 *
 * @param fmt The format string
 * @param ts The format arguments
 *
 * @returns The formatted string
 */
auto
format(std::string_view fmt, auto&&... ts)
{
	return fmt::format(fmt::runtime(fmt),
	                   std::forward<decltype(ts)>(ts)...,
	                   fmt::arg("c_reset", _g_colors.named.reset),
	                   fmt::arg("c_red", _g_colors.named.red),
	                   fmt::arg("c_green", _g_colors.named.green),
	                   fmt::arg("c_blue", _g_colors.named.blue),
	                   fmt::arg("c_yellow", _g_colors.named.yellow),
	                   fmt::arg("c_bold", _g_colors.named.bold),
	                   fmt::arg("c_italic", _g_colors.named.italic),
	                   fmt::arg("c_underline", _g_colors.named.underline));
}

} // ctest

#endif // CTEST_COLORS_HPP
