#include "colors.hpp"

using namespace ctest;

colors ctest::_g_colors = colors{ { "", "", "", "", "", "", "", "" } };

void
colors::intitialize(bool enabled)
{
	if (enabled)
		_g_colors.named = {
			.reset = "\033[0m",
			.red = "\033[1;31m",
			.green = "\033[1;32m",
			.blue = "\033[1;34m",
			.yellow = "\033[1;33m",
			.bold = "\033[1m",
			.italic = "\033[3m",
			.underline = "\033[4m",
		};
	else
		_g_colors = ctest::colors{ {
		  "",
		  "",
		  "",
		  "",
		  "",
		  "",
		  "",
		  "",
		} };
}
