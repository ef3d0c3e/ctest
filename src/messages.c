#include "messages.h"
#include <string.h>

static union ctest_colors_data _G_colors = { {
  "",
  "",
  "",
  "",
  "",
} };

void
__ctest_colors_set(int enable)
{
	if (enable)

		_G_colors = (union ctest_colors_data){
			.reset = "\033[0m",
			.red = "\033[1;31m",
			.green = "\033[1;32m",
			.blue = "\033[1;34m",
			.yellow = "\033[1;33m",
		};
	else
		_G_colors = (union ctest_colors_data){ {
		  "",
		  "",
		  "",
		  "",
		  "",
		} };
}

const char*
__ctest_color(enum ctest_color color)
{
	return _G_colors.colors[color];
}

char*
__ctest_colorize(enum ctest_color color, const char* s)
{
	const size_t len_color = strlen(_G_colors.colors[color]);
	const size_t len_reset = strlen(_G_colors.reset);
	const size_t len = strlen(s);
	char* result = malloc(len + len_reset + len_color + 1);

	memcpy(result, _G_colors.colors[color], len_color);
	memcpy(result + len_color, s, len);
	memcpy(result + len_color + len, _G_colors.reset, len_reset);
	result[len + len_reset + len_color] = 0;

	return result;
}
