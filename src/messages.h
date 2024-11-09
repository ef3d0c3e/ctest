#ifndef CTEST_MESSAGES_H
#define CTEST_MESSAGES_H

#include <stdlib.h>
enum ctest_color
{
	CTEST_COLOR_RESET,
	CTEST_COLOR_RED,
	CTEST_COLOR_GREEN,
	CTEST_COLOR_BLUE,
	CTEST_COLOR_YELLOW,
	__CTEST_COLOR_SIZE,
};

/**
 * @brief Colors data structure
 */
union ctest_colors_data
{
	struct
	{
		const char* reset;
		const char* red;
		const char* green;
		const char* blue;
		const char* yellow;
	};
	const char* colors[__CTEST_COLOR_SIZE];
};

/**
 * @brief Enables or disables colors
 *
 * By default colors are disabled until enabled by this function.
 */
void
__ctest_colors_set(int enable);

/**
 * @brief Get a color by it's enum value
 *
 * @returns Color by it's enum value
 */
const char*
__ctest_color(enum ctest_color color);

/**
 * @brief Applies colors to a string
 *
 * @returns The colored version of the struct, needs to be freed()
 */
char*
__ctest_colorize(enum ctest_color color, const char* s);

#endif // CTEST_MESSAGES_H
