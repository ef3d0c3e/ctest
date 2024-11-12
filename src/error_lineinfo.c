#include "error.h"
#include "messages.h"
#include "result.h"
#include <errno.h>
#include <elfutils/libdwfl.h>
#include <string.h>

/* Reads the file to memory and print lines in [line_number-1, line_number+1] */
static void
print_source_line_from_file(int fd, const char* source_file, int line_number)
{
	FILE* file = fopen(source_file, "r");
	if (!file) {
		perror("Error opening file");
		return;
	}

	int current_line = 1;

	char* line = NULL;
	size_t sz = 0;
	ssize_t read;
	dprintf(fd, "%sFile '%s', line %d:%s\n", __ctest_color(CTEST_COLOR_UNDERLINE), source_file, line_number, __ctest_color(CTEST_COLOR_RESET));
	while ((read = getline(&line, &sz, file)) != -1) {
		if (current_line < line_number - 1) {
			current_line++;
			continue;
		} else if (current_line > line_number + 1)
			break;

		if (current_line == line_number)
			dprintf(fd,
			        " %s%d>\t|%s %s%s%s",
			        __ctest_color(CTEST_COLOR_GREEN),
			        current_line,
			        __ctest_color(CTEST_COLOR_RESET),
			        __ctest_color(CTEST_COLOR_RED),
			        line,
			        __ctest_color(CTEST_COLOR_RESET));
		else
			dprintf(fd,
			        " %s%d\t|%s %s",
			        __ctest_color(CTEST_COLOR_GREEN),
			        current_line,
			        __ctest_color(CTEST_COLOR_RESET),
			        line);
		current_line++;
	}
	if (line)
		free(line);
	fclose(file);
}

void
__ctest_print_source_line(struct ctest_result* result, int fd, uintptr_t rip)
{
	Dwfl* dwfl;
	Dwfl_Callbacks callbacks = {
		.find_elf = dwfl_linux_proc_find_elf,
		.find_debuginfo = dwfl_standard_find_debuginfo,
	};

	dwfl = dwfl_begin(&callbacks);
	if (!dwfl) {
		fprintf(stderr, "Failed to initialize Dwfl");
		exit(1);
	}

	if (dwfl_linux_proc_report(dwfl, result->child) != 0) {
		fprintf(stderr, "dwfl_linux_proc_report failed: %s\n", strerror(errno));
		exit(1);
	}

	if (dwfl_report_end(dwfl, NULL, NULL) != 0) {
		fprintf(stderr, "dwfl_report_end failed: %s\n", strerror(errno));
		exit(1);
	}

	Dwfl_Module* module = dwfl_addrmodule(dwfl, rip);
	const char* source_file;
	int line_nr;

	if (module) {
		Dwfl_Line* line = dwfl_module_getsrc(module, rip);
		if (line) {
			source_file = dwfl_lineinfo(line, &rip, &line_nr, NULL, NULL, NULL);
			print_source_line_from_file(fd, source_file, line_nr);
		} else
			fprintf(stderr, "<Failed to get line information, likely no debug informations>\n");
	} else {
		fprintf(stderr, "Failed to get module information\n");
		exit(1);
	}

	dwfl_end(dwfl);
}
