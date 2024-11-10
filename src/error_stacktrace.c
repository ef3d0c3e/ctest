#include "error.h"
#include "messages.h"
#include "result.h"
#include <errno.h>
#include <elfutils/libdwfl.h>
#include <string.h>
#include <sys/ptrace.h>

void
print_function_and_source_line_from_addr(int fd, Dwfl* dwfl, Dwarf_Addr pc)
{
	Dwfl_Module* module = dwfl_addrmodule(dwfl, pc);
	if (!module) {
		printf("No module found for address %lx\n", pc);
		return;
	}

	// Retrieve source line information using dwfl_module_getsrc
	Dwfl_Line* line = dwfl_module_getsrc(module, pc);
	const char* file = NULL;
	int line_nr = 0;
	Dwarf_Addr addr;
	if (line) {
		file = dwfl_lineinfo(line, &addr, &line_nr, NULL, NULL, NULL);
	}

	// Print source line information
	if (file) {
		dprintf(fd, "%s:%d ", file, line_nr);
	} else {
		dprintf(fd, "<unknown> ");
	}

	// Get function name using dwfl_addrmodule
	GElf_Sym sym;
	const char* symbol = dwfl_module_addrsym(module, pc, &sym, NULL);
	if (symbol)
		dprintf(fd, "%s%s()%s\n", __ctest_color(CTEST_COLOR_GREEN), symbol, __ctest_color(CTEST_COLOR_RESET));
	else
		dprintf(fd, "%s<unknown>()%s\n", __ctest_color(CTEST_COLOR_GREEN), __ctest_color(CTEST_COLOR_RESET));
	
	return;
}

// Function to print the stack trace of the current process
void
__ctest_print_stack_trace(struct ctest_result* result, int fd, struct user_regs_struct* regs)
{
	// Setup Dwfl context
	Dwfl* dwfl;
	Dwfl_Callbacks callbacks = {
		.find_elf = dwfl_linux_proc_find_elf,
		.find_debuginfo = dwfl_standard_find_debuginfo,
	};
	dwfl = dwfl_begin(&callbacks);

	if (dwfl_linux_proc_report(dwfl, result->child) != 0) {
		fprintf(stderr, "dwfl_linux_proc_report failed: %s\n", strerror(errno));
		exit(1);
	}

	if (dwfl_report_end(dwfl, NULL, NULL) != 0) {
		fprintf(stderr, "dwfl_report_end failed: %s\n", strerror(errno));
		exit(1);
	}

	// Walk the stack frame
	Dwarf_Addr pc = regs->rip;
	Dwarf_Addr sp = regs->rsp;
	static const size_t max_frames = 10;

	for (size_t i = 0; i < max_frames && pc; ++i) {
		dprintf(fd,
		  " %s#%zu%s ", __ctest_color(CTEST_COLOR_YELLOW), i, __ctest_color(CTEST_COLOR_RESET));
		print_function_and_source_line_from_addr(fd, dwfl, pc);

		// Read the next frame pointer and instruction pointer
		pc = ptrace(PTRACE_PEEKDATA, result->child, sp + sizeof(void*), NULL);
		sp = ptrace(PTRACE_PEEKDATA, result->child, sp, NULL);

		// Stop on error
		if (pc == (Dwarf_Addr)-1 || sp == (Dwarf_Addr)-1)
			break;
	}

	dwfl_end(dwfl);
}
