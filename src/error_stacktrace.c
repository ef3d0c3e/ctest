#include "error.h"
#include "messages.h"
#include "result.h"
#include <elfutils/libdwfl.h>
#include <errno.h>
#include <libunwind-ptrace.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>

static void
print_function_and_source_line_from_addr(int fd, Dwfl* dwfl, Dwarf_Addr pc)
{
	Dwfl_Module* module = dwfl_addrmodule(dwfl, pc);
	if (!module) {
		dprintf(STDERR_FILENO, "No module found for address %lx\n", pc);
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
		dprintf(fd,
		        "%s%s()%s\n",
		        __ctest_color(CTEST_COLOR_GREEN),
		        symbol,
		        __ctest_color(CTEST_COLOR_RESET));
	else
		dprintf(fd,
		        "%s<unknown>()%s\n",
		        __ctest_color(CTEST_COLOR_GREEN),
		        __ctest_color(CTEST_COLOR_RESET));

	return;
}

static int
access_reg(unw_addr_space_t as, unw_regnum_t regnum, unw_word_t* val, int write, void* arg)
{
	pid_t pid = *(pid_t*)arg;
	struct user_regs_struct regs;

	if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
		return -1;
	}

	if (write) {
		errno = EINVAL; // Writing is unsupported in this scenario
		return -1;
	}

	switch (regnum) {
		case UNW_X86_64_RIP:
			*val = regs.rip;
			break;
		case UNW_X86_64_RSP:
			*val = regs.rsp;
			break;
		case UNW_X86_64_RBP:
			*val = regs.rbp;
			break;
		// Map other registers as needed
		default:
			errno = EINVAL;
			return -1;
	}

	return 0;
}

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

	// Setup libunwind
	unw_addr_space_t addr_space = unw_create_addr_space(&_UPT_accessors, 0);
	if (!addr_space) {
		fprintf(stderr, "Failed to create libunwind address space\n");
		exit(1);
	}

	unw_set_caching_policy(addr_space, UNW_CACHE_GLOBAL);
	void* upt_info = _UPT_create(result->child);
	if (!upt_info) {
		fprintf(stderr, "Failed to initialize libunwind UPT info\n");
		exit(1);
	}

	unw_cursor_t cursor;
	if (unw_init_remote(&cursor, addr_space, upt_info) < 0) {
		fprintf(stderr, "Failed to initialize unwinding\n");
		exit(1);
	}

	size_t i = 0;
	while (unw_step(&cursor) > 0) {
		unw_word_t ip, sp;

		unw_get_reg(&cursor, UNW_REG_IP, &ip);
		unw_get_reg(&cursor, UNW_REG_SP, &sp);

		dprintf(fd,
				" %s#%zu%s ", __ctest_color(CTEST_COLOR_YELLOW), i, __ctest_color(CTEST_COLOR_RESET));
		print_function_and_source_line_from_addr(fd, dwfl, ip);
		++i;
	}

	_UPT_destroy(upt_info);
	unw_destroy_addr_space(addr_space);
	dwfl_end(dwfl);
}
