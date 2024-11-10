#include "error.h"
#include "messages.h"
#include "result.h"
#include "test.h"
#include <capstone/capstone.h>
#include <elfutils/libdwfl.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>

/* Recover from signal, jump either to jmp_recover in handling mode, or to jmp_end for graceful
 * shutdown */
static void
signal_recover(struct ctest_result* result)
{
	if (result->sigdata.handling)
		siglongjmp(result->jmp_recover, 1);
	else
		siglongjmp(result->jmp_end, 1);
}

void
__ctest_handle_sigsegv(struct ctest_result* result, struct user_regs_struct* regs)
{
	if (!result->sigdata.handling)
		__ctest_raise_parent_error(result, regs, "Program SEGFAULTED unexpectedly\n");

	result->sigdata.signum = SIGSEGV;
	regs->rip = (uintptr_t)signal_recover;
	regs->rdi = (uintptr_t)result->child_result;

	// Set the modified registers
	if (ptrace(PTRACE_SETREGS, result->child, NULL, regs) < 0) {
		perror("ptrace(SETREGS)");
		exit(1);
	}
}

void
__ctest_raise_parent_error(struct ctest_result* result,
                           struct user_regs_struct* regs,
                           const char* fmt,
                           ...)
{
	// Message heading
	fprintf(stderr,
	        " %s--[ CTest test %s#%zu failed ]--%s\n",
	        __ctest_color(CTEST_COLOR_RED),
	        result->unit->file,
	        result->unit->id,
	        __ctest_color(CTEST_COLOR_RESET));

	// Print registers
	fprintf(stderr,
	        "%s * Register dump:%s\n",
	        __ctest_color(CTEST_COLOR_BLUE),
	        __ctest_color(CTEST_COLOR_RESET));
	__ctest_print_registers(STDERR_FILENO, regs);

	// Output opcodes
	const size_t code_size = 15;
	uint8_t code[code_size];

	unsigned long addr = ptrace(PTRACE_PEEKUSER, result->child, 8 * RIP, 0);
	for (size_t i = 0; i < code_size; i++)
		code[i] = ptrace(PTRACE_PEEKTEXT, result->child, addr + i, 0) & 0xff;

	csh handle;
	cs_insn* insn;
	size_t count;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
		fprintf(stderr, "Failed to initialize Capstone engine\n");
		return;
	}

	fprintf(stderr,
	        "%s * ASM dump:%s\n",
	        __ctest_color(CTEST_COLOR_BLUE),
	        __ctest_color(CTEST_COLOR_RESET));
	count = cs_disasm(handle, code, code_size, regs->rip, 0, &insn);
	if (count > 0) {
		for (size_t i = 0; i < count; i++) {
			if (i == 0) {
				printf("%s0x%" PRIx64 "%s: %s%s %s%s <--\n",
				       __ctest_color(CTEST_COLOR_GREEN),
				       insn[i].address,
				       __ctest_color(CTEST_COLOR_RESET),
				       __ctest_color(CTEST_COLOR_RED),
				       insn[i].mnemonic,
				       insn[i].op_str,
				       __ctest_color(CTEST_COLOR_RESET));
			} else {
				printf("%s0x%" PRIx64 "%s: %s %s\n",
				       __ctest_color(CTEST_COLOR_GREEN),
				       insn[i].address,
				       __ctest_color(CTEST_COLOR_RESET),
				       insn[i].mnemonic,
				       insn[i].op_str);
			}
		}
		cs_free(insn, count);
	} else {
		fprintf(stderr, "Failed to disassemble given code\n");
	}

	cs_close(&handle);

	fprintf(
	  stderr, "%sWHAT:%s ", __ctest_color(CTEST_COLOR_BLUE), __ctest_color(CTEST_COLOR_RESET));

	// Custom message
	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);

	__ctest_print_source_line(result, STDERR_FILENO, regs->rip);

	// Stacktrace
	fprintf(stderr,
	        "%s * Stacktrace:%s\n",
	        __ctest_color(CTEST_COLOR_BLUE),
	        __ctest_color(CTEST_COLOR_RESET));
	__ctest_print_stack_trace(result, STDERR_FILENO, regs);
}

static const char*
get_allocator_name(uintptr_t allocator)
{
	if (allocator == (uintptr_t)malloc)
		return "malloc";
	if (allocator == (uintptr_t)realloc)
		return "realloc";
	if (allocator == (uintptr_t)mmap)
		return "mmap";
	if (allocator == (uintptr_t)mremap)
		return "mremap";
	if (allocator == (uintptr_t)brk)
		return "brk";
	if (allocator == (uintptr_t)sbrk)
		return "sbrk";
	return "<unknown allocator>";
}

void
__ctest_print_alloc_info(struct ctest_result* result, struct ctest_mem_allocation* alloc)
{
	fprintf(stderr,
	        " %s* Buffer [%p; %zu] allocated by %s():%s\n",
	        __ctest_color(CTEST_COLOR_BLUE),
	        (void*)alloc->ptr,
	        alloc->size,
	        get_allocator_name(alloc->allocator),
	        __ctest_color(CTEST_COLOR_RESET));
	uintptr_t addr = ptrace(PTRACE_PEEKTEXT, result->child, alloc->regs.rsp, NULL);
	__ctest_print_source_line(result, STDERR_FILENO, addr);
}

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
	dprintf(fd, "File '%s', line %d:\n", source_file, line_number);
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
__ctest_print_source_line(struct ctest_result* result, int fd, uintptr_t addr)
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

	Dwfl_Module* module = dwfl_addrmodule(dwfl, addr);
	const char* source_file;
	int line_nr;

	if (module) {
		Dwfl_Line* line = dwfl_module_getsrc(module, addr);
		if (line) {
			source_file = dwfl_lineinfo(line, &addr, &line_nr, NULL, NULL, NULL);
			print_source_line_from_file(fd, source_file, line_nr);
		} else
			fprintf(stderr, "<Failed to get line information, likely no debug informations>\n");
	} else {
		fprintf(stderr, "Failed to get module information\n");
		exit(1);
	}

	dwfl_end(dwfl);
}
