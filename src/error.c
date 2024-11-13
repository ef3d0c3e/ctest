#include "error.h"
#include "messages.h"
#include "result.h"
#include <ctest.h>
#include <capstone/capstone.h>
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


	fprintf(stderr,
	        "%s * ASM dump:%s\n",
	        __ctest_color(CTEST_COLOR_BLUE),
	        __ctest_color(CTEST_COLOR_RESET));
	cs_insn* insn;
	const size_t count = cs_disasm(result->capstone_handle, code, code_size, regs->rip, 0, &insn);
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

static const char*
get_deallocator_name(uintptr_t allocator)
{
	if (allocator == (uintptr_t)malloc || allocator == (uintptr_t)realloc)
		return "free";
	if (allocator == (uintptr_t)mmap || allocator == (uintptr_t)mremap)
		return "munmap";
	// TODO: brk/sbrk
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
	__ctest_print_source_line(result, STDERR_FILENO, alloc->alloc_rip);

	if (!alloc->freed_rip)
		return;

	fprintf(stderr,
	        " %s* Buffer [%p; %zu] deallocated by %s():%s\n",
	        __ctest_color(CTEST_COLOR_BLUE),
	        (void*)alloc->ptr,
	        alloc->size,
	        get_deallocator_name(alloc->allocator),
	        __ctest_color(CTEST_COLOR_RESET));
	__ctest_print_source_line(result, STDERR_FILENO, alloc->freed_rip);
}
