#include "error.h"
#include "messages.h"
#include "result.h"
#include <capstone/capstone.h>
#include <signal.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>

/* Recover from signal, jump either to jmp_recover in handling mode, or to jmp_end for graceful shutdown */
static void signal_recover(struct ctest_result *result)
{
	if (result->sigdata.handling)
		siglongjmp(result->jmp_recover, 1);
	else
		siglongjmp(result->jmp_end, 1);
}

void __ctest_handle_sigsegv(struct ctest_result *result, struct user_regs_struct *regs)
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

static void
reg_pair(FILE* stream, const char* name1, uintptr_t r1, const char* name2, uintptr_t r2)
{
	char buf[255];
	size_t len = snprintf(buf, sizeof(buf), "%s=%lx", name1, r1);
	while (len < 22)
		buf[len++] = ' ';
	len += snprintf(buf + len, sizeof(buf) - len, "%s=%lx\n", name2, r2);
	write(fileno(stream), buf, len);
}

static void
reg_eflags(FILE* stream, uintptr_t efl)
{
	char buf[1024];
	size_t len = snprintf(buf, sizeof(buf), "EFLAGS=%lx ", efl);

	for (int i = 0; i < 32; ++i) {
		if (!(efl & (1 << i)))
			continue;
		switch (i) {
			case 0:
				len += snprintf(buf + len, sizeof(buf) - len, "CF ");
				break;
			case 1:
				len += snprintf(buf + len, sizeof(buf) - len, "1 ");
				break;
			case 2:
				len += snprintf(buf + len, sizeof(buf) - len, "PF ");
				break;
			case 4:
				len += snprintf(buf + len, sizeof(buf) - len, "AF ");
				break;
			case 6:
				len += snprintf(buf + len, sizeof(buf) - len, "ZF ");
				break;
			case 7:
				len += snprintf(buf + len, sizeof(buf) - len, "SF ");
				break;
			case 8:
				len += snprintf(buf + len, sizeof(buf) - len, "TF ");
				break;
			case 9:
				len += snprintf(buf + len, sizeof(buf) - len, "IF ");
				break;
			case 10:
				len += snprintf(buf + len, sizeof(buf) - len, "DF ");
				break;
			case 11:
				len += snprintf(buf + len, sizeof(buf) - len, "OF ");
				break;
			case 12:
				len += snprintf(buf + len, sizeof(buf) - len, "IOPL(12) ");
				break;
			case 13:
				len += snprintf(buf + len, sizeof(buf) - len, "IOPL(13) ");
				break;
			case 14:
				len += snprintf(buf + len, sizeof(buf) - len, "NT ");
				break;
			case 15:
				len += snprintf(buf + len, sizeof(buf) - len, "MD ");
				break;
			case 16:
				len += snprintf(buf + len, sizeof(buf) - len, "RF ");
				break;
			case 17:
				len += snprintf(buf + len, sizeof(buf) - len, "VM ");
				break;
			case 18:
				len += snprintf(buf + len, sizeof(buf) - len, "AC ");
				break;
			case 19:
				len += snprintf(buf + len, sizeof(buf) - len, "VIF ");
				break;
			case 20:
				len += snprintf(buf + len, sizeof(buf) - len, "VIP ");
				break;
			case 21:
				len += snprintf(buf + len, sizeof(buf) - len, "ID ");
				break;
			case 31:
				len += snprintf(buf + len, sizeof(buf) - len, "AI ");
				break;
		}
	}
	buf[len++] = '\n';
	write(fileno(stream), buf, len);
}

static void
print_registers(FILE* stream, struct user_regs_struct* regs)
{
	reg_pair(stream, "RAX", regs->rax, "ORAX", regs->orig_rax);
	reg_pair(stream, "RBX", regs->rbx, "R8", regs->r9);
	reg_pair(stream, "RCX", regs->rcx, "R9", regs->r9);
	reg_pair(stream, "RDX", regs->rdx, "R10", regs->r10);
	reg_pair(stream, "RSI", regs->rsi, "R11", regs->r11);
	reg_pair(stream, "RDI", regs->rdi, "R12", regs->r12);
	reg_pair(stream, "RBP", regs->rbp, "R13", regs->r13);
	reg_pair(stream, "RSP", regs->rsp, "R14", regs->r14);
	reg_pair(stream, "RIP", regs->rip, "R15", regs->r15);
	reg_eflags(stream, regs->eflags);
}

void
__ctest_raise_parent_error(struct ctest_result* result,
                           struct user_regs_struct* regs,
                           const char* fmt,
                           ...)
{
	// Message heading
	char* header = __ctest_colorize(CTEST_COLOR_RED, " --[ CTest test failed ]--");
	char* what = __ctest_colorize(CTEST_COLOR_BLUE, "WHAT:");
	fprintf(stderr, "%s\n%s ", header, what);
	free(what);
	free(header);

	// Custom message
	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);

	// Print registers
	fprintf(stderr, "%s * Register dump:%s\n", __ctest_color(CTEST_COLOR_BLUE), __ctest_color(CTEST_COLOR_RESET));
	print_registers(stderr, regs);

	// Output opcodes
	const size_t code_size = 32;
	uint8_t code[code_size];

	unsigned long addr = ptrace(PTRACE_PEEKUSER, result->child, 8 * RIP, 0);
	for(size_t i = 0; i < code_size; i++)
		code[i] = ptrace(PTRACE_PEEKTEXT, result->child, addr + i, 0) & 0xff;

    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        fprintf(stderr, "Failed to initialize Capstone engine\n");
        return;
    }

	fprintf(stderr, "%s * ASM dump:%s\n", __ctest_color(CTEST_COLOR_BLUE), __ctest_color(CTEST_COLOR_RESET));
    count = cs_disasm(handle, code, code_size, regs->rip, 0, &insn);
    if (count > 0) {
        for (size_t i = 0; i < count; i++) {
			if (i == 0)
			{
				printf("%s0x%" PRIx64 "%s: %s%s %s%s <--\n", __ctest_color(CTEST_COLOR_GREEN), insn[i].address, __ctest_color(CTEST_COLOR_RESET),
						__ctest_color(CTEST_COLOR_RED), insn[i].mnemonic, insn[i].op_str, __ctest_color(CTEST_COLOR_RESET));
			}
			else
			{
				printf("%s0x%" PRIx64 "%s: %s %s\n", __ctest_color(CTEST_COLOR_GREEN), insn[i].address, __ctest_color(CTEST_COLOR_RESET),
						insn[i].mnemonic, insn[i].op_str);
			}
        }
        cs_free(insn, count);
    } else {
        fprintf(stderr, "Failed to disassemble given code\n");
    }

    cs_close(&handle);

	// TODO: Use libunwind for stacktrace
}
