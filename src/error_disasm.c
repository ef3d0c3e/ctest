#include "error.h"
#include <stdio.h>

static void
reg_pair(int fd, const char* name1, uintptr_t r1, const char* name2, uintptr_t r2)
{
	char buf[255];
	size_t len = snprintf(buf, sizeof(buf), "%s=%lx", name1, r1);
	while (len < 22)
		buf[len++] = ' ';
	len += snprintf(buf + len, sizeof(buf) - len, "%s=%lx\n", name2, r2);
	write(fd, buf, len);
}

static void
reg_eflags(int fd, uintptr_t efl)
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
	write(fd, buf, len);
}

void
__ctest_print_registers(int fd, struct user_regs_struct* regs)
{
	reg_pair(fd, "RAX", regs->rax, "ORAX", regs->orig_rax);
	reg_pair(fd, "RBX", regs->rbx, "R8", regs->r9);
	reg_pair(fd, "RCX", regs->rcx, "R9", regs->r9);
	reg_pair(fd, "RDX", regs->rdx, "R10", regs->r10);
	reg_pair(fd, "RSI", regs->rsi, "R11", regs->r11);
	reg_pair(fd, "RDI", regs->rdi, "R12", regs->r12);
	reg_pair(fd, "RBP", regs->rbp, "R13", regs->r13);
	reg_pair(fd, "RSP", regs->rsp, "R14", regs->r14);
	reg_pair(fd, "RIP", regs->rip, "R15", regs->r15);
	reg_eflags(fd, regs->eflags);
}