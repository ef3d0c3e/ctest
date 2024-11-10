#include "insn.h"
#include "result.h"
#include <errno.h>
#include <sys/ptrace.h>
#include <string.h>

/* Read current instruction from the child's memory */
static void
read_instruction_bytes(pid_t pid, uintptr_t address, uint8_t* buffer, size_t length)
{
	size_t i;
	for (i = 0; i < length; i += sizeof(long)) {
		errno = 0;
		long word = ptrace(PTRACE_PEEKTEXT, pid, address + i, NULL);

		if (errno != 0) {
			perror("ptrace(PEEKTEXT)");
			break;
		}

		// Copy the bytes into the buffer, handling partial reads at the end
		size_t copy_length = (i + sizeof(long) > length) ? (length - i) : sizeof(long);
		memcpy(buffer + i, &word, copy_length);
	}
}

void
__ctest_insn_hook(struct ctest_result* result,
                  struct user_regs_struct* regs,
                  void (*insn_hook)(struct ctest_result*, struct user_regs_struct*, cs_insn*))
{
	const static size_t MAX_INSN_LEN = 15; // Maximum length for x86_64
	uint8_t code[MAX_INSN_LEN];
	read_instruction_bytes(result->child, regs->rip, code, MAX_INSN_LEN);

	cs_insn* insn;
	size_t count = cs_disasm(result->capstone_handle, code, MAX_INSN_LEN, regs->rip, 0, &insn);
	if (count <= 0) {
		printf("%s: Error decoding instructions\n", __FUNCTION__);
		exit(1);
	}

	insn_hook(result, regs, insn);
	cs_free(insn, count);
}
