#include "tracer.h"
#include "error.h"
#include "memory.h"
#include <asm/prctl.h>
#include <capstone/capstone.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/wait.h>

uintptr_t
get_register_value(x86_reg reg, struct user_regs_struct* regs)
{
	switch (reg) {
		case X86_REG_RAX:
			return regs->rax;
		case X86_REG_RBX:
			return regs->rbx;
		case X86_REG_RCX:
			return regs->rcx;
		case X86_REG_RDX:
			return regs->rdx;
		case X86_REG_RSI:
			return regs->rsi;
		case X86_REG_RDI:
			return regs->rdi;
		case X86_REG_RBP:
			return regs->rbp;
		case X86_REG_RSP:
			return regs->rsp;
		case X86_REG_R8:
			return regs->r8;
		case X86_REG_R9:
			return regs->r9;
		case X86_REG_R10:
			return regs->r10;
		case X86_REG_R11:
			return regs->r11;
		case X86_REG_R12:
			return regs->r12;
		case X86_REG_R13:
			return regs->r13;
		case X86_REG_R14:
			return regs->r14;
		case X86_REG_R15:
			return regs->r15;
		case X86_REG_RIP:
			return regs->rip;
		default:
			fprintf(stderr, "Unhandled register: %d\n", reg);
			return 0;
	}
}

uintptr_t
get_segment_base(x86_reg segment, pid_t pid)
{
	uint64_t base = 0;
	if (segment == X86_REG_FS) {
		ptrace(PTRACE_ARCH_PRCTL, pid, ARCH_GET_FS, &base);
	} else if (segment == X86_REG_GS) {
		ptrace(PTRACE_ARCH_PRCTL, pid, ARCH_GET_GS, &base);
	}
	return base;
}

uint64_t
calculate_effective_address(pid_t pid, cs_x86_op* op, struct user_regs_struct* regs)
{

	// Get base register if available
	uintptr_t base = 0;
	if (op->mem.base != X86_REG_INVALID) {
		base = get_register_value(op->mem.base, regs);
	}

	uintptr_t index = 0;
	// Get index register and apply scale if available
	if (op->mem.index != X86_REG_INVALID) {
		index = get_register_value(op->mem.index, regs) * op->mem.scale;
	}

	// Add displacement
	uintptr_t displacement = op->mem.disp;

	// Handle segment base if segment register is used
	uintptr_t segment = 0;
	if (op->mem.segment != X86_REG_INVALID) {
		segment = get_segment_base(op->mem.segment, pid);
	}

	return base + index + displacement + segment;
}

void
read_instruction_bytes(pid_t pid, uint64_t address, uint8_t* buffer, size_t length)
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

// FIXME: Read once and store to a structure
// Then update the structure as calls to mmap, munmap, mremap and brk are made.
int is_address_mapped(pid_t pid, uint64_t address) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *maps = fopen(path, "r");
    if (!maps) {
        perror("Failed to open /proc/[pid]/maps");
        return 0;
    }

    uint64_t start, end;
    while (fscanf(maps, "%lx-%lx", &start, &end) == 2) {
        if (address >= start && address < end) {
            fclose(maps);
            return 1;  // Address is valid
        }
        // Skip to next line
        while (fgetc(maps) != '\n' && !feof(maps));
    }
    fclose(maps);
    return 0;  // Address is not mapped
}

static void
process_insn(struct ctest_result* result, struct user_regs_struct* regs)
{
	csh handle;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
		fprintf(stderr, "Failed to initialize Capstone engine\n");
		return;
	}
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	const size_t MAX_INSN_LEN = 15; // Maximum length for x86_64
	uint8_t code[MAX_INSN_LEN];
	read_instruction_bytes(result->child, regs->rip, code, MAX_INSN_LEN);

	cs_insn* insn;
	size_t count = cs_disasm(handle, code, MAX_INSN_LEN, regs->rip, 0, &insn);
	if (count <= 0) {
		printf("Error decoding instructions\n");
		cs_close(&handle);
		return;
	}

	for (int i = 0; i < 1; i++) {
		cs_x86_op* op = &(insn[0].detail->x86.operands[i]);
		if (op->type == X86_OP_MEM) {
			// struct memory_access access;
			//(op->access & CS_AC_READ);
			//(op->access & CS_AC_WRITE);
			uintptr_t address = calculate_effective_address(result->child, op, regs);
			//if (is_address_mapped(result->child, address))
			//	printf("Accessed memory: %p\n", address);
			//  Populate other memory access details here
		}
				printf("0x%" PRIx64 ": %s %s\n", insn[i].address,
						insn[i].mnemonic, insn[i].op_str);
	}

	cs_free(insn, count);
	cs_close(&handle);
}

void
__ctest_tracer_start(struct ctest_result* result)
{
	if (ptrace(PTRACE_ATTACH, result->child, NULL, NULL) < 0) {
		int errsv = errno;
		perror("ptrace(ATTACH)");
		exit(1);
	}

	int status;
	if (waitpid(result->child, &status, 0) != result->child) {
		fprintf(stderr, "Failed to ptrace program\n");
		exit(1);
	}

	if (ptrace(PTRACE_SETOPTIONS, result->child, 0, PTRACE_O_TRACESYSGOOD) < 0) {
		perror("ptrace(SETOPTIONS)");
		exit(1);
	}

	printf("Hooked result: %p\n", (void*)result);
	printf("Shutdown jmp : %p\n", (void*)result->jmp_end);

	int incoming_mman = 0;
	while (1) {
		if (ptrace(PTRACE_SINGLESTEP, result->child, 0, 0) < 0) {
			perror("ptrace(SINGLESTEP)");
			exit(1);
		}

		if (waitpid(result->child, &status, 0) != result->child) {
			perror("waitpid");
			exit(1);
		}

		if (WIFEXITED(status)) {
			printf("Child process exited with status %d\n", WEXITSTATUS(status));
			break;
		} else if (WIFSIGNALED(status)) {
			printf("Child process exited with status %d\n", WEXITSTATUS(status));
			break;
		} else if (WIFSTOPPED(status)) {
			const int signal = WSTOPSIG(status);

			if (signal == SIGSEGV) {
				struct user_regs_struct regs;
				if (ptrace(PTRACE_GETREGS, result->child, 0, &regs) < 0) {
					perror("ptrace(GETREGS)");
					exit(EXIT_FAILURE);
				}

				__ctest_handle_sigsegv(result, &regs);
				continue;
			} else if (signal != SIGTRAP) {
				dprintf(result->messages, "Received signal: %d\n", signal);
				if (ptrace(PTRACE_DETACH, result->child, NULL, NULL) < 0) {
					perror("ptrace(DETACH)");
					exit(1);
				}
				break;
			}
		}
		if (!result->in_function)
			continue;
		// Wait for the current memory hook to finish
		if (result->mem.in_hook)
			continue;
		// Process memory hooks results
		else if (incoming_mman) {
			__ctest_mem_arena_add(result);
			incoming_mman = 0;
		}

		struct user_regs_struct regs;
		if (ptrace(PTRACE_GETREGS, result->child, 0, &regs) < 0) {
			perror("ptrace(GETREGS)");
			exit(EXIT_FAILURE);
		}

		// Process insn
		process_insn(result, &regs);

		// Memory management
		if (regs.rip == (uintptr_t)malloc || regs.rip == (uintptr_t)realloc ||
		    regs.rip == (uintptr_t)free) {
			incoming_mman = __ctest_mem_memman_hook(result, &regs);

			ptrace(PTRACE_SETREGS, result->child, 0, &regs);
		}
	}
	// Print the arena
	__ctest_mem_arena_print(result, 1);
}
