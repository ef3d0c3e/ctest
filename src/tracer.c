#include "tracer.h"
#include "calls.h"
#include "error.h"
#include "insn.h"
#include "mem_access.h"
#include "result.h"
#include <asm/prctl.h>
#include <asm/unistd_64.h>
#include <capstone/capstone.h>
#include <errno.h>
#include <setjmp.h>
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

/* Graceful shutdown function */
static void
shutdown(struct ctest_result* result)
{
	longjmp(result->jmp_end, 1);
}

static int
insn_hook(struct ctest_result* result, struct user_regs_struct* regs, cs_insn* insn)
{
	// Check for call insn
	int is_call = 0;
	for (int i = 0; i < insn[0].detail->groups_count; ++i) {
		if (insn[0].detail->groups[i] == CS_GRP_CALL) {
			is_call = 1;
			break;
		}
	}

	if (is_call && !__ctest_calls_insn_hook(result, regs, insn))
		return 0;
	if (!__ctest_mem_access_insn_hook(result, regs, insn))
		return 0;
	return 1;
}

void
__ctest_tracer_start(struct ctest_result* result)
{
	if (ptrace(PTRACE_ATTACH, result->child, NULL, NULL) < 0) {
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

	// Populate the maps
	result->mem.maps = __ctest_mem_maps_parse(result->child);

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
			fprintf(stderr, "Child process exited with status %d\n", WEXITSTATUS(status));
			break;
		} else if (WIFSIGNALED(status)) {
			fprintf(stderr, "Child process exited with status %d\n", WEXITSTATUS(status));
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
		// Do not run hooks before the tested function is running
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

		// Process insn, shut down on failure
		if (!__ctest_insn_hook(result, &regs, insn_hook)) {
			regs.rip = (uintptr_t)shutdown;
			regs.rdi = (uintptr_t)result->child_result;

			ptrace(PTRACE_SETREGS, result->child, 0, &regs);
			break;
		}

		if (regs.rip == (uintptr_t)brk || regs.rip == (uintptr_t)sbrk) {
			fprintf(stderr, "syscall [s]brk detected\n");
			exit(1);
		}
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
