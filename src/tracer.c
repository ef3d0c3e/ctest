#include "tracer.h"
#include "error.h"
#include "memory.h"
#include <capstone/capstone.h>
#include <errno.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/wait.h>

void
__ctest_tracer_start(pid_t pid, struct ctest_result* result)
{
	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
		int errsv = errno;
		perror("ptrace(ATTACH)");
		exit(1);
	}

	int status;
	if (waitpid(pid, &status, 0) != pid) {
		fprintf(stderr, "Failed to ptrace program\n");
		exit(1);
	}

	if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD) < 0) {
		perror("ptrace(SETOPTIONS)");
		exit(1);
	}

	printf("Hooked result: %p\n", (void*)result);
	printf("Shutdown jmp : %p\n", (void*)result->jmp_end);

	int incoming_mman = 0;
	while (1) {
		if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) < 0) {
			perror("ptrace(SINGLESTEP)");
			exit(1);
		}

		if (waitpid(pid, &status, 0) != pid) {
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
				if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0) {
					perror("ptrace(GETREGS)");
					exit(EXIT_FAILURE);
				}

				__ctest_handle_sigsegv(result, &regs);
				continue;
			}
			else if (signal != SIGTRAP)
			{
				dprintf(result->messages, "Received signal: %d\n", signal);
				if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
					perror("ptrace(DETACH)");
					exit(1);
				}
				break;
			}
		}
		// Wait for the current memory hook to finish
		if (result->mem.in_hook)
			continue;
		// Process memory hooks results
		else if (incoming_mman) {
			__ctest_mem_arena_add(result);
			incoming_mman = 0;
		}

		struct user_regs_struct regs;
		if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0) {
			perror("ptrace(GETREGS)");
			exit(EXIT_FAILURE);
		}

		// Memory management
		if (regs.rip == (uintptr_t)malloc || regs.rip == (uintptr_t)realloc ||
		    regs.rip == (uintptr_t)free) {
			incoming_mman = __ctest_mem_memman_hook(result, &regs);

			ptrace(PTRACE_SETREGS, pid, 0, &regs);
		}
	}
	// Print the arena
	__ctest_mem_arena_print(result, 1);
}
