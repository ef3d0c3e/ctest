#include "tracer.h"
#include "memory.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

static void
handle_child_signal(struct ctest_result* result, pid_t pid, int signum)
{
	fprintf(stderr, "Child sent signal %d\n", signum);
}
// Write data to child's memory
void
write_to_child(pid_t child_pid, uintptr_t addr, const void* data, size_t len)
{
	const unsigned long* ptr = (const unsigned long*)data;
	for (size_t i = 0; i < (len + sizeof(long) - 1) / sizeof(long); i++) {
		ptrace(PTRACE_POKEDATA, child_pid, addr + i * sizeof(long), ptr[i]);
	}
}

// Read data from child's memory
void
read_from_child(pid_t child_pid, uintptr_t addr, void* data, size_t len)
{
	unsigned long* ptr = (unsigned long*)data;
	for (size_t i = 0; i < (len + sizeof(long) - 1) / sizeof(long); i++) {
		ptr[i] = ptrace(PTRACE_PEEKDATA, child_pid, addr + i * sizeof(long), NULL);
	}
}

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

	int incoming_mem_hook = 0;
	while (1) {
		if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) < 0) {
			perror("ptrace(SINGLESTEP)");
			exit(EXIT_FAILURE);
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

			if (signal != SIGTRAP) {
				// FIXME
				struct user_regs_struct regs;
				if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0) {
					perror("ptrace(GETREGS)");
					exit(EXIT_FAILURE);
				}

				printf("Signal %d\n", signal);
				regs.rip = (uintptr_t)result->jmp_end[0].__jmpbuf[7]; // Program counter
				regs.rsp = (uintptr_t)result->jmp_end[0].__jmpbuf[6]; // Stack pointer
				regs.rbp = (uintptr_t)result->jmp_end[0].__jmpbuf[1]; // Base pointer
				regs.rax = 1;

				// Set the modified registers
				if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) {
					perror("ptrace(SETREGS)");
					exit(1);
				}
				dprintf(result->messages, "Failed\n");
				// Detach from the process
				if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
					perror("ptrace(DETACH)");
					exit(1);
				}
				break;
			}
		}
		// Process memory hooks results
		if (result->arena.in_memory_hook)
			continue;
		else if (incoming_mem_hook)
		{
			printf("-> Incoming: %p\n", result->message_in.mem.malloc.ptr);
			__ctest_mem_add(result);
			incoming_mem_hook = 0;
		}

		struct user_regs_struct regs;
		if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0) {
			perror("ptrace(GETREGS)");
			exit(EXIT_FAILURE);
		}

		// Memory management
		if (regs.rip == (uintptr_t)malloc || regs.rip == (uintptr_t)realloc ||
		    regs.rip == (uintptr_t)free) {
			incoming_mem_hook = __ctest_mem_hook(result, &regs);

			ptrace(PTRACE_SETREGS, pid, 0, &regs);
		}
	}
	__ctest_mem_print(result, 1);
}
