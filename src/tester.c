#define _GNU_SOURCE
#include "tester.h"
#include "result.h"
#include "signal.h"
#include <errno.h>
#include <execinfo.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <linux/ptrace.h>
#include <threads.h>
#include <unistd.h>

static struct ctest_result* _G_result;
static void
sighandler(int signum)
{
	__ctest_signal_handler(sighandler, _G_result, signum);
}

static void*
thread_start(void* data)
{
	ptrace(PTRACE_TRACEME, 0, NULL, NULL);
	const struct ctest_unit* unit = data;

	// Set sighandlers
	/*
	for (int i = 0; i < 32; ++i)
	{
	    // https://www.gnu.org/software/libc/manual/html_node/Blocking-for-Handler.html
	    struct sigaction act;
	    act.sa_handler = sighandler;
	    sigemptyset (&act.sa_mask);
	    act.sa_flags = SA_RESETHAND | SA_NODEFER;
	    if (i != 0 && i != 9 && i != 19 && sigaction(i, &act, NULL) == -1)
	    {
	        int errsv = errno;
	        fprintf(stderr, "Failed to set signal handler for signal %d: %s\n", i,
	strerror(errsv));
	    }
	}*/

	struct ctest_result result = __ctest_result_new();
	_G_result = &result;
	// Run unit
	if (!setjmp(result.jmp_end)) {
		unit->fn(&result);
	}
	_G_result = NULL;
	// TODO: Raise errors on unhandled stdout/stderr content
	__ctest_result_print(&result);
	__ctest_result_free(&result);
	exit(1);
	return NULL;
}

void
run_test(struct ctest_data* data, const struct ctest_unit* unit)
{
	// TODO REDIR
	pid_t pid = fork();
	if (pid > 0) {
		if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
			int errsv = errno;
			fprintf(stderr, "CRITICAL: PTRACE_ATTACH failed: %s\n", strerror(errsv));
			exit(1);
		}

		int status;
		if (waitpid(pid, &status, 0) != pid) {
			printf("CRITICAL: Failed to ptrace program\n");
			exit(1);
		}

		if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD) < 0)
		{
			perror("ptrace(SETOPTIONS)");
			exit(1);
		}

		while (1) {
			if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) < 0) {
				perror("ptrace(SINGLESTEP)");
				exit(EXIT_FAILURE);
			}

			if (waitpid(pid, &status, 0) != pid || WIFEXITED(status)) {
				printf("Child process exited with status %d\n", WEXITSTATUS(status));
				break;
			}

			struct user_regs_struct regs;
			if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0) {
				perror("ptrace(GETREGS)");
				exit(EXIT_FAILURE);
			}

			// Print the child's instruction pointer
			if ((regs.rip & 0xFF) == 0x080) {
				//printf("Syscall detected at 0x%llx %lld\n", regs.rip, regs.rax);
			} else if (regs.rip == (unsigned long long)malloc) {
				printf("malloc(%lld) at 0x%llx\n", regs.rdi, regs.rip);
			} else if (regs.rip == (unsigned long long)free) {
				printf("free() at 0x%llx\n", regs.rip);
			} else {
				// Print the child's instruction pointer
			}
			/*
			int signum = 0;
			printf("Getting Registers %d\n", pid);

			if ((ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL)) < 0) {
				perror("ptrace(CONT)");
				exit(1);
			}

			if (wait(&status) == -1)
				perror("wait(&status)");
			signum = WSTOPSIG(status);
			if (signum == SIGTRAP) {
				signum = 0;
				if ((ptrace(PTRACE_GETREGS, pid, NULL, &regs)) < 0) {
					perror("ptrace(GETREGS):");
					exit(1);
				}
				if (regs.orig_rax ==
				    __NR_mmap) { // Check for mmap
					             // Handle mmap call, get parameters from regs
					             // On syscall exit, check the return value for the address
					printf("Inside\n");
				}
				printf("%lld\n", regs.orig_rax);
				// Similar checks for brk or other relevant calls
				ptrace(PTRACE_CONT, pid, 0, 0); // Continue to next syscall
			} else {
				printf("Unexpected signal %d\n", signum);
				ptrace(PTRACE_CONT, pid, 0, signum);
				break;
			}
			*/
		}
	} else {
		thread_start((void*)unit);
	}
}
