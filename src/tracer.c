#include "tracer.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

void __ctest_tracer_start(pid_t pid) {
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

    // Memory management
    if (regs.rip == (unsigned long long)malloc ||
        regs.rip == (unsigned long long)realloc ||
        regs.rip == (unsigned long long)mmap) {
		printf("Allocate\n");
    } else if (regs.rip == (unsigned long long)free ||
               regs.rip == (unsigned long long)munmap) {
		printf("Free\n");
    }
  }
}
