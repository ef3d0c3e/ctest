#ifndef CTEST_CALLS_H
#define CTEST_CALLS_H

#include <capstone/capstone.h>
#include <sys/user.h>
struct ctest_result;

int __ctest_calls_hook(struct ctest_result* result, struct user_regs_struct* regs, cs_insn* insn);

#endif // CTEST_CALLS_H
