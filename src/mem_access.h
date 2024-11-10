#ifndef CTEST_MEM_ACCESS_H
#define CTEST_MEM_ACCESS_H

#include <capstone/capstone.h>
#include <sys/user.h>
struct ctest_result;

void __ctest_mem_access_insn_hook(struct ctest_result* result, struct user_regs_struct* regs, cs_insn* insn);

#endif // CTEST_MEM_ACCESS_H
