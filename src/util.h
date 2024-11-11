#ifndef CTEST_UTIL_H
#define CTEST_UTIL_H

#include <capstone/capstone.h>
#include <sys/user.h>
#include <stdint.h>

uintptr_t
__ctest_util_get_register_value(x86_reg reg, struct user_regs_struct* regs);

#endif // CTEST_UTIL_H
