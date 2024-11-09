#include "test.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

void* f()
{
	return malloc(256);
}

CTEST_UNIT(test, {
	char *s = f();
	s[0] = 1;
	s[1] = 2;
	s[2] = 3;
	((int*)s)[1] = 0x12345678;
})
