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
	char *s = 0;
	s[0] = rand();
	s[1] = 2;
	s[2] = 3;
	((int*)s)[1] = 0x12345678;
})
