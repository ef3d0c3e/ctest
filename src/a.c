#include "test.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

CTEST_UNIT(test, {
	char s[255];
	s[0] = 1;
	s[1] = 2;
	s[2] = 3;
})
