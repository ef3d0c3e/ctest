#include "test.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

CTEST_UNIT(test, {
	write(0, " -- START -- \n", 14);
	char *buf = 0;
	buf[126] = 0;
	write(0, " -- END -- \n", 12);
})
