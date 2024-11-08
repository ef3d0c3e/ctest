#include "test.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

CTEST_UNIT(test, {
	write(0, " -- START -- \n", 14);
	free((void*)1);
	write(0, " -- END -- \n", 12);
})
