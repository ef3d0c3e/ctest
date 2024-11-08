#include "test.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

CTEST_UNIT(test, {
	write(0, " -- START -- \n", 14);
	void *ptr = malloc(64);
	free(ptr);
	free(ptr);
	write(0, " -- END -- \n", 12);
})
