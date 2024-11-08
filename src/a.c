#include "test.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

CTEST_UNIT(test, {
	printf(" -- START -- \n");
	printf("Addr=%p\n", malloc(64));
	printf(" -- END -- \n");
})
