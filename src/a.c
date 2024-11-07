#include "test.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

int main() {}

CTEST_UNIT(test, {
		volatile int len = 32;
		printf(" -- START -- \n");
		int *x = malloc(len);
		free(x);
		printf(" -- END -- \n");
})
