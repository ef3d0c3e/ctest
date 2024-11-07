#include "test.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

int main() {}

CTEST_UNIT(test, {
		printf(" -- START -- \n");
		int *x = 0;
		x = malloc(32);
		printf("Addr=%p\n", x);
		free(x);
		printf(" -- END -- \n");
})
