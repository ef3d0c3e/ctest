#include "test.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {}

CTEST_UNIT(test, {
	CTEST_CRASH("Program didn't crash", {
		printf("Hello World\n");
		*(int*)0 = 64;
	})
	sleep(1);
	*(int*)0 = 64;
	printf("Hello World\n");
})
