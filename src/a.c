#include "test.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {}

CTEST_UNIT(test, {
	printf("1\n");
	CTEST_CRASH("Program didn't crash", {
		*(int*)0 = 64;
	})
	printf("2\n");
	*(int*)0 = 64;
	printf("3\n");
})
