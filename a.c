#include "includes/ctest.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

void g()
{}

void f()
{
	//char *buf = malloc(16);
	//read(1, buf, 17);
	//int x = 7;
}

CTEST_UNIT(test, {
		f();
})
