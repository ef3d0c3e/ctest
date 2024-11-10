#include "result.h"
#include "memory.h"
#include "signal.h"
#include <capstone/capstone.h>
#include <elfutils/libdwfl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

struct ctest_result*
__ctest_result_new(const struct ctest_unit* unit)
{
	int messages = memfd_create("ctest_buffer_messages", 0);
	if (messages == -1) {
		const int errsv = errno;
		fprintf(stderr, "Failed to create message buffer: %s", strerror(errsv));
	}

	int out = memfd_create("ctest_buffer_stdout", 0);
	if (out == -1) {
		const int errsv = errno;
		fprintf(stderr, "Failed to create stdout buffer: %s", strerror(errsv));
	}

	int err = memfd_create("ctest_buffer_stderr", 0);
	if (err == -1) {
		const int errsv = errno;
		fprintf(stderr, "Failed to create stderr buffer: %s", strerror(errsv));
	}

	struct ctest_result* mem = mmap(NULL,
	                                sizeof(struct ctest_result),
	                                PROT_READ | PROT_WRITE,
	                                MAP_SHARED | MAP_ANONYMOUS,
	                                -1,
	                                0);
	mem->unit = unit;
	mem->messages = messages;
	mem->stdout = out;
	mem->stderr = err;
	mem->in_function = 0;
	mem->sigdata = __ctest_signal_new();
	mem->mem = __ctest_mem_new();

	// Initialize capstone
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &mem->capstone_handle) != CS_ERR_OK) {
		fprintf(stderr, "Failed to initialize Capstone engine\n");
		exit(1);
	}
	cs_option(mem->capstone_handle, CS_OPT_DETAIL, CS_OPT_ON);

	return mem;
}

void
__ctest_result_free(struct ctest_result* res)
{
	if (res->messages != -1)
		close(res->messages);
	if (res->stdout != -1)
		close(res->stdout);
	if (res->stderr != -1)
		close(res->stderr);
	__ctest_signal_free(&res->sigdata);
	__ctest_mem_free(&res->mem);
	cs_close(&res->capstone_handle);
	munmap(res, sizeof(struct ctest_result));
}

void
__ctest_result_print(struct ctest_result* res)
{
	char buf[4096];
	lseek(res->messages, 0, SEEK_SET);

	ssize_t size = read(res->messages, buf, sizeof(buf));
	while (size > 0) {
		fwrite(buf, 1, size, stderr);
		size = read(res->messages, buf, sizeof(buf));
	}
}
