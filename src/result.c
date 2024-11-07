#include "signal.h"
#define _GNU_SOURCE
#include "result.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

struct ctest_result
__ctest_result_new()
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

	return (struct ctest_result){
		.messages = messages,
		.stdout = out,
		.stderr = err,
		.sigdata = __ctest_signal_new(),
	};
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
