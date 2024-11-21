#include "session.hpp"
#include "colors.hpp"
#include "exceptions.hpp"
#include <condition_variable>
#include <csignal>
#include <fmt/core.h>
#include <iostream>
#include <mutex>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <unistd.h>

using namespace ctest;

session::session(const ctest_unit* unit)
  : unit{ unit }
  , dwfl_handle{ NULL }
{
	// Init test_data
	test_data = (ctest_data*)mmap(NULL, sizeof(struct ctest_data), PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
	test_data->in_function = 0;
	test_data->message_fd = memfd_create("child_message", 0);

	// Init capstone
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &capstone_handle) != CS_ERR_OK)
		throw exception("Failed to initialize capstone");
	cs_option(capstone_handle, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(capstone_handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
}

session::~session()
{
	if (dwfl_handle)
		dwfl_end(dwfl_handle);
	munmap(test_data, sizeof(ctest_data));
}

void session::child_start()
{
	child_session = (uintptr_t)this;
	stdout = memfd_create("child_stdout", 0);
	dup2(stdout, STDOUT_FILENO);
	stderr = memfd_create("child_stderr", 0);
	dup2(stderr, STDERR_FILENO);

	if (!(unit->flags & CTEST_DISABLE_PTRACE))
		ptrace(PTRACE_TRACEME);
	
	// Don't use printf as it calls to malloc()
	write(test_data->message_fd, " -- Begin Trace --\n", 15);
	if (!setjmp(jmp_exit))
	{
		unit->fn(test_data);
	}
	write(test_data->message_fd, " -- End Trace --\n", 13);
	test_data->in_function = 0;
}

bool
session::start()
{
	colors::intitialize(true);

	child = fork();
	if (child > 0) {
		std::cout << format("thisptr={c_red}{0:p}{c_reset}", (void*)this) << std::endl;
		//__ctest_tracer_start(result);
		return true;
	} else {
		child_start();
	}
	return false;
}
