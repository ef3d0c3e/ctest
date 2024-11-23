#include "session.hpp"
#include "colors.hpp"
#include "exceptions.hpp"
#include <csignal>
#include <cstring>
#include <fmt/core.h>
#include "tracer.hpp"
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <thread>
#include <unistd.h>
#include <sys/wait.h>
#include <utility>

using namespace ctest;

session::session(const ctest_unit* unit)
  : unit{ unit }
  , dwfl_handle{ NULL }
{
	// Init test_data
	test_data = (ctest_data) {
		.in_function = 0,
		.message_fd = memfd_create("child_message", 0),
		.sigstatus = {
			.signum = 0,
			.recover = 0,
			.recovery_point = {}
		}
	};

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
	cs_close(&capstone_handle);
}

void
session::tracer_start()
{
	if (ptrace(PTRACE_ATTACH, child, NULL, NULL) < 0)
		throw exception(fmt::format("ptrace(ATTACH) failed: {}", strerror(errno)));

	if (int status; waitpid(child, &status, 0) != child)
		throw exception(fmt::format("waitpid({}): {}", child, strerror(errno)));

	if (ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD) < 0)
		throw exception(fmt::format("ptrace(SETOPTIONS) failed: {}", strerror(errno)));
	
	trace_status.store(1);

	// Parse maps
	memory.maps.parse(child);

	// Setup Dwfl context
	Dwfl_Callbacks callbacks = {
		.find_elf = dwfl_linux_proc_find_elf,
		.find_debuginfo = dwfl_standard_find_debuginfo,
	};
	dwfl_handle = dwfl_begin(&callbacks);

	if (dwfl_linux_proc_report(dwfl_handle, child) != 0)
		throw exception(fmt::format("dwfl_linux_proc_report failed: {}", strerror(errno)));

	if (dwfl_report_end(dwfl_handle, NULL, NULL) != 0)
		throw exception(fmt::format("dwfl_report_end failed: {}", strerror(errno)));

	tracer tracer{*this};
	tracer.trace();
}

void
session::child_start()
{
	child_session = (uintptr_t)this;
	stdout = memfd_create("child_stdout", 0);
	dup2(stdout, STDOUT_FILENO);
	stderr = memfd_create("child_stderr", 0);
	dup2(stderr, STDERR_FILENO);

	while (trace_status.load() != 1)
		std::this_thread::sleep_for(std::chrono::milliseconds{5});

	if (!(unit->flags & CTEST_DISABLE_PTRACE))
		ptrace(PTRACE_TRACEME);


	// Don't use printf as it calls to malloc()
	write(test_data.message_fd, " -- Begin Trace --\n", 19);
	if (!setjmp(jmp_exit))
	{
		unit->fn(&test_data);
	}
	test_data.in_function = 0;
	write(test_data.message_fd, " -- End Trace --\n", 17);
	std::_Exit(0);
}

bool
session::start()
{
	colors::intitialize(true);

	pid_t pid = fork();
	if (pid > 0) {
		child = pid;
		tracer_start();
		return true;
	} else {
		child_start();
	}
	std::unreachable();
}
