#include "tracer.hpp"
#include "exceptions.hpp"
#include "reporting/report.hpp"
#include "session.hpp"
#include <csignal>
#include <cstdlib>
#include <fmt/format.h>
#include <iostream>
#include <sys/ptrace.h>
#include <sys/wait.h>

using namespace ctest;

tracer::tracer(ctest::session& session)
  : session{ session }
{
}

bool
tracer::handle_sigsegv()
{
	static auto recover = +[](tracer& tracer){
		if (tracer.session.test_data.sigstatus.recover)
			siglongjmp(tracer.session.test_data.sigstatus.recovery_point, 1);
		else
			siglongjmp(tracer.session.jmp_exit, 1);
	};

	if (!session.test_data.sigstatus.recover)
	{
		// TODO: error
	}

	struct user_regs_struct regs;
	if (ptrace(PTRACE_GETREGS, session.child, 0, &regs) < 0)
		throw exception(
		  fmt::format("ptrace(GETREGS) failed: {0}", strerror(errno)));

	session.test_data.sigstatus.signum = SIGSEGV;
	regs.rip = (uintptr_t)recover;
	regs.rdi = session.child_session;

	// Set the modified registers
	if (ptrace(PTRACE_SETREGS, session.child, NULL, regs) < 0)
		throw exception(
		  fmt::format("ptrace(SETREGS) failed: {0}", strerror(errno)));

	return session.test_data.sigstatus.recover;
}

void
tracer::trace()
{
	while (true) {
		if (ptrace(PTRACE_SINGLESTEP, session.child, 0, 0) < 0)
			throw exception(
			  fmt::format("ptrace(SINGLESTEP) failed: {0}", strerror(errno)));
		if (int status; waitpid(session.child, &status, 0) != session.child)
			throw exception(fmt::format(
			  "waitpid({}) failed: {}", session.child, strerror(errno)));
		// Process signals
		else if (const int code = WIFEXITED(status); code) {
			std::cerr << fmt::format("Child process exited with code: {0}", code)
			          << std::endl;
			break;
		} else if (const int code = WIFSIGNALED(status); code) {
			std::cerr << fmt::format("Child process exited with signal: {0}",
			                         code)
			          << std::endl;
			break;
		}
		// Handle signals from child
		else if (const int signal = WSTOPSIG(status); WIFSTOPPED(status)) {
			if (signal == SIGSEGV && !handle_sigsegv()) {
				break;
			} else if (signal != SIGTRAP) {
				std::cerr << fmt::format("Child sent signal {0}, exiting",
				                         signal)
				          << std::endl;
				break;
			}
		}

		if (!session.test_data.in_function)
			continue;

		struct user_regs_struct regs;
		if (ptrace(PTRACE_GETREGS, session.child, 0, &regs) < 0)
			throw exception(
					fmt::format("ptrace(GETREGS) failed: {0}", strerror(errno)));
		//report::stack_trace(session, regs.rip);
		//std::cerr << "\n---\n";
		// TODO...
	}
}
