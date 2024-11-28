#include "syscalls.hpp"
#include "../session.hpp"
#include <asm/unistd_64.h>
#include <unistd.h>

using namespace ctest::calls;

ssize_t
syscalls::read_hook(ctest::session& session)
{
	session.syscalls.msg_out.read.nread = read(session.syscalls.msg_in.read.fd, (void*)session.syscalls.msg_in.read.buffer, session.syscalls.msg_in.read.count);
	session.syscalls.in_hook = false;
	return session.syscalls.msg_out.read.nread;
}

[[nodiscard]] bool
syscalls::process_syscalls(ctest::session& session,
                           user_regs_struct& regs,
                           system_call&& call)
{
	switch (call.id) {
		case __NR_read: {
			auto&& [fd, buffer, count] = get_syscall_parameter(regs, read);
			msg_in.read.fd = fd;
			msg_in.read.buffer = (uintptr_t)buffer;
			msg_in.read.count = count;
			syscall_detour(session.child, regs, read_hook, session.child_session);
			break;
		}
		default:
			break;
	}

	return true;
}

bool
syscalls::process_messages(ctest::session& session, user_regs_struct& regs)
{
	if (current_hook == (uintptr_t)read_hook) {
		// Mark as read
	}

	// Restore rdi
	regs.rdi = saved_rdi;
	return true;
}
