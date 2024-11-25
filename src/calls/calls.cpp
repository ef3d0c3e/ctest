#include "calls.hpp"
#include "../session.hpp"
#include "../exceptions.hpp"
#include "fmt/format.h"
#include <iostream>

using namespace ctest::calls;

void* calls::malloc_hook(ctest::session& session)
{
	void* ptr = malloc(session.calls.msg_in.malloc.size);
	if (!ptr)
	{
		write(session.test_data.message_fd, "malloc() failed unexpectedly\n", 29);
		exit(1);
	}
	session.calls.msg_out.malloc.ptr = (uintptr_t)ptr;
	session.calls.in_hook = false;

	return ptr;
}

bool
calls::process_calls(ctest::session& session,
                     user_regs_struct& regs,
                     function_call&& call)
{
	if (call.resolved == (uintptr_t)malloc)
	{
		auto&& [size] = get_call_parameter(session.child, regs, malloc);
		msg_in.malloc.size = size;

		std::cerr << "CALL LENGT=" << std::hex << regs.rip+call.call_length << std::endl;
		make_call(session.child, regs, malloc_hook, call.call_length, session.child_session);
	}
	return true;
}

void calls::process_messages(ctest::session& session, const user_regs_struct& regs)
{
	// TODO
}
