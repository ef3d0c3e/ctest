#include "calls.hpp"
#include "../exceptions.hpp"
#include "../session.hpp"
#include "fmt/format.h"
#include <iostream>
#include <unistd.h>

using namespace ctest::calls;

void*
calls::malloc_hook(ctest::session& session)
{
	void* ptr = malloc(session.calls.msg_in.malloc.size);
	if (!ptr) {
		write(
		  session.test_data.message_fd, "malloc() failed unexpectedly\n", 29);
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
	if (call.resolved == (uintptr_t)malloc) {
		auto&& [size] = get_call_parameter(session.child, regs, malloc);
		msg_in.malloc.size = size;

		make_call(session.child,
		          regs,
		          malloc_hook,
		          call.call_length,
		          session.child_session);
	}
	return true;
}

void
calls::process_messages(ctest::session& session, const user_regs_struct& regs)
{
	if (current_hook == (uintptr_t)malloc_hook) {
		// Parse maps in case brk was called
		session.memory.maps.parse(session.child);

		session.memory.heap.insert(mem::heap_block{
		  .allocator = (uintptr_t)malloc,
		  .deallocator = 0,
		  .address = msg_out.malloc.ptr,
		  .size = msg_in.malloc.size,
		  .initialized = std::vector<bool>(msg_in.malloc.size, false),
		  .alloc_pc = pc_before_hook,
		  .free_pc = 0,
		});
	}
}
