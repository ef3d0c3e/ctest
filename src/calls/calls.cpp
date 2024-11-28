#include "calls.hpp"
#include "../colors.hpp"
#include "../reporting/report.hpp"
#include "../session.hpp"
#include <iostream>
#include <malloc.h>
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

void*
calls::calloc_hook(ctest::session& session)
{
	void* ptr = calloc(session.calls.msg_in.calloc.size, 1);
	if (!ptr) {
		write(
		  session.test_data.message_fd, "calloc() failed unexpectedly\n", 29);
		exit(1);
	}
	session.calls.msg_out.calloc.ptr = (uintptr_t)ptr;
	session.calls.in_hook = false;

	return ptr;
}

void
calls::free_hook(ctest::session& session)
{
	free((void*)session.calls.msg_in.free.ptr);
	session.calls.in_hook = false;
}

calls::calls()
{
	pc_hooks.insert((uintptr_t)malloc);
	pc_hooks.insert((uintptr_t)calloc);
	pc_hooks.insert((uintptr_t)free);
}

bool
calls::process_calls(ctest::session& session,
                     user_regs_struct& regs,
                     function_call&& call)
{
	if (call.resolved == (uintptr_t)malloc) {
		auto&& [size] = get_call_parameter(session.child, regs, malloc);
		msg_in.malloc.size = size;

		make_call(
		  session.child, regs, malloc_hook, call, session.child_session);
	} else if (call.resolved == (uintptr_t)calloc) {
		auto&& [size, nmemb] = get_call_parameter(session.child, regs, calloc);
		msg_in.malloc.size = size * nmemb;

		make_call(
		  session.child, regs, calloc_hook, call, session.child_session);
	} else if (call.resolved == (uintptr_t)free) {
		auto&& [ptr] = get_call_parameter(session.child, regs, free);
		const auto result = session.memory.heap.get((uintptr_t)ptr);
		/* Wrong free */
		if (!result.has_value()) {
			report::error_message(
			  session,
			  regs,
			  format("Free on unknown address: {c_blue}{:x}{c_reset}"sv,
			         msg_in.free.ptr));
			std::cerr << format(" {c_blue}-> Heap block:{c_reset}\n");
			return false;
		} else {
			auto& block = result.value().get();
			/* Double free */
			if (block.free_pc != 0) {
				report::error_message(
				  session, regs, format("Double free detected"sv));
				std::cerr << format(" {c_blue}-> Heap block:{c_reset}\n");
				report::allocation(session, block);
				return false;
			}
		}
		msg_in.free.ptr = (uintptr_t)ptr;

		make_call(session.child, regs, free_hook, call, session.child_session);
	}
	return true;
}

bool
calls::process_from_pc(ctest::session& session, user_regs_struct& regs)
{
	const auto it = pc_hooks.find(regs.rip);
	if (it != pc_hooks.cend())
		return process_calls(session,
		                     regs,
		                     function_call{
		                       .addr = regs.rip,
		                       .resolved = regs.rip,
		                       .call_length = 0,
		                       .inside = true,
		                     });
	return true;
}

bool
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
	} else if (current_hook == (uintptr_t)calloc_hook) {
		// Parse maps in case brk was called
		session.memory.maps.parse(session.child);

		session.memory.heap.insert(mem::heap_block{
		  .allocator = (uintptr_t)calloc,
		  .deallocator = 0,
		  .address = msg_out.calloc.ptr,
		  .size = msg_in.calloc.size,
		  .initialized = std::vector<bool>(msg_in.calloc.size, true),
		  .alloc_pc = pc_before_hook,
		  .free_pc = 0,
		});
	} else if (current_hook == (uintptr_t)free_hook) {
		// Parse maps in case brk was called
		session.memory.maps.parse(session.child);

		auto& block = session.memory.heap.get(msg_in.free.ptr).value().get();
		block.deallocator = (uintptr_t)free;
		block.free_pc = pc_before_hook;
	}
	return true;
}
