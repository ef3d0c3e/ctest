#include "insn.hpp"
#include "../exceptions.hpp"
#include "../session.hpp"
#include "fmt/format.h"
#include <capstone/capstone.h>
#include <cstring>
#include <sys/ptrace.h>

using namespace ctest::hooks;

void
insn::add(insn_hook_t&& hook)
{
	hooks.push_back(std::move(hook));
}

bool
insn::process(session& session, const user_regs_struct& regs) const
{
	auto read_bytes =
	  [](pid_t pid, uintptr_t address, uint8_t* buffer, size_t length) {
		  for (std::size_t i = 0; i < length; i += sizeof(long)) {
			  errno = 0;
			  const long word = ptrace(PTRACE_PEEKTEXT, pid, address + i, NULL);
			  if (errno != 0)
				  throw exception(fmt::format("ptrace(PEEKTEXT) failed: {0}",
				                              strerror(errno)));

			  // Copy the bytes into the buffer, handling partial reads at the
			  // end
			  size_t copy_length =
			    (i + sizeof(long) > length) ? (length - i) : sizeof(long);
			  memcpy(buffer + i, &word, copy_length);
		  }
	  };
	const static size_t MAX_INSN_LEN = 15; // Maximum length for x86_64
	uint8_t code[MAX_INSN_LEN];
	read_bytes(session.child, regs.rip, code, MAX_INSN_LEN);

	cs_insn* insn;
	size_t count = cs_disasm(
	  session.capstone_handle, code, MAX_INSN_LEN, regs.rip, 0, &insn);
	if (count <= 0)
		throw exception(
		  fmt::format("Failed to decode instructions at {0:x}", regs.rip));

	for (const auto& hook : hooks) {
		if (!hook(session, regs, insn)) {
			cs_free(insn, count);
			return false;
		}
	}
	cs_free(insn, count);
	return true;
}

static uintptr_t
get_register_value(x86_reg reg, const struct user_regs_struct& regs)
{
	switch (reg) {
		case X86_REG_RAX:
			return regs.rax;
		case X86_REG_RBX:
			return regs.rbx;
		case X86_REG_RCX:
			return regs.rcx;
		case X86_REG_RDX:
			return regs.rdx;
		case X86_REG_RSI:
			return regs.rsi;
		case X86_REG_RDI:
			return regs.rdi;
		case X86_REG_RBP:
			return regs.rbp;
		case X86_REG_RSP:
			return regs.rsp;
		case X86_REG_R8:
			return regs.r8;
		case X86_REG_R9:
			return regs.r9;
		case X86_REG_R10:
			return regs.r10;
		case X86_REG_R11:
			return regs.r11;
		case X86_REG_R12:
			return regs.r12;
		case X86_REG_R13:
			return regs.r13;
		case X86_REG_R14:
			return regs.r14;
		case X86_REG_R15:
			return regs.r15;
		case X86_REG_RIP:
			return regs.rip;
		default:
			throw ctest::exception(fmt::format("Unhandled register: {0}", (int)reg));
	}
}

std::vector<ctest::mem::mem_access>
ctest::hooks::get_memory_access(const user_regs_struct& regs, const cs_insn* insn)
{
	/* Calculates effective address */
	auto effective_address = [](const cs_x86_op& op,
	                            const struct user_regs_struct& regs) {
		// Get base register if available
		uintptr_t base = 0;
		if (op.mem.base != X86_REG_INVALID) {
			base = get_register_value(op.mem.base, regs);
		}

		uintptr_t index = 0;
		// Get index register and apply scale if available
		if (op.mem.index != X86_REG_INVALID) {
			index = get_register_value(op.mem.index, regs) * op.mem.scale;
		}

		// Add displacement
		uintptr_t displacement = op.mem.disp;

		// Handle segment base if segment register is used
		uintptr_t segment = 0;
		if (op.mem.segment == X86_REG_FS) {
			segment = regs.fs_base;
		} else if (op.mem.segment == X86_REG_GS) {
			segment = regs.gs_base;
		}

		return base + index + displacement + segment;
	};

	// For stuff like nop dword ptr [rax, rax]
	if (insn[0].id == X86_INS_NOP)
		return {};
	// Capstone treats LEA as reads
	else if (insn[0].id == X86_INS_LEA)
		return {};
	std::vector<mem::mem_access> access;
	for (uint8_t i = 0; i < insn[0].detail->x86.op_count; ++i) {
		const cs_x86_op& op = (insn[0].detail->x86.operands[i]);
		if (op.type != X86_OP_MEM)
			continue;

		access.push_back({
		  .address = effective_address(op, regs),
		  .size = op.size,
		  .access = (mem::access_type)(
		    (op.access & CS_AC_READ ? (int)mem::access_type::READ : 0) |
		    (op.access & CS_AC_WRITE ? (int)mem::access_type::WRITE : 0)),
		});
	}
	return access;
}
