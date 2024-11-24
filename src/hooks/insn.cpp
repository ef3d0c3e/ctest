#include "insn.hpp"
#include "../exceptions.hpp"
#include "../session.hpp"
#include "fmt/format.h"
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <cstring>
#include <iostream>
#include <ranges>
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
			throw ctest::exception(
			  fmt::format("Unhandled register: {0}", (int)reg));
	}
}

std::vector<ctest::mem::mem_access>
ctest::hooks::get_memory_access(const user_regs_struct& regs,
                                const cs_insn* insn)
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
	for (const auto i : std::ranges::iota_view{
	       std::uint8_t{}, insn[0].detail->x86.op_count }) {
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

/* Get the PLT range for a module */
static std::pair<uintptr_t, size_t>
get_plt_range(Dwfl_Module* mod)
{
	Dwarf_Addr bias;
	Elf* elf = dwfl_module_getelf(mod, &bias);
	if (!elf)
		throw ctest::exception("Failed to get ELF handle for module");

	size_t shstrndx;
	if (elf_getshdrstrndx(elf, &shstrndx) < 0)
		throw ctest::exception(
		  "Failed to get section header string table index");

	Elf_Scn* scn = nullptr;
	while ((scn = elf_nextscn(elf, scn)) != nullptr) {
		GElf_Shdr shdr;
		if (gelf_getshdr(scn, &shdr) == nullptr) {
			continue;
		}

		const char* name = elf_strptr(elf, shstrndx, shdr.sh_name);
		if (name && std::string_view{ name } == ".plt") {
			return { shdr.sh_addr + bias, shdr.sh_size };
		}
	}

	throw ctest::exception("PLT section not found");
}

/* Find the GOT entry for a module */
static uintptr_t
find_got_entry(Dwfl_Module* mod, uintptr_t plt_addr)
{
	Dwarf_Addr bias;
	Elf* elf = dwfl_module_getelf(mod, &bias);
	if (!elf)
		throw ctest::exception("Failed to get ELF handle");

	// Get rela.plt section
	Elf_Scn* rela_plt = nullptr;
	while ((rela_plt = elf_nextscn(elf, rela_plt)) != nullptr) {
		GElf_Shdr rela_shdr;
		if (gelf_getshdr(rela_plt, &rela_shdr) == nullptr)
			continue;

		size_t shstrndx;
		if (elf_getshdrstrndx(elf, &shstrndx) < 0)
			continue;

		const char* name = elf_strptr(elf, shstrndx, rela_shdr.sh_name);
		if (!name || strcmp(name, ".rela.plt") != 0)
			continue;

		// Found .rela.plt - now find the matching entry
		Elf_Data* data = elf_getdata(rela_plt, nullptr);
		if (!data)
			throw ctest::exception("Failed to get .rela.plt data");

		for (const auto i : std::ranges::iota_view{
		       std::size_t{}, rela_shdr.sh_size / sizeof(GElf_Rela) }) {
			GElf_Rela rela;
			if (gelf_getrela(data, i, &rela) == nullptr)
				continue;

			// Check if this relocation corresponds to our PLT entry
			if (rela.r_offset > plt_addr - bias)
				return rela.r_offset +
				       bias; // Return GOT entry address with bias applied
		}
	}

	throw ctest::exception("GOT entry not found");
}

/* Resolve call address */
static uintptr_t
resolve_calls(const ctest::session& session, uintptr_t called_address)
{
	Dwfl_Module* mod = dwfl_addrmodule(session.dwfl_handle, called_address);
	if (!mod)
		throw ctest::exception(
		  fmt::format("Call in unknown module: {:x}", called_address));

	// Return if not in PLT
	auto [plt_start, plt_size] = get_plt_range(mod);
	if (called_address < plt_start || called_address >= plt_start + plt_size)
		return called_address;

	// Find corresponding GOT entry
	uintptr_t got_addr = find_got_entry(mod, called_address);

	errno = 0;
	const long got_content =
	  ptrace(PTRACE_PEEKDATA, session.child, (void*)got_addr, nullptr);
	if (errno != 0)
		throw ctest::exception(fmt::format(
		  "Failed to read GOT entry for address={0:x}, got_entry={1:x}: {2}",
		  called_address,
		  got_addr,
		  strerror(errno)));

	return (uintptr_t)got_content;
}

std::vector<ctest::calls::function_call>
ctest::hooks::get_function_calls(const session& session,
                                 const user_regs_struct& regs,
                                 const cs_insn* insn)
{
	// TODO...
	auto effective_address =
	  [](const cs_x86_op& op,
	     const struct user_regs_struct& regs) -> uintptr_t {
		if (op.type == X86_OP_IMM) {
			return op.imm;
		}

		// Check for indirect CALL via register
		else if (op.type == X86_OP_REG) {
			return get_register_value(op.reg, regs);
		}

		// Check for indirect CALL via memory
		else if (op.type == X86_OP_MEM) {
			uintptr_t base_val = 0;
			uintptr_t index_val = 0;
			uintptr_t segment_base = 0;

			// Handle the base register if available
			if (op.mem.base != X86_REG_INVALID) {
				base_val = get_register_value(op.mem.base, regs);
			}

			// Handle the index register if available
			if (op.mem.index != X86_REG_INVALID) {
				index_val =
				  get_register_value(op.mem.index, regs) * op.mem.scale;
			}

			// Handle the segment register if it's FS or GS
			if (op.mem.segment == X86_REG_FS) {
				segment_base = regs.fs_base;
			} else if (op.mem.segment == X86_REG_GS) {
				segment_base = regs.gs_base;
			}

			// Calculate the effective address for indirect CALL
			return segment_base + base_val + index_val + op.mem.disp;
		}

		throw exception(fmt::format("Unsupported call operands "));
	};

	bool is_call = false;
	for (const auto i : std::ranges::iota_view{
	       std::uint8_t{}, insn[0].detail->groups_count }) {
		if (insn[0].detail->groups[i] != CS_GRP_CALL)
			continue;
		is_call = true;
		break;
	}
	if (!is_call)
		return {};
	std::vector<calls::function_call> calls;
	for (const auto i : std::ranges::iota_view{
	       std::uint8_t{}, insn[0].detail->x86.op_count }) {
		const cs_x86_op& op = (insn[0].detail->x86.operands[i]);
		calls::function_call call{
			.addr = effective_address(op, regs),
			.resolved = 0,
		};
		call.resolved = resolve_calls(session, call.addr);
		calls.push_back(std::move(call));
	}
	return calls;
}
