#include "../colors.hpp"
#include "../session.hpp"
#include "report.hpp"
#include <iostream>
#include <ranges>
#include <sys/ptrace.h>
#include <sys/reg.h>

using namespace ctest;

void
ctest::report::info_message(const session& session,
                             const user_regs_struct& regs,
                             std::string what)
{
	// Heading
	std::cerr << format(" {c_red}--[ CTest test {0}#{1} information ]--{c_reset}\n",
	                    session.unit->file,
	                    session.unit->id);

	// Print registers
	std::cerr << format(" {c_blue}* Register dump:{c_reset}\n");
	registers(regs);

	// Print opcodes
	const size_t code_size = 15;
	uint8_t code[code_size];

	unsigned long addr = ptrace(PTRACE_PEEKUSER, session.child, 8 * RIP, 0);
	for (const auto i : std::ranges::iota_view{ std::size_t{}, code_size })
		code[i] = ptrace(PTRACE_PEEKTEXT, session.child, addr + i, 0) & 0xff;

	std::cerr << format(" {c_blue}* ASM dump:{c_reset}\n");
	cs_insn* insn;
	const std::size_t count =
	  cs_disasm(session.capstone_handle, code, code_size, regs.rip, 0, &insn);
	if (count <= 0) {
		std::cerr << format(
		  "{c_italic}<Failed to produce disassembly>{c_reset}\n");
		return;
	}
	for (const auto i : std::ranges::iota_view{ std::size_t{}, count }) {
		if (i == 0)
			std::cerr << format(
			  "{c_green}{0:x}{c_reset}: {c_red}{1} {2}{c_reset} <--\n",
			  insn[i].address,
			  insn[i].mnemonic,
			  insn[i].op_str);
		else
			std::cerr << format(
			  "{c_green}{0:x}{c_reset}: {1} {2}\n",
			  insn[i].address,
			  insn[i].mnemonic,
			  insn[i].op_str);
	}
	cs_free(insn, count);

	// Custom message:
	std::cerr << format("{c_blue}{c_bold}WHAT: {c_reset}{0}\n"sv, what);

	// Source line
	source_line(session, regs.rip);

	// Stacktrace
	std::cerr << format(" {c_blue}* Stacktrace: {c_reset}\n");
	stack_trace(session, regs.rip);
}
