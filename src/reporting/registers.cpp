#include "../colors.hpp"
#include "../exceptions.hpp"
#include "report.hpp"
#include <array>
#include <fmt/ranges.h>
#include <iostream>
#include <ranges>

void
ctest::report::registers(const struct user_regs_struct& regs)
{
	const int width = 18;
	auto pair = [&](std::string_view a_name,
	                uintptr_t a,
	                std::string_view b_name,
	                uintptr_t b) {
		return format(
		  "{c_green}{0}{c_reset}={1: <{4}x}{c_green}{2}{c_reset}={3: <{4}x}{c_reset}\n"sv,
		  a_name,
		  a,
		  b_name,
		  b,
		  width);
	};

	std::cerr << pair("RAX", regs.rax, "R8 ", regs.r8)
	          << pair("RBX", regs.rbx, "R9 ", regs.r9)
	          << pair("RCX", regs.rcx, "R10", regs.r10)
	          << pair("RDX", regs.rdx, "R11", regs.r11)
	          << pair("RSI", regs.rsi, "R12", regs.r12)
	          << pair("RDI", regs.rdi, "R13", regs.r13)
	          << pair("RBP", regs.rbp, "R14", regs.r14)
	          << pair("RSP", regs.rsp, "R15", regs.r15)
	          << pair("FS ", regs.fs_base, "GS ", regs.gs_base)
	          << format("{c_green}RIP{c_reset}={0: "
	                    "<{1}x}\n",
	                    regs.rip,
	                    width);

	// Get eflags
	static const std::array<std::string_view, 32> eflags = {
		"CF", "1",  "PF", "AF",       "ZF",       "SF", "TF",
		"IF", "DF", "OF", "IOPL(12)", "IOPL(13)", "NT", "MD",
		"RF", "VM", "AC", "VIF",      "VIP",      "ID", "AI"
	};
	std::vector<std::string_view> flags;
	for (const auto i : std::ranges::iota_view{ size_t{}, eflags.size() }) {
		if (regs.eflags & (1 << i))
			flags.push_back(eflags[i]);
	}
	std::cerr << format(
	  "{c_green}EF{c_reset}={0:x} {c_yellow}[ {1} ]{c_reset}\n"sv,
	  regs.eflags,
	  fmt::join(flags, " "));
}
