#include "maps.hpp"
#include "../exceptions.hpp"
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fmt/format.h>
#include <iostream>
#include <string>

using namespace ctest::mem;

void
maps::parse(pid_t pid)
{
	auto parse_hex16 = [](char* it, uintptr_t* value) -> char* {
		*value = 0;
		while ((*it >= '0' && *it <= '9') || (*it >= 'a' && *it <= 'f')) {
			*value = *value * 16 + (*it - (*it < 'a' ? '0' : 'a' - 10));
			++it;
		}
		return it;
	};

	auto parse_access = [](char* it, enum access* access) -> char* {
		if (it[0] == 'r')
			*(uint8_t*)access |= (uint8_t)access::READ;
		else if (it[0] != '-')
			return NULL;
		if (it[1] == 'w')
			*(uint8_t*)access |= (uint8_t)access::WRITE;
		else if (it[1] != '-')
			return NULL;
		if (it[2] == 'x')
			*(uint8_t*)access |= (uint8_t)access::EXECUTE;
		else if (it[2] != '-')
			return NULL;
		if (it[3] == 's')
			*(uint8_t*)access |= (uint8_t)access::SHARED;
		else if (it[3] != 'p')
			return NULL;

		return it + 4;
	};

	entries.clear();
	FILE* f = fopen(fmt::format("/proc/{}/maps", pid).c_str(), "ro");
	if (!f)
		throw exception(
		  fmt::format("fopen(\"/proc/{}/maps\"): {}", pid, strerror(errno)));

	char* line = NULL;
	size_t sz = 0;
	ssize_t read;
	while ((read = getline(&line, &sz, f)) != -1) {
		map_entry ent = map_entry{};

		char* it = line;
		it = parse_hex16(it, &ent.start);
		if (*(it++) != '-')
			throw exception(
			  fmt::format("Invalid /proc/{}/maps: Missing separating '-' "
			              "between start and end address.",
			              pid));
		it = parse_hex16(it, &ent.end);
		if (*(it++) != ' ')
			throw exception(fmt::format(
			  "Invalid /proc/{}/maps: Missing separating ' ' between "
			  "end address and access flags.",
			  pid));

		if (!(it = parse_access(it, &ent.access_flags)))
			throw exception(
			  fmt::format("Invalid /proc/{}/maps: Invalid access flags", pid));
		if (*(it++) != ' ')
			throw exception(fmt::format(
			  "Invalid /proc/{}/maps: Missing separating ' ' between "
			  "access flags and offset.",
			  pid));
		it = parse_hex16(it, &ent.offset);
		if (*(it++) != ' ') {
			throw exception(fmt::format(
			  "Invalid /proc/{}/maps: Missing separating ' ' between "
			  "offset and device.",
			  pid));
			break;
		}
		// Skip device
		while (*it != ' ')
			++it;
		if (*(it++) != ' ')
			throw exception(fmt::format(
			  "Invalid /proc/{}/maps: Missing separating ' ' between "
			  "device and inode.",
			  pid));
		// Skip inode
		while (*it != ' ')
			++it;
		// Skip to name
		while (*it != '\n' && *it == ' ')
			++it;
		size_t it_len = strlen(it);
		ent.pathname = std::string(it, it + it_len - 1);

		entries.insert({ range{ ent.start, ent.end }, std::move(ent) });
	}
	if (line)
		free(line);

	fclose(f);
}

std::optional<std::reference_wrapper<map_entry>>
maps::get(uintptr_t address)
{
	// FIXME: This is not right...
	auto it = entries.lower_bound(range{ address, address });
	if (it == entries.begin() || --it == entries.begin())
		return {};
	if ((--it)->first.end <= address)
		return { it->second };
	return {};
}
