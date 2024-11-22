#include "maps.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>

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
	char pathbuf[256];
	snprintf(pathbuf, sizeof(pathbuf), "/proc/%d/maps", pid);
	FILE* f = fopen(pathbuf, "ro");
	if (!f) {
		perror("fopen(/proc/PID/maps)");
		exit(1);
	}

	char* line = NULL;
	size_t sz = 0;
	ssize_t read;
	while ((read = getline(&line, &sz, f)) != -1) {
		entry ent = entry{};

		char* it = line;
		it = parse_hex16(it, &ent.start);
		if (*(it++) != '-') {
			fprintf(stderr,
			        "Invalid /proc/%d/maps: Missing separating '-' between "
			        "start and end address.\n",
			        pid);
			break;
		}
		it = parse_hex16(it, &ent.end);
		if (*(it++) != ' ') {

			fprintf(stderr,
			        "Invalid /proc/%d/maps: Missing separating ' ' between "
			        "end address and access flags.\n",
			        pid);
			break;
		}
		if (!(it = parse_access(it, &ent.access_flags))) {
			fprintf(
			  stderr, "Invalid /proc/%d/maps: Invalid access flags\n", pid);
			break;
		}
		if (*(it++) != ' ') {
			fprintf(stderr,
			        "Invalid /proc/%d/maps: Missing separating ' ' between "
			        "access flags and offset.\n",
			        pid);
			break;
		}
		it = parse_hex16(it, &ent.offset);
		if (*(it++) != ' ') {
			fprintf(stderr,
			        "Invalid /proc/%d/maps: Missing separating ' ' between "
			        "offset and device.\n",
			        pid);
			break;
		}
		// Skip device
		while (*it != ' ')
			++it;
		if (*(it++) != ' ') {
			fprintf(stderr,
			        "Invalid /proc/%d/maps: Missing separating ' ' between "
			        "device and inode.\n",
			        pid);
			break;
		}
		// Skip inode
		while (*it != ' ')
			++it;
		// Skip to name
		while (*it != '\n' && *it == ' ')
			++it;
		size_t it_len = strlen(it);
		ent.pathname = new char[it_len];
		std::memcpy(ent.pathname, it, it_len - 1);
		ent.pathname[it_len - 1] = 0;
	}
	if (line)
		free(line);

	fclose(f);
}
