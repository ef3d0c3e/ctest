#include "memory_maps.h"
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

static char* parse_hex16(char *it, uintptr_t *value)
{
	*value = 0;
	while ((*it >= '0' && *it <= '9') || (*it >= 'a' && *it <= 'f'))
	{
		*value = *value * 16 + (*it - (*it < 'a' ? '0' : 'a'-10));
		++it;
	}
	return it;
}

static char* parse_access(char *it, enum ctest_map_access* access)
{
	if (it[0] == 'r')
		*access |= CTEST_MAP_READ;
	else if (it[0] != '-')
		return NULL;
	if (it[1] == 'w')
		*access |= CTEST_MAP_WRITE;
	else if (it[1] != '-')
		return NULL;
	if (it[2] == 'x')
		*access |= CTEST_MAP_EXECUTE;
	else if (it[2] != '-')
		return NULL;
	if (it[3] == 'p')
		*access |= CTEST_MAP_PRESENT;
	else if (it[3] != '-')
		return NULL;

	return it + 4;
}

static char* skip_spaces(char *it)
{
	while (*it == ' ')
		++it;
	return it;
}

struct ctest_map_entry* __ctest_mem_maps_parse(pid_t pid)
{
	char pathbuf[256];
	snprintf(pathbuf, sizeof(pathbuf), "/proc/%d/maps", pid);
	FILE *f = fopen(pathbuf, "ro");
	if (!f)
	{
		perror("fopen(/proc/PID/maps)");
		exit(1);
	}

	char *line = NULL;
	size_t sz = 0;
	ssize_t read;
	while ((read = getline(&line, &sz, f)))
	{
		struct ctest_map_entry ent;
		char* it = line;
		it = parse_hex16(it, &ent.start);
		if (*(it++) != '-')
		{
			fprintf(stderr, "Invalid /proc/%d/maps: Missing separating '-' between start and end address.\n", pid);
			break;
		}
		it = parse_hex16(it, &ent.end);
		if (*(it++) != ' ')
		{
			fprintf(stderr, "Invalid /proc/%d/maps: Missing separating ' ' between end address and access flags.\n", pid);
			break;
		}
		if (!(it = parse_access(it, &ent.access_flags)))
		{
			fprintf(stderr, "Invalid /proc/%d/maps: Invalid access flags\n", pid);
			break;
		}
		if (*(it++) != ' ')
		{
			fprintf(stderr, "Invalid /proc/%d/maps: Missing separating ' ' between end access flags and offset.\n", pid);
			break;
		}
		it = parse_hex16(it, &ent.offset);
		if (*(it++) != ' ')
		{
			fprintf(stderr, "Invalid /proc/%d/maps: Missing separating ' ' between end access flags and device.\n", pid);
			break;
		}
		// Skip device
		while (*it != ' ')
			++it;
		// Skip inode
		while (*it != ' ')
			++it;
		// Skip to name
		while (*it && *it != ' ')
			++it;
		ent.pathname = malloc(line-it + read);
		memcpy(ent.pathname, it, line-it - 1 + read);
		ent.pathname[line-it - 1] = 0;
	}
	if (line)
		free(line);
	
	fclose(f);
	// TODO
}
