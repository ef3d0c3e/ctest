#include "mem_maps.h"
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

static void
grow(struct ctest_maps* maps)
{
	if (!maps->data) {
		maps->data = malloc(sizeof(struct ctest_map_entry));
		maps->capacity = 1;
	} else {
		maps->capacity *= 2;
		maps->data = realloc(maps->data, maps->capacity * sizeof(struct ctest_map_entry));
	}
}

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
	if (it[3] == 's')
		*access |= CTEST_MAP_SHARED;
	else if (it[3] != 'p')
		return NULL;

	return it + 4;
}

struct ctest_maps
__ctest_mem_maps_parse(pid_t pid)
{
	char pathbuf[256];
	snprintf(pathbuf, sizeof(pathbuf), "/proc/%d/maps", pid);
	FILE *f = fopen(pathbuf, "ro");
	if (!f)
	{
		perror("fopen(/proc/PID/maps)");
		exit(1);
	}

	struct ctest_maps maps = {
		.data = NULL,
		.size = 0,
		.capacity = 0,
	};

	char *line = NULL;
	size_t sz = 0;
	ssize_t read;
	while ((read = getline(&line, &sz, f)) != -1)
	{
		if (maps.size >= maps.capacity)
			grow(&maps);
		struct ctest_map_entry *ent = &maps.data[maps.size++];

		char* it = line;
		it = parse_hex16(it, &ent->start);
		if (*(it++) != '-')
		{
			fprintf(stderr, "Invalid /proc/%d/maps: Missing separating '-' between start and end address.\n", pid);
			break;
		}
		it = parse_hex16(it, &ent->end);
		if (*(it++) != ' ')
		{

			fprintf(stderr, "Invalid /proc/%d/maps: Missing separating ' ' between end address and access flags.\n", pid);
			break;
		}
		if (!(it = parse_access(it, &ent->access_flags)))
		{
			fprintf(stderr, "Invalid /proc/%d/maps: Invalid access flags\n", pid);
			break;
		}
		if (*(it++) != ' ')
		{
			fprintf(stderr, "Invalid /proc/%d/maps: Missing separating ' ' between access flags and offset.\n", pid);
			break;
		}
		it = parse_hex16(it, &ent->offset);
		if (*(it++) != ' ')
		{
			fprintf(stderr, "Invalid /proc/%d/maps: Missing separating ' ' between offset and device.\n", pid);
			break;
		}
		// Skip device
		while (*it != ' ')
			++it;
		if (*(it++) != ' ')
		{
			fprintf(stderr, "Invalid /proc/%d/maps: Missing separating ' ' between device and inode.\n", pid);
			break;
		}
		// Skip inode
		while (*it != ' ')
			++it;
		// Skip to name
		while (*it != '\n' && *it == ' ')
			++it;
		size_t it_len = strlen(it);
		ent->pathname = malloc(it_len);
		memcpy(ent->pathname, it, it_len-1);
		ent->pathname[it_len-1] = 0;
	}
	if (line)
		free(line);

	fclose(f);
	return maps;
}

void __ctest_mem_maps_free(struct ctest_maps* maps)
{
	if (!maps->data)
		return;
	for (size_t i = 0; i < maps->size; ++i)
		free(maps->data[i].pathname);
	free(maps->data);
}

struct ctest_map_entry* __ctest_mem_maps_get(struct ctest_maps* maps, uintptr_t address)
{
	for (size_t i = 0; i < maps->size; ++i)
	{
		if (maps->data[i].start <= address && maps->data[i].end >= address)
			return &maps->data[i];
	}
	return NULL;
}
