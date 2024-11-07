#include "tester.h"
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static int
starts_with(const char* s, const char* start)
{
	while (*start) {
		if (*s != *start)
			return (0);
		++s;
		++start;
	}
	return (1);
}

static void
iterate_tests(ElfW(Ehdr) * ehdr, void* handle, struct ctest_data* data)
{
	ElfW(Shdr)* shdr = (ElfW(Shdr)*)((char*)ehdr + ehdr->e_shoff);
	char* shstrtab = (char*)ehdr + shdr[ehdr->e_shstrndx].sh_offset;

	char* strtab = NULL;
	for (int i = 0; i < ehdr->e_shnum; i++) {
		if (shdr[i].sh_type & SHT_SYMTAB && strcmp(shstrtab + shdr[i].sh_name, ".strtab") == 0) {
			strtab = (char*)ehdr + shdr[i].sh_offset;
		}
	}
	if (!strtab) {
		fprintf(stderr, "Failed to locate .strtab\n");
		return;
	}

	for (int i = 0; i < ehdr->e_shnum; i++) {
		if (!(shdr[i].sh_type & SHT_SYMTAB) || strcmp(shstrtab + shdr[i].sh_name, ".symtab") != 0)
			continue;

		ElfW(Sym)* sym = (ElfW(Sym)*)((char*)ehdr + shdr[i].sh_offset);
		for (ElfW(Word) j = 0; j < shdr[i].sh_size / sizeof(ElfW(Sym)); ++j) {
			if (!(sym[j].st_info & STT_OBJECT) ||
			    !starts_with(strtab + sym[j].st_name, "__ctest_unit_"))
				continue;
			struct ctest_unit* unit = dlsym(handle, strtab + sym[j].st_name);
			if (!unit) {
				fprintf(stderr,
				        "Failed to locate symbol '%s': %s\n",
				        strtab + sym[j].st_name,
				        dlerror());
				continue;
			}
			run_test(data, unit);
		}
	}
}

int
main(int argc, char** argv)
{
	if (argc <= 1) {
		fprintf(stderr, "Usage: %s <executable> [filter]", argv[0]);
		exit(1);
	}

	const int fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		const int errsv = errno;
		fprintf(stderr, "Failed to open executable: `%s`: %s\n", argv[1], strerror(errsv));
		exit(1);
	}

	struct stat sb;
	if (fstat(fd, &sb) == -1) {
		const int errsv = errno;
		close(fd);
		fprintf(stderr, "Failed to open stat executable: `%s`: %s\n", argv[1], strerror(errsv));
		exit(1);
	}

	void* map = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED) {
		const int errsv = errno;
		close(fd);
		fprintf(stderr, "Failed to mmap executable: `%s`: %s\n", argv[1], strerror(errsv));
		exit(1);
	}
	void* handle = dlopen(argv[1], RTLD_NOW);
	if (!handle) {
		munmap(map, sb.st_size);
		close(fd);
		fprintf(stderr, "Failed to dlopen() executable: `%s`: %s\n", argv[1], dlerror());
		exit(1);
	}

	struct ctest_data data = {
		.filter = (argc >= 3) ? argv[2] : NULL,
		.successes = 0,
		.failures = 0,
	};
	iterate_tests(map, handle, &data);

	munmap(map, sb.st_size);
	close(fd);
	return 0;
}
