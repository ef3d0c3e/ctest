#include "exceptions.hpp"
#include "session.hpp"
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <exception>
#include <fcntl.h>
#include <format>
#include <iostream>
#include <link.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static void
iterate_tests(const ElfW(Ehdr) * ehdr, void* handle)
{
	ElfW(Shdr)* shdr = (ElfW(Shdr)*)((char*)ehdr + ehdr->e_shoff);
	char* shstrtab = (char*)ehdr + shdr[ehdr->e_shstrndx].sh_offset;

	char* strtab = NULL;
	for (int i = 0; i < ehdr->e_shnum; i++) {
		if (shdr[i].sh_type & SHT_SYMTAB && strcmp(shstrtab + shdr[i].sh_name, ".strtab") == 0) {
			strtab = (char*)ehdr + shdr[i].sh_offset;
		}
	}
	if (!strtab)
		throw ctest::exception("Failed to locate .strtab");

	for (int i = 0; i < ehdr->e_shnum; i++) {
		if (!(shdr[i].sh_type & SHT_SYMTAB) || strcmp(shstrtab + shdr[i].sh_name, ".symtab") != 0)
			continue;

		ElfW(Sym)* sym = (ElfW(Sym)*)((char*)ehdr + shdr[i].sh_offset);
		for (ElfW(Word) j = 0; j < shdr[i].sh_size / sizeof(ElfW(Sym)); ++j) {
			const char* name = strtab + sym[j].st_name;
			if (!(sym[j].st_info & STT_OBJECT) ||
			    !std::string_view(name).starts_with("__ctest_unit_"))
				continue;
			void* unit = dlsym(handle, name);
			if (!unit)
				throw ctest::exception(std::format("Failed to locale symbol '{}': {}", name, dlerror()));
			// run_test(data, unit);
		}
	}
}

int
main(int argc, char** argv)
{
	if (argc < 2) {
		std::cerr << "USAGE: " << argv[0] << " ./PATH.so" << std::endl;
		return EXIT_FAILURE;
	}

	try {
		// Open file
		const int fd = open(argv[1], O_RDONLY);
		if (fd < 0)
			throw ctest::exception(
			  std::format("Failed to open '{}': {}", argv[1], strerror(errno)));
		// Mmap
		struct stat sb;
		if (fstat(fd, &sb) == -1) {
			close(fd);
			throw ctest::exception(
			  std::format("Failed to stat '{}': {}", argv[1], strerror(errno)));
		}
		void* map = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
		if (map == (void*)-1) {
			close(fd);
			throw ctest::exception(
			  std::format("Failed to mmap '{}': {}", argv[1], strerror(errno)));
		}
		// Dlopen
		void* handle = dlopen(argv[1], RTLD_NOW);
		if (!handle) {
			close(fd);
			throw ctest::exception(std::format("Failed to dlopen '{}': {}", argv[1], dlerror()));
		}

		iterate_tests(reinterpret_cast<const ElfW(Ehdr)*>(map), handle);

		dlclose(handle);
		munmap(map, sb.st_size);
		close(fd);
	} catch (ctest::exception& e) {
		std::cerr << "-- CTest crashed --\nWHAT: " << e.what() << "\n"
		          << " * Stacktrace:\n"
		          << e.trace();
	} catch (std::exception& e) {
		std::cerr << "-- CTest crashed --\nWHAT: " << e.what() << std::endl;
	}
	return EXIT_SUCCESS;
}
