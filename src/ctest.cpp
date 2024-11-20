#include "exceptions.hpp"
#include "session.hpp"
#include <cstdlib>
#include <exception>
#include <iostream>

int
main(int argc, char** argv)
{
	if (argc < 2) {
		std::cerr << "USAGE: " << argv[0] << " ./PATH.so" << std::endl;
		return EXIT_FAILURE;
	}

	try {
		ctest::session();
	} catch (ctest::exception& e) {
		std::cerr << "-- CTest crashed --\nWHAT: " << e.what() << "\n"
		          << " * Stacktrace:\n"
		          << e.trace();
	} catch (std::exception& e) {
		std::cerr << "-- CTest crashed --\nWHAT: " << e.what() << std::endl;
	}
	return EXIT_SUCCESS;
}
