cmake_minimum_required(VERSION 3.1)

project(ctest
	LANGUAGES CXX
	VERSION 1.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++20 -Wall -Wextra -pedantic -rdynamic -g3")

file(GLOB_RECURSE SOURCES "src/*.cpp")
add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME}
	capstone
	dw
	elf
	unwind-ptrace
	unwind-generic
	unwind)


