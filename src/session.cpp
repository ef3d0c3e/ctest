#include "session.hpp"
#include "exceptions.hpp"

using namespace ctest;

session::session()
{
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &capstone_handle) == CS_ERR_OK)
		throw exception("Failed to initialize capstone");
	cs_option(capstone_handle, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(capstone_handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
}

session::~session() {}
