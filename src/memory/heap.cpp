#include "heap.hpp"
#include "../exceptions.hpp"
#include <fmt/format.h>

using namespace ctest::mem;

void
heap::insert(heap_block&& block)
{
	auto it = blocks.lower_bound(range{ block.address, block.address });
	if ((it != blocks.end() && it->first.start <= block.address + block.size &&
	     it->second.free_pc != 0) ||
	    (it != blocks.begin() && (--it)->first.end <= block.address &&
	     it->second.free_pc != 0))
		throw exception(
		  fmt::format(fmt::runtime("Overlapping heap blocks. Previous block: "
		                           "[{:p}-{:p}] New block: [{:p}-{:p}]"),
		              it->first.start,
		              it->first.end,
		              block.address,
		              block.address + block.size));
	blocks.insert(
	  { range{ block.address, block.address + block.size }, std::move(block) });
}

std::optional<std::reference_wrapper<heap_block>>
heap::get(uintptr_t address)
{
	auto it = blocks.lower_bound(range{ address, address });
	if (it != blocks.begin() && (--it)->first.end <= address)
		return { it->second };
	return {};
}
