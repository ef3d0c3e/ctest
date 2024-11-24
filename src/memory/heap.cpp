#include "heap.hpp"
#include "../exceptions.hpp"
#include <fmt/format.h>
#include <string_view>
#include <sys/mman.h>

using namespace ctest::mem;

std::string_view heap_block::allocated_by() const
{
	if (allocator == (uintptr_t)malloc)
		return std::string_view{"malloc"};
	else if (allocator == (uintptr_t)realloc)
		return std::string_view{"realloc"};
	else if (allocator == (uintptr_t)mmap)
		return std::string_view{"mmap"};
	else if (allocator == (uintptr_t)mremap)
		return std::string_view{"mmap"};
	else
		throw exception(fmt::format("Unknown allocator: {0}", allocator));
}

std::string_view heap_block::deallocated_by() const
{
	if (deallocator == (uintptr_t)free)
		return std::string_view{"free"};
	else if (deallocator == (uintptr_t)munmap)
		return std::string_view{"munmap"};
	else
		throw exception(fmt::format("Unknown deallocator: {0}", deallocator));
}

void
heap::insert(heap_block&& block)
{
	auto it = blocks.lower_bound(block.address);
	if ((it != blocks.end() && it->second.address <= block.address &&
	     it->second.free_pc != 0) ||
	    (it != blocks.begin() &&
	     (--it)->second.address + it->second.size >= block.address &&
	     it->second.free_pc != 0))
		throw exception(
		  fmt::format(fmt::runtime("Overlapping heap blocks. Previous block: "
		                           "[{:p}-{:p}] New block: [{:p}-{:p}]"),
		              it->second.address,
		              it->second.address + it->second.size,
		              block.address,
		              block.address + block.size));
	blocks.insert({ block.address, std::move(block) });
}

std::variant<heap::range_result_ok,
             heap::range_result_unbounded,
             heap::range_result_unknown>
heap::get_range(const range& r)
{
	auto it = blocks.lower_bound(r.start);

	if (it == blocks.end()) {
		if (it == blocks.begin())
			return range_result_unknown{ {}, {} };
		else
			return range_result_unknown{ {}, (--it)->second };
	}

	if (it->second.address == r.start) {
		if (it->second.address + it->second.size > r.end)
			return range_result_ok{ it->second };
		else
			return range_result_unbounded{
				it->second, it->second.address + it->second.size - r.end, 0
			};
	} else if (it == blocks.begin())
		return range_result_unknown{ it->second, {} };
	--it;
	if (it->second.address > r.start)
		return range_result_unbounded{ it->second,
			                           0,
			                           it->second.address - r.start };
	else if (it->second.address + it->second.size < r.end)
		return range_result_unbounded{
			it->second, it->second.address + it->second.size - r.end, 0
		};
	return range_result_ok{ it->second };
}
