#include "heap.hpp"
#include "../exceptions.hpp"
#include <algorithm>
#include <fmt/format.h>
#include <iostream>
#include <ranges>
#include <string_view>
#include <sys/mman.h>

using namespace ctest::mem;

std::string_view
heap_block::allocated_by() const
{
	if (allocator == (uintptr_t)malloc)
		return std::string_view{ "malloc" };
	else if (allocator == (uintptr_t)realloc)
		return std::string_view{ "realloc" };
	else if (allocator == (uintptr_t)mmap)
		return std::string_view{ "mmap" };
	else if (allocator == (uintptr_t)mremap)
		return std::string_view{ "mmap" };
	else
		throw exception(fmt::format("Unknown allocator: {0}", allocator));
}

std::string_view
heap_block::deallocated_by() const
{
	if (deallocator == (uintptr_t)free)
		return std::string_view{ "free" };
	else if (deallocator == (uintptr_t)munmap)
		return std::string_view{ "munmap" };
	else
		throw exception(fmt::format("Unknown deallocator: {0}", deallocator));
}

bool heap_block::is_initialized(const range& r) const
{
	for (const auto i : std::ranges::iota_view{r.start, r.end})
		if (!initialized[i])
			return false;
	return true;
}

void heap_block::set_initialized(const range& r)
{
	for (const auto i : std::ranges::iota_view{r.start, r.end})
		initialized[i] = true;
}

void
heap::insert(heap_block&& block)
{
	auto it = blocks.lower_bound({ block.address, 0 });
	if (it != blocks.begin())
		--it;

	while (it != blocks.end() &&
	       it->first.start <= block.address + block.size) {
		if (it->second.free_pc == 0 &&
		    it->first.overlaps({ block.address, block.address + block.size }))
			throw exception(fmt::format(
			  fmt::runtime("Overlapping heap blocks. Previous block: "
			               "[{:p}-{:p}] New block: [{:p}-{:p}]"),
			  it->second.address,
			  it->second.address + it->second.size,
			  block.address,
			  block.address + block.size));
		++it;
	}
	blocks.insert(
	  { { block.address, block.address + block.size }, std::move(block) });
}

std::optional<std::reference_wrapper<heap_block>> heap::get(uintptr_t address)
{
	auto it = blocks.upper_bound({address, address});
	if (it != blocks.begin())
		--it;
	if (it->second.address == address)
		return it->second;
	return {};
}

std::expected<std::reference_wrapper<heap_block>, heap::range_error>
heap::get_range(const range& r)
{
	if (blocks.empty())
		return std::unexpected{ range_error{} };

	if (r.start >= r.end)
		throw exception("Invalid range: start must be less than end");

	// Find the first range that could contain our start
	auto it = blocks.upper_bound({ r.start, 0 });
	if (it != blocks.begin())
		--it;

	std::vector<std::reference_wrapper<const heap_block>> overlapping;

	// Find all potentially relevant entries
	while (it != blocks.end() && it->first.start <= r.end) {
		if (it->first.overlaps({ r.start, r.end }))
			overlapping.push_back(it->second);
		++it;
	}

	// If we found more than one overlapping entry, return them all as an error
	if (overlapping.size() > 1)
		return std::unexpected{ range_error{ std::move(overlapping), {}, {} } };
	
	// If we found exactly one entry, build the result
	range_error err{ std::move(overlapping), {}, {} };
	if (err.overlapping.size() == 1) {
		const heap_block& block = err.overlapping[0].get();
		if (block.address > r.start || block.address + block.size < r.end) {
			auto prev_it = blocks.lower_bound({ r.start, 0 });
			while (prev_it != blocks.begin() && prev_it->second.free_pc != 0) {
				--prev_it;
			}
			err.previous = (++prev_it)->second;
			auto next_it = blocks.upper_bound({ r.end, 0 });
			while (next_it != blocks.end() && next_it->second.free_pc == 0) {
				++next_it;
			}
			err.next = (--next_it)->second;
		} else if (err.overlapping[0].get().free_pc == 0)
			return const_cast<heap_block&>(err.overlapping[0].get());
	}

	return std::unexpected{ err };
}
