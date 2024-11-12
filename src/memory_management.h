#ifndef CTEST_MEMORY_MANAGEMENT_H
#define CTEST_MEMORY_MANAGEMENT_H

struct ctest_result;

/**
 * @brief Adds a new allocation/deallocation to the arena
 *
 * The allocation is retrieved from @ref ctest_mem_msg_out and @ref ctest_mem_msg_in
 * In case of a deallocation, this function will move the allocation from the allocation arena to
 * the deallocation arena
 *
 * @param Result the result from which the allocation is retrieved
 */
void
__ctest_mem_process_allocation(struct ctest_result* result);

#endif // CTEST_MEMORY_MANAGEMENT_H
