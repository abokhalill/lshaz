#include "stats.h"

void *workerEntry(void *) {
    for (int i = 0; i < 1000; ++i)
        g_stats.workerOps.fetch_add(1, std::memory_order_relaxed);
    return nullptr;
}
