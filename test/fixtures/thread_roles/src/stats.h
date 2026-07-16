#pragma once
#include <atomic>

// Both counters share one cache line; writers live on different threads
// in different TUs. The pair the pipeline must attribute as disjoint.
struct SharedStats {
    std::atomic<unsigned long> mainOps;
    std::atomic<unsigned long> workerOps;
};
extern SharedStats g_stats;

// Control: same layout, both fields written from main-reachable code
// only. Must NOT receive the cross-thread attribution escalation.
struct LocalStats {
    std::atomic<unsigned long> ctrlA;
    std::atomic<unsigned long> ctrlB;
};
extern LocalStats g_local;

void *workerEntry(void *);
