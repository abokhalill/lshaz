#include "stats.h"
#include <pthread.h>

SharedStats g_stats;
LocalStats g_local;

void mainSide() {
    g_stats.mainOps.fetch_add(1, std::memory_order_relaxed);
}

void ctrlWriteA() {
    g_local.ctrlA.fetch_add(1, std::memory_order_relaxed);
}

void ctrlWriteB() {
    g_local.ctrlB.fetch_add(1, std::memory_order_relaxed);
}

int main() {
    pthread_t t;
    pthread_create(&t, nullptr, workerEntry, nullptr);
    for (int i = 0; i < 1000; ++i) {
        mainSide();
        ctrlWriteA();
        ctrlWriteB();
    }
    pthread_join(t, nullptr);
    return 0;
}
