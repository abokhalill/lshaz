#include "app.h"

// Reads the config on every iteration and stores to the live counters. The
// config line is shared read-only; the counter line is genuinely contended
// with serve_one on the main thread.
void *worker_entry(void *arg) {
    (void)arg;
    for (int i = 0; i < 1000000; ++i) {
        if (g_config.max_clients > (uint64_t)i && g_config.timeout_ms)
            g_live.dropped++;
        else
            g_live.served++;
    }
    return 0;
}
