#include "app.h"

#include <pthread.h>

struct AppConfig g_config;
struct LiveCounters g_live;

void load_config(void) {
    g_config.max_clients = 4096;
    g_config.timeout_ms = 250;
}

void serve_one(void) {
    for (int i = 0; i < 1000; ++i) {
        if (g_config.timeout_ms)
            g_live.served++;
        else
            g_live.dropped++;
    }
}

int main(void) {
    // Ordering is the whole fixture. Everything load_config stores happens
    // before the thread below exists, so no second core can hold the line.
    load_config();

    pthread_t t;
    pthread_create(&t, 0, worker_entry, 0);
    serve_one();
    pthread_join(t, 0);
    return (int)(g_live.served & 1);
}
