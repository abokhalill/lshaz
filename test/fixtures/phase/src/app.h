#ifndef PHASE_APP_H
#define PHASE_APP_H

#include <stdint.h>

// Two fields on one cache line, both stored during startup and never again.
// The worker only ever loads them, so every copy of the line is clean for the
// whole run: no RFO from a peer, no HITM. This is the case the phase
// partition exists to withdraw.
struct AppConfig {
    uint64_t max_clients;
    uint64_t timeout_ms;
};

// The same shape, stored on both sides while the worker runs. The control:
// nothing about it is on the near side of the first thread creation, so it
// must survive.
struct LiveCounters {
    uint64_t served;
    uint64_t dropped;
};

extern struct AppConfig g_config;
extern struct LiveCounters g_live;

void load_config(void);
void *worker_entry(void *arg);
void serve_one(void);

#endif
