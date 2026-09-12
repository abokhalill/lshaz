// Known-positive canary for rules the hft_core fixture does not reach.
//
// Every registered rule must fire on some canary, enforced by
// scan_test. A rule that stops firing is a silent recall loss, and both
// defects found in the FL002/FL041 audit were exactly that: caught by a
// fixture, never by a gate.
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <thread>

extern "C" {
// Reached from a thread body so the cross-TU hot verdict covers the C
// fixtures. The remark channel keys on that verdict, not a local attribute.
long canary_scale_into(long *out, const long *bound, long n);
int canary_drain_pending(int id);
void canary_churn(int n);
}

namespace canary {

// FL060. NUMA-unfriendly shared structure: >=256B, escapes, mutable.
struct alignas(64) SharedRegistry {
    std::atomic<uint64_t> sequence{0};
    std::atomic<uint64_t> epoch{0};
    uint64_t slots[48];
    uint64_t checkpoints[16];
};
static SharedRegistry g_registry;

// FL090. Hazard amplification: atomics on distinct lines of one shared
// object, written from thread bodies. hft_core cannot canary this rule:
// it spawns no threads at all, so amplification has no mechanism there and
// firing on it was evidence-free.
struct AmplifiedCounters {
    std::atomic<uint64_t> head{0};
    uint64_t pad_a[7];
    std::atomic<uint64_t> tail{0};
    uint64_t pad_b[7];
    std::atomic<uint64_t> drops{0};
    uint64_t pad_c[7];
};
static AmplifiedCounters g_amplified;

// FL002. The thread-pool shape: one shared object, two adjacent plain
// counters, ONE writer function run by every pool thread. Requiring two
// distinct writer *functions* rejected this, which is backwards: two
// *cores* is the requirement, and a pool already has them.
struct PoolCounters {
    uint64_t hits;
    uint64_t misses;
};
static PoolCounters g_pool_counters;
static void record_pool_event(int hit) {
    if (hit) g_pool_counters.hits++;
    else     g_pool_counters.misses++;
}

// FL003. Striped per-thread array: one slot per thread, packed several to
// a line, written under a thread-index.
static uint64_t g_thread_bytes[64];

void account(int thread_id, uint64_t n) { g_thread_bytes[thread_id] += n; }

uint64_t total_accounted() {
    uint64_t t = 0;
    for (int i = 0; i < 64; ++i) t += g_thread_bytes[i];
    return t;
}

// FL003 write forms that are not assignments to a bare subscript. Each was
// a miss until the write side learned to reach the striped subscript
// through the shape wrapping it.
static uint64_t g_slot_via_ptr[64];
static struct { uint64_t v; char pad[16]; } g_slot_nested[64];
// 96B stride: not a line multiple, so element boundaries fall mid-line
// wherever the linker puts the base.
static struct { uint64_t a, b, c, d, e, f, g, h, i, j, k, l; } g_slot_stride[64];

void account_indirect(int thread_id, uint64_t n) {
    uint64_t *slot = &g_slot_via_ptr[thread_id];
    *slot += n;
    g_slot_nested[thread_id].pad[0] = static_cast<char>(n);
    g_slot_stride[thread_id].a += n;
}

// FL004. Correctly padded and aligned, so FL003 is right to stay silent, and
// a loop that reads every slot still downgrades each owner out of Modified.
struct alignas(64) SweptSlot { uint64_t v; char pad[56]; };
static SweptSlot g_swept[64];

void account_swept(int thread_id, uint64_t n) { g_swept[thread_id].v += n; }

__attribute__((hot))
uint64_t total_swept() {
    uint64_t t = 0;
    for (int i = 0; i < 64; ++i) t += g_swept[i].v;
    return t;
}

// FL002 read/write pair. A store to one field invalidates the line, so a core
// reading a different field on it re-fetches and pays the same miss a second
// writer would.
struct DispatchEntry {
    uint64_t spec_a, spec_b, spec_c;   // read on the lookup path
    uint64_t calls;                    // stored on the dispatch path
};
static DispatchEntry g_dispatch_table[8];

void bump_dispatch(int slot) { g_dispatch_table[slot & 7].calls++; }

uint64_t read_specs(int slot) {
    const DispatchEntry &e = g_dispatch_table[slot & 7];
    return e.spec_a + e.spec_b + e.spec_c;
}

// FL061. Centralized dispatcher: hot function with high fan-out.
static void op_add(uint64_t v)  { g_registry.sequence.fetch_add(v); }
static void op_sub(uint64_t v)  { g_registry.sequence.fetch_sub(v); }
static void op_mark(uint64_t v) { g_registry.epoch.store(v); }
static void op_slot(uint64_t v) { g_registry.slots[v & 47] = v; }
static void op_ckpt(uint64_t v) { g_registry.checkpoints[v & 15] = v; }
static void op_seq(uint64_t v)  { g_registry.sequence.store(v); }
static void op_bump(uint64_t v) { g_registry.epoch.fetch_add(v); }
static void op_zero(uint64_t v) { g_registry.slots[v & 47] = 0; }
static void op_tag(uint64_t v)  { g_registry.checkpoints[v & 15] += v; }

__attribute__((hot))
void dispatch(int opcode, uint64_t v) {
    switch (opcode) {
        case 0:  op_add(v);  break;
        case 1:  op_sub(v);  break;
        case 2:  op_mark(v); break;
        case 3:  op_slot(v); break;
        case 4:  op_ckpt(v); break;
        case 5:  op_seq(v);  break;
        case 6:  op_bump(v); break;
        case 7:  op_zero(v); break;
        default: op_tag(v);  break;
    }
}

static void worker(int id) {
    long buf[64] = {0}, bound = 3;
    uint64_t acc = 0;
    for (int i = 0; i < 1000; ++i) {
        canary_scale_into(buf, &bound, 64);
        canary_drain_pending(id);
        canary_churn(2);
        record_pool_event(i & 1);
        g_amplified.head.fetch_add(1);
        g_amplified.tail.fetch_add(1);
        g_amplified.drops.fetch_add(id & 1);
        account(id, static_cast<uint64_t>(i));
        account_swept(id, static_cast<uint64_t>(i));
        bump_dispatch(i);
        acc += read_specs(i);
        (void)total_swept();
        dispatch(i & 7, static_cast<uint64_t>(i));
    }
    (void)acc;
}

void run() {
    std::thread a(worker, 0);
    std::thread b(worker, 1);
    a.join();
    b.join();
}

// A loop-swept subscript reached outside any enclosing function. Writer
// attribution is keyed on the current function, which does not exist here, so
// the state has to be filtered rather than dereferenced. A crash is a silent
// recall loss for the whole TU.
static constexpr int kSeedLen = 8;
static int seed_table[kSeedLen] = {0, 1, 2, 3, 4, 5, 6, 7};
struct SeedSum {
    int value = [] {
        int acc = 0;
        for (int i = 0; i < kSeedLen; ++i) acc += seed_table[i];
        return acc;
    }();
};
static SeedSum g_seed_sum;

} // namespace canary

extern "C" {
// Reachable from main so the cross-TU hot verdict covers the C fixtures;
// the remark channel keys on that verdict rather than on a local attribute.
long canary_scale_into(long *out, const long *bound, long n);
int canary_drain_pending(int id);
}

// FL092. Two fields on one line whose writers sit on provably disjoint
// thread roles, on a type this fixture does not isolate while SharedRegistry
// above already is. The compound is gated on that role attribution landing,
// so a fixture with the layout alone never reaches it.
namespace canary {
struct RoleSplitCounters {
    uint64_t produced;
    uint64_t consumed;
};
static RoleSplitCounters g_role_split;

unsigned long observed_seconds();

// Sink for the FL006 read. Deliberately not one of the role-split counters:
// accumulating into those would give the producer thread a write to both
// fields, which removes their distinct-role writers and takes FL002's
// role attribution on this type with it.
static unsigned long g_time_observations;

static void *produce_thread(void *) {
    for (int i = 0; i < 1000; i++) {
        g_role_split.produced++;
        // FL006. Reads the time cache the main thread republishes and never
        // writes it. One field, two roles, so no pair of fields is involved
        // and padding cannot help: this thread wants the value.
        g_time_observations += observed_seconds();
    }
    return nullptr;
}

void consume_on_main() { g_role_split.consumed++; }

// FL005. A value coarsened by a literal divisor, stored unconditionally into a
// shared global from a function that runs more than once. The canonical shape
// is a cached clock: microseconds divided down to seconds and stored per
// operation, so all but one store per second writes a value already there.
struct TimeCache {
    unsigned long usec;
    unsigned long sec;
};
static TimeCache g_time_cache;

unsigned long observed_seconds() { return g_time_cache.sec; }

__attribute__((hot))
void refresh_time(unsigned long us) {
    g_time_cache.usec = us;
    g_time_cache.sec = us / 1000000;
}

void tick_a(unsigned long us) { refresh_time(us); }
void tick_b(unsigned long us) { refresh_time(us + 1); }

// Republished from the main loop, which is what makes the invalidation
// recur. A field written once at startup settles in Shared state and costs
// nothing, so the rule asks about the writer's rate rather than about how
// many store statements the source contains.
void tick_loop(int n) {
    for (int i = 0; i < n; i++) refresh_time(static_cast<unsigned long>(i));
}

void spawn_producer() {
    pthread_t t;
    pthread_create(&t, nullptr, produce_thread, nullptr);
    pthread_join(t, nullptr);
}
} // namespace canary

int main() {
    canary::run();
    canary::spawn_producer();
    canary::consume_on_main();
    canary::tick_a(1);
    canary::tick_b(2);
    canary::tick_loop(16);
    return static_cast<int>(canary::total_accounted() & 1);
}

// The read half of the cross-TU line-sharing canary. Reads the key specs and
// never touches 'calls'; the store is in canary_c.c.
#include "canary_xtu.h"

extern "C" unsigned long canary_xtu_lookup(int slot) {
    const canary_xtu_cmd &e = canary_xtu_table[slot & 3];
    return e.key_spec_a + e.key_spec_b + e.key_spec_c;
}
