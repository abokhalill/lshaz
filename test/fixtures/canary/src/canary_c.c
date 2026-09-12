// Known-positive canaries for detection paths that exist only in C.
//
// The registry gate asks whether a rule fires on some canary. With C++
// fixtures alone, a rule matching only C++ spellings satisfies that gate
// while reporting nothing on any C codebase.
#include <pthread.h>
#include <stdatomic.h>

#define CANARY_UNPAUSED 0
#define CANARY_PAUSING  1
#define CANARY_PAUSED   2

typedef struct {
    _Atomic int paused;
} canary_io_thread;

static canary_io_thread canary_io_threads[4];

// FL013. Bare spin on a C11 _Atomic through atomic_load_explicit, which Clang
// models as an AtomicExpr and not a CallExpr.
__attribute__((hot))
void canary_wait_paused(int id) {
    int paused = CANARY_PAUSING;
    while (paused != CANARY_PAUSED)
        paused = atomic_load_explicit(&canary_io_threads[id].paused,
                                      memory_order_seq_cst);
}

void canary_release(int id) {
    atomic_store_explicit(&canary_io_threads[id].paused, CANARY_UNPAUSED,
                          memory_order_seq_cst);
}

// FL003. Owner-indexed striping. The subscript is a field of an object the
// caller handed in, so it names that object's owning thread and not the one
// executing the write, and a single thread can drive every slot. Grades below
// canary.cpp's g_thread_bytes, which subscripts on its own parameter and so
// names its writer.
typedef struct {
    int tid;
} canary_client;

static int canary_clients_per_thread[64];

__attribute__((hot))
void canary_bind_client(canary_client *c) {
    canary_clients_per_thread[c->tid]++;
}

__attribute__((hot))
void canary_unbind_client(canary_client *c) {
    canary_clients_per_thread[c->tid]--;
}

// FL014. Atomic through a cast the compiler cannot prove aligned. At offset
// 60 of a 16-aligned buffer the 8-byte access crosses the line under one of
// the four realizable placements, so x86 serializes the core and ARM64
// faults. A packed _Atomic field does not reach here: Clang lowers that to
// libatomic instead.
static char canary_wire[256];

void canary_bump_wire(void) {
    __atomic_fetch_add((long *)(canary_wire + 60), 1, __ATOMIC_RELAXED);
}

// FL012. POSIX lock through a free function, which arrives as a CallExpr
// and not a member call. Two sequential lock/unlock pairs, so a depth
// tracker that ignores unlock reports the second as nested.
static pthread_mutex_t canary_handoff_mutex[4];
static int canary_pending[4];

__attribute__((hot))
int canary_drain_pending(int id) {
    pthread_mutex_lock(&canary_handoff_mutex[id]);
    int n = canary_pending[id];
    canary_pending[id] = 0;
    pthread_mutex_unlock(&canary_handoff_mutex[id]);

    pthread_mutex_lock(&canary_handoff_mutex[id]);
    canary_pending[id] += n;
    pthread_mutex_unlock(&canary_handoff_mutex[id]);
    return n;
}

// FL012 again, through a wrapper. A tree that takes nearly every lock through
// its own name reaches none of the pthread names above, so those are the case
// that does not occur in the codebases the rule is aimed at.
typedef struct { volatile long lock; } canary_shmtx_t;
void canary_shmtx_lock(canary_shmtx_t *m);
void canary_shmtx_unlock(canary_shmtx_t *m);

static canary_shmtx_t canary_zone_mtx, canary_slab_mtx;

__attribute__((hot))
void canary_zone_commit(void) {
    canary_shmtx_lock(&canary_zone_mtx);
    canary_shmtx_lock(&canary_slab_mtx);   // nested, and the grade says so
    canary_pending[0]++;
    canary_shmtx_unlock(&canary_slab_mtx);
    canary_shmtx_unlock(&canary_zone_mtx);
}

// C002. The bound load is loop-invariant but a store through `out` may alias
// it, so LICM cannot hoist and it reloads every iteration.
__attribute__((noinline))
long canary_scale_into(long *out, const long *bound, long n) {
    long hits = 0;
    for (long i = 0; i < n; i++) {
        out[i] = *bound + i;
        if (out[i] > *bound) hits++;
    }
    return hits;
}

// FL020. Allocation through a project wrapper, named in lshaz.config.yaml.
// Without that name the rule sees nothing here.
extern void *canary_alloc_buf(unsigned long n);
extern void canary_release_buf(void *p);

__attribute__((hot))
void canary_churn(int n) {
    for (int i = 0; i < n; i++) {
        void *p = canary_alloc_buf(4096);
        canary_release_buf(p);
    }
}

// FL070 through a wrapper. A 4MB mapping one call deep is invisible to a rule
// that matches mmap by name, while the identical direct call fires.
void *canary_map_arena(unsigned long n);

__attribute__((hot))
void *canary_reserve_replay(void) {
    return canary_map_arena(4ul << 20);
}

// The store half of the cross-TU line-sharing canary. Its reader lives in
// canary.cpp, so neither TU sees a writer and a distinct reader on this line.
#include "canary_xtu.h"

canary_xtu_cmd canary_xtu_table[4];

static void *canary_xtu_dispatch(void *arg) {
    long id = (long)arg;
    for (int i = 0; i < 1000; i++)
        canary_xtu_table[id & 3].calls++;
    return 0;
}

void canary_xtu_spawn(void) {
    pthread_t t;
    pthread_create(&t, 0, canary_xtu_dispatch, (void *)0);
    pthread_join(t, 0);
}
