// SPDX-License-Identifier: Apache-2.0
//
// `lshaz sample`: what the machine actually did to the storage the analyzer
// reasoned about, keyed by ObjectId.
//
// The event is MEM_LOAD_L3_HIT_RETIRED.XSNP_HITM, which is PEBS-backed on
// Intel client parts, so every sample is a load the hardware confirmed found
// its line dirty in another core, carrying the data address. Nothing is
// inferred from co-location: co-location was tried and it measured thread
// migration, because a thread the scheduler moves touches one line from
// several cores milliseconds apart and that is not sharing.
//
// The address is resolved through the target's memory map and symbol tables
// to "g:<symbol>" plus a byte offset, the identity points-to already uses.
// That is the whole point: a symbol survives inlining because storage does,
// and a byte offset names the field where a source line cannot.
#include "sample.h"

#include "lshaz/core/version.h"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <asm/unistd.h>
#include <elf.h>
#include <sched.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <cerrno>
#include <csignal>

namespace lshaz {
namespace {

long perfEventOpen(perf_event_attr *a, pid_t pid, int cpu, int grp,
                   unsigned long flags) {
    return syscall(__NR_perf_event_open, a, pid, cpu, grp, flags);
}


// ---------- target memory map ----------

struct MapRegion {
    uint64_t start = 0, end = 0, offset = 0;
    std::string perms, path;
};

std::vector<MapRegion> readMaps(pid_t pid) {
    std::vector<MapRegion> out;
    char p[64];
    snprintf(p, sizeof p, "/proc/%d/maps", pid);
    FILE *f = fopen(p, "r");
    if (!f) return out;
    char line[4096];
    while (fgets(line, sizeof line, f)) {
        MapRegion m;
        char perms[8] = {0}, path[3072] = {0};
        unsigned long s, e, off;
        int n = sscanf(line, "%lx-%lx %7s %lx %*s %*s %3071[^\n]",
                       &s, &e, perms, &off, path);
        if (n < 4) continue;
        m.start = s; m.end = e; m.offset = off; m.perms = perms;
        char *q = path;
        while (*q == ' ') ++q;
        m.path = q;
        out.push_back(std::move(m));
    }
    fclose(f);
    return out;
}

// ---------- ELF symbol tables ----------
//
// Parsed here rather than shelled out to nm: the resolver has to run inside
// the sampling loop's budget and has to know segment vaddrs to compute the
// load bias, which nm does not report.

struct Sym {
    uint64_t value = 0, size = 0;
    std::string name;
    char kind = '?';   // O object, F func
    // st_size was 0: a linker marker like __TMC_END__ or _DYNAMIC, not
    // storage. Containment gives it one byte so an exact hit still resolves,
    // but it must never be reported as something sharing a line.
    bool sized = true;
};

struct ObjectFile {
    std::string path;
    uint64_t minVaddr = ~0ull;   // lowest PT_LOAD p_vaddr, for the bias
    bool pie = false;
    std::vector<Sym> syms;       // sorted by value
};

bool loadElf(const std::string &path, ObjectFile &out) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return false;
    off_t len = lseek(fd, 0, SEEK_END);
    if (len <= 0) { close(fd); return false; }
    auto *base = (uint8_t *)mmap(nullptr, len, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) return false;

    auto *eh = (Elf64_Ehdr *)base;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 ||
        eh->e_ident[EI_CLASS] != ELFCLASS64) { munmap(base, len); return false; }
    out.path = path;
    out.pie = (eh->e_type == ET_DYN);

    auto *ph = (Elf64_Phdr *)(base + eh->e_phoff);
    for (int i = 0; i < eh->e_phnum; ++i)
        if (ph[i].p_type == PT_LOAD && ph[i].p_vaddr < out.minVaddr)
            out.minVaddr = ph[i].p_vaddr;
    if (out.minVaddr == ~0ull) out.minVaddr = 0;

    auto *sh = (Elf64_Shdr *)(base + eh->e_shoff);
    const char *shstr = (const char *)(base + sh[eh->e_shstrndx].sh_offset);
    (void)shstr;
    for (int i = 0; i < eh->e_shnum; ++i) {
        if (sh[i].sh_type != SHT_SYMTAB && sh[i].sh_type != SHT_DYNSYM)
            continue;
        auto *sym = (Elf64_Sym *)(base + sh[i].sh_offset);
        size_t n = sh[i].sh_size / sizeof(Elf64_Sym);
        const char *str = (const char *)(base + sh[sh[i].sh_link].sh_offset);
        for (size_t k = 0; k < n; ++k) {
            unsigned t = ELF64_ST_TYPE(sym[k].st_info);
            if (t != STT_OBJECT && t != STT_FUNC) continue;
            if (!sym[k].st_value) continue;
            Sym s;
            s.value = sym[k].st_value;
            s.size = sym[k].st_size ? sym[k].st_size : 1;
            s.sized = sym[k].st_size != 0;
            s.name = str + sym[k].st_name;
            s.kind = (t == STT_OBJECT) ? 'O' : 'F';
            if (!s.name.empty()) out.syms.push_back(std::move(s));
        }
    }
    munmap(base, len);
    std::sort(out.syms.begin(), out.syms.end(),
              [](const Sym &a, const Sym &b) { return a.value < b.value; });
    return true;
}

// ---------- the resolver ----------

struct Resolution {
    const char *region = "?";   // bss/data/heap/stack/anon/file/vdso
    std::string object;         // symbol name when storage is named
    uint64_t offset = 0;        // byte offset into that object
    std::string file;
};

class Resolver {
public:
    explicit Resolver(pid_t pid) : pid_(pid) { refresh(); }

    void refresh() {
        maps_ = readMaps(pid_);
        for (const auto &m : maps_) {
            if (m.path.empty() || m.path[0] == '[') continue;
            if (objs_.count(m.path)) continue;
            ObjectFile o;
            if (loadElf(m.path, o)) objs_.emplace(m.path, std::move(o));
        }
        // Load bias per file: lowest mapped start minus lowest PT_LOAD vaddr.
        bias_.clear();
        std::map<std::string, uint64_t> lowest;
        for (const auto &m : maps_) {
            if (m.path.empty() || m.path[0] == '[') continue;
            auto it = lowest.find(m.path);
            if (it == lowest.end() || m.start < it->second)
                lowest[m.path] = m.start;
        }
        for (const auto &[path, lo] : lowest) {
            auto o = objs_.find(path);
            if (o == objs_.end()) continue;
            bias_[path] = o->second.pie ? lo - o->second.minVaddr : 0;
        }
    }

    Resolution resolve(uint64_t addr) const {
        Resolution r;
        const MapRegion *m = nullptr;
        for (const auto &x : maps_)
            if (addr >= x.start && addr < x.end) { m = &x; break; }
        if (!m) { r.region = "unmapped"; return r; }

        r.file = m->path;
        if (m->path == "[heap]") r.region = "heap";
        else if (m->path == "[stack]") r.region = "stack";
        else if (m->path.empty()) r.region = "anon";
        else if (m->path[0] == '[') r.region = "special";
        else r.region = (m->perms.size() > 1 && m->perms[1] == 'w')
                            ? "file-rw" : "file-ro";

        auto o = objs_.find(m->path);
        auto b = bias_.find(m->path);
        if (o == objs_.end() || b == bias_.end()) return r;

        const uint64_t v = addr - b->second;   // back to link-time vaddr
        const auto &S = o->second.syms;
        // Last symbol whose value <= v, then a containment check.
        auto it = std::upper_bound(S.begin(), S.end(), v,
                                   [](uint64_t x, const Sym &s) { return x < s.value; });
        if (it == S.begin()) return r;
        --it;
        if (v >= it->value && v < it->value + it->size) {
            r.object = it->name;
            r.offset = v - it->value;
        }
        return r;
    }

    // Every other named object whose storage touches the cache line this
    // address sits on, with its start relative to the sampled object's start.
    //
    // Which objects share a line is decided by the linker, not by the source,
    // so no amount of AST reading produces this. Measured on an i9-9900K: a
    // read-only flag took 9727 hit-modified samples because a counter eight
    // bytes below it was being written from another core. Attributing that
    // line to the flag alone is true as an observation and wrong as an
    // explanation.
    // `addr` must be an address the sample actually landed on, not the line
    // base: the anchor is the object that CONTAINS it. Passing the line base
    // resolved the anchor to whichever symbol happened to start the line,
    // which on a two-object line reported the pair backwards.
    std::vector<std::pair<std::string, int64_t>>
    neighboursOn(uint64_t addr, uint64_t lineBytes) const {
        std::vector<std::pair<std::string, int64_t>> out;
        if (!lineBytes) return out;
        const MapRegion *m = nullptr;
        for (const auto &x : maps_)
            if (addr >= x.start && addr < x.end) { m = &x; break; }
        if (!m) return out;
        auto o = objs_.find(m->path);
        auto b = bias_.find(m->path);
        if (o == objs_.end() || b == bias_.end()) return out;

        const uint64_t v = addr - b->second;
        const uint64_t lineLo = v & ~(lineBytes - 1);
        const auto &S = o->second.syms;

        const Sym *self = nullptr;
        for (const auto &s : S)
            if (s.value <= v && v < s.value + s.size) { self = &s; break; }

        for (const auto &s : S) {
            if (s.kind != 'O' || !s.sized) continue;
            if (s.value >= lineLo + lineBytes) break;   // sorted by value
            if (s.value + s.size <= lineLo) continue;
            if (self && s.value == self->value && s.name == self->name)
                continue;
            out.emplace_back(s.name,
                             self ? (int64_t)s.value - (int64_t)self->value
                                  : (int64_t)s.value - (int64_t)lineLo);
        }
        std::sort(out.begin(), out.end());
        out.erase(std::unique(out.begin(), out.end()), out.end());
        return out;
    }

private:
    pid_t pid_;
    std::vector<MapRegion> maps_;
    std::map<std::string, ObjectFile> objs_;
    std::map<std::string, uint64_t> bias_;
};

struct OffsetAgg {
    uint64_t offset = 0, samples = 0, weightSum = 0, weightCount = 0;
    std::set<unsigned> cpus;
};

struct Sample {
    uint64_t ip = 0, addr = 0, weight = 0, dataSrc = 0, phys = 0, time = 0;
    uint32_t pid = 0, tid = 0, cpu = 0;
};

// ---------- the perf ring set ----------
//
// One ring per core, because coherence is between cores and a per-thread event
// follows a thread the scheduler may keep on one.
class PerfRings {
public:
    ~PerfRings() { closeAll(); }

    // Returns the number of cores that opened. Zero means the PMU refused the
    // encoding or the caller lacks permission, and those are different from a
    // machine that moved no lines.
    size_t open(const perf_event_attr &attr, size_t nPages) {
        pageSz_ = (size_t)sysconf(_SC_PAGESIZE);
        const int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
        perf_event_attr a = attr;
        for (int c = 0; c < ncpu; ++c) {
            const int fd = (int)perfEventOpen(&a, -1, c, -1, 0);
            if (fd < 0) { lastErrno_ = errno; continue; }
            void *m = mmap(nullptr, (nPages + 1) * pageSz_,
                           PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            if (m == MAP_FAILED) { lastErrno_ = errno; close(fd); continue; }
            rings_.push_back({fd, (perf_event_mmap_page *)m,
                              (uint8_t *)m + pageSz_, nPages * pageSz_, 0});
        }
        mapBytes_ = (nPages + 1) * pageSz_;
        return rings_.size();
    }

    void enable()  { for (auto &r : rings_) ioctl(r.fd, PERF_EVENT_IOC_ENABLE, 0); }
    void disable() { for (auto &r : rings_) ioctl(r.fd, PERF_EVENT_IOC_DISABLE, 0); }
    bool empty() const { return rings_.empty(); }
    int lastErrno() const { return lastErrno_; }
    uint64_t lost() const { return lost_; }
    uint64_t desyncs() const { return desyncs_; }

    // Drains every ring once. Returns true if any record was consumed.
    template <class F>
    bool drain(F &&onSample) {
        bool any = false;
        for (auto &r : rings_) {
            const uint64_t head =
                __atomic_load_n(&r.meta->data_head, __ATOMIC_ACQUIRE);
            uint64_t tail = r.meta->data_tail;
            while (tail < head) {
                // The kernel rounds every record to a multiple of 8, so an
                // 8-byte header at an 8-aligned offset cannot cross the end of
                // the buffer and can be read in place. That invariant is what
                // makes the read below safe, so it is checked rather than
                // assumed: one bad size desynchronises tail permanently, and
                // every later header read would then straddle for real.
                auto *h = (perf_event_header *)(r.data + (tail % r.sz));
                const uint64_t sz = h->size;
                if (sz < sizeof(perf_event_header) || (sz % 8) != 0 ||
                    sz > r.sz || tail + sz > head) {
                    ++desyncs_;
                    tail = head;   // resync to the writer, losing the backlog
                    break;
                }
                if (flat_.size() < sz) flat_.resize(sz);
                const size_t off = tail % r.sz;
                if (off + sz <= r.sz) {
                    std::memcpy(flat_.data(), r.data + off, sz);
                } else {
                    const size_t first = r.sz - off;
                    std::memcpy(flat_.data(), r.data + off, first);
                    std::memcpy(flat_.data() + first, r.data, sz - first);
                }
                auto *hh = (perf_event_header *)flat_.data();
                if (hh->type == PERF_RECORD_SAMPLE) {
                    const uint8_t *p = flat_.data() + sizeof(perf_event_header);
                    Sample s;
                    auto rd = [&](auto &dst) {
                        std::memcpy(&dst, p, sizeof dst); p += sizeof dst;
                    };
                    rd(s.ip); rd(s.pid); rd(s.tid); rd(s.time); rd(s.addr);
                    { uint32_t c, resv; rd(c); rd(resv); s.cpu = c; }
                    rd(s.weight); rd(s.dataSrc); rd(s.phys);
                    onSample(s);
                } else if (hh->type == PERF_RECORD_LOST) {
                    uint64_t nn = 0;
                    std::memcpy(&nn,
                                flat_.data() + sizeof(perf_event_header) + 8, 8);
                    lost_ += nn;
                }
                tail += sz;
                any = true;
            }
            __atomic_store_n(&r.meta->data_tail, tail, __ATOMIC_RELEASE);
        }
        return any;
    }

    void closeAll() {
        for (auto &r : rings_) {
            if (r.meta) munmap(r.meta, mapBytes_);
            if (r.fd >= 0) close(r.fd);
        }
        rings_.clear();
    }

private:
    struct Ring {
        int fd = -1;
        perf_event_mmap_page *meta = nullptr;
        uint8_t *data = nullptr;
        size_t sz = 0;
        uint64_t pad = 0;
    };
    std::vector<Ring> rings_;
    std::vector<uint8_t> flat_;   // reused: the drain loop is the hot path here
    size_t pageSz_ = 4096, mapBytes_ = 0;
    uint64_t lost_ = 0, desyncs_ = 0;
    int lastErrno_ = 0;
};

volatile sig_atomic_t g_stop = 0;
void onAlarm(int) { g_stop = 1; }

// ---------- machine identity ----------

std::string cpuIdentity() {
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (!f) return {};
    char line[512];
    std::string vendor, family, model;
    while (fgets(line, sizeof line, f)) {
        const char *c = strchr(line, ':');
        if (!c) continue;
        std::string key(line, c - line);
        std::string val(c + 1);
        while (!key.empty() && (key.back() == ' ' || key.back() == '\t'))
            key.pop_back();
        while (!val.empty() && (val.front() == ' ' || val.front() == '\t'))
            val.erase(val.begin());
        while (!val.empty() && (val.back() == '\n' || val.back() == ' '))
            val.pop_back();
        if (key == "vendor_id" && vendor.empty())    vendor = val;
        else if (key == "cpu family" && family.empty()) family = val;
        else if (key == "model" && model.empty())    model = val;
        if (!vendor.empty() && !family.empty() && !model.empty()) break;
    }
    fclose(f);
    if (vendor.empty()) return {};
    return vendor + "-" + family + "-" + model;
}

// ---------- known-positive control ----------
//
// An instrument that reports nothing looks exactly like a clean machine, which
// is why bench/accept.sh will not believe perf c2c until it has seen a known
// positive. The same rule has to apply to the encoding itself: PERF_TYPE_RAW
// accepts any config, a wrong one still produces real samples, and nothing in
// the sample stream says which event they came from.
//
// So: build sharing on purpose, on a line whose address is known, and check
// that the event fires on it.

struct SelfTest {
    bool ran = false;
    bool passed = false;
    uint64_t hits = 0;        // samples on the line two cores fought over
    uint64_t privateHits = 0; // samples on two lines worked equally hard, unshared
    uint64_t storeHits = 0;   // same shared line, written with plain stores
    uint64_t total = 0;       // samples the event produced anywhere
    // Measured, not assumed: a load event sees nothing when two cores share a
    // line by storing to it, and that pattern is a real hazard. What the
    // instrument cannot see bounds what its silence is allowed to refute.
    bool storeBlind = true;
    std::string problem;
};

// Two CPUs on distinct physical cores. SMT siblings share an L1, so a line
// they pass between transfers nothing and the control would fail against a
// perfectly good PMU.
std::vector<int> distinctCoreCpus() {
    const int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
    std::set<std::pair<int, int>> seen;
    std::vector<int> out;
    for (int c = 0; c < ncpu && out.size() < 2; ++c) {
        char p[128];
        int core = -1, pkg = 0;
        snprintf(p, sizeof p,
                 "/sys/devices/system/cpu/cpu%d/topology/core_id", c);
        if (FILE *f = fopen(p, "r")) { if (fscanf(f, "%d", &core) != 1) core = -1;
                                       fclose(f); }
        snprintf(p, sizeof p,
                 "/sys/devices/system/cpu/cpu%d/topology/physical_package_id", c);
        if (FILE *f = fopen(p, "r")) { if (fscanf(f, "%d", &pkg) != 1) pkg = 0;
                                       fclose(f); }
        if (core < 0) continue;
        if (seen.insert({pkg, core}).second) out.push_back(c);
    }
    return out;
}

// The shared line both threads fight over, and two lines a page apart that
// they work exactly as hard without sharing. One page of separation keeps the
// negative control clear of adjacent-line prefetch and 4K aliasing.
alignas(4096) std::atomic<uint64_t> g_victim[8];
alignas(4096) std::atomic<uint64_t> g_privateA[8];
alignas(4096) std::atomic<uint64_t> g_privateB[8];

SelfTest runSelfTest(uint64_t event) {
    SelfTest st;
    const auto cpus = distinctCoreCpus();
    if (cpus.size() < 2) {
        st.problem = "fewer than two physical cores are online, so no line can "
                     "be moved between cores to test against";
        return st;
    }

    perf_event_attr attr{};
    attr.size = sizeof(attr);
    attr.type = PERF_TYPE_RAW;
    attr.config = event;
    // Fixed and short regardless of what the caller chose for the target run.
    // This measures whether the encoding works, not how busy the workload is,
    // and a coarse period would report a dead PMU as a quiet one.
    attr.sample_period = 50;
    attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME |
                       PERF_SAMPLE_ADDR | PERF_SAMPLE_CPU | PERF_SAMPLE_WEIGHT |
                       PERF_SAMPLE_DATA_SRC | PERF_SAMPLE_PHYS_ADDR;
    attr.precise_ip = 2;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    attr.disabled = 1;
    attr.use_clockid = 1;
    attr.clockid = CLOCK_MONOTONIC;

    PerfRings rings;
    if (!rings.open(attr, 64)) {
        st.problem = std::string("perf_event_open refused the encoding on every "
                                 "core: ") + std::strerror(rings.lastErrno());
        return st;
    }
    st.ran = true;

    // One phase of the control. `shared` decides whether the two threads work
    // the same line or a line each; everything else is identical, so the only
    // difference between the two runs is coherence.
    auto phase = [&](bool shared, bool rmw, uint64_t &hits) {
        std::atomic<uint64_t> *slotA = &g_victim[0];
        std::atomic<uint64_t> *slotB = shared ? &g_victim[1] : &g_privateB[0];
        if (!shared) slotA = &g_privateA[0];

        std::atomic<bool> stop{false};
        auto worker = [&](int cpu, std::atomic<uint64_t> *slot) {
            cpu_set_t set;
            CPU_ZERO(&set);
            CPU_SET(cpu, &set);
            sched_setaffinity(0, sizeof set, &set);
            while (!stop.load(std::memory_order_relaxed))
                for (int i = 0; i < 1024; ++i) {
                    if (rmw) slot->fetch_add(1, std::memory_order_relaxed);
                    else     slot->store(i, std::memory_order_relaxed);
                }
        };

        const uint64_t lineA = (uint64_t)(uintptr_t)slotA & ~63ull;
        const uint64_t lineB = (uint64_t)(uintptr_t)slotB & ~63ull;
        auto count = [&](const Sample &s) {
            ++st.total;
            if ((s.addr & ~63ull) == lineA || (s.addr & ~63ull) == lineB)
                ++hits;
        };

        std::thread a(worker, cpus[0], slotA);
        std::thread b(worker, cpus[1], slotB);
        struct timespec now{};
        clock_gettime(CLOCK_MONOTONIC, &now);
        const uint64_t endNs = (uint64_t)now.tv_sec * 1000000000ull +
                               now.tv_nsec + 400000000ull;
        for (;;) {
            rings.drain(count);
            clock_gettime(CLOCK_MONOTONIC, &now);
            if ((uint64_t)now.tv_sec * 1000000000ull + now.tv_nsec >= endNs)
                break;
            usleep(2000);
        }
        stop.store(true);
        a.join();
        b.join();
        rings.drain(count);
    };

    rings.enable();
    phase(/*shared=*/true,  /*rmw=*/true,  st.hits);
    phase(/*shared=*/false, /*rmw=*/true,  st.privateHits);
    phase(/*shared=*/true,  /*rmw=*/false, st.storeHits);
    rings.disable();
    rings.closeAll();

    // Measured on an i9-9900K: XSNP_HITM reports 20016 samples on a line two
    // cores read-modify-write and 0 on the same line written with plain
    // stores, which is the same 0 an unshared line gives. Store-only sharing
    // is a real hazard and the single-writer-per-slot idiom FL002 exists for
    // produces exactly it, so a profile has to carry whether its instrument
    // can see that class rather than letting silence read as absence.
    st.storeBlind = st.storeHits * 8 < st.hits;

    // Firing on the shared line is not enough. MEM_INST_RETIRED.ALL_LOADS
    // fires on it too, at the same rate, because the line is being hammered
    // and not because it is being shared; so does ALL_STORES. Both were
    // measured passing a liveness-only check on an i9-9900K.
    //
    // The discriminating question is whether the event goes quiet when the
    // same work stops sharing. A coherence event collapses; an access event
    // does not move.
    constexpr uint64_t kMinHits = 16;
    constexpr uint64_t kMinRatio = 8;
    if (st.hits < kMinHits) {
        st.problem =
            "two threads on distinct physical cores fought over one line for "
            "400ms and the event reported " + std::to_string(st.hits) +
            " sample(s) on it (" + std::to_string(st.total) +
            " anywhere). This encoding sees no cross-core traffic on this "
            "machine";
    } else if (st.hits < kMinRatio * (st.privateHits + 1)) {
        st.problem =
            "the event fired " + std::to_string(st.hits) +
            " time(s) on a shared line and " + std::to_string(st.privateHits) +
            " time(s) on two unshared lines driven by the same work. An event "
            "that does not go quiet when the sharing stops is counting "
            "accesses, not coherence, and every verdict built on it would "
            "name a mechanism it never measured";
    } else {
        st.passed = true;
    }
    return st;
}

std::string jsonEscape(const std::string &s) {
    std::string o;
    o.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n";  break;
            default:   o += c;
        }
    }
    return o;
}

void usage() {
    std::printf(
        "Usage: lshaz sample --pid PID [options]\n"
        "\n"
        "Record which storage the machine moved between cores, keyed by the\n"
        "same ObjectId the scan reasons about, and write it as JSON for\n"
        "`lshaz scan --memory-profile`.\n"
        "\n"
        "Options:\n"
        "  --pid PID          process to observe (required)\n"
        "  --seconds N        how long to sample (default 10)\n"
        "  --period N         events per sample (default 100)\n"
        "  --output PATH      write here instead of stdout\n"
        "  --machine NAME     recorded in the profile, for the calibration key\n"
        "  --workload NAME    recorded in the profile\n"
        "  --event EVENT      raw PMU config in hex; default 0x04d2, which is\n"
        "                     MEM_LOAD_L3_HIT_RETIRED.XSNP_HITM on Intel client\n"
        "                     parts. Other vendors need their own encoding.\n"
        "  --self-test-only   check the encoding against a known positive and\n"
        "                     exit; no target needed\n"
        "  --no-self-test     skip the check. The profile records that it was\n"
        "                     skipped and the scan will rank from it but not\n"
        "                     establish a mechanism with it\n"
        "  --self-test-optional  sample even if the check fails\n"
        "\n"
        "Before sampling, two threads pinned to distinct physical cores fight\n"
        "over one cache line and the event must fire on it. A raw encoding that\n"
        "names coherence traffic on one part names something else on the next,\n"
        "and the samples look the same either way.\n"
        "\n"
        "Needs perf_event_paranoid <= 0, or CAP_PERFMON.\n");
}

} // namespace

int runSample(int argc, const char **argv) {
    pid_t target = 0;
    unsigned seconds = 10;
    uint64_t period = 100, event = 0x04d2;
    bool selfTest = true, selfTestOptional = false, selfTestOnly = false;
    std::string outPath, machine, workload;

    for (int i = 0; i < argc; ++i) {
        const std::string a = argv[i];
        auto next = [&]() -> std::string {
            return (i + 1 < argc) ? argv[++i] : std::string();
        };
        if (a == "--pid") target = atoi(next().c_str());
        else if (a == "--seconds") seconds = (unsigned)atoi(next().c_str());
        else if (a == "--period") period = strtoull(next().c_str(), nullptr, 0);
        else if (a == "--event") event = strtoull(next().c_str(), nullptr, 0);
        else if (a == "--output") outPath = next();
        else if (a == "--machine") machine = next();
        else if (a == "--workload") workload = next();
        else if (a == "--no-self-test") { selfTest = false; }
        else if (a == "--self-test-optional") { selfTestOptional = true; }
        else if (a == "--self-test-only") { selfTestOnly = true; }
        else if (a == "--help" || a == "-h") { usage(); return 0; }
        else {
            std::fprintf(stderr, "lshaz sample: unknown option '%s'\n",
                         a.c_str());
            usage();
            return 2;
        }
    }
    // After the whole line is parsed, not where the flag appeared: acting on
    // half-parsed state made --self-test-only --event X test the default
    // encoding and report a pass for whatever the caller asked about.
    if (selfTestOnly) {
        const SelfTest s = runSelfTest(event);
        if (s.passed) {
            std::fprintf(stderr,
                "lshaz sample: event 0x%llx measures cross-core hit-modified "
                "traffic here\n"
                "  shared line, read-modify-write: %llu sample(s)\n"
                "  same work, unshared lines:      %llu\n"
                "  shared line, plain stores:      %llu  (%s)\n"
                "  anywhere:                       %llu\n",
                (unsigned long long)event, (unsigned long long)s.hits,
                (unsigned long long)s.privateHits,
                (unsigned long long)s.storeHits,
                s.storeBlind ? "blind to this class, absence refutes nothing"
                             : "visible",
                (unsigned long long)s.total);
            return 0;
        }
        std::fprintf(stderr, "lshaz sample: event 0x%llx: %s\n",
                     (unsigned long long)event, s.problem.c_str());
        return 1;
    }
    if (!target) {
        std::fprintf(stderr, "lshaz sample: --pid is required\n");
        usage();
        return 2;
    }
    if (kill(target, 0) != 0) {
        std::fprintf(stderr, "lshaz sample: no process %d\n", target);
        return 1;
    }

    perf_event_attr attr{};
    attr.size = sizeof(attr);
    attr.type = PERF_TYPE_RAW;
    attr.config = event;
    attr.sample_period = period;
    // CPU is not optional: coherence is between cores. Two threads on one
    // core share L1 and transfer nothing.
    attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME |
                       PERF_SAMPLE_ADDR | PERF_SAMPLE_CPU | PERF_SAMPLE_WEIGHT |
                       PERF_SAMPLE_DATA_SRC | PERF_SAMPLE_PHYS_ADDR;
    attr.precise_ip = 2;          // PEBS, required for a usable data address
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    attr.disabled = 1;
    attr.use_clockid = 1;
    attr.clockid = CLOCK_MONOTONIC;

    // Before the target: prove the encoding measures what the profile will
    // claim it measured. A profile that skipped this cannot establish a
    // mechanism downstream, and says so in its own text rather than being
    // quietly weaker.
    SelfTest st;
    if (selfTest) {
        st = runSelfTest(event);
        if (st.passed) {
            std::fprintf(stderr,
                "lshaz sample: self-test passed, %llu sample(s) on a line two "
                "pinned threads shared against %llu on the same work "
                "unshared\n",
                (unsigned long long)st.hits,
                (unsigned long long)st.privateHits);
        } else {
            std::fprintf(stderr,
                "lshaz sample: self-test FAILED: %s\n", st.problem.c_str());
            if (!selfTestOptional) {
                std::fprintf(stderr,
                    "  Refusing to sample with an instrument that cannot see a "
                    "hazard built on purpose.\n"
                    "  Pass --event with an encoding for this part, or "
                    "--no-self-test to record\n"
                    "  an unverified profile that can rank findings but will "
                    "not establish a mechanism.\n");
                return 1;
            }
        }
    }

    PerfRings rings;
    if (!rings.open(attr, 256)) {
        std::fprintf(stderr,
            "lshaz sample: perf_event_open failed on every CPU: %s\n"
            "  Needs perf_event_paranoid <= 0 (check\n"
            "  /proc/sys/kernel/perf_event_paranoid) and a PMU that\n"
            "  implements event 0x%llx. Refusing to emit an empty\n"
            "  profile, which would read like a machine that moved\n"
            "  no cache lines.\n",
            std::strerror(rings.lastErrno()), (unsigned long long)event);
        return 1;
    }

    Resolver res(target);
    rings.enable();
    signal(SIGALRM, onAlarm);
    alarm(seconds);

    struct timespec t0{}, t1{};
    clock_gettime(CLOCK_MONOTONIC, &t0);

    std::map<std::string, std::map<uint64_t, OffsetAgg>> acc;
    uint64_t kept = 0, unresolved = 0;

    // Absolute line addresses a sample landed on, per object. Resolved to
    // co-occupants after the run, because the symbol lookup is too slow to do
    // per sample and the answer does not change while the process lives.
    std::map<std::string, std::map<uint64_t, std::pair<uint64_t, uint64_t>>>
        linesSeen;

    auto consume = [&](const Sample &s) {
        if ((pid_t)s.pid != target) return;
        Resolution rr = res.resolve(s.addr);
        if (rr.object.empty()) { ++unresolved; return; }
        const std::string id = "g:" + rr.object;
        auto &o = acc[id][rr.offset];
        o.offset = rr.offset;
        ++o.samples;
        o.cpus.insert(s.cpu);
        if (s.weight) { o.weightSum += s.weight; ++o.weightCount; }
        // One representative address per line: the neighbour lookup anchors
        // on the object containing it, so a line base will not do.
        linesSeen[id].emplace(s.addr & ~63ull,
                              std::make_pair(s.addr, rr.offset));
        ++kept;
    };

    while (!g_stop)
        if (!rings.drain(consume)) usleep(2000);

    clock_gettime(CLOCK_MONOTONIC, &t1);
    rings.drain(consume);
    rings.disable();
    const uint64_t lost = rings.lost();
    const uint64_t desyncs = rings.desyncs();

    const uint64_t wall = (uint64_t)(t1.tv_sec - t0.tv_sec) * 1000000000ull +
                          (uint64_t)(t1.tv_nsec - t0.tv_nsec);

    if (kept == 0) {
        std::fprintf(stderr,
            "lshaz sample: %llu sample(s) for pid %d, none resolved to named "
            "storage.\n"
            "  A profile of nothing would read like a machine that moved no\n"
            "  cache lines, so none is written. Usual causes: the target's\n"
            "  hot data is heap or anonymous rather than a named global, or\n"
            "  the binary is stripped.\n",
            (unsigned long long)(kept + unresolved), target);
        return 1;
    }

    std::string buf;
    buf += "{\n  \"kind\": \"lshaz.memory-profile\",\n";
    buf += "  \"version\": \"" + std::string(kToolVersion) + "\",\n";
    buf += "  \"origin\": \"lshaz sample --pid " + std::to_string(target) + "\",\n";
    buf += "  \"machine\": \"" + jsonEscape(machine) + "\",\n";
    buf += "  \"workload\": \"" + jsonEscape(workload) + "\",\n";
    buf += "  \"event\": \"0x" + [&]{ char b[32];
             std::snprintf(b, sizeof b, "%llx", (unsigned long long)event);
             return std::string(b); }() + "\",\n";
    buf += "  \"cpu\": \"" + jsonEscape(cpuIdentity()) + "\",\n";
    // Whether this instrument was shown to measure what the profile claims.
    // A consumer that cannot see this has to take the encoding on trust, and
    // an encoding is exactly the thing that is silently wrong on a new part.
    buf += "  \"selfTest\": \"" +
           std::string(!selfTest ? "skipped" : (st.passed ? "pass" : "fail")) +
           "\",\n";
    buf += "  \"selfTestSamples\": " + std::to_string(st.hits) + ",\n";
    buf += "  \"selfTestUnshared\": " + std::to_string(st.privateHits) + ",\n";
    buf += "  \"selfTestStoreOnly\": " + std::to_string(st.storeHits) + ",\n";
    // What this instrument cannot see. A consumer that refutes on absence has
    // to read this first, or it retires findings the event was never able to
    // observe in the first place.
    buf += "  \"storeOnlySharing\": \"" +
           std::string(!selfTest ? "unknown" : (st.storeBlind ? "blind"
                                                              : "visible")) +
           "\",\n";
    buf += "  \"samplePeriod\": " + std::to_string(period) + ",\n";
    buf += "  \"wallNanos\": " + std::to_string(wall) + ",\n";
    buf += "  \"unresolvedSamples\": " + std::to_string(unresolved) + ",\n";
    buf += "  \"lostSamples\": " + std::to_string(lost) + ",\n";
    buf += "  \"ringDesyncs\": " + std::to_string(desyncs) + ",\n";
    buf += "  \"objects\": [\n";
    bool firstObj = true;
    for (const auto &[id, offs] : acc) {
        uint64_t tot = 0;
        for (const auto &[o, a] : offs) tot += a.samples;
        if (!firstObj) buf += ",\n";
        firstObj = false;
        std::map<std::string, std::pair<int64_t, uint64_t>> nb;
        if (auto ls = linesSeen.find(id); ls != linesSeen.end())
            for (const auto &[line, w] : ls->second)
                for (auto &[name, rel] : res.neighboursOn(w.first, 64))
                    nb.emplace("g:" + name, std::make_pair(rel, w.second));

        buf += "    {\"id\": \"" + jsonEscape(id) + "\", \"samples\": " +
               std::to_string(tot);
        if (!nb.empty()) {
            buf += ", \"neighbours\": [";
            bool firstN = true;
            for (const auto &[name, v] : nb) {
                if (!firstN) buf += ", ";
                firstN = false;
                buf += "{\"id\": \"" + jsonEscape(name) + "\", \"at\": " +
                       std::to_string(v.first) + ", \"witness\": " +
                       std::to_string(v.second) + "}";
            }
            buf += "]";
        }
        buf += ", \"offsets\": [";
        bool firstOff = true;
        for (const auto &[o, a] : offs) {
            if (!firstOff) buf += ", ";
            firstOff = false;
            buf += "{\"offset\": " + std::to_string(a.offset) +
                   ", \"samples\": " + std::to_string(a.samples) +
                   ", \"weightSum\": " + std::to_string(a.weightSum) +
                   ", \"weightCount\": " + std::to_string(a.weightCount) +
                   ", \"cpus\": [";
            bool firstCpu = true;
            for (unsigned c : a.cpus) {
                if (!firstCpu) buf += ",";
                firstCpu = false;
                buf += std::to_string(c);
            }
            buf += "]}";
        }
        buf += "]}";
    }
    buf += "\n  ]\n}\n";

    if (outPath.empty()) {
        std::fputs(buf.c_str(), stdout);
    } else {
        FILE *f = std::fopen(outPath.c_str(), "w");
        if (!f) {
            std::fprintf(stderr, "lshaz sample: cannot write %s: %s\n",
                         outPath.c_str(), std::strerror(errno));
            return 1;
        }
        std::fputs(buf.c_str(), f);
        std::fclose(f);
    }

    std::fprintf(stderr,
        "lshaz sample: %llu cross-core hit-modified sample(s) on %zu named "
        "object(s) over %.1fs\n",
        (unsigned long long)kept, acc.size(), wall / 1e9);
    std::fprintf(stderr,
        "  %llu sample(s) landed on storage this build cannot name "
        "(heap, anonymous or stripped)\n",
        (unsigned long long)unresolved);
    if (lost)
        std::fprintf(stderr, "  %llu sample(s) lost to ring overflow\n",
                     (unsigned long long)lost);
    return 0;
}

} // namespace lshaz
