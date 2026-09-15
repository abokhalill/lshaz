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
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

#include <asm/unistd.h>
#include <elf.h>
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

volatile sig_atomic_t g_stop = 0;
void onAlarm(int) { g_stop = 1; }

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
        "\n"
        "Needs perf_event_paranoid <= 0, or CAP_PERFMON.\n");
}

} // namespace

int runSample(int argc, const char **argv) {
    pid_t target = 0;
    unsigned seconds = 10;
    uint64_t period = 100, event = 0x04d2;
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
        else if (a == "--help" || a == "-h") { usage(); return 0; }
        else {
            std::fprintf(stderr, "lshaz sample: unknown option '%s'\n",
                         a.c_str());
            usage();
            return 2;
        }
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

    const int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
    const size_t pageSz = (size_t)sysconf(_SC_PAGESIZE);
    const size_t nPages = 256;

    struct Ring { int fd; perf_event_mmap_page *meta; uint8_t *data; size_t sz; };
    std::vector<Ring> rings;
    for (int c = 0; c < ncpu; ++c) {
        const int fd = (int)perfEventOpen(&attr, -1, c, -1, 0);
        if (fd < 0) {
            if (rings.empty() && c == ncpu - 1) {
                std::fprintf(stderr,
                    "lshaz sample: perf_event_open failed on every CPU: %s\n"
                    "  Needs perf_event_paranoid <= 0 (currently check\n"
                    "  /proc/sys/kernel/perf_event_paranoid) and a PMU that\n"
                    "  implements event 0x%llx. Refusing to emit an empty\n"
                    "  profile, which would read like a machine that moved\n"
                    "  no cache lines.\n",
                    std::strerror(errno), (unsigned long long)event);
                return 1;
            }
            continue;
        }
        void *m = mmap(nullptr, (nPages + 1) * pageSz, PROT_READ | PROT_WRITE,
                       MAP_SHARED, fd, 0);
        if (m == MAP_FAILED) { close(fd); continue; }
        rings.push_back({fd, (perf_event_mmap_page *)m,
                         (uint8_t *)m + pageSz, nPages * pageSz});
    }
    if (rings.empty()) {
        std::fprintf(stderr, "lshaz sample: no ring buffers could be opened\n");
        return 1;
    }

    Resolver res(target);
    for (auto &r : rings) ioctl(r.fd, PERF_EVENT_IOC_ENABLE, 0);
    signal(SIGALRM, onAlarm);
    alarm(seconds);

    struct timespec t0{}, t1{};
    clock_gettime(CLOCK_MONOTONIC, &t0);

    std::map<std::string, std::map<uint64_t, OffsetAgg>> acc;
    uint64_t kept = 0, unresolved = 0, lost = 0;

    while (!g_stop) {
        bool any = false;
        for (auto &r : rings) {
            uint64_t head = __atomic_load_n(&r.meta->data_head, __ATOMIC_ACQUIRE);
            uint64_t tail = r.meta->data_tail;
            while (tail < head) {
                auto *h = (perf_event_header *)(r.data + (tail % r.sz));
                if (h->size == 0) break;
                std::vector<uint8_t> flat(h->size);
                for (size_t k = 0; k < h->size; ++k)
                    flat[k] = r.data[(tail + k) % r.sz];
                auto *hh = (perf_event_header *)flat.data();
                if (hh->type == PERF_RECORD_SAMPLE) {
                    const uint8_t *p = flat.data() + sizeof(perf_event_header);
                    Sample s;
                    auto rd = [&](auto &dst) {
                        std::memcpy(&dst, p, sizeof dst); p += sizeof dst;
                    };
                    rd(s.ip); rd(s.pid); rd(s.tid); rd(s.time); rd(s.addr);
                    { uint32_t c, resv; rd(c); rd(resv); s.cpu = c; }
                    rd(s.weight); rd(s.dataSrc); rd(s.phys);
                    if ((pid_t)s.pid == target) {
                        Resolution rr = res.resolve(s.addr);
                        if (rr.object.empty()) {
                            ++unresolved;
                        } else {
                            auto &o = acc["g:" + rr.object][rr.offset];
                            o.offset = rr.offset;
                            ++o.samples;
                            o.cpus.insert(s.cpu);
                            if (s.weight) { o.weightSum += s.weight;
                                            ++o.weightCount; }
                            ++kept;
                        }
                    }
                } else if (hh->type == PERF_RECORD_LOST) {
                    uint64_t idv = 0, nn = 0;
                    std::memcpy(&idv, flat.data() + sizeof(perf_event_header), 8);
                    std::memcpy(&nn, flat.data() + sizeof(perf_event_header) + 8, 8);
                    lost += nn;
                }
                tail += hh->size;
                any = true;
            }
            __atomic_store_n(&r.meta->data_tail, tail, __ATOMIC_RELEASE);
        }
        if (!any) usleep(2000);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    for (auto &r : rings) ioctl(r.fd, PERF_EVENT_IOC_DISABLE, 0);

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
    buf += "  \"samplePeriod\": " + std::to_string(period) + ",\n";
    buf += "  \"wallNanos\": " + std::to_string(wall) + ",\n";
    buf += "  \"unresolvedSamples\": " + std::to_string(unresolved) + ",\n";
    buf += "  \"lostSamples\": " + std::to_string(lost) + ",\n";
    buf += "  \"objects\": [\n";
    bool firstObj = true;
    for (const auto &[id, offs] : acc) {
        uint64_t tot = 0;
        for (const auto &[o, a] : offs) tot += a.samples;
        if (!firstObj) buf += ",\n";
        firstObj = false;
        buf += "    {\"id\": \"" + jsonEscape(id) + "\", \"samples\": " +
               std::to_string(tot) + ", \"offsets\": [";
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
