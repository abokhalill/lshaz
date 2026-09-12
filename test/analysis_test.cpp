// Checks CacheLineMap against ASTRecordLayout. Parses C++ fragments through
// Clang tooling and asserts exact field offsets, line assignments, atomic
// counts, straddle flags and bucket populations, so a refactor that changes
// offset computation fails here rather than in a scan.

#include "lshaz/analysis/cache_line.h"
#include "lshaz/analysis/call_graph.h"
#include "lshaz/analysis/escape.h"
#include "lshaz/analysis/thread_role.h"
#include "lshaz/analysis/event_profile.h"
#include "lshaz/analysis/loop_shape.h"
#include "lshaz/core/config.h"
#include "lshaz/core/cost_calibration.h"
#include "lshaz/core/hot_path.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/DeclCXX.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Frontend/ASTUnit.h>
#include <clang/Tooling/Tooling.h>

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <string>
#include <vector>

namespace {

int failures = 0;
int passed = 0;

void check(bool cond, const char *msg) {
    if (!cond) {
        std::cerr << "  FAIL: " << msg << "\n";
        ++failures;
    } else {
        ++passed;
    }
}

// Parse source, find the named CXXRecordDecl, run callback with ASTContext.
void withRecord(const std::string &source, const std::string &recordName,
                std::function<void(const clang::CXXRecordDecl *,
                                   clang::ASTContext &)> fn) {
    auto AST = clang::tooling::buildASTFromCode(source, "test_input.cpp",
        std::make_shared<clang::PCHContainerOperations>());
    if (!AST) {
        std::cerr << "  FAIL: AST parse failed for record '" << recordName << "'\n";
        ++failures;
        return;
    }

    class Finder : public clang::RecursiveASTVisitor<Finder> {
    public:
        const std::string &target;
        const clang::CXXRecordDecl *found = nullptr;
        explicit Finder(const std::string &t) : target(t) {}
        bool VisitCXXRecordDecl(clang::CXXRecordDecl *RD) {
            if (RD->isCompleteDefinition() && RD->getNameAsString() == target)
                found = RD;
            return true;
        }
    };

    Finder finder(recordName);
    finder.TraverseDecl(AST->getASTContext().getTranslationUnitDecl());
    if (!finder.found) {
        std::cerr << "  FAIL: record '" << recordName << "' not found in AST\n";
        ++failures;
        return;
    }

    fn(finder.found, AST->getASTContext());
}

// Lookup a field by name in the CacheLineMap fields list.
const lshaz::FieldLineEntry *findField(const lshaz::CacheLineMap &map,
                                        const std::string &name) {
    for (const auto &f : map.fields()) {
        if (f.name == name)
            return &f;
    }
    return nullptr;
}

// Simple POD struct, no padding, no atomics.
// struct Simple { int a; int b; char c; };
// sizeof = 12 (with 0 padding between a,b,c, but trailing pad to 4 -> 12)
void testSimplePOD() {
    std::cerr << "test: simple POD struct layout\n";
    const char *src = R"(
        struct Simple { int a; int b; char c; };
    )";

    withRecord(src, "Simple", [](const clang::CXXRecordDecl *RD,
                                  clang::ASTContext &Ctx) {
        lshaz::CacheLineMap map(RD, Ctx, 64);

        check(map.recordSizeBytes() == 12, "sizeof Simple == 12");
        check(map.linesSpanned() == 1, "fits in 1 cache line");
        check(map.totalAtomicFields() == 0, "no atomics");
        check(map.totalMutableFields() == 3, "3 mutable fields");
        check(map.straddlingFields().empty(), "no straddling");

        auto *fa = findField(map, "a");
        auto *fb = findField(map, "b");
        auto *fc = findField(map, "c");
        check(fa && fa->offsetBytes == 0, "a at offset 0");
        check(fa && fa->sizeBytes == 4, "a is 4 bytes");
        check(fb && fb->offsetBytes == 4, "b at offset 4");
        check(fc && fc->offsetBytes == 8, "c at offset 8");
        check(fc && fc->sizeBytes == 1, "c is 1 byte");

        check(fa && fa->startLine == 0 && fa->endLine == 0, "a on line 0");
        check(fb && fb->startLine == 0 && fb->endLine == 0, "b on line 0");
        check(fc && fc->startLine == 0 && fc->endLine == 0, "c on line 0");
    });
}

// Struct with padding, natural alignment of double.
// struct Padded { char x; double y; int z; };
// x at 0 (1B), 7B pad, y at 8 (8B), z at 16 (4B), 4B tail pad -> 24B
void testPaddedStruct() {
    std::cerr << "test: padded struct layout\n";
    const char *src = R"(
        struct Padded { char x; double y; int z; };
    )";

    withRecord(src, "Padded", [](const clang::CXXRecordDecl *RD,
                                  clang::ASTContext &Ctx) {
        lshaz::CacheLineMap map(RD, Ctx, 64);

        check(map.recordSizeBytes() == 24, "sizeof Padded == 24");
        check(map.linesSpanned() == 1, "fits in 1 cache line");

        auto *fx = findField(map, "x");
        auto *fy = findField(map, "y");
        auto *fz = findField(map, "z");
        check(fx && fx->offsetBytes == 0, "x at offset 0");
        check(fy && fy->offsetBytes == 8, "y at offset 8 (after 7B padding)");
        check(fy && fy->sizeBytes == 8, "y is 8 bytes");
        check(fz && fz->offsetBytes == 16, "z at offset 16");
    });
}

// Struct spanning 2 cache lines.
// struct Wide { char data[65]; };
// 65 bytes -> spans lines 0 and 1.
void testCacheLineSpanning() {
    std::cerr << "test: cache line spanning struct\n";
    const char *src = R"(
        struct Wide { char data[65]; };
    )";

    withRecord(src, "Wide", [](const clang::CXXRecordDecl *RD,
                                clang::ASTContext &Ctx) {
        lshaz::CacheLineMap map(RD, Ctx, 64);

        check(map.recordSizeBytes() == 65, "sizeof Wide == 65");
        check(map.linesSpanned() == 2, "spans 2 cache lines");

        auto *fd = findField(map, "data");
        check(fd && fd->offsetBytes == 0, "data at offset 0");
        check(fd && fd->sizeBytes == 65, "data is 65 bytes");
        check(fd && fd->straddles, "data straddles line boundary");
        check(fd && fd->startLine == 0 && fd->endLine == 1, "data on lines 0-1");
    });
}

// Struct with std::atomic fields, atomic detection.
void testAtomicDetection() {
    std::cerr << "test: atomic field detection\n";
    const char *src = R"(
        #include <atomic>
        struct AtomicStruct {
            int plain;
            std::atomic<int> counter;
            std::atomic<bool> flag;
            double value;
        };
    )";

    withRecord(src, "AtomicStruct", [](const clang::CXXRecordDecl *RD,
                                        clang::ASTContext &Ctx) {
        lshaz::CacheLineMap map(RD, Ctx, 64);

        check(map.totalAtomicFields() == 2, "2 atomic fields");
        // plain(4B) + pad(0) + counter(4B) + flag(1B) + pad(7B) + value(8B) = 24B
        // Actual layout: plain@0(4), counter@4(4), flag@8(1), pad(7), value@16(8) = 24B
        check(map.recordSizeBytes() == 24, "sizeof AtomicStruct == 24");

        auto *fc = findField(map, "counter");
        auto *ff = findField(map, "flag");
        auto *fp = findField(map, "plain");
        auto *fv = findField(map, "value");

        check(fc && fc->isAtomic, "counter is atomic");
        check(ff && ff->isAtomic, "flag is atomic");
        check(fp && !fp->isAtomic, "plain is not atomic");
        check(fv && !fv->isAtomic, "value is not atomic");

        check(fc && fc->offsetBytes == 4, "counter at offset 4");
        check(ff && ff->offsetBytes == 8, "flag at offset 8");

        auto pairs = map.atomicPairsOnSameLine();
        check(pairs.size() == 1, "1 atomic pair on same line");
    });
}

// Inheritance, base class fields at base offset.
// struct Base { int x; int y; };
// struct Derived : Base { int z; };
// Layout: x@0, y@4, z@8 -> 12B
void testInheritanceLayout() {
    std::cerr << "test: inheritance layout\n";
    const char *src = R"(
        struct Base { int x; int y; };
        struct Derived : Base { int z; };
    )";

    withRecord(src, "Derived", [](const clang::CXXRecordDecl *RD,
                                   clang::ASTContext &Ctx) {
        lshaz::CacheLineMap map(RD, Ctx, 64);

        check(map.recordSizeBytes() == 12, "sizeof Derived == 12");

        auto *fx = findField(map, "x");
        auto *fy = findField(map, "y");
        auto *fz = findField(map, "z");
        check(fx && fx->offsetBytes == 0, "base field x at offset 0");
        check(fy && fy->offsetBytes == 4, "base field y at offset 4");
        check(fz && fz->offsetBytes == 8, "derived field z at offset 8");
    });
}

// Alignas. Forced alignment changes offset layout.
// struct Aligned { char a; alignas(64) int b; };
// a@0, b@64 -> sizeof at least 128 (64-byte aligned b, then tail pad)
void testAlignasLayout() {
    std::cerr << "test: alignas layout\n";
    const char *src = R"(
        struct Aligned { char a; alignas(64) int b; };
    )";

    withRecord(src, "Aligned", [](const clang::CXXRecordDecl *RD,
                                   clang::ASTContext &Ctx) {
        lshaz::CacheLineMap map(RD, Ctx, 64);

        check(map.recordSizeBytes() == 128, "sizeof Aligned == 128");
        check(map.linesSpanned() == 2, "spans 2 cache lines");

        auto *fa = findField(map, "a");
        auto *fb = findField(map, "b");
        check(fa && fa->offsetBytes == 0, "a at offset 0");
        check(fb && fb->offsetBytes == 64, "b at offset 64 (alignas(64))");
        check(fa && fa->startLine == 0, "a on line 0");
        check(fb && fb->startLine == 1, "b on line 1");
    });
}

// Nested struct, sub-fields are recursively collected.
// struct Inner { int a; int b; };
// struct Outer { Inner inner; int c; };
// inner.a@0, inner.b@4, c@8 -> 12B
void testNestedStruct() {
    std::cerr << "test: nested struct recursive field collection\n";
    const char *src = R"(
        struct Inner { int a; int b; };
        struct Outer { Inner inner; int c; };
    )";

    withRecord(src, "Outer", [](const clang::CXXRecordDecl *RD,
                                 clang::ASTContext &Ctx) {
        lshaz::CacheLineMap map(RD, Ctx, 64);

        check(map.recordSizeBytes() == 12, "sizeof Outer == 12");

        // CacheLineMap should collect both the top-level field "inner"
        // AND the recursive sub-fields "a" and "b".
        auto *finner = findField(map, "inner");
        check(finner && finner->offsetBytes == 0, "inner at offset 0");
        check(finner && finner->sizeBytes == 8, "inner is 8 bytes");

        // Sub-fields from recursion into Inner.
        auto *fa = findField(map, "a");
        auto *fb = findField(map, "b");
        check(fa && fa->offsetBytes == 0, "inner.a at offset 0");
        check(fb && fb->offsetBytes == 4, "inner.b at offset 4");

        auto *fc = findField(map, "c");
        check(fc && fc->offsetBytes == 8, "c at offset 8");
    });
}

// Mixed atomic/non-atomic on same line -> false sharing candidate.
// struct MixedLine {
//     std::atomic<int> counter;   // 0-3, line 0, atomic
//     int               plain;    // 4-7, line 0, non-atomic mutable
// };
void testFalseSharingCandidate() {
    std::cerr << "test: false sharing candidate detection\n";
    const char *src = R"(
        #include <atomic>
        struct MixedLine {
            std::atomic<int> counter;
            int plain;
        };
    )";

    withRecord(src, "MixedLine", [](const clang::CXXRecordDecl *RD,
                                     clang::ASTContext &Ctx) {
        lshaz::CacheLineMap map(RD, Ctx, 64);

        check(map.totalAtomicFields() == 1, "1 atomic field");
        check(map.totalMutableFields() == 2, "2 mutable fields");

        auto candidates = map.falseSharingCandidateLines();
        check(!candidates.empty(), "at least 1 false sharing candidate line");

        const auto &buckets = map.buckets();
        // With alignof(4), struct can start at offset 60 within a cache line,
        // so maxLinesSpanned may be 2. Verify bucket 0 has the expected fields.
        check(!buckets.empty(), "at least 1 bucket");
        if (!buckets.empty()) {
            check(buckets[0].atomicCount == 1, "bucket 0: 1 atomic");
            check(buckets[0].mutableCount == 2, "bucket 0: 2 mutable");
        }
    });
}

// Field straddling cache line boundary.
// Pack to defeat natural alignment padding so the int lands at offset 62.
// #pragma pack(1):
//     pad[62]@0 + straddler(4)@62 + tail(1)@66 = 67B
//     straddler bytes 62-65 span line 0 (0-63) and line 1 (64-127).
void testFieldStraddling() {
    std::cerr << "test: field straddling cache line boundary\n";
    const char *src = R"(
        #pragma pack(push, 1)
        struct CrossLine {
            char pad[62];
            int straddler;
            char tail;
        };
        #pragma pack(pop)
    )";

    withRecord(src, "CrossLine", [](const clang::CXXRecordDecl *RD,
                                     clang::ASTContext &Ctx) {
        lshaz::CacheLineMap map(RD, Ctx, 64);

        check(map.recordSizeBytes() == 67, "sizeof CrossLine == 67");
        check(map.linesSpanned() == 2, "spans 2 lines");

        auto *fs = findField(map, "straddler");
        check(fs && fs->offsetBytes == 62, "straddler at offset 62");
        check(fs && fs->sizeBytes == 4, "straddler is 4 bytes");
        check(fs && fs->straddles, "straddler straddles line boundary");
        check(fs && fs->startLine == 0, "straddler starts on line 0");
        check(fs && fs->endLine == 1, "straddler ends on line 1");

        auto straddlers = map.straddlingFields();
        // With alignof(1), worst shift = 63. pad[62] at offset 0 also
        // straddles under worst-case alignment: (0+63)/64=0, (0+63+62-1)/64=1.
        check(straddlers.size() >= 1, "straddler detected");
    });
}

// Custom cache line size (128B for ARM64 Apple).
// struct Small { char data[100]; };
// With 64B lines: 2 lines. With 128B lines: 1 line.
void testCustomCacheLineSize() {
    std::cerr << "test: custom cache line size (128B)\n";
    const char *src = R"(
        struct Small { char data[100]; };
    )";

    withRecord(src, "Small", [](const clang::CXXRecordDecl *RD,
                                 clang::ASTContext &Ctx) {
        lshaz::CacheLineMap map64(RD, Ctx, 64);
        lshaz::CacheLineMap map128(RD, Ctx, 128);

        check(map64.linesSpanned() == 2, "64B lines: 2 lines");
        check(map128.linesSpanned() == 1, "128B lines: 1 line");
        check(map64.recordSizeBytes() == map128.recordSizeBytes(),
              "sizeof identical regardless of line size");
    });
}

// Empty base optimization.
// struct Empty {};
// struct WithEmpty : Empty { int x; };
// Layout: EBO applies, sizeof WithEmpty == 4.
void testEmptyBaseOptimization() {
    std::cerr << "test: empty base optimization\n";
    const char *src = R"(
        struct Empty {};
        struct WithEmpty : Empty { int x; };
    )";

    withRecord(src, "WithEmpty", [](const clang::CXXRecordDecl *RD,
                                     clang::ASTContext &Ctx) {
        lshaz::CacheLineMap map(RD, Ctx, 64);

        check(map.recordSizeBytes() == 4, "sizeof WithEmpty == 4 (EBO)");

        auto *fx = findField(map, "x");
        check(fx && fx->offsetBytes == 0, "x at offset 0");
    });
}

// Mutable keyword field detection.
// struct WithMutable {
//     mutable int cache;
//     const int immutable;
// };
void testMutableFieldDetection() {
    std::cerr << "test: mutable keyword field detection\n";
    const char *src = R"(
        struct WithMutable {
            mutable int cache;
            const int immutable;
        };
    )";

    withRecord(src, "WithMutable", [](const clang::CXXRecordDecl *RD,
                                       clang::ASTContext &Ctx) {
        lshaz::CacheLineMap map(RD, Ctx, 64);

        auto *fc = findField(map, "cache");
        auto *fi = findField(map, "immutable");
        check(fc && fc->isMutable, "mutable int cache is mutable");
        check(fi && !fi->isMutable, "const int immutable is not mutable");
        check(map.totalMutableFields() == 1, "1 mutable field");
    });
}

// Bucket population, verify per-line field grouping.
// struct TwoLine {
//     char line0[64];   // exactly fills line 0
//     int  line1_a;     // line 1, offset 64
//     int  line1_b;     // line 1, offset 68
// };
void testBucketPopulation() {
    std::cerr << "test: bucket population per cache line\n";
    const char *src = R"(
        struct TwoLine {
            char line0[64];
            int  line1_a;
            int  line1_b;
        };
    )";

    withRecord(src, "TwoLine", [](const clang::CXXRecordDecl *RD,
                                   clang::ASTContext &Ctx) {
        lshaz::CacheLineMap map(RD, Ctx, 64);

        check(map.recordSizeBytes() == 72, "sizeof TwoLine == 72");
        check(map.linesSpanned() == 2, "best-case 2 cache lines");

        const auto &buckets = map.buckets();
        // alignof(TwoLine) == 4, worst shift = 60. maxLinesSpanned = 3.
        check(buckets.size() >= 2, "at least 2 buckets");

        // Under best-case alignment (shift=0):
        //   bucket 0: line0 (bytes 0-63)
        //   bucket 1: line1_a (64-67), line1_b (68-71)
        // Under worst-case (shift=60):
        //   line0 spans buckets 0-1, line1_a/line1_b in bucket 1 or 2.
        // Key invariant: line1_a and line1_b always share at least one bucket.
        bool foundPairBucket = false;
        for (const auto &b : buckets) {
            unsigned pairCount = 0;
            for (const auto *f : b.fields) {
                if (f->name == "line1_a" || f->name == "line1_b")
                    ++pairCount;
            }
            if (pairCount == 2) { foundPairBucket = true; break; }
        }
        check(foundPairBucket, "line1_a and line1_b share at least one bucket");
    });
}

// Alignment-aware bucketing, struct not cache-line-aligned.
// struct NearBoundary { int a; char pad[52]; int b; };
// sizeof = 60, alignof = 4. Best case: 1 line. Worst case (shift=60):
// a at absolute 60 (line 0), b at absolute 116 (line 1).
// Fields that look co-located under best-case split under worst-case.
void testAlignmentAwareBucketing() {
    std::cerr << "test: alignment-aware bucketing (non-cache-line-aligned)\n";
    const char *src = R"(
        struct NearBoundary { int a; char pad[52]; int b; };
    )";

    withRecord(src, "NearBoundary", [](const clang::CXXRecordDecl *RD,
                                        clang::ASTContext &Ctx) {
        lshaz::CacheLineMap map(RD, Ctx, 64);

        check(map.recordSizeBytes() == 60, "sizeof NearBoundary == 60");
        check(map.linesSpanned() == 1, "best-case: 1 cache line");
        check(map.maxLinesSpanned() == 2, "worst-case: 2 cache lines");
        check(!map.isCacheLineAligned(), "not cache-line-aligned");

        auto *fa = findField(map, "a");
        auto *fb = findField(map, "b");
        check(fa && fa->startLine == 0, "a best-case line 0");
        check(fb && fb->startLine == 0, "b best-case line 0");

        // Under worst-case shift, b moves to line 1.
        check(fb && fb->worstStartLine > fb->startLine,
              "b worst-case line > best-case line");

        // Key: a and b should appear in separate buckets under worst-case,
        // but ALSO share bucket 0 under best-case. The union bucketing
        // means both appear in bucket 0 (best-case) and b also in bucket 1.
        const auto &buckets = map.buckets();
        check(buckets.size() == 2, "2 buckets (worst-case span)");
    });
}

// Alignas(64) struct, best-case == worst-case.
void testCacheLineAlignedBucketing() {
    std::cerr << "test: cache-line-aligned struct (alignas(64))\n";
    const char *src = R"(
        struct alignas(64) Aligned64 { int a; int b; };
    )";

    withRecord(src, "Aligned64", [](const clang::CXXRecordDecl *RD,
                                     clang::ASTContext &Ctx) {
        lshaz::CacheLineMap map(RD, Ctx, 64);

        check(map.isCacheLineAligned(), "cache-line-aligned");
        check(map.linesSpanned() == map.maxLinesSpanned(),
              "best-case == worst-case for aligned struct");
        check(map.linesSpanned() == 1, "1 cache line");

        auto *fa = findField(map, "a");
        check(fa && fa->startLine == fa->worstStartLine,
              "a: best == worst when struct is aligned");
    });
}

// Thread-role fact collection: entry detection through
// pthread_create / std::thread, name-keyed call edges, and
// field-writer names. The map half of the cross-TU reduce.
void testThreadRoleFactCollection() {
    std::cerr << "test: thread-role fact collection\n";
    const std::string src = R"cpp(
        typedef unsigned long pthread_t;
        extern "C" int pthread_create(pthread_t*, const void*,
                                      void *(*)(void*), void*);
        struct Stats { int mainCount; int ioCount; };
        Stats g;
        void helper() { g.mainCount++; }
        void *ioLoop(void *) { g.ioCount++; return nullptr; }
        int main() {
            pthread_t t;
            pthread_create(&t, nullptr, &ioLoop, nullptr);
            helper();
            return 0;
        }
    )cpp";

    auto AST = clang::tooling::buildASTFromCode(src, "test_input.cpp",
        std::make_shared<clang::PCHContainerOperations>());
    if (!AST) {
        std::cerr << "  FAIL: AST parse failed\n";
        ++failures;
        return;
    }
    auto &Ctx = AST->getASTContext();
    auto *TU = Ctx.getTranslationUnitDecl();

    lshaz::CallGraph cg(Ctx);
    cg.buildFromTU(TU);
    check(cg.threadEntryNames().count("ioLoop") == 1,
          "pthread_create arg detected as entry through unary &");

    lshaz::ThreadRoleSummary facts;
    cg.snapshotForThreadRoles(facts);
    check(facts.threadEntries.count("ioLoop") == 1,
          "entry survives snapshot");
    check(facts.callEdges.count("main") == 1 &&
              facts.callEdges["main"].count("helper") == 1,
          "direct edge main->helper snapshotted by name");

    lshaz::EscapeAnalysis escape(Ctx);
    escape.scanTranslationUnit(TU);
    escape.appendFieldAccessNames(facts);
    check(facts.fieldWriters.count("Stats::mainCount") == 1 &&
              facts.fieldWriters["Stats::mainCount"].count("helper") == 1,
          "field writer attributed by name");
    check(facts.fieldWriters.count("Stats::ioCount") == 1 &&
              facts.fieldWriters["Stats::ioCount"].count("ioLoop") == 1,
          "io-side field writer attributed");

    // The full loop: facts -> verdicts -> disjointness.
    auto v = lshaz::computeThreadRoles(facts, {}, {});
    check(v.fieldsHaveDisjointWriterRoles(facts, "Stats::mainCount",
                                          "Stats::ioCount"),
          "end-to-end: main vs io writer fields are disjoint");
}

void testThreadRoleSpawnerWrapper() {
    std::cerr << "test: spawner-wrapper entry detection\n";
    const std::string src = R"cpp(
        typedef unsigned long pthread_t;
        extern "C" int pthread_create(pthread_t*, const void*,
                                      void *(*)(void*), void*);
        static void create_worker(void *(*func)(void *), void *arg) {
            pthread_t t;
            pthread_create(&t, nullptr, func, arg);
        }
        void *poolWorker(void *) { return nullptr; }
        void setup() { create_worker(poolWorker, nullptr); }
    )cpp";

    auto AST = clang::tooling::buildASTFromCode(src, "test_input.cpp",
        std::make_shared<clang::PCHContainerOperations>());
    if (!AST) {
        std::cerr << "  FAIL: AST parse failed\n";
        ++failures;
        return;
    }
    lshaz::CallGraph cg(AST->getASTContext());
    cg.buildFromTU(AST->getASTContext().getTranslationUnitDecl());
    check(cg.threadEntryNames().count("poolWorker") == 1,
          "function literal through spawner wrapper detected as entry");
    check(cg.threadEntryNames().count("create_worker") == 0,
          "the wrapper itself is not an entry");
}

// Contention needs two cores, not two writer functions. A pool running one
// writer already has them, so multiplicity has to be visible -- and the loop
// is normally around the *wrapper*, not the pthread_create inside it.
void testPoolRoleMultiplicity() {
    std::cerr << "test: loop-spawned thread entries are pool roles\n";
    const std::string src = R"cpp(
        typedef unsigned long pthread_t;
        extern "C" int pthread_create(pthread_t*, const void*,
                                      void *(*)(void*), void*);
        static void create_worker(void *(*func)(void *), void *arg) {
            pthread_t t;
            pthread_create(&t, nullptr, func, arg);
        }
        void *poolWorker(void *) { return nullptr; }
        void *loneWorker(void *) { return nullptr; }
        void bump();
        void *poolCallee(void *) { bump(); return nullptr; }
        void spawnPool() {
            for (int i = 0; i < 4; ++i) create_worker(poolWorker, nullptr);
        }
        void spawnOne() {
            pthread_t t;
            pthread_create(&t, nullptr, loneWorker, nullptr);
        }
    )cpp";

    auto AST = clang::tooling::buildASTFromCode(src, "test_input.cpp",
        std::make_shared<clang::PCHContainerOperations>());
    if (!AST) {
        std::cerr << "  FAIL: AST parse failed\n";
        ++failures;
        return;
    }
    auto &Ctx = AST->getASTContext();
    lshaz::CallGraph cg(Ctx);
    cg.buildFromTU(Ctx.getTranslationUnitDecl());

    class FnFinder : public clang::RecursiveASTVisitor<FnFinder> {
    public:
        std::map<std::string, const clang::FunctionDecl *> fns;
        bool VisitFunctionDecl(clang::FunctionDecl *FD) {
            if (FD->getIdentifier()) fns[FD->getNameAsString()] = FD;
            return true;
        }
    } finder;
    finder.TraverseDecl(Ctx.getTranslationUnitDecl());

    check(cg.runsOnManyThreads(finder.fns["poolWorker"]),
          "entry spawned in a loop through a wrapper is a pool role");
    check(!cg.runsOnManyThreads(finder.fns["loneWorker"]),
          "entry spawned once is not a pool role");
}

// atomic_type_names is documented as THE remedy for codebases that wrap
// atomics in an opaque struct. It reached only rules that constructed a
// CacheLineMap, so five others stayed blind on exactly those codebases.
// The wrapper here is deliberately plain: no _Atomic, no volatile, and a
// name without "atomic" in it, so nothing but the configuration can see it
// and the test cannot pass for an unrelated reason.
void testConfiguredAtomicWrapperIsSeen() {
    std::cerr << "test: config-named atomic wrappers reach escape analysis\n";
    const std::string src = R"cpp(
        typedef struct { long counter; } refcnt_t;
        struct ShardStats { refcnt_t hits; refcnt_t misses; long pad[6]; };
        struct Plain { long a; long b; };
    )cpp";

    withRecord(src, "ShardStats",
        [](const clang::CXXRecordDecl *RD, clang::ASTContext &Ctx) {
            lshaz::EscapeAnalysis bare(Ctx);
            check(!bare.hasAtomicMembers(RD),
                  "unconfigured: opaque wrapper is invisible, as documented");

            lshaz::EscapeAnalysis configured(Ctx);
            configured.setAtomicTypeNames({"refcnt_t"});
            check(configured.hasAtomicMembers(RD),
                  "configured: opaque wrapper is recognised as atomic");
        });

    withRecord(src, "Plain",
        [](const clang::CXXRecordDecl *RD, clang::ASTContext &Ctx) {
            lshaz::EscapeAnalysis configured(Ctx);
            configured.setAtomicTypeNames({"refcnt_t"});
            check(!configured.hasAtomicMembers(RD),
                  "configured: an unrelated record is not swept up");
        });
}

// Sharing and a handoff are indistinguishable by writer count: both are
// written from several functions, one of them thread-borne. What separates
// them is how the writer reaches the object. A queued request object has
// one owner at any instant however many threads touch it, and grading it
// as contended was the dominant FL002 false positive.
void testStandingVersusHandedWrites() {
    std::cerr << "test: standing writes distinguish sharing from handoff\n";
    const std::string src = R"cpp(
        struct Shared { long hits; long misses; };
        struct Handed { long len; long off; };
        static Shared g_shared;
        void bumpShared(int hit) {
            if (hit) g_shared.hits++; else g_shared.misses++;
        }
        void fillHanded(Handed *h, long n) { h->len = n; h->off = 0; }
    )cpp";

    withRecord(src, "Shared",
        [&](const clang::CXXRecordDecl *RD, clang::ASTContext &Ctx) {
            lshaz::EscapeAnalysis ea(Ctx);
            ea.scanTranslationUnit(Ctx.getTranslationUnitDecl());
            check(ea.hasStandingWrites(RD),
                  "a named global object is written by standing access");
        });

    withRecord(src, "Handed",
        [&](const clang::CXXRecordDecl *RD, clang::ASTContext &Ctx) {
            lshaz::EscapeAnalysis ea(Ctx);
            ea.scanTranslationUnit(Ctx.getTranslationUnitDecl());
            check(!ea.hasStandingWrites(RD),
                  "an object written only through a parameter is handed over");
        });
}

void testThreadRoleStdThreadEntry() {
    std::cerr << "test: std::thread constructor entry detection\n";
    const std::string src = R"cpp(
        namespace std {
        class thread {
        public:
            template <class F> thread(F f);
            template <class F, class O> thread(F f, O o);
        };
        template <class F, class... A> int bind(F, A...);
        }
        void workerFn() {}
        void spawn() { std::thread t(workerFn); }
        struct Engine {
            void run();
            void bound();
        };
        void spawnMember(Engine *e) { std::thread t(&Engine::run, e); }
        void spawnBind(Engine *e) { std::thread t(std::bind(&Engine::bound, e)); }
    )cpp";

    auto AST = clang::tooling::buildASTFromCode(src, "test_input.cpp",
        std::make_shared<clang::PCHContainerOperations>());
    if (!AST) {
        std::cerr << "  FAIL: AST parse failed\n";
        ++failures;
        return;
    }
    lshaz::CallGraph cg(AST->getASTContext());
    cg.buildFromTU(AST->getASTContext().getTranslationUnitDecl());
    check(cg.threadEntryNames().count("workerFn") == 1,
          "std::thread ctor arg detected as entry");
    check(cg.threadEntryNames().count("Engine::run") == 1,
          "member-function-pointer entry detected");
    check(cg.threadEntryNames().count("Engine::bound") == 1,
          "std::bind target detected as entry");
}

void testThreadRoleLambdaEntry() {
    std::cerr << "test: lambda thread entry with own-node attribution\n";
    const std::string src = R"cpp(
        namespace std {
        class thread {
        public:
            template <class F> thread(F f);
        };
        }
        struct Stats { int mainCount; int ioCount; };
        Stats g;
        void mainSide() { g.mainCount++; }
        void spawn() {
            std::thread t([] { g.ioCount++; });
            mainSide();
        }
        int main() { spawn(); return 0; }
    )cpp";

    auto AST = clang::tooling::buildASTFromCode(src, "test_input.cpp",
        std::make_shared<clang::PCHContainerOperations>());
    if (!AST) {
        std::cerr << "  FAIL: AST parse failed\n";
        ++failures;
        return;
    }
    auto &Ctx = AST->getASTContext();
    auto *TU = Ctx.getTranslationUnitDecl();

    lshaz::CallGraph cg(Ctx);
    cg.buildFromTU(TU);
    check(cg.threadEntryNames().size() == 1 &&
              cg.threadEntryNames().begin()->rfind("spawn::lambda:", 0) == 0,
          "lambda entry named by enclosing function + position");

    lshaz::ThreadRoleSummary facts;
    cg.snapshotForThreadRoles(facts);
    lshaz::EscapeAnalysis escape(Ctx);
    escape.scanTranslationUnit(TU);
    escape.appendFieldAccessNames(facts);

    // The worker lambda's write must attribute to the lambda node, not
    // the spawner, and the pair must come out disjoint end to end.
    bool ioWriterIsLambda = false;
    auto it = facts.fieldWriters.find("Stats::ioCount");
    if (it != facts.fieldWriters.end() && it->second.size() == 1)
        ioWriterIsLambda =
            it->second.begin()->rfind("spawn::lambda:", 0) == 0;
    check(ioWriterIsLambda, "lambda-body write attributed to lambda node");

    auto v = lshaz::computeThreadRoles(facts, {}, {});
    check(v.fieldsHaveDisjointWriterRoles(facts, "Stats::mainCount",
                                          "Stats::ioCount"),
          "end-to-end: lambda worker vs main writers disjoint");
}

} // anonymous namespace

// The parser behind every non-coherence measurement the tool takes. A silent
// failure here reads as a machine that did nothing, which is the one thing
// the rest of this codebase spends its effort making impossible.
void testPerfReportParsing() {
    using namespace lshaz;
    const std::string report =
        "# To display the perf.data header info, please use --header\n"
        "#\n"
        "# Samples: 56K of event 'branch-misses'\n"
        "#\n"
        "# Overhead  Symbol\n"
        "# ........  ......\n"
        "#\n"
        "    19.61%  [.] dictPrefetcherRun.lto_priv.0\n"
        "     8.44%  [.] processCommand\n"
        "     0.01%  [k] __softirqentry_text_start\n"
        "     0.00%  [.] neverRuns\n";
    EventProfile ev;
    std::string err;
    check(parsePerfReport(report, ev, err), "perf report parses");
    // Linker specialisation suffixes are not part of the name a finding
    // knows the function by.
    check(ev.ran("dictPrefetcherRun"), "linker suffix stripped from symbol");
    check(ev.samplesFor("dictPrefetcherRun") == 196100, "share read as ppm");
    check(ev.samplesFor("processCommand") == 84400, "second share read");
    // Present at zero is not absent: the symbol ran, the event did not
    // happen there, and those are different answers.
    check(ev.ran("neverRuns"), "present at zero is not absent");
    check(ev.samplesFor("neverRuns") == 0, "a zero share reads as zero");
    check(!ev.ran("notInTheProfile"), "absent symbol is absent");
    check(ev.samplesFor("notInTheProfile") == 0, "absent symbol has no share");

    EventProfile empty;
    std::string err2;
    check(!parsePerfReport("nothing here at all\n", empty, err2),
          "a file naming no symbol is an error, not an empty profile");
    check(!err2.empty(), "the error says what was expected");
}

// Loop bounds the source states, which is what separates a sixteen-iteration
// loop from one over a runtime bound. Zero means not derivable, and the
// caller substitutes its own default rather than this guessing.
void testConstantTripCounts() {
    using namespace lshaz;
    struct Case { const char *code; uint64_t want; };
    const Case cases[] = {
        {"void f(){ for (int i = 0; i < 16; i++) g(); }", 16},
        {"void f(){ for (int i = 0; i <= 15; i++) g(); }", 16},
        {"void f(){ for (int i = 0; i < 32; i += 4) g(); }", 8},
        {"void f(){ for (int i = 10; i > 0; i--) g(); }", 10},
        {"enum { N = 24 }; void f(){ for (int i = 0; i < N; i++) g(); }", 24},
        {"void f(int n){ for (int i = 0; i < n; i++) g(); }", 0},
        {"void f(){ for (int i = 0; i > 8; i++) g(); }", 0},
        {"void f(){ int i; for (i = 0; i < 7; ++i) g(); }", 7},
    };
    for (const auto &c : cases) {
        const std::string src = std::string("void g();\n") + c.code;
        auto unit = clang::tooling::buildASTFromCode(src, "t.cpp");
        check(unit != nullptr, "fragment parses");
        const clang::ForStmt *loop = nullptr;
        struct V : clang::RecursiveASTVisitor<V> {
            const clang::ForStmt **out;
            bool VisitForStmt(clang::ForStmt *S) { *out = S; return false; }
        } v{};
        v.out = &loop;
        v.TraverseDecl(unit->getASTContext().getTranslationUnitDecl());
        check(loop != nullptr, "loop found");
        const uint64_t got = constantTripCount(loop, unit->getASTContext());
        if (got != c.want)
            std::cerr << "    trip count for [" << c.code << "] got " << got
                      << " want " << c.want << "\n";
        check(got == c.want, "trip count matches what the source states");
    }
}


// Ratios taken from one divide measured three ways: the instruction alone,
// its share of a cycles profile, and end to end. The spread is the scopes,
// not noise, so the median is wrong for all three.
void testInstrumentScopesDoNotBlend() {
    using namespace lshaz;
    CostCalibration c;
    auto row = [&](Milli measured, const char *instrument) {
        CostObservation o;
        o.mechanism = "divide";
        o.machine = "test-machine";
        o.workload = "mixed-read-write";
        o.site = "clock.c:81";
        o.predicted = toMilli(1);
        o.measured = measured;
        o.instrument = instrument;
        c.observe(o);
    };
    row(710, "microbench");
    row(1080, "cycles-profile");
    row(1440, "throughput-ab");

    auto any = c.factorFor("divide", "test-machine", "mixed-read-write",
                           "clock.c:81");
    check(any.has_value(), "unfiltered query finds the rows");
    check(any->value == 1080, "unfiltered median is the middle scope");
    check(any->mixedInstruments,
          "a median spanning three instruments says so");

    struct { const char *instrument; Milli want; } cases[] = {
        {"microbench", 710}, {"cycles-profile", 1080}, {"throughput-ab", 1440},
    };
    for (const auto &w : cases) {
        auto f = c.factorFor("divide", "test-machine", "mixed-read-write",
                             "clock.c:81", w.instrument);
        check(f.has_value(), "each instrument answers on its own");
        check(f->value == w.want, "and returns its own scope, not the median");
        check(!f->mixedInstruments, "a single instrument is not mixed");
    }
}

// Rows predating the instrument column still load, and do not answer a query
// that names one.
void testLegacyRowsRoundTrip() {
    using namespace lshaz;
    const std::string path = "/tmp/lshaz_calib_legacy.tsv";
    {
        std::ofstream out(path, std::ios::trunc);
        out << "coherence\tbox\twl\t1000\t500\tfoo.c:1\n";
    }
    CostCalibration c;
    std::string err;
    check(c.load(path, err), "a store without the instrument column loads");
    check(c.size() == 1, "and keeps its row");

    auto legacy = c.factorFor("coherence", "box", "wl", "foo.c:1");
    check(legacy.has_value() && legacy->value == 500,
          "an unfiltered query still corrects from it");
    check(!c.factorFor("coherence", "box", "wl", "foo.c:1", "throughput-ab")
               .has_value(),
          "but it does not answer for an instrument it never named");

    check(c.save(path, err), "and it writes back with the new column");
    CostCalibration again;
    check(again.load(path, err) && again.size() == 1, "which reloads");
    std::remove(path.c_str());
}

// A config glob and a profile both mark a function hot with no severity
// ceiling, so an assertion the profile declines to corroborate would otherwise
// grade exactly like a measurement, forever and invisibly.
void testProfileContradictsDeclaration() {
    std::cerr << "test: a profile that omits a declared-hot function says so\n";
    using namespace lshaz;
    const std::string src = R"cpp(
        void declaredHot() {}
        void alsoProfiled() {}
    )cpp";
    auto AST = clang::tooling::buildASTFromCode(src, "test_input.cpp",
        std::make_shared<clang::PCHContainerOperations>());
    if (!AST) { std::cerr << "  FAIL: AST parse failed\n"; ++failures; return; }
    auto &Ctx = AST->getASTContext();

    const clang::FunctionDecl *declared = nullptr, *profiled = nullptr;
    for (auto *D : Ctx.getTranslationUnitDecl()->decls())
        if (auto *FD = llvm::dyn_cast<clang::FunctionDecl>(D)) {
            if (FD->getNameAsString() == "declaredHot") declared = FD;
            if (FD->getNameAsString() == "alsoProfiled") profiled = FD;
        }
    check(declared && profiled, "both functions found");
    if (!declared || !profiled) return;

    Config cfg;
    cfg.hotFunctionPatterns = {"declaredHot", "alsoProfiled"};

    // No profile supplied: a declaration is all the evidence there is, and
    // nothing contradicts it.
    {
        HotPathOracle oracle(cfg);
        check(oracle.isFunctionHot(declared), "config glob marks it hot");
        check(!oracle.profileContradictsDeclaration(declared),
              "with no profile there is nothing to disagree with");
    }

    // A profile naming only one of them contradicts the other.
    {
        HotPathOracle oracle(cfg);
        oracle.loadProfileHotFunctions({"alsoProfiled"});
        check(oracle.isFunctionHot(declared) && oracle.isFunctionHot(profiled),
              "both still register as hot");
        check(oracle.profileContradictsDeclaration(declared),
              "the declared-only function is uncorroborated");
        check(!oracle.profileContradictsDeclaration(profiled),
              "the one the profile names is corroborated");
        check(oracle.hotnessSource(profiled) == HotnessSource::Profiled,
              "and it upgrades to profile-sourced hotness");
    }
}

int main() {
    testProfileContradictsDeclaration();
    testInstrumentScopesDoNotBlend();
    testLegacyRowsRoundTrip();
    testPerfReportParsing();
    testConstantTripCounts();
    testSimplePOD();
    testPaddedStruct();
    testCacheLineSpanning();
    testAtomicDetection();
    testInheritanceLayout();
    testAlignasLayout();
    testNestedStruct();
    testFalseSharingCandidate();
    testFieldStraddling();
    testCustomCacheLineSize();
    testEmptyBaseOptimization();
    testMutableFieldDetection();
    testBucketPopulation();
    testAlignmentAwareBucketing();
    testCacheLineAlignedBucketing();
    testThreadRoleFactCollection();
    testThreadRoleSpawnerWrapper();
    testPoolRoleMultiplicity();
    testConfiguredAtomicWrapperIsSeen();
    testStandingVersusHandedWrites();
    testThreadRoleStdThreadEntry();
    testThreadRoleLambdaEntry();

    std::cerr << "\n" << passed << " passed, " << failures << " failed\n";
    if (failures > 0) {
        std::cerr << "ANALYSIS GROUND TRUTH TESTS FAILED\n";
        return 1;
    }
    std::cerr << "All analysis ground truth tests passed.\n";
    return 0;
}
