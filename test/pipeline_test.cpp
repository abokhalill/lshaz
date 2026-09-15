// Covers matchesGlob, filterSources, CompileDBResolver and RepoProvider.
// No subprocesses, so these stay isolated and deterministic.

#include "pmu_calib.h"

#include "lshaz/analysis/escape_summary.h"
#include "lshaz/hypothesis/pmu_calibration.h"
#include "lshaz/analysis/thread_role.h"
#include "lshaz/analysis/phase.h"
#include "lshaz/analysis/memory_profile.h"
#include "lshaz/core/diagnostic.h"
#include "lshaz/core/ladder.h"
#include "lshaz/analysis/memory.h"
#include "lshaz/pipeline/compile_db.h"
#include "lshaz/pipeline/repo.h"
#include "lshaz/pipeline/filter.h"

#include "../src/pipeline/shard_ipc.h"

#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

int failures = 0;
int passed = 0;

void check(bool cond, const char *label) {
    if (!cond) {
        std::cerr << "  FAIL: " << label << "\n";
        ++failures;
    } else {
        ++passed;
    }
}

// ===== matchesGlob =====

void testMatchesGlobSuffix() {
    std::cerr << "test: matchesGlob suffix\n";
    using lshaz::matchesGlob;
    check(matchesGlob("/a/b/file.cpp", "*.cpp"), "*.cpp matches .cpp");
    check(matchesGlob("/a/b/file.hpp", "*.hpp"), "*.hpp matches .hpp");
    check(!matchesGlob("/a/b/file.cpp", "*.hpp"), "*.hpp rejects .cpp");
    check(matchesGlob("/a/b/c.h", "*.h"), "*.h matches .h");
    check(!matchesGlob("/a/b/c.hpp", "*.h"), "*.h rejects .hpp");
}

void testMatchesGlobContainment() {
    std::cerr << "test: matchesGlob containment\n";
    using lshaz::matchesGlob;
    check(matchesGlob("/src/test/foo.cpp", "*test*"), "*test* matches");
    check(!matchesGlob("/src/prod/foo.cpp", "*test*"), "*test* rejects");
    check(matchesGlob("/a/b/main.cpp", "*main*"), "*main* matches");
}

void testMatchesGlobSubstring() {
    std::cerr << "test: matchesGlob fnmatch literals\n";
    using lshaz::matchesGlob;
    // fnmatch: bare string is a literal match, not substring.
    check(!matchesGlob("/a/b/feed_handler.cpp", "feed_handler"), "bare literal no match");
    check(matchesGlob("feed_handler", "feed_handler"), "exact literal match");
    check(matchesGlob("/a/b/feed_handler.cpp", "*feed_handler*"), "containment via *...*");
    check(!matchesGlob("/a/b/order_book.cpp", "*feed_handler*"), "rejects non-match");
    // fnmatch supports ? and character classes.
    check(matchesGlob("/a/b/foo.cpp", "/a/b/fo?.cpp"), "? wildcard");
    check(matchesGlob("/a/b/foo.cpp", "/a/b/[fg]oo.cpp"), "character class");
}

void testMatchesGlobEmpty() {
    std::cerr << "test: matchesGlob empty pattern\n";
    using lshaz::matchesGlob;
    check(!matchesGlob("/a/b.cpp", ""), "empty pattern never matches");
}

void testMatchesGlobEdgeCases() {
    std::cerr << "test: matchesGlob edge cases\n";
    using lshaz::matchesGlob;
    check(matchesGlob("a.cpp", "*.cpp"), "no path prefix");
    check(matchesGlob("*.cpp", "*.cpp"), "literal asterisk in filename");
    check(!matchesGlob("", "*.cpp"), "empty path");
    check(matchesGlob("/a/b/c", "*"), "single asterisk matches all");
}

// ===== filterSources =====

void testFilterSourcesNoFilters() {
    std::cerr << "test: filterSources no filters\n";
    lshaz::FilterOptions f;
    std::vector<std::string> src = {"a.cpp", "b.cpp", "c.cpp"};
    auto out = lshaz::filterSources(src, f);
    check(out.size() == 3, "all pass through");
}

void testFilterSourcesInclude() {
    std::cerr << "test: filterSources include\n";
    lshaz::FilterOptions f;
    f.includeFiles = {"*.cpp"};
    std::vector<std::string> src = {"a.cpp", "b.h", "c.cpp"};
    auto out = lshaz::filterSources(src, f);
    check(out.size() == 2, "only .cpp files");
    check(out[0] == "a.cpp" && out[1] == "c.cpp", "correct files");
}

void testFilterSourcesExclude() {
    std::cerr << "test: filterSources exclude\n";
    lshaz::FilterOptions f;
    f.excludeFiles = {"*test*"};
    std::vector<std::string> src = {"src/main.cpp", "test/foo.cpp", "src/bar.cpp"};
    auto out = lshaz::filterSources(src, f);
    check(out.size() == 2, "test file excluded");
}

void testFilterSourcesMaxFiles() {
    std::cerr << "test: filterSources maxFiles\n";
    lshaz::FilterOptions f;
    f.maxFiles = 2;
    std::vector<std::string> src = {"a.cpp", "b.cpp", "c.cpp", "d.cpp"};
    auto out = lshaz::filterSources(src, f);
    check(out.size() == 2, "capped at 2");
    check(out[0] == "a.cpp" && out[1] == "b.cpp", "first 2");
}

void testFilterSourcesCombined() {
    std::cerr << "test: filterSources combined\n";
    lshaz::FilterOptions f;
    f.includeFiles = {"*.cpp"};
    f.excludeFiles = {"*test*"};
    f.maxFiles = 1;
    std::vector<std::string> src = {"test.cpp", "main.cpp", "util.cpp"};
    auto out = lshaz::filterSources(src, f);
    check(out.size() == 1, "one result");
    check(out[0] == "main.cpp", "correct file after all filters");
}

void testFilterSourcesEmpty() {
    std::cerr << "test: filterSources empty input\n";
    lshaz::FilterOptions f;
    f.includeFiles = {"*.cpp"};
    auto out = lshaz::filterSources({}, f);
    check(out.empty(), "empty input -> empty output");
}

// ===== CompileDBResolver =====

void testCandidatePaths() {
    std::cerr << "test: CompileDBResolver candidatePaths\n";
    auto paths = lshaz::CompileDBResolver::candidatePaths("/project");
    check(!paths.empty(), "non-empty candidate list");
    bool hasBuild = false;
    for (const auto &p : paths) {
        if (p.find("/project/build/compile_commands.json") != std::string::npos)
            hasBuild = true;
    }
    check(hasBuild, "build/ is a candidate");
}

void testDiscoverFindsExisting() {
    std::cerr << "test: CompileDBResolver discover\n";
    auto tmp = fs::temp_directory_path() / ("lshaz_unit_disc_" + std::to_string(getpid()));
    fs::create_directories(tmp / "build");
    std::ofstream(tmp / "build" / "compile_commands.json") << "[]";

    auto found = lshaz::CompileDBResolver::discover(tmp.string());
    check(!found.empty(), "found compile_commands.json");
    check(found.find("build/compile_commands.json") != std::string::npos, "in build/");

    fs::remove_all(tmp);
}

void testDiscoverReturnsEmptyWhenMissing() {
    std::cerr << "test: CompileDBResolver discover missing\n";
    auto tmp = fs::temp_directory_path() / ("lshaz_unit_miss_" + std::to_string(getpid()));
    fs::create_directories(tmp);

    auto found = lshaz::CompileDBResolver::discover(tmp.string());
    check(found.empty(), "empty when not found");

    fs::remove_all(tmp);
}

void testDiscoverPriority() {
    std::cerr << "test: CompileDBResolver discover priority (build/ before .)\n";
    auto tmp = fs::temp_directory_path() / ("lshaz_unit_prio_" + std::to_string(getpid()));
    fs::create_directories(tmp / "build");
    std::ofstream(tmp / "build" / "compile_commands.json") << "[{\"build\":true}]";
    std::ofstream(tmp / "compile_commands.json") << "[{\"root\":true}]";

    auto found = lshaz::CompileDBResolver::discover(tmp.string());
    check(found.find("/build/") != std::string::npos, "build/ wins over .");

    fs::remove_all(tmp);
}

// ===== RepoProvider =====

void testIsRemoteURL() {
    std::cerr << "test: RepoProvider isRemoteURL\n";
    using lshaz::RepoProvider;
    check(RepoProvider::isRemoteURL("https://github.com/foo/bar"), "https");
    check(RepoProvider::isRemoteURL("http://github.com/foo/bar"), "http");
    check(RepoProvider::isRemoteURL("git@github.com:foo/bar.git"), "git@");
    check(!RepoProvider::isRemoteURL("/home/user/project"), "local path");
    check(!RepoProvider::isRemoteURL("./relative"), "relative path");
    check(!RepoProvider::isRemoteURL(""), "empty string");
}

void testAcquireLocalPath() {
    std::cerr << "test: RepoProvider acquire local path\n";
    auto acq = lshaz::RepoProvider::acquire("/some/local/path");
    check(acq.localPath == "/some/local/path", "passthrough");
    check(acq.tempDir.empty(), "no temp dir");
    check(!acq.cloned, "not cloned");
    check(acq.error.empty(), "no error");
}

// ===== EscapeSummary =====

void testEscapeSummaryMerge() {
    std::cerr << "test: EscapeSummary merge overlapping types\n";
    using namespace lshaz;
    TypeEscapeSignals a;
    a.hasAtomics = true;
    a.accessorCount = 3;

    TypeEscapeSignals b;
    b.hasSyncPrims = true;
    b.hasPublication = true;
    b.accessorCount = 2;

    a.merge(b);
    check(a.hasAtomics, "atomics preserved");
    check(a.hasSyncPrims, "sync merged in");
    check(a.hasPublication, "publication merged in");
    check(a.accessorCount == 5, "accessor counts summed");
    check(a.hasStructuralEscape(), "structural escape true");
    check(a.hasAnyEscape(), "any escape true");
}

void testEscapeSummaryMergeDisjoint() {
    std::cerr << "test: EscapeSummary merge disjoint types\n";
    using namespace lshaz;
    EscapeSummary s1, s2;
    s1["TypeA"].hasAtomics = true;
    s2["TypeB"].hasVolatile = true;

    mergeEscapeSummaries(s1, s2);
    check(s1.size() == 2, "both types present");
    check(s1["TypeA"].hasAtomics, "TypeA atomics");
    check(s1["TypeB"].hasVolatile, "TypeB volatile");
}

void testEscapeSummaryMergeAccessorAccumulation() {
    std::cerr << "test: EscapeSummary accessor count accumulates across TUs\n";
    using namespace lshaz;
    EscapeSummary s1, s2, s3;
    s1["Foo"].accessorCount = 4;
    s2["Foo"].accessorCount = 7;
    s3["Foo"].accessorCount = 1;

    mergeEscapeSummaries(s1, s2);
    mergeEscapeSummaries(s1, s3);
    check(s1["Foo"].accessorCount == 12, "4+7+1 = 12");
}

void testEscapeSummaryStructuralVsPublication() {
    std::cerr << "test: EscapeSummary structural vs publication distinction\n";
    using namespace lshaz;
    TypeEscapeSignals pubOnly;
    pubOnly.hasPublication = true;
    check(!pubOnly.hasStructuralEscape(), "publication alone not structural");
    check(pubOnly.hasAnyEscape(), "publication counts as any escape");

    TypeEscapeSignals none;
    check(!none.hasStructuralEscape(), "empty has no structural");
    check(!none.hasAnyEscape(), "empty has no escape");
}

// The only negative strong enough to retire a finding. A predicate that never
// fires and one that always fires are equally invisible in a scan summary, so
// both directions are pinned here.
void testSharingRouteRefutationSeparates() {
    std::cerr << "test: sharing-route refutation separates program from tracker\n";
    using namespace lshaz;

    TypeEscapeSignals seen;
    seen.hasStandingWrites = true;
    check(!seen.hasSharingRoute(), "standing writes alone are not a route");
    check(seen.sharingRouteRefuted(),
          "a working tracker finding no route refutes the mechanism");

    TypeEscapeSignals shared = seen;
    shared.hasPublication = true;
    check(shared.hasSharingRoute(), "publication is a route");
    check(!shared.sharingRouteRefuted(), "a live route is not refuted");

    TypeEscapeSignals blind;
    blind.fieldExtents["buf"] = FieldExtent{0, 64, false, /*plainScalar=*/false};
    check(!blind.writesObservable(), "an aggregate field hides writes");
    check(!blind.sharingRouteRefuted(),
          "silence about an unobservable field refutes nothing");

    TypeEscapeSignals scalars;
    scalars.fieldExtents["head"] = FieldExtent{0, 8, false, /*plainScalar=*/true};
    scalars.fieldExtents["tail"] = FieldExtent{8, 8, false, /*plainScalar=*/true};
    check(scalars.writesObservable(), "plain scalars are observable");
    check(scalars.sharingRouteRefuted(),
          "observable silence about every field is a program fact");

    TypeEscapeSignals atomics;
    atomics.fieldExtents["seq"] = FieldExtent{0, 8, /*isAtomic=*/true, false};
    check(atomics.writesObservable(), "atomic writes are observable");

    TypeEscapeSignals empty;
    check(!empty.writesObservable(), "no extents means nothing was examined");
    check(!empty.sharingRouteRefuted(), "an unexamined type is not refuted");
}

// An unmatched thread-creation vocabulary looks exactly like a single-threaded
// program, so a wrapped pthread_create would become corpus-wide recall loss.
void testThreadRouteIsItsOwnPositiveControl() {
    std::cerr << "test: thread route doubles as a vocabulary positive control\n";
    using namespace lshaz;

    EscapeSummary dark;
    dark["Ring"].hasStandingWrites = true;
    dark["Slab"].hasGlobalInstance = true;
    bool anyRoute = false;
    for (const auto &[n, s] : dark)
        if (s.hasThreadRoute()) anyRoute = true;
    check(!anyRoute, "no type reports a route when nothing spawns a thread");
    check(dark["Ring"].sharingRouteRefuted(),
          "the per-type verdict reads refuted, so the override must be "
          "scan-level");

    EscapeSummary live = dark;
    live["Conn"].hasThreadWriters = true;
    anyRoute = false;
    for (const auto &[n, s] : live)
        if (s.hasThreadRoute()) anyRoute = true;
    check(anyRoute, "one thread-borne type proves the vocabulary matches");
}

void testEscapeSummaryIPCRoundTrip() {
    std::cerr << "test: EscapeSummary IPC round-trip via JSON\n";
    using namespace lshaz;
    // Construct a JSON string matching the IPC format and verify parse.
    // This is a black-box test of the compact format {a,s,o,v,p,n}.
    EscapeSummary original;
    original["ns::Widget"].hasAtomics = true;
    original["ns::Widget"].hasSyncPrims = false;
    original["ns::Widget"].hasSharedOwner = true;
    original["ns::Widget"].hasVolatile = false;
    original["ns::Widget"].hasPublication = true;
    original["ns::Widget"].accessorCount = 42;
    original["Plain"] = {};

    // Simulate serialize -> deserialize by building JSON and re-parsing.
    // Build the compact JSON format manually.
    std::string json = "{";
    bool first = true;
    for (const auto &[name, sig] : original) {
        if (!first) json += ',';
        json += "\"" + name + "\":{";
        json += "\"a\":" + std::to_string(sig.hasAtomics ? 1 : 0);
        json += ",\"s\":" + std::to_string(sig.hasSyncPrims ? 1 : 0);
        json += ",\"o\":" + std::to_string(sig.hasSharedOwner ? 1 : 0);
        json += ",\"v\":" + std::to_string(sig.hasVolatile ? 1 : 0);
        json += ",\"p\":" + std::to_string(sig.hasPublication ? 1 : 0);
        json += ",\"n\":" + std::to_string(sig.accessorCount);
        json += "}";
        first = false;
    }
    json += "}";

    // Parse back (simulate deserializer logic).
    EscapeSummary parsed;
    size_t i = 1; // skip '{'
    while (i < json.size() && json[i] != '}') {
        if (json[i] == ',') ++i;
        // parse key
        if (json[i] != '"') break;
        ++i;
        size_t ks = i;
        while (i < json.size() && json[i] != '"') ++i;
        std::string key = json.substr(ks, i - ks);
        ++i; // skip closing "
        if (i < json.size() && json[i] == ':') ++i;
        if (i < json.size() && json[i] == '{') ++i;
        TypeEscapeSignals sig;
        while (i < json.size() && json[i] != '}') {
            if (json[i] == ',') ++i;
            if (json[i] != '"') break;
            ++i;
            size_t fk = i;
            while (i < json.size() && json[i] != '"') ++i;
            std::string fkey = json.substr(fk, i - fk);
            ++i; // "
            if (i < json.size() && json[i] == ':') ++i;
            int val = 0;
            while (i < json.size() && json[i] >= '0' && json[i] <= '9') {
                val = val * 10 + (json[i] - '0');
                ++i;
            }
            if (fkey == "a") sig.hasAtomics = val != 0;
            else if (fkey == "s") sig.hasSyncPrims = val != 0;
            else if (fkey == "o") sig.hasSharedOwner = val != 0;
            else if (fkey == "v") sig.hasVolatile = val != 0;
            else if (fkey == "p") sig.hasPublication = val != 0;
            else if (fkey == "n") sig.accessorCount = static_cast<unsigned>(val);
        }
        if (i < json.size() && json[i] == '}') ++i;
        parsed[key] = sig;
    }

    check(parsed.size() == original.size(), "same number of types");
    auto wit = parsed.find("ns::Widget");
    check(wit != parsed.end(), "ns::Widget present");
    if (wit != parsed.end()) {
        check(wit->second.hasAtomics == true, "atomics round-trip");
        check(wit->second.hasSyncPrims == false, "sync round-trip");
        check(wit->second.hasSharedOwner == true, "shared_owner round-trip");
        check(wit->second.hasVolatile == false, "volatile round-trip");
        check(wit->second.hasPublication == true, "publication round-trip");
        check(wit->second.accessorCount == 42, "accessor count round-trip");
    }
    auto pit = parsed.find("Plain");
    check(pit != parsed.end(), "Plain present");
    if (pit != parsed.end()) {
        check(!pit->second.hasAnyEscape(), "Plain has no escape");
    }
}

void testCrossTUSuppressionWithSummary() {
    std::cerr << "test: cross-TU suppression with EscapeSummary\n";
    using namespace lshaz;

    // Type with no escape evidence in global summary -> should be suppressed.
    // Type with escape evidence -> should survive.
    EscapeSummary globalEscape;
    globalEscape["EscapedType"].hasAtomics = true;
    // "LocalOnlyType" deliberately absent from summary.

    Diagnostic d1;
    d1.ruleID = "FL002";
    d1.structuralEvidence = {{"thread_escape", "true"}, {"type_name", "EscapedType"}};
    d1.evidenceTier = EvidenceTier::Likely;

    Diagnostic d2;
    d2.ruleID = "FL002";
    d2.structuralEvidence = {{"thread_escape", "true"}, {"type_name", "LocalOnlyType"}};
    d2.evidenceTier = EvidenceTier::Likely;

    // Simulate suppression inline (since applyCrossTUEscapeSuppression is static).
    auto suppressWithSummary = [](std::vector<Diagnostic> &diags,
                                  const EscapeSummary &esc, unsigned totalTUs) {
        if (totalTUs <= 1) return 0u;
        unsigned suppressed = 0;
        for (auto &d : diags) {
            if (d.suppressed) continue;
            auto eit = d.structuralEvidence.find("thread_escape");
            if (eit == d.structuralEvidence.end()) continue;
            if (eit->second != "true" && eit->second != "yes") continue;
            if (d.evidenceTier == EvidenceTier::Proven) continue;
            auto tit = d.structuralEvidence.find("type_name");
            if (tit == d.structuralEvidence.end()) continue;
            auto git = esc.find(tit->second);
            if (git != esc.end() && git->second.hasAnyEscape()) continue;
            d.suppressed = true;
            ++suppressed;
        }
        return suppressed;
    };

    std::vector<Diagnostic> diags = {d1, d2};
    unsigned count = suppressWithSummary(diags, globalEscape, 5);
    check(count == 1, "one suppressed");
    check(!diags[0].suppressed, "EscapedType survives");
    check(diags[1].suppressed, "LocalOnlyType suppressed");
}

void testCrossTUSuppressionPreservesProven() {
    std::cerr << "test: cross-TU suppression preserves Proven tier\n";
    using namespace lshaz;

    EscapeSummary globalEscape; // empty = no evidence for anything

    Diagnostic d;
    d.ruleID = "FL002";
    d.structuralEvidence = {{"thread_escape", "true"}, {"type_name", "Unknown"}};
    d.evidenceTier = EvidenceTier::Proven;

    auto suppressWithSummary = [](std::vector<Diagnostic> &diags,
                                  const EscapeSummary &esc, unsigned totalTUs) {
        for (auto &d : diags) {
            if (d.suppressed) continue;
            auto eit = d.structuralEvidence.find("thread_escape");
            if (eit == d.structuralEvidence.end()) continue;
            if (eit->second != "true" && eit->second != "yes") continue;
            if (d.evidenceTier == EvidenceTier::Proven) continue;
            auto tit = d.structuralEvidence.find("type_name");
            if (tit == d.structuralEvidence.end()) continue;
            auto git = esc.find(tit->second);
            if (git != esc.end() && git->second.hasAnyEscape()) continue;
            d.suppressed = true;
        }
    };

    std::vector<Diagnostic> diags = {d};
    suppressWithSummary(diags, globalEscape, 5);
    check(!diags[0].suppressed, "Proven never suppressed");
}

void testCrossTUSuppressionNoTypeName() {
    std::cerr << "test: cross-TU suppression skips diags without type_name\n";
    using namespace lshaz;

    EscapeSummary globalEscape;

    Diagnostic d;
    d.ruleID = "FL050";
    d.structuralEvidence = {{"thread_escape", "true"}};
    d.evidenceTier = EvidenceTier::Likely;

    auto suppressWithSummary = [](std::vector<Diagnostic> &diags,
                                  const EscapeSummary &esc, unsigned totalTUs) {
        for (auto &d : diags) {
            if (d.suppressed) continue;
            auto eit = d.structuralEvidence.find("thread_escape");
            if (eit == d.structuralEvidence.end()) continue;
            if (eit->second != "true" && eit->second != "yes") continue;
            if (d.evidenceTier == EvidenceTier::Proven) continue;
            auto tit = d.structuralEvidence.find("type_name");
            if (tit == d.structuralEvidence.end()) continue;
            auto git = esc.find(tit->second);
            if (git != esc.end() && git->second.hasAnyEscape()) continue;
            d.suppressed = true;
        }
    };

    std::vector<Diagnostic> diags = {d};
    suppressWithSummary(diags, globalEscape, 5);
    check(!diags[0].suppressed, "no type_name = not suppressed");
}

// ===== ThreadRoleSummary =====

// The real serializer and the real parser, not a reimplementation of the
// format. A test that reimplements the parser passes while the production
// path drops a field, which is exactly the failure this boundary produces:
// correct at --jobs 1, silently incomplete in parallel.
void testShardIPCFieldAccessRoundTrip() {
    std::cerr << "test: per-field access facts survive the shard boundary\n";
    using namespace lshaz;
    ThreadRoleSummary tr;
    tr.fieldWriters["S::hot"] = {"writer"};
    tr.fieldReaders["S::hot"] = {"reader_a", "reader_b"};
    auto &fa = tr.fieldAccess["S::hot"];
    fa.writeSites = 7;
    fa.loopWriteSites = 3;
    fa.standingWriteSites = 6;
    fa.handedWriteSites = 1;
    fa.readSites = 11;
    // A field touched only by reads still has to arrive, or a line whose
    // writer compiled into another shard reads as never written.
    tr.fieldAccess["S::cold"].readSites = 2;

    const std::string wire = serializeShardResult(
        0, {}, {}, EscapeSummary{}, tr, StripedArraySummary{}, ScanCoverage{},
        MemorySummary{});
    ShardIPC parsed;
    check(deserializeShardResult(wire, parsed), "shard record parses");

    const auto &got = parsed.threadRoles.fieldAccess;
    auto it = got.find("S::hot");
    check(it != got.end(), "written field crossed the boundary");
    check(it->second.writeSites == 7, "write sites preserved");
    check(it->second.loopWriteSites == 3, "loop write sites preserved");
    check(it->second.standingWriteSites == 6, "standing writes preserved");
    check(it->second.handedWriteSites == 1, "handed writes preserved");
    check(it->second.readSites == 11, "read sites preserved");
    check(it->second.standing(), "standing verdict survives the round trip");

    auto cold = got.find("S::cold");
    check(cold != got.end(), "read-only field crossed the boundary");
    check(cold->second.readSites == 2, "read-only counts preserved");
}

// The partition is solved in the parent from facts the children collect, so
// every one of them has to cross the boundary. Forgetting one is the failure
// mode this protocol exists to prevent: right at --jobs 1, quietly different
// in parallel.
void testShardIPCPhaseFactsRoundTrip() {
    std::cerr << "test: phase facts survive the shard boundary\n";
    using namespace lshaz;
    ThreadRoleSummary tr;
    tr.callEdges["main"] = {"init", "spawn_all"};
    tr.edgeOrder["main"]["init"] = {1, 1};
    tr.edgeOrder["main"]["spawn_all"] = {2, 5};
    tr.spawnPoints["spawn_all"] = {3, 3};
    tr.indirectCalls["dispatch"]["void *(void *)"] = {4, 4};
    tr.indirectSlotCalls["apply"]["P:apply|0"] = {1, 2};
    tr.addressTakenBySignature["void *(void *)"] = {"worker"};
    tr.fnSlotTargets["P:apply|0"] = {"defrag_alloc"};
    tr.fnSlotForwards["P:inner|1"] = {"P:apply|0"};
    tr.fnSlotOpaque = {"F:T::cb"};
    tr.preMainFunctions = {"ctor"};
    tr.orderUnknown = {"spaghetti"};
    tr.noReturnFunctions = {"die"};
    tr.tailCallee["fatal_with_info"] = "fatal";
    tr.returningFunctions = {"ordinary"};
    tr.callSiteCount["fatal"] = 9;
    tr.unreachableAfterCount["fatal"] = 8;

    const std::string wire = serializeShardResult(
        0, {}, {}, EscapeSummary{}, tr, StripedArraySummary{}, ScanCoverage{},
        MemorySummary{});
    ShardIPC parsed;
    check(deserializeShardResult(wire, parsed), "record with phase facts parses");

    const auto &g = parsed.threadRoles;
    check(g.edgeOrder.at("main").at("init").first == 1 &&
              g.edgeOrder.at("main").at("init").last == 1,
          "a single-statement call position round-trips in short form");
    check(g.edgeOrder.at("main").at("spawn_all").first == 2 &&
              g.edgeOrder.at("main").at("spawn_all").last == 5,
          "a spread call position keeps both ends");
    check(g.spawnPoints.at("spawn_all").first == 3, "spawn position");
    check(g.indirectCalls.at("dispatch").count("void *(void *)"),
          "signature-keyed indirect site");
    check(g.indirectSlotCalls.at("apply").count("P:apply|0"),
          "slot-keyed indirect site");
    check(g.addressTakenBySignature.at("void *(void *)").count("worker"),
          "address-taken by signature");
    check(g.fnSlotTargets.at("P:apply|0").count("defrag_alloc"), "slot target");
    check(g.fnSlotForwards.at("P:inner|1").count("P:apply|0"), "slot forward");
    check(g.fnSlotOpaque.count("F:T::cb"), "opaque slot");
    check(g.preMainFunctions.count("ctor"), "pre-main function");
    check(g.orderUnknown.count("spaghetti"), "unordered body");
    check(g.noReturnFunctions.count("die"), "declared noreturn");
    check(g.tailCallee.at("fatal_with_info") == "fatal", "tail callee");
    check(g.returningFunctions.count("ordinary"), "returning function");
    check(g.callSiteCount.at("fatal") == 9, "call site count");
    check(g.unreachableAfterCount.at("fatal") == 8, "unreachable-after count");
}

// Counts are per-TU partials. Two shards each seeing part of the writes must
// sum, or a threshold on recurrence answers differently depending on which
// shard compiled the writer.
void testFieldAccessMergesAsPartials() {
    std::cerr << "test: per-field access counts sum across shards\n";
    using namespace lshaz;
    ThreadRoleSummary a, b;
    a.fieldAccess["S::x"].writeSites = 2;
    a.fieldAccess["S::x"].standingWriteSites = 2;
    b.fieldAccess["S::x"].writeSites = 3;
    b.fieldAccess["S::x"].handedWriteSites = 3;
    b.fieldAccess["S::x"].loopWriteSites = 1;
    a.merge(b);
    const auto &fa = a.fieldAccess["S::x"];
    check(fa.writeSites == 5, "write sites summed");
    check(fa.loopWriteSites == 1, "loop writes summed");
    check(fa.standingWriteSites == 2 && fa.handedWriteSites == 3,
          "reach counts summed independently");
    check(!fa.standing(), "an even-ish split does not claim standing access");
}

void testThreadRoleSummaryMerge() {
    std::cerr << "test: ThreadRoleSummary merge unions facts\n";
    using namespace lshaz;
    ThreadRoleSummary a, b;
    a.threadEntries = {"worker"};
    a.callEdges["main"] = {"f"};
    a.fieldWriters["T::x"] = {"f"};
    b.threadEntries = {"worker2"};
    b.callEdges["main"] = {"g"};
    b.fieldWriters["T::x"] = {"g"};
    a.merge(b);
    check(a.threadEntries.size() == 2, "entries unioned");
    check(a.callEdges["main"].size() == 2, "edges unioned per caller");
    check(a.fieldWriters["T::x"].size() == 2, "writers unioned per field");
}

void testThreadRolePropagation() {
    std::cerr << "test: thread role BFS propagation\n";
    using namespace lshaz;
    // main -> a -> shared; worker -> c -> shared. worker spawned via
    // pthread_create observed in some TU (already in threadEntries).
    ThreadRoleSummary facts;
    facts.threadEntries = {"worker"};
    facts.callEdges["main"]   = {"a"};
    facts.callEdges["a"]      = {"shared"};
    facts.callEdges["worker"] = {"c"};
    facts.callEdges["c"]      = {"shared"};
    facts.fieldWriters["T::mainField"]   = {"a"};
    facts.fieldWriters["T::workerField"] = {"c"};
    facts.fieldWriters["T::sharedField"] = {"shared"};
    facts.fieldWriters["T::orphanField"] = {"nowhere_reachable"};

    auto v = computeThreadRoles(facts, {}, {});
    check(v.roleOf("main") == ROLE_MAIN, "main is MAIN");
    check(v.roleOf("a") == ROLE_MAIN, "a inherits MAIN");
    check(v.roleOf("worker") == ROLE_WORKER, "worker is WORKER");
    check(v.roleOf("c") == ROLE_WORKER, "c inherits WORKER");
    check(v.roleOf("shared") == (ROLE_MAIN | ROLE_WORKER),
          "shared reachable from both");
    check(v.roleOf("nowhere_reachable") == ROLE_NONE, "unreached is unknown");

    check(v.fieldsHaveDisjointWriterRoles(facts, "T::mainField",
                                          "T::workerField"),
          "main-only vs worker-only fields are disjoint");
    check(!v.fieldsHaveDisjointWriterRoles(facts, "T::mainField",
                                           "T::sharedField"),
          "mixed-role writer defeats disjointness");
    check(!v.fieldsHaveDisjointWriterRoles(facts, "T::mainField",
                                           "T::orphanField"),
          "unknown writer defeats disjointness");
    check(!v.fieldsHaveDisjointWriterRoles(facts, "T::mainField",
                                           "T::absent"),
          "absent field is never disjoint");
}

void testThreadRolePatternRoots() {
    std::cerr << "test: thread role pattern-seeded roots\n";
    using namespace lshaz;
    // No thread-creation observed (function-pointer dispatch); config
    // globs name the roots instead.
    ThreadRoleSummary facts;
    facts.callEdges["main"] = {"dispatch"};
    facts.callEdges["io_thread_run"] = {"handle_io"};
    facts.fieldWriters["C::state"] = {"handle_io"};
    facts.fieldWriters["C::bytes"] = {"dispatch"};

    auto v = computeThreadRoles(facts, {"io_thread_*"}, {});
    check(v.roleOf("io_thread_run") == ROLE_WORKER, "glob seeds worker root");
    check(v.roleOf("handle_io") == ROLE_WORKER, "worker role propagates");
    check(v.fieldsHaveDisjointWriterRoles(facts, "C::state", "C::bytes"),
          "attribution works from pattern roots");
}

void testThreadRoleNoWorkers() {
    std::cerr << "test: thread role single-threaded null verdict\n";
    using namespace lshaz;
    ThreadRoleSummary facts;
    facts.callEdges["main"] = {"a"};
    facts.fieldWriters["T::x"] = {"a"};
    auto v = computeThreadRoles(facts, {}, {});
    check(v.functionRoles.empty(), "no worker roots = no attribution");
    check(!v.fieldsHaveDisjointWriterRoles(facts, "T::x", "T::x"),
          "no verdicts, no disjointness");
}

void testThreadRoleCycle() {
    std::cerr << "test: thread role propagation terminates on cycles\n";
    using namespace lshaz;
    ThreadRoleSummary facts;
    facts.threadEntries = {"w"};
    facts.callEdges["main"] = {"a"};
    facts.callEdges["a"] = {"b"};
    facts.callEdges["b"] = {"a"};
    facts.callEdges["w"] = {"w"};
    auto v = computeThreadRoles(facts, {}, {});
    check(v.roleOf("a") == ROLE_MAIN && v.roleOf("b") == ROLE_MAIN,
          "mutual recursion converges");
    check(v.roleOf("w") == ROLE_WORKER, "self-recursion converges");
}

// ===== Concurrency phase partition =====

// main calls init() then spawns, so init and everything under it is on the
// near side of the happens-before edge and serve() is not.
void testPhaseWindow() {
    std::cerr << "test: phase partition splits main at the spawn\n";
    using namespace lshaz;
    ThreadRoleSummary f;
    f.threadEntries = {"worker"};
    f.spawnPoints["spawn_all"] = {2, 2};
    f.callEdges["main"] = {"init", "spawn_all", "serve"};
    f.edgeOrder["main"]["init"] = {1, 1};
    f.edgeOrder["main"]["spawn_all"] = {2, 2};
    f.edgeOrder["main"]["serve"] = {3, 3};
    f.callEdges["init"] = {"load"};
    f.edgeOrder["init"]["load"] = {1, 1};
    f.callEdges["serve"] = {"load"};
    f.edgeOrder["serve"]["load"] = {1, 1};
    f.callEdges["worker"] = {"tick"};
    f.edgeOrder["worker"]["tick"] = {1, 1};

    auto v = computePhases(f);
    check(!v.dark, "spawn site and main both present");
    check(v.isPreThread("main"), "main starts before any thread");
    check(v.isPreThread("init"), "called before the spawn");
    check(!v.isPreThread("serve"), "called after the spawn");
    check(!v.isPreThread("load"),
          "reached from both sides, so concurrent wins");
    check(!v.isPreThread("tick"), "under a thread entry");
    check(!v.isPreThread("never_seen"), "unknown reads as concurrent");
    check(v.allPreThread({"main", "init"}), "all-pre-thread set");
    check(!v.allPreThread({"init", "serve"}), "one live member is enough");
    check(!v.allPreThread({}), "a claim about nobody is not a claim");
}

// The positive controls. Refuting on an absence is how a partition turns a
// precision gain into silent recall loss, so each one is checked separately.
void testPhaseDarkness() {
    std::cerr << "test: phase partition declines to answer when blind\n";
    using namespace lshaz;
    {
        ThreadRoleSummary f;
        f.callEdges["main"] = {"init"};
        f.edgeOrder["main"]["init"] = {1, 1};
        auto v = computePhases(f);
        check(v.dark, "no thread-creation site anywhere");
        check(!v.isPreThread("init"), "dark refutes nothing");
        check(v.concurrentSubset({"init"}).size() == 1,
              "dark keeps every writer in the rate");
    }
    {
        ThreadRoleSummary f;
        f.spawnPoints["start"] = {1, 1};
        f.callEdges["start"] = {"worker"};
        auto v = computePhases(f);
        check(v.dark, "no main to partition from");
    }
    {
        ThreadRoleSummary f;
        f.spawnPoints["ctor_spawn"] = {1, 1};
        f.preMainFunctions = {"ctor_spawn"};
        f.callEdges["main"] = {"init"};
        f.edgeOrder["main"]["init"] = {1, 1};
        f.callEdges["ctor_spawn"] = {"worker"};
        auto v = computePhases(f);
        check(v.dark, "a global constructor spawns before main runs");
    }
}

// A spawn inside a loop reaches statements above it, since the loop runs
// again. Encoded as the enclosing loop's head index rather than the call
// site's own.
void testPhaseLoopReachesBackward() {
    std::cerr << "test: a spawn in a loop reaches the whole loop\n";
    using namespace lshaz;
    ThreadRoleSummary f;
    f.threadEntries = {"worker"};
    f.spawnPoints["spawn_one"] = {2, 4};
    f.callEdges["main"] = {"before", "prep", "spawn_one"};
    f.edgeOrder["main"]["before"] = {1, 1};
    f.edgeOrder["main"]["prep"] = {2, 3};    // inside the loop, head at 2
    f.edgeOrder["main"]["spawn_one"] = {2, 4};

    auto v = computePhases(f);
    check(v.isPreThread("before"), "outside the loop, above it");
    check(!v.isPreThread("prep"),
          "inside the loop with the spawn, so a later iteration overlaps");
}

// An indirect call is only a spawn point if something that can reach it
// spawns. Signature alone answers yes far too often.
void testPhaseIndirectResolution() {
    std::cerr << "test: indirect calls resolve through slots, not signatures\n";
    using namespace lshaz;
    ThreadRoleSummary f;
    f.threadEntries = {"worker"};
    f.spawnPoints["worker"] = {1, 1};
    f.addressTakenBySignature["void *(void *)"] = {"worker", "defrag_alloc"};
    f.callEdges["main"] = {"apply", "spawn_all"};
    f.edgeOrder["main"]["apply"] = {1, 1};
    f.edgeOrder["main"]["spawn_all"] = {2, 2};
    f.spawnPoints["spawn_all"] = {1, 1};
    // apply(defrag_alloc) then calls it through its own parameter.
    f.callEdges["apply"] = {};
    f.fnSlotTargets["P:apply|0"] = {"defrag_alloc"};
    f.indirectSlotCalls["apply"]["P:apply|0"] = {1, 1};

    auto v = computePhases(f);
    check(!v.spawning.count("apply"),
          "the slot names defrag_alloc, which does not spawn");
    check(v.isPreThread("apply"), "so the call above the spawn stays early");

    // The same shape with the slot opaque cannot be answered, and the
    // conservative answer is the one that refutes nothing.
    f.fnSlotOpaque.insert("P:apply|0");
    auto blind = computePhases(f);
    check(blind.spawning.count("apply"), "an opaque slot may hold anything");
    check(!blind.isPreThread("apply"), "and that closes the window early");
}

// A call that never returns cannot make the statement after it concurrent.
// Most codebases spell the fatal path without the attribute, so the site
// evidence has to carry it.
void testPhaseNoReturn() {
    std::cerr << "test: an unreachable-terminated callee blocks propagation\n";
    using namespace lshaz;
    ThreadRoleSummary f;
    f.threadEntries = {"worker"};
    f.spawnPoints["crash_report"] = {1, 1};
    f.callEdges["main"] = {"check", "spawn_all"};
    f.edgeOrder["main"]["check"] = {1, 1};
    f.edgeOrder["main"]["spawn_all"] = {2, 2};
    f.spawnPoints["spawn_all"] = {1, 1};
    f.callEdges["check"] = {"fatal"};
    f.edgeOrder["check"]["fatal"] = {1, 1};
    f.callEdges["fatal"] = {"crash_report"};
    f.edgeOrder["fatal"]["crash_report"] = {1, 1};

    // Without the evidence, the crash path makes every caller of an assert
    // a thread creation.
    f.callSiteCount["fatal"] = 3;
    auto live = computePhases(f);
    check(live.spawning.count("check"), "fatal is taken as returning");
    check(!live.isPreThread("check"), "so the window closes at the assert");

    // Two sites say unreachable outright; the third is the tail call of a
    // wrapper whose own sites all do.
    f.unreachableAfterCount["fatal"] = 2;
    f.tailCallee["fatal_with_info"] = "fatal";
    f.callSiteCount["fatal_with_info"] = 5;
    f.unreachableAfterCount["fatal_with_info"] = 5;
    auto dead = computePhases(f);
    check(!dead.spawning.count("check"), "fatal no longer returns");
    check(dead.isPreThread("check"), "and the window reopens past it");
}


// ===== Measured memory profile =====

void testMemoryProfileParse() {
    std::cerr << "test: memory profile round trip and shape checks\n";
    using namespace lshaz;
    const std::string js = R"({
      "kind": "lshaz.memory-profile",
      "origin": "lshaz sample --pid 42",
      "machine": "i9-9900K", "workload": "bench",
      "samplePeriod": 50, "wallNanos": 8000000000,
      "unresolvedSamples": 52139,
      "objects": [
        {"id": "g:redisCommandTable", "samples": 9867, "offsets": [
          {"offset": 93888, "samples": 9000, "weightSum": 90000, "weightCount": 1000,
           "cpus": [0,1,2,3]},
          {"offset": 93896, "samples": 867, "weightSum": 0, "weightCount": 0,
           "cpus": [5]}]},
        {"id": "g:quiet", "samples": 4, "offsets": [
          {"offset": 0, "samples": 4, "weightSum": 0, "weightCount": 0, "cpus": [1]}]}
      ]})";
    MemoryProfile p;
    std::string err;
    check(parseMemoryProfile(js, p, err), "a well formed profile parses");
    check(p.live(), "it is live");
    check(p.objects.size() == 2, "both objects arrived");
    check(p.totalSamples == 9871, "samples summed across objects");
    check(p.machine == "i9-9900K" && p.samplePeriod == 50, "scalars arrived");

    const auto *o = p.find("g:redisCommandTable");
    check(o != nullptr, "lookup by ObjectId");
    check(o->byOffset.size() == 2, "both byte offsets arrived");
    check(o->cpus.size() == 5, "core set is the union over offsets");
    check(o->byOffset.at(93888).meanCycles() == 90, "weighted mean latency");
    check(o->byOffset.at(93896).meanCycles() == 0,
          "unweighted offset reports no latency rather than a made up one");

    // Share is against everything sampled, not against what we could name.
    // 9867 of 9871 named plus 52139 unnamed.
    const int pct = static_cast<int>(p.shareOf("g:redisCommandTable") * 100 + 0.5);
    check(pct == 16, "share is of all sampled traffic, not of the named subset");
    check(static_cast<int>(p.resolutionRate() * 100) == 15,
          "resolution rate reported so absence can be weighed");
}

void testMemoryProfileFalseSharingShape() {
    std::cerr << "test: false-sharing shape needs two offsets and two cores\n";
    using namespace lshaz;
    ObjectCoherence oc;
    oc.objectId = "g:t";
    // two offsets on one 64B line, different cores: the signature
    oc.byOffset[0]  = {0,  100, {1}, 0, 0};
    oc.byOffset[8]  = {8,  100, {2}, 0, 0};
    // one offset alone on the next line, many cores: contention on a field
    oc.byOffset[64] = {64, 100, {1,2,3}, 0, 0};
    // two offsets on a third line but only ever one core: no transfer
    oc.byOffset[128] = {128, 50, {4}, 0, 0};
    oc.byOffset[136] = {136, 50, {4}, 0, 0};

    const auto fs = oc.falseSharedLines(64);
    check(fs.size() == 1, "exactly one line has the false-sharing shape");
    check(fs[0] == 0, "and it is the line with two offsets and two cores");
    check(oc.linesOf(64).size() == 3, "offsets group onto their lines");
}

void testSharingDiscrimination() {
    std::cerr << "test: measured offsets separate false sharing from true\n";
    using namespace lshaz;

    // Two fields of one line, both busy. Padding them apart works.
    const std::vector<ClaimedField> pair = {{"head", 0, 8}, {"tail", 8, 8}};
    {
        ObjectCoherence oc;
        oc.objectId = "g:q";
        oc.byOffset[0] = {0, 400, {1}, 0, 0};
        oc.byOffset[8] = {8, 300, {2}, 0, 0};
        oc.samples = 700;
        const auto e = discriminateSharing(oc, pair, 64);
        check(e.verdict == SharingVerdict::MultiField,
              "traffic in two named fields of one line is false sharing");
        check(e.fieldsHit.size() == 2, "both fields reported");
        check(e.fieldsHit[0] == "head", "busiest field first");
        check(e.lineBase == 0, "on the line they share");
    }

    // One field of that line carries everything. Padding moves the traffic
    // and removes none of it: a different mechanism with a different fix.
    {
        ObjectCoherence oc;
        oc.objectId = "g:q";
        oc.byOffset[0] = {0, 700, {1, 2, 3}, 0, 0};
        oc.samples = 700;
        const auto e = discriminateSharing(oc, pair, 64);
        check(e.verdict == SharingVerdict::SingleField,
              "all traffic in one named field is true sharing, not false");
        check(e.fieldsHit.size() == 1 && e.fieldsHit[0] == "head",
              "and it names which field");
    }

    // Same shape, too little of it. A second field taking a fifth of the line
    // would be missed at this count, so the profile must not refute.
    {
        ObjectCoherence oc;
        oc.objectId = "g:q";
        oc.byOffset[0] = {0, 20, {1, 2}, 0, 0};
        oc.samples = 20;
        const auto e = discriminateSharing(oc, pair, 64);
        check(e.verdict == SharingVerdict::TooFewSamples,
              "one field with thin evidence refutes nothing");
    }

    // The object is contended somewhere else entirely. The measurement is
    // real and the finding's explanation of it is not.
    {
        ObjectCoherence oc;
        oc.objectId = "g:q";
        oc.byOffset[4096] = {4096, 900, {1, 2}, 0, 0};
        oc.samples = 900;
        const auto e = discriminateSharing(oc, pair, 64);
        check(e.verdict == SharingVerdict::OffClaimedLines,
              "traffic away from the named pair leaves the pair unsupported");
        check(e.samplesOnObject == 900, "while still reporting the object moved");
    }

    // A straddling field belongs to both lines its bytes touch.
    {
        const std::vector<ClaimedField> straddle = {{"wide", 56, 16},
                                                    {"next", 72, 8}};
        ObjectCoherence oc;
        oc.objectId = "g:s";
        oc.byOffset[68] = {68, 400, {1}, 0, 0};
        oc.byOffset[72] = {72, 400, {2}, 0, 0};
        oc.samples = 800;
        const auto e = discriminateSharing(oc, straddle, 64);
        check(e.verdict == SharingVerdict::MultiField,
              "a field crossing a boundary is not lost from the second line");
        check(e.lineBase == 64, "reported on the line the traffic landed on");
    }

    // The linker put a different object on the line. Traffic in one field no
    // longer means one field is contended, and padding the struct fixes
    // nothing. Measured on an i9-9900K: a read-only flag took 6370 samples
    // because a counter eight bytes below it was written from another core.
    {
        ObjectCoherence oc;
        oc.objectId = "g:q";
        oc.byOffset[0] = {0, 700, {1, 2}, 0, 0};
        oc.samples = 700;
        oc.neighbours.push_back({"g:alpha_counter", -8, 0});
        const auto e = discriminateSharing(oc, pair, 64);
        check(e.verdict == SharingVerdict::CrossObjectLine,
              "a line shared with another object is not field contention");
        check(e.lineNeighbours.size() == 1 &&
                  e.lineNeighbours[0] == "g:alpha_counter",
              "and the other object is named");
    }

    // A neighbour on some other line does not contaminate this one.
    {
        ObjectCoherence oc;
        oc.objectId = "g:q";
        oc.byOffset[0] = {0, 700, {1, 2}, 0, 0};
        oc.samples = 700;
        oc.neighbours.push_back({"g:far", 4096, 4096});
        const auto e = discriminateSharing(oc, pair, 64);
        check(e.verdict == SharingVerdict::SingleField,
              "a neighbour off the contended line leaves the verdict alone");
        check(e.lineNeighbours.empty(), "and is not reported against it");
    }

    // No claim to check against, so nothing is decided rather than assumed.
    {
        ObjectCoherence oc;
        oc.objectId = "g:q";
        oc.byOffset[0] = {0, 700, {1, 2}, 0, 0};
        oc.samples = 700;
        const auto e = discriminateSharing(oc, {}, 64);
        check(e.verdict == SharingVerdict::NoTraffic,
              "with no named fields the offsets settle nothing");
    }
}

void testInstrumentProvenance() {
    std::cerr << "test: an unverified instrument ranks but settles nothing\n";
    using namespace lshaz;
    auto parse = [](const char *extra) {
        MemoryProfile p;
        std::string err, js = std::string("{\"kind\":\"lshaz.memory-profile\",") +
            extra + ",\"objects\":[{\"id\":\"g:x\",\"samples\":9,\"offsets\":["
            "{\"offset\":0,\"samples\":9,\"cpus\":[1,2]}]}]}";
        parseMemoryProfile(js, p, err);
        return p;
    };

    const auto pass = parse("\"event\":\"0x4d2\",\"cpu\":\"GenuineIntel-6-158\","
                            "\"selfTest\":\"pass\",\"selfTestSamples\":41233");
    check(pass.coherenceVerified(), "a profile whose control fired may settle");
    check(pass.provenanceProblem().empty(), "and reports no problem");
    check(pass.selfTestSamples == 41233, "the control's count is carried");

    const auto fail = parse("\"event\":\"0xc0\",\"cpu\":\"GenuineIntel-6-158\","
                            "\"selfTest\":\"fail\",\"selfTestSamples\":0");
    check(!fail.coherenceVerified(),
          "an encoding that missed a hazard built on purpose settles nothing");
    check(fail.provenanceProblem().find("0xc0") != std::string::npos,
          "and the refusal names the encoding it distrusts");

    const auto skipped = parse("\"event\":\"0x4d2\",\"selfTest\":\"skipped\"");
    check(!skipped.coherenceVerified(), "skipping the control is not passing it");

    // The instrument's own blind spot, measured by the instrument. XSNP_HITM
    // reports 20016 samples on a line two cores read-modify-write and 0 on the
    // same line written with plain stores, so its silence cannot refute.
    check(!pass.seesStoreOnlySharing(),
          "a profile that did not record store visibility does not claim it");
    const auto blind = parse("\"selfTest\":\"pass\",\"storeOnlySharing\":\"blind\"");
    check(blind.coherenceVerified() && !blind.seesStoreOnlySharing(),
          "an instrument can be verified for coherence and still be store-blind");
    const auto sees = parse("\"selfTest\":\"pass\",\"storeOnlySharing\":\"visible\"");
    check(sees.seesStoreOnlySharing(),
          "and one that saw store-only sharing says so");

    // Neighbours arrive with their sign: a negative offset is an object the
    // linker placed before this one on the same line.
    MemoryProfile n;
    std::string nerr;
    check(parseMemoryProfile(
              R"({"kind":"lshaz.memory-profile","objects":[{"id":"g:stopf",
                  "samples":6370,"neighbours":[{"id":"g:alpha_counter","at":-8,"witness":0}],
                  "offsets":[{"offset":0,"samples":6370,"cpus":[1,2]}]}]})",
              n, nerr),
          "a profile carrying line neighbours parses");
    // The join key is the source-level name, because that is what the analyzer
    // writes. A namespaced C++ global resolves to _ZN6engine4book8countersE in
    // the symbol table and to engine::book::counters in a finding, and before
    // the sampler demangled, the two never met on any C++ target.
    MemoryProfile cxx;
    std::string cerr2;
    check(parseMemoryProfile(
              R"({"kind":"lshaz.memory-profile","objects":[
                  {"id":"g:engine::book::counters","samples":16016,
                   "symbol":"_ZN6engine4book8countersE",
                   "offsets":[{"offset":0,"samples":16016,"cpus":[0,1]}]}]})",
              cxx, cerr2),
          "a demangled object id parses");
    const auto *cc = cxx.find("g:engine::book::counters");
    check(cc != nullptr, "and is found under the name a finding would use");
    check(cc && cc->symbol == "_ZN6engine4book8countersE",
          "with the linker name kept for a human to grep for");
    check(!cc->ambiguous, "and is unambiguous by default");

    // Two file statics called `initialized` in two TUs are two objects. The
    // samples are their sum, so they belong to the one a finding meant no more
    // than to the one it did not.
    MemoryProfile amb;
    std::string aerr;
    check(parseMemoryProfile(
              R"({"kind":"lshaz.memory-profile","objects":[
                  {"id":"g:initialized","samples":16016,"ambiguous":true,
                   "offsets":[{"offset":0,"samples":8008,"cpus":[0]},
                              {"offset":8,"samples":8008,"cpus":[1]}]}]})",
              amb, aerr),
          "a profile flagging a duplicated name parses");
    const auto *ai = amb.find("g:initialized");
    check(ai && ai->ambiguous,
          "and the flag survives, so nothing settles on the wrong object");

    const auto *so = n.find("g:stopf");
    check(so && so->neighbours.size() == 1, "the neighbour arrived");
    check(so->neighbours[0].at == -8,
          "a negative offset survives the unsigned number parser");
    check(so->neighboursOnLine(0, 64).size() == 1,
          "and it lands on the line the traffic did");

    // The samples are real whatever produced them, so ranking survives.
    check(fail.live() && fail.shareOf("g:x") > 0.0,
          "an unverified profile still carries a share to rank by");

    // A profile written before the control existed must not be grandfathered:
    // it was taken with an instrument nobody checked.
    const auto legacy = parse("\"event\":\"0x4d2\"");
    check(!legacy.coherenceVerified(),
          "a profile with no self-test field is unverified, not trusted");
    check(!legacy.provenanceProblem().empty(), "and says so");
}

void testMemoryProfileRejectsImposters() {
    std::cerr << "test: a document that is not a profile is refused\n";
    using namespace lshaz;
    MemoryProfile p;
    std::string err;
    check(!parseMemoryProfile("{}", p, err), "empty object refused");
    check(!err.empty(), "and says why");
    check(!parseMemoryProfile(R"({"kind":"other","objects":[]})", p, err),
          "wrong kind refused");
    check(!parseMemoryProfile(R"({"kind":"lshaz.memory-profile"})", p, err),
          "no objects array refused, since it would read as a clean machine");
    MemoryProfile q;
    check(parseMemoryProfile(R"({"kind":"lshaz.memory-profile","objects":[]})",
                             q, err),
          "an empty but well formed profile parses");
    check(!q.live(), "but is not live, so it can settle nothing");
}

void testFilterSourcesSkipsVendored() {
    std::vector<std::string> src = {
        "/p/src/server.c", "/p/deps/jemalloc/jemalloc.c",
        "/p/third_party/lua/lua.c", "/p/vendor/x.c", "/p/src/db.c"};
    const std::vector<std::string> pats = {
        "*/deps/*", "*/third_party/*", "*/vendor/*"};

    lshaz::FilterOptions f;
    f.vendorPatterns = pats;
    unsigned skipped = 0;
    auto out = lshaz::filterSources(src, f, skipped);
    check(out.size() == 2 && skipped == 3, "vendored trees skipped by default");

    f.skipVendored = false;
    auto all = lshaz::filterSources(src, f, skipped);
    check(all.size() == 5 && skipped == 0, "--include-vendored restores them");

    // Patterns are config-driven: a project whose own module lives under
    // external/ must be able to stop the default from hiding it.
    lshaz::FilterOptions narrowed;
    narrowed.vendorPatterns = {"*/deps/*"};
    auto kept = lshaz::filterSources(src, narrowed, skipped);
    check(kept.size() == 4 && skipped == 1,
          "vendor patterns are overridable, not baked in");

    // An explicit --include is a direct instruction and outranks the default.
    lshaz::FilterOptions inc;
    inc.vendorPatterns = pats;
    inc.includeFiles = {"*/deps/*"};
    auto only = lshaz::filterSources(src, inc, skipped);
    check(only.size() == 1 && skipped == 0,
          "explicit include outranks the vendored default");
}

// --- mechanism claims -----------------------------------------------------

void testMechanismClaimCeiling() {
    using lshaz::MechanismClaim;
    lshaz::Diagnostic d;

    // A rule that declares nothing is unconstrained rather than clamped to
    // Informational, so migrating rules one at a time cannot silently gut
    // the ones not yet migrated.
    check(d.severitySupportedByClaims() == lshaz::Severity::Critical,
          "no declared claims leaves severity unconstrained");

    // The shape of every defect found in the audit: the effect carrying the
    // high grade is exactly the one whose precondition was never checked.
    d.mechanismClaims = {
        {"lock acquisition cost", "a lock on a hot path",
         lshaz::ClaimState::Established, lshaz::Severity::Medium},
        {"convoy: futex wait and context switch",
         "a second thread contending", lshaz::ClaimState::Unknown,
         lshaz::Severity::Critical},
    };
    check(d.severitySupportedByClaims() == lshaz::Severity::Medium,
          "an unknown claim cannot raise the ceiling");

    d.mechanismClaims[1].state = lshaz::ClaimState::Established;
    check(d.severitySupportedByClaims() == lshaz::Severity::Critical,
          "establishing the precondition restores the grade");

    // Nothing established at all: the finding is structural only.
    d.mechanismClaims[0].state = lshaz::ClaimState::Unknown;
    d.mechanismClaims[1].state = lshaz::ClaimState::Unknown;
    check(d.severitySupportedByClaims() == lshaz::Severity::Informational,
          "no established claim supports nothing above Informational");
    check(d.refutedPrecondition() == nullptr,
          "unknown is not refuted, so nothing is withdrawn");
}

// Refutation is a verdict, not a low score. An evidence source that looked
// for a precondition and found it absent retires the finding by name.
// --- points-to ------------------------------------------------------------

namespace pt {
using namespace lshaz;

Constraint addrOf(std::string p, std::string o, uint64_t off = 0) {
    return {Constraint::Kind::AddrOf, std::move(p), std::move(o), off};
}
Constraint copy(std::string p, std::string q) {
    return {Constraint::Kind::Copy, std::move(p), std::move(q), 0};
}
Constraint load(std::string p, std::string q, uint64_t off = 0) {
    return {Constraint::Kind::Load, std::move(p), std::move(q), off};
}
Constraint store(std::string p, std::string q, uint64_t off = 0) {
    return {Constraint::Kind::Store, std::move(p), std::move(q), off};
}
bool has(const lshaz::PointsToSolution &s, const std::string &p,
         const std::string &o) {
    return s.of(p).count(o) > 0;
}
} // namespace pt

void testPointsToBasics() {
    std::cerr << "test: points-to address, copy, transitive copy\n";
    using namespace lshaz;
    using namespace pt;

    std::set<Constraint> cs{
        addrOf("a", obj::global("g_stats")),
        copy("b", "a"),
        copy("c", "b"),
    };
    auto sol = solvePointsTo(cs);
    check(has(sol, "a", "g:g_stats"), "address-of seeds the set");
    check(has(sol, "b", "g:g_stats"), "copy propagates one hop");
    check(has(sol, "c", "g:g_stats"), "copy propagates transitively");
    check(!sol.truncated, "a three-constraint program fits the budget");
}

void testPointsToLoadStore() {
    std::cerr << "test: points-to through a load and a store\n";
    using namespace lshaz;
    using namespace pt;

    // box = &cell; *box = &target; out = *box;
    std::set<Constraint> cs{
        addrOf("box", obj::global("cell")),
        addrOf("val", obj::global("target")),
        store("box", "val"),
        load("out", "box"),
    };
    auto sol = solvePointsTo(cs);
    check(has(sol, "g:cell", "g:target"), "the store lands in the object");
    check(has(sol, "out", "g:target"), "the load reads it back out");
}

void testPointsToFieldSensitivity() {
    std::cerr << "test: points-to keeps distinct field offsets apart\n";
    using namespace lshaz;
    using namespace pt;

    // s.head = &a; s.tail = &b; two offsets on one object.
    std::set<Constraint> cs{
        addrOf("p", obj::global("s")),
        addrOf("pa", obj::global("a")),
        addrOf("pb", obj::global("b")),
        store("p", "pa", 0),
        store("p", "pb", 8),
        load("readHead", "p", 0),
        load("readTail", "p", 8),
    };
    auto sol = solvePointsTo(cs);
    check(has(sol, "readHead", "g:a"), "offset 0 reads what offset 0 stored");
    check(has(sol, "readTail", "g:b"), "offset 8 reads what offset 8 stored");
    check(!has(sol, "readHead", "g:b"),
          "a field-insensitive solver would merge these");
    check(!has(sol, "readTail", "g:a"), "and merge them the other way too");
}

void testPointsToTerminatesOnCycles() {
    std::cerr << "test: points-to terminates on a copy cycle\n";
    using namespace lshaz;
    using namespace pt;

    std::set<Constraint> cs{
        addrOf("a", obj::global("o")),
        copy("b", "a"), copy("c", "b"), copy("a", "c"),
    };
    auto sol = solvePointsTo(cs);
    check(has(sol, "a", "g:o") && has(sol, "b", "g:o") && has(sol, "c", "g:o"),
          "every node in the cycle sees the object");
    check(!sol.truncated, "a cycle is a fixed point, not a budget overrun");
}

// The reason this analysis is in the reduce phase. The call is compiled in one
// TU and the callee's body in another, so neither shard can resolve the
// parameter alone and a per-TU solve would answer "unknown" for both.
void testPointsToCrossesTheShardBoundary() {
    std::cerr << "test: points-to resolves a parameter across two shards\n";
    using namespace lshaz;
    using namespace pt;

    // Shard A compiled the caller: update(&g_conn)
    std::set<Constraint> shardA{
        addrOf("tmp", obj::global("g_conn")),
        copy(obj::param("update", 0), "tmp"),
    };
    // Shard B compiled the callee: void update(Conn *c) { c->n = ...; }
    std::set<Constraint> shardB{
        copy("c", obj::param("update", 0)),
    };

    auto alone = solvePointsTo(shardB);
    check(!alone.resolves("c"), "the callee's shard cannot resolve it alone");

    std::set<Constraint> merged = shardA;
    merged.insert(shardB.begin(), shardB.end());
    auto both = solvePointsTo(merged);
    check(has(both, "c", "g:g_conn"),
          "merged, the parameter resolves to the caller's object");

    // Merge order is not an input to a least fixed point.
    std::set<Constraint> other = shardB;
    other.insert(shardA.begin(), shardA.end());
    auto reversed = solvePointsTo(other);
    check(reversed.pointsTo == both.pointsTo,
          "the solution does not depend on which shard reported first");
}

void testPointsToBudgetIsReported() {
    std::cerr << "test: points-to reports truncation instead of hiding it\n";
    using namespace lshaz;
    using namespace pt;

    std::set<Constraint> cs;
    for (int i = 0; i < 40; ++i)
        cs.insert(addrOf("p", obj::global("o" + std::to_string(i))));
    for (int i = 0; i < 40; ++i)
        cs.insert(copy("q" + std::to_string(i), "p"));

    auto full = solvePointsTo(cs);
    check(!full.truncated, "the default budget covers this");
    check(full.objectsDiscovered == 40, "all forty objects are distinct");

    auto squeezed = solvePointsTo(cs, /*objectBudget=*/50);
    check(squeezed.truncated, "a solution cut short says so");
}

// Constraints that stay in the child make the solve wrong rather than
// thinner, and wrong only under --jobs > 1. The symptom this guards against
// is the one the repo calls the worst kind.
void testMemorySummaryCrossesIPC() {
    std::cerr << "test: memory summary survives the shard boundary\n";
    using namespace lshaz;

    MemorySummary m;
    m.constraints.insert({Constraint::Kind::AddrOf, "s:caller::t",
                          obj::global("g_conn"), 0});
    m.constraints.insert({Constraint::Kind::Copy, obj::param("update", 0),
                          "s:caller::t", 0});
    m.constraints.insert({Constraint::Kind::Load, "tmp", "s:cb::p", 24});
    m.constraints.insert({Constraint::Kind::Store, "s:cb::p", "tmp", 8});
    m.unnameableAccesses = 7;

    PendingAccess a;
    a.base = obj::global("g_conn");
    a.offset = 16; a.size = 8;
    a.function = "update"; a.site = "conn.c:42";
    a.isWrite = true; a.inLoop = true; a.isAtomic = false;
    a.fieldName = "bytes";
    m.accesses.push_back(a);

    const std::string wire = serializeShardResult(
        0, {}, {}, EscapeSummary{}, ThreadRoleSummary{}, StripedArraySummary{},
        ScanCoverage{}, m);
    ShardIPC parsed;
    check(deserializeShardResult(wire, parsed), "record with memory parses");

    check(parsed.memory.constraints.size() == 4, "every constraint arrives");
    check(parsed.memory.constraints == m.constraints,
          "constraints arrive unchanged, kind and offset included");
    check(parsed.memory.unnameableAccesses == 7,
          "the unnameable count is not dropped on the floor");

    check(parsed.memory.accesses.size() == 1, "the access arrives");
    const auto &g = parsed.memory.accesses.front();
    check(g.base == a.base && g.offset == 16 && g.size == 8,
          "base and extent survive");
    check(g.function == "update" && g.site == "conn.c:42",
          "attribution survives");
    check(g.isWrite && g.inLoop && !g.isAtomic, "the flags survive");
    check(g.fieldName == "bytes", "the field name survives");

    // The point of shipping them: merged, the parameter resolves.
    auto sol = solvePointsTo(parsed.memory.constraints);
    check(sol.of(obj::param("update", 0)).count("g:g_conn") == 1,
          "the reassembled constraints still solve");
}

// The case the type-name key provably cannot answer. Two globals of one type,
// written by different functions: keyed by type they are a single node with
// two writers, which reads as contention. Keyed by object they are two nodes
// with one writer each, which is no mechanism at all.
void testTwoGlobalsOfOneTypeStayApart() {
    std::cerr << "test: two globals of one type are two objects\n";
    using namespace lshaz;

    MemorySummary m;
    auto touch = [&](const char *object, const char *fn, uint64_t off,
                     bool write) {
        PendingAccess a;
        a.base = object; a.offset = off; a.size = 8;
        a.function = fn; a.site = "s.c:1"; a.isWrite = write;
        a.fieldName = off == 0 ? "head" : "tail";
        m.accesses.push_back(a);
    };
    // Same record type, two instances, one writer each.
    touch(obj::global("g_rx").c_str(), "rxPoll", 0, true);
    touch(obj::global("g_tx").c_str(), "txPush", 0, true);

    auto sol = solvePointsTo(m.constraints);
    auto model = buildMemoryModel(m, sol);

    check(model.objects.size() == 2, "two instances are two objects");
    check(model.multiWriterObjects().empty(),
          "one writer each is not a multi-writer object");
    check(model.staticObjects().size() == 2, "both are static storage");

    // Now a genuine second writer on one of them.
    touch(obj::global("g_rx").c_str(), "rxReset", 0, true);
    auto shared = buildMemoryModel(m, solvePointsTo(m.constraints));
    auto multi = shared.multiWriterObjects();
    check(multi.size() == 1 && multi.front() == "g:g_rx",
          "only the object with two writers is named");
}

// A heap block has no type-name identity at all, so the old key could not
// represent it. Two allocation sites are two objects even when the pointee
// type is identical.
void testHeapObjectsAreDistinctPerSite() {
    std::cerr << "test: allocation sites are distinct heap objects\n";
    using namespace lshaz;

    MemorySummary m;
    m.constraints.insert({Constraint::Kind::AddrOf, "s:mkRx::p",
                          obj::heap("net.c", 40), 0});
    m.constraints.insert({Constraint::Kind::AddrOf, "s:mkTx::p",
                          obj::heap("net.c", 90), 0});

    PendingAccess a;
    a.base = "s:mkRx::p"; a.size = 8; a.isWrite = true; a.function = "mkRx";
    m.accesses.push_back(a);
    a.base = "s:mkTx::p"; a.function = "mkTx";
    m.accesses.push_back(a);

    auto model = buildMemoryModel(m, solvePointsTo(m.constraints));
    check(model.objects.count("h:net.c:40") == 1, "the first site is an object");
    check(model.objects.count("h:net.c:90") == 1, "the second site is another");
    check(model.staticObjects().empty(),
          "heap blocks are not static storage and cannot false-share as one");
}

// Coverage, not silence. A model that resolved nothing must not present as a
// model that found nothing to report.
void testUnresolvedAccessesAreCounted() {
    std::cerr << "test: unresolved accesses are counted, not absorbed\n";
    using namespace lshaz;

    MemorySummary m;
    PendingAccess a;
    a.base = obj::param("handle", 0);  // never resolved by any constraint
    a.size = 8; a.function = "handle"; a.isWrite = true;
    m.accesses.push_back(a);
    m.unnameableAccesses = 3;

    auto model = buildMemoryModel(m, solvePointsTo(m.constraints));
    check(model.objects.empty(), "an unresolved cell becomes no object");
    check(model.unresolvedAccesses == 1, "the access is counted as unresolved");
    check(model.unnameableAccesses == 3, "unnameable accesses carry through");
    check(model.resolutionRate() == 0.0, "and the rate says so");
}

// The reachability question the object-level sharing verdict asks. A line only
// ever read costs no coherence traffic, and roles are counted over the
// attributed touchers because an unattributed one can only add a role.
void testObjectReachedByTwoRoles() {
    std::cerr << "test: two roles reaching one object, and the cases that are not\n";
    using namespace lshaz;

    ThreadRoleVerdicts roles;
    roles.functionRoles["ioThread"] = 1;
    roles.functionRoles["workerThread"] = 2;
    roles.functionRoles["alsoIo"] = 1;

    auto touched = [&](std::initializer_list<std::pair<const char *, bool>> fns) {
        MemorySummary m;
        for (auto [fn, write] : fns) {
            PendingAccess a;
            a.base = obj::global("g_shared");
            a.size = 8; a.function = fn; a.isWrite = write;
            m.accesses.push_back(a);
        }
        return buildMemoryModel(m, solvePointsTo(m.constraints));
    };

    auto rolesOn = [&](const MemoryModel &model) {
        const auto &acc = model.objects.at("g:g_shared");
        std::set<std::string> all = acc.writers();
        const auto r = acc.readers();
        all.insert(r.begin(), r.end());
        return ThreadRoleVerdicts::roleCount(roles.knownRolesOf(all));
    };

    auto twoRoles = touched({{"ioThread", true}, {"workerThread", true}});
    check(rolesOn(twoRoles) >= 2, "two writing roles reach it");

    auto writeAndRead = touched({{"ioThread", true}, {"workerThread", false}});
    check(rolesOn(writeAndRead) >= 2,
          "a reader on the other role pays the same miss a writer would");

    auto sameRole = touched({{"ioThread", true}, {"alsoIo", true}});
    check(rolesOn(sameRole) == 1, "two functions of one role are one role");

    auto readOnly = touched({{"ioThread", false}, {"workerThread", false}});
    check(readOnly.objects.at("g:g_shared").writers().empty(),
          "a read-only object has no writer to invalidate the line");

    auto unattributed = touched({{"ioThread", true}, {"mystery", true}});
    check(rolesOn(unattributed) == 1,
          "an unattributed toucher adds no role, so the count is a lower bound");
}

void testLadderRankIsOrdinal() {
    std::cerr << "test: ladder rank is ordinal and never claims certainty\n";
    using namespace lshaz;

    enum class Four : unsigned { A, B, C, D, Count };
    check(rungRank(Four::A) < rungRank(Four::B), "rank rises with position");
    check(rungRank(Four::B) < rungRank(Four::C), "rank rises with position");
    check(rungRank(Four::C) < rungRank(Four::D), "rank rises with position");
    check(rungRank(Four::A) > 0.0, "a finding that exists clears the bottom");
    check(rungRank(Four::D) < 1.0, "the best rung of one rule is not certainty");
    check(ladderSize<Four>() == 4, "Count is the length, not a rung");

    enum class Two : unsigned { A, B, Count };
    check(rungRank(Two::A) > rungRank(Four::A),
          "a shorter ladder spreads its rungs wider");
    check(rungRank(Two::B) < 1.0, "still no certainty on a two-rung ladder");

    enum class One : unsigned { Only, Count };
    check(rungRank(One::Only) == 0.5, "nothing to rank sits in the middle");
}

void testRefutationWithdrawsTheFinding() {
    std::cerr << "test: a refuted precondition withdraws the finding\n";
    lshaz::Diagnostic d;

    // A refuted alternative simply stops contributing while another stands.
    d.mechanismClaims = {
        {"inlining barrier", "a virtual call on a hot path",
         lshaz::ClaimState::Established, lshaz::Severity::High},
        {"indirect branch misprediction", "the call survives devirtualization",
         lshaz::ClaimState::Refuted, lshaz::Severity::Critical},
    };
    check(d.severitySupportedByClaims() == lshaz::Severity::High,
          "a refuted alternative cannot contribute its severity");
    check(d.refutedPrecondition() == nullptr,
          "one surviving mechanism keeps the finding alive");

    // Refute the last standing alternative: nothing is being asserted.
    d.mechanismClaims[0].state = lshaz::ClaimState::Refuted;
    const auto *dead = d.refutedPrecondition();
    check(dead != nullptr, "refuting every alternative withdraws the finding");

    // A refuted gate is a necessary precondition known false.
    lshaz::Diagnostic g;
    g.mechanismClaims = {
        {"arena contention", "an allocation on a hot path",
         lshaz::ClaimState::Established, lshaz::Severity::High},
        {"the allocation happens at all",
         "the call survives optimization", lshaz::ClaimState::Refuted,
         lshaz::Severity::Critical, /*gating=*/true},
    };
    const auto *gate = g.refutedPrecondition();
    check(gate != nullptr && gate->gating,
          "a refuted gate withdraws however well the mechanism is evidenced");
}

// --- PMU instrument election ---------------------------------------------
//
// Recorded curves over strides {4,8,16,32,64,128,256}B, so index 4 is the 64B
// line. Exercising the predicate against recorded data keeps the gate testable
// on a host with no PMU.

void testPMUCliffAtLineSize() {
    // PMCx043 umask 0x02 (local-CCX cache fill). A real coherence counter.
    const uint64_t curve[] = {43334, 43659, 48248, 65025, 1, 1, 1};
    check(lshaz_pmu_cliff_index(curve, 7) == 4, "coherence curve collapses at 64B");
}

void testPMUCliffRejectsWrongMechanism() {
    // PMCx000 umask 0x10. Separates the two arms (nonzero shared, zero
    // isolated) and so passes a two-point ratio test, but collapses at 16B.
    // Whatever it counts is not cache-line coherence.
    const uint64_t curve[] = {736, 3196, 0, 0, 0, 0, 0};
    check(lshaz_pmu_cliff_index(curve, 7) == 2, "non-coherence curve collapses at 16B");
}

void testPMUCliffNoTransition() {
    const uint64_t flat[] = {40000, 41000, 39500, 40200, 40100, 39900, 40050};
    check(lshaz_pmu_cliff_index(flat, 7) == 0, "flat curve has no cliff");
}

void testPMUCliffRejectsLowCounts() {
    // Perfect separation on a handful of events is not evidence.
    const uint64_t sparse[] = {50, 60, 0, 0, 0, 0, 0};
    check(lshaz_pmu_cliff_index(sparse, 7) == 0, "low counts fail the power gate");
}

void testPMUCliffIgnoresTransientDip() {
    const uint64_t dip[] = {50000, 1, 50000, 1, 1, 1, 1};
    check(lshaz_pmu_cliff_index(dip, 7) == 3, "only a durable collapse is a cliff");
}

void testPMURatioLowerBoundPenalisesSparseCounts() {
    // The defect this replaces: clamping a zero control arm to 1 scores a
    // 60-event candidate above a 195070-event one.
    const double real = lshaz_pmu_ratio_lb(195070, 3);
    const double sparse = lshaz_pmu_ratio_lb(60, 0);
    check(real > sparse, "dense evidence outranks a sparse perfect separation");
    check(lshaz_pmu_ratio_lb(0, 0) == 0.0, "no evidence scores zero, not infinity");
    check(lshaz_pmu_ratio_lb(200, 20) < lshaz_pmu_ratio_lb(2000, 20),
          "lower bound rises with treatment counts");
}

void testPMUTemplateEmbedded() {
    const char *tpl = lshaz::pmuCalibrationTemplate();
    check(tpl != nullptr && std::string(tpl).find("lshaz_pmu_calibrate") !=
              std::string::npos,
          "embedded template carries the election entry point");
}

} // anonymous namespace

int main() {
    // matchesGlob
    testMatchesGlobSuffix();
    testMatchesGlobContainment();
    testMatchesGlobSubstring();
    testMatchesGlobEmpty();
    testMatchesGlobEdgeCases();

    // filterSources
    testFilterSourcesNoFilters();
    testFilterSourcesInclude();
    testFilterSourcesExclude();
    testFilterSourcesMaxFiles();
    testFilterSourcesCombined();
    testFilterSourcesEmpty();
    testFilterSourcesSkipsVendored();

    // CompileDBResolver
    testCandidatePaths();
    testDiscoverFindsExisting();
    testDiscoverReturnsEmptyWhenMissing();
    testDiscoverPriority();

    // RepoProvider
    testIsRemoteURL();
    testAcquireLocalPath();

    // EscapeSummary
    testEscapeSummaryMerge();
    testEscapeSummaryMergeDisjoint();
    testEscapeSummaryMergeAccessorAccumulation();
    testEscapeSummaryStructuralVsPublication();
    testSharingRouteRefutationSeparates();
    testThreadRouteIsItsOwnPositiveControl();
    testEscapeSummaryIPCRoundTrip();
    testCrossTUSuppressionWithSummary();
    testCrossTUSuppressionPreservesProven();
    testCrossTUSuppressionNoTypeName();

    // ThreadRoleSummary
    testShardIPCFieldAccessRoundTrip();
    testShardIPCPhaseFactsRoundTrip();
    testFieldAccessMergesAsPartials();
    testThreadRoleSummaryMerge();
    testThreadRolePropagation();
    testThreadRolePatternRoots();
    testThreadRoleNoWorkers();
    testThreadRoleCycle();
    testPhaseWindow();
    testPhaseDarkness();
    testPhaseLoopReachesBackward();
    testPhaseIndirectResolution();
    testPhaseNoReturn();
    testMemoryProfileParse();
    testMemoryProfileFalseSharingShape();
    testSharingDiscrimination();
    testInstrumentProvenance();
    testMemoryProfileRejectsImposters();

    // PMU instrument election
    testMechanismClaimCeiling();
    testObjectReachedByTwoRoles();
    testTwoGlobalsOfOneTypeStayApart();
    testHeapObjectsAreDistinctPerSite();
    testUnresolvedAccessesAreCounted();
    testMemorySummaryCrossesIPC();
    testPointsToBasics();
    testPointsToLoadStore();
    testPointsToFieldSensitivity();
    testPointsToTerminatesOnCycles();
    testPointsToCrossesTheShardBoundary();
    testPointsToBudgetIsReported();
    testLadderRankIsOrdinal();
    testRefutationWithdrawsTheFinding();
    testPMUCliffAtLineSize();
    testPMUCliffRejectsWrongMechanism();
    testPMUCliffNoTransition();
    testPMUCliffRejectsLowCounts();
    testPMUCliffIgnoresTransientDip();
    testPMURatioLowerBoundPenalisesSparseCounts();
    testPMUTemplateEmbedded();

    std::cerr << "\n" << passed << " passed, " << failures << " failed\n";
    if (failures > 0) {
        std::cerr << "PIPELINE UNIT TESTS FAILED\n";
        return 1;
    }
    std::cerr << "All pipeline unit tests passed.\n";
    return 0;
}
