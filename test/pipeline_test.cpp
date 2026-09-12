// Covers matchesGlob, filterSources, CompileDBResolver and RepoProvider.
// No subprocesses, so these stay isolated and deterministic.

#include "pmu_calib.h"

#include "lshaz/analysis/escape_summary.h"
#include "lshaz/hypothesis/pmu_calibration.h"
#include "lshaz/analysis/thread_role.h"
#include "lshaz/core/diagnostic.h"
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
        0, {}, {}, EscapeSummary{}, tr, StripedArraySummary{}, ScanCoverage{});
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
        {"lock acquisition cost", "a lock on a hot path", true,
         lshaz::Severity::Medium},
        {"convoy: futex wait and context switch",
         "a second thread contending", false, lshaz::Severity::Critical},
    };
    check(d.severitySupportedByClaims() == lshaz::Severity::Medium,
          "an unestablished claim cannot raise the ceiling");

    d.mechanismClaims[1].established = true;
    check(d.severitySupportedByClaims() == lshaz::Severity::Critical,
          "establishing the precondition restores the grade");

    // Nothing established at all: the finding is structural only.
    d.mechanismClaims[0].established = false;
    d.mechanismClaims[1].established = false;
    check(d.severitySupportedByClaims() == lshaz::Severity::Informational,
          "no established claim supports nothing above Informational");
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
    testEscapeSummaryIPCRoundTrip();
    testCrossTUSuppressionWithSummary();
    testCrossTUSuppressionPreservesProven();
    testCrossTUSuppressionNoTypeName();

    // ThreadRoleSummary
    testShardIPCFieldAccessRoundTrip();
    testFieldAccessMergesAsPartials();
    testThreadRoleSummaryMerge();
    testThreadRolePropagation();
    testThreadRolePatternRoots();
    testThreadRoleNoWorkers();
    testThreadRoleCycle();

    // PMU instrument election
    testMechanismClaimCeiling();
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
