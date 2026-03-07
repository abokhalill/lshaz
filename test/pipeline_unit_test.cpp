// Unit tests for pipeline components.
//
// Tests: matchesGlob, filterSources, CompileDBResolver, RepoProvider.
// No subprocess invocations. Isolated, deterministic.

#include "lshaz/pipeline/CompileDBResolver.h"
#include "lshaz/pipeline/RepoProvider.h"
#include "lshaz/pipeline/SourceFilter.h"

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
    std::cerr << "test: matchesGlob substring fallback\n";
    using lshaz::matchesGlob;
    check(matchesGlob("/a/b/feed_handler.cpp", "feed_handler"), "plain substring");
    check(!matchesGlob("/a/b/order_book.cpp", "feed_handler"), "rejects non-match");
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

    // CompileDBResolver
    testCandidatePaths();
    testDiscoverFindsExisting();
    testDiscoverReturnsEmptyWhenMissing();
    testDiscoverPriority();

    // RepoProvider
    testIsRemoteURL();
    testAcquireLocalPath();

    std::cerr << "\n" << passed << " passed, " << failures << " failed\n";
    if (failures > 0) {
        std::cerr << "PIPELINE UNIT TESTS FAILED\n";
        return 1;
    }
    std::cerr << "All pipeline unit tests passed.\n";
    return 0;
}
