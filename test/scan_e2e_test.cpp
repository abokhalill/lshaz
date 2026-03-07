// End-to-end integration test for the lshaz scan pipeline.
//
// Tests the complete path: scan subcommand dispatch, compile DB
// autodiscovery, cmake generation, config-driven hot path classification,
// all output formats, filtering guardrails, exit code semantics,
// and output determinism.
//
// Fixture: test/fixtures/hft_core — realistic HFT order book, matching
// engine, and feed handler. No synthetic annotations. Hot paths
// classified via lshaz.config.yaml pattern matching.
//
// Requires: lshaz binary, cmake on PATH.

#include <unistd.h>
#include <sys/wait.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
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

bool contains(const std::string &s, const std::string &sub) {
    return s.find(sub) != std::string::npos;
}

int countOccurrences(const std::string &s, const std::string &sub) {
    int count = 0;
    size_t pos = 0;
    while ((pos = s.find(sub, pos)) != std::string::npos) {
        ++count;
        pos += sub.size();
    }
    return count;
}

struct ExecResult {
    int exitCode;
    std::string out;
    std::string err;
};

ExecResult run(const std::string &cmd) {
    auto tmpErr = fs::temp_directory_path() /
        ("lshaz_e2e_err_" + std::to_string(getpid()) + ".txt");
    std::string full = cmd + " 2>" + tmpErr.string();

    FILE *pipe = popen(full.c_str(), "r");
    if (!pipe) return {-1, "", ""};

    std::ostringstream out;
    std::array<char, 8192> buf;
    while (fgets(buf.data(), buf.size(), pipe))
        out << buf.data();

    int status = pclose(pipe);
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;

    std::string errStr;
    if (std::ifstream ifs(tmpErr); ifs) {
        std::ostringstream ss;
        ss << ifs.rdbuf();
        errStr = ss.str();
    }
    fs::remove(tmpErr);
    return {code, out.str(), errStr};
}

std::string lshazBin() {
    if (const char *env = std::getenv("LSHAZ_BIN"))
        return env;
    if (fs::exists("build/lshaz"))
        return "build/lshaz";
    return "./lshaz";
}

std::string fixturePath() {
    if (fs::exists("test/fixtures/hft_core"))
        return "test/fixtures/hft_core";
    return "";
}

// Copy fixture to isolated temp directory. Returns temp root path.
fs::path isolateFixture(const std::string &fixture, const std::string &suffix) {
    auto tmp = fs::temp_directory_path() /
        ("lshaz_e2e_" + suffix + "_" + std::to_string(getpid()));
    fs::create_directories(tmp);
    fs::copy(fixture, tmp / "project",
             fs::copy_options::recursive |
             fs::copy_options::overwrite_existing);
    // Remove stale build dir to avoid CMakeCache.txt path mismatch.
    fs::remove_all(tmp / "project" / "build");
    return tmp;
}

// ===== CLI dispatch tests =====

void testHelp(const std::string &bin) {
    std::cerr << "test: scan --help\n";
    auto r = run(bin + " scan --help");
    check(r.exitCode == 0, "exit 0");
    check(contains(r.err, "Usage: lshaz scan"), "usage text");
    check(contains(r.err, "--compile-db"), "--compile-db in help");
    check(contains(r.err, "--include"), "--include in help");
    check(contains(r.err, "--exclude"), "--exclude in help");
    check(contains(r.err, "--max-files"), "--max-files in help");
    check(contains(r.err, "--format"), "--format in help");
}

void testMissingTarget(const std::string &bin) {
    std::cerr << "test: scan missing target\n";
    auto r = run(bin + " scan");
    check(r.exitCode == 3, "exit 3");
    check(contains(r.err, "missing target"), "error message");
}

void testNonexistentPath(const std::string &bin) {
    std::cerr << "test: scan nonexistent path\n";
    auto r = run(bin + " scan /tmp/lshaz_no_such_" + std::to_string(getpid()));
    check(r.exitCode == 3, "exit 3");
}

void testUnknownOption(const std::string &bin) {
    std::cerr << "test: scan unknown option\n";
    auto r = run(bin + " scan . --bogus");
    check(r.exitCode == 3, "exit 3");
    check(contains(r.err, "unknown option"), "error message");
}

// ===== Compile DB resolution tests =====

void testCMakeGeneration(const std::string &bin, const std::string &fixture) {
    std::cerr << "test: cmake auto-generation of compile_commands.json\n";
    auto tmp = isolateFixture(fixture, "cmake");
    auto project = (tmp / "project").string();

    auto r = run(bin + " scan " + project + " --no-ir --format json");
    check(contains(r.err, "running cmake") || contains(r.err, "Found"),
          "compile DB resolved");
    check(r.exitCode == 0 || r.exitCode == 1, "valid exit code");

    fs::remove_all(tmp);
}

void testExplicitCompileDB(const std::string &bin, const std::string &fixture) {
    std::cerr << "test: explicit --compile-db path\n";
    auto tmp = isolateFixture(fixture, "explicit");
    auto project = (tmp / "project").string();

    // Pre-generate compile DB.
    auto cmakeR = run("cmake -S " + project + " -B " + project +
                      "/build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON");
    check(cmakeR.exitCode == 0, "cmake configure");

    std::string db = project + "/build/compile_commands.json";
    check(fs::exists(db), "compile_commands.json exists");

    auto r = run(bin + " scan " + project + " --compile-db " + db +
                 " --no-ir --format json");
    check(r.exitCode == 0 || r.exitCode == 1, "valid exit code");
    check(contains(r.out, "\"diagnostics\""), "JSON output produced");

    fs::remove_all(tmp);
}

void testDirectCompileDBPath(const std::string &bin, const std::string &fixture) {
    std::cerr << "test: scan <compile_commands.json> directly\n";
    auto tmp = isolateFixture(fixture, "directdb");
    auto project = (tmp / "project").string();

    auto cmakeR = run("cmake -S " + project + " -B " + project +
                      "/build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON");
    check(cmakeR.exitCode == 0, "cmake configure");

    std::string db = project + "/build/compile_commands.json";
    auto r = run(bin + " scan " + db + " --no-ir --format json");
    check(r.exitCode == 0 || r.exitCode == 1, "valid exit code");
    check(contains(r.out, "\"diagnostics\""), "JSON output");

    fs::remove_all(tmp);
}

// ===== Hazard detection tests (config-driven hot paths) =====

void testHazardDetectionWithConfig(const std::string &bin,
                                    const std::string &fixture) {
    std::cerr << "test: hazard detection with config-driven hot paths\n";
    auto tmp = isolateFixture(fixture, "hazards");
    auto project = (tmp / "project").string();
    std::string config = project + "/lshaz.config.yaml";

    auto r = run(bin + " scan " + project + " --config " + config +
                 " --no-ir --format json");

    check(r.exitCode == 1, "exit 1 (findings)");
    check(contains(r.out, "\"diagnostics\""), "has diagnostics");

    // Struct-level rules (no hot path required).
    check(contains(r.out, "FL001"), "FL001: OrderBookLevel spans cache lines");
    check(contains(r.out, "FL002") || contains(r.out, "FL041"),
          "FL002/FL041: OrderQueue false sharing or contended queue");

    // Hot-path rules (classified via config patterns).
    check(contains(r.out, "FL012") || contains(r.out, "FL010"),
          "FL012/FL010: lock contention or overly strong ordering in hot path");

    // Validate diagnostic structure completeness.
    check(contains(r.out, "\"ruleID\""), "diagnostics have ruleID");
    check(contains(r.out, "\"severity\""), "diagnostics have severity");
    check(contains(r.out, "\"confidence\""), "diagnostics have confidence");
    check(contains(r.out, "\"location\""), "diagnostics have location");
    check(contains(r.out, "\"hardwareReasoning\""), "diagnostics have hardwareReasoning");
    check(contains(r.out, "\"structuralEvidence\""), "diagnostics have structuralEvidence");
    check(contains(r.out, "\"mitigation\""), "diagnostics have mitigation");

    fs::remove_all(tmp);
}

void testMultipleTUs(const std::string &bin, const std::string &fixture) {
    std::cerr << "test: multi-TU analysis\n";
    auto tmp = isolateFixture(fixture, "multitu");
    auto project = (tmp / "project").string();
    std::string config = project + "/lshaz.config.yaml";

    auto r = run(bin + " scan " + project + " --config " + config +
                 " --no-ir --format json");

    // Fixture has 4 TUs: main.cpp, order_book.cpp, matching_engine.cpp, feed_handler.cpp
    check(contains(r.err, "4 translation unit"), "all 4 TUs analyzed");

    fs::remove_all(tmp);
}

// ===== Output format tests =====

void testJSONOutput(const std::string &bin, const std::string &fixture) {
    std::cerr << "test: JSON output format\n";
    auto tmp = isolateFixture(fixture, "json");
    auto project = (tmp / "project").string();
    std::string config = project + "/lshaz.config.yaml";

    auto r = run(bin + " scan " + project + " --config " + config +
                 " --no-ir --format json");

    check(contains(r.out, "\"version\""), "JSON has version");
    check(contains(r.out, "\"schemaVersion\""), "JSON has schemaVersion");
    check(contains(r.out, "\"metadata\""), "JSON has metadata");
    check(contains(r.out, "\"timestamp\""), "metadata has timestamp");
    check(contains(r.out, "\"sourceFiles\""), "metadata has sourceFiles");
    check(contains(r.out, "\"diagnostics\""), "JSON has diagnostics");

    // Verify it's valid-ish JSON (starts with { ends with })
    auto trimmed = r.out;
    while (!trimmed.empty() && (trimmed.back() == '\n' || trimmed.back() == ' '))
        trimmed.pop_back();
    check(!trimmed.empty() && trimmed.front() == '{' && trimmed.back() == '}',
          "JSON envelope");

    fs::remove_all(tmp);
}

void testSARIFOutput(const std::string &bin, const std::string &fixture) {
    std::cerr << "test: SARIF output format\n";
    auto tmp = isolateFixture(fixture, "sarif");
    auto project = (tmp / "project").string();
    std::string config = project + "/lshaz.config.yaml";

    auto r = run(bin + " scan " + project + " --config " + config +
                 " --no-ir --format sarif");

    check(r.exitCode == 1, "exit 1 (findings)");
    check(contains(r.out, "\"$schema\""), "SARIF $schema");
    check(contains(r.out, "sarif-schema-2.1.0"), "SARIF 2.1.0");
    check(contains(r.out, "\"version\": \"2.1.0\""), "SARIF version");
    check(contains(r.out, "\"runs\""), "SARIF runs");
    check(contains(r.out, "\"tool\""), "SARIF tool");
    check(contains(r.out, "\"results\""), "SARIF results");
    check(contains(r.out, "\"ruleId\""), "SARIF ruleId in results");

    fs::remove_all(tmp);
}

void testCLIOutput(const std::string &bin, const std::string &fixture) {
    std::cerr << "test: CLI output format\n";
    auto tmp = isolateFixture(fixture, "cli");
    auto project = (tmp / "project").string();
    std::string config = project + "/lshaz.config.yaml";

    auto r = run(bin + " scan " + project + " --config " + config +
                 " --no-ir --format cli");

    check(r.exitCode == 1, "exit 1 (findings)");
    check(contains(r.out, "FL001") || contains(r.out, "FL002"),
          "CLI shows rule IDs");
    check(contains(r.out, ".cpp"), "CLI shows filenames");

    fs::remove_all(tmp);
}

void testOutputToFile(const std::string &bin, const std::string &fixture) {
    std::cerr << "test: --output writes to file\n";
    auto tmp = isolateFixture(fixture, "outfile");
    auto project = (tmp / "project").string();
    auto outFile = (tmp / "report.json").string();

    auto r = run(bin + " scan " + project + " --no-ir --format json --output " + outFile);

    check(fs::exists(outFile), "output file created");
    if (fs::exists(outFile)) {
        std::ifstream ifs(outFile);
        std::ostringstream ss;
        ss << ifs.rdbuf();
        std::string content = ss.str();
        check(contains(content, "\"diagnostics\""), "file has diagnostics");
        check(r.out.empty() || !contains(r.out, "\"diagnostics\""),
              "stdout empty when writing to file");
    }

    fs::remove_all(tmp);
}

// ===== Filtering guardrail tests =====

void testExcludeAllFiles(const std::string &bin, const std::string &fixture) {
    std::cerr << "test: --exclude all files\n";
    auto tmp = isolateFixture(fixture, "exclall");
    auto project = (tmp / "project").string();

    auto r = run(bin + " scan " + project + " --exclude \"*.cpp\" --no-ir");
    check(r.exitCode == 0, "exit 0 when all excluded");
    check(contains(r.err, "0 translation unit"), "0 TUs");

    fs::remove_all(tmp);
}

void testIncludeFilter(const std::string &bin, const std::string &fixture) {
    std::cerr << "test: --include filter\n";
    auto tmp = isolateFixture(fixture, "incl");
    auto project = (tmp / "project").string();

    auto r = run(bin + " scan " + project + " --include \"*feed_handler*\" --no-ir");
    check(contains(r.err, "1 translation unit"), "1 TU matched");

    fs::remove_all(tmp);
}

void testExcludeFilter(const std::string &bin, const std::string &fixture) {
    std::cerr << "test: --exclude filter\n";
    auto tmp = isolateFixture(fixture, "excl");
    auto project = (tmp / "project").string();

    // Exclude main.cpp, should leave 3 TUs.
    auto r = run(bin + " scan " + project + " --exclude \"*main*\" --no-ir");
    check(contains(r.err, "3 translation unit"), "3 TUs after excluding main");

    fs::remove_all(tmp);
}

void testMaxFiles(const std::string &bin, const std::string &fixture) {
    std::cerr << "test: --max-files cap\n";
    auto tmp = isolateFixture(fixture, "maxf");
    auto project = (tmp / "project").string();

    auto r = run(bin + " scan " + project + " --max-files 2 --no-ir");
    check(contains(r.err, "2 translation unit"), "capped to 2 TUs");

    fs::remove_all(tmp);
}

void testCombinedFilters(const std::string &bin, const std::string &fixture) {
    std::cerr << "test: combined --include + --exclude + --max-files\n";
    auto tmp = isolateFixture(fixture, "combo");
    auto project = (tmp / "project").string();

    // Include *.cpp, exclude *main*, max 2 → should get 2 of the 3 remaining.
    auto r = run(bin + " scan " + project +
                 " --include \"*.cpp\" --exclude \"*main*\" --max-files 2 --no-ir");
    check(contains(r.err, "2 translation unit"), "2 TUs after combined filters");

    fs::remove_all(tmp);
}

// ===== Severity/evidence filtering tests =====

void testMinSeverityFilter(const std::string &bin, const std::string &fixture) {
    std::cerr << "test: --min-severity filter\n";
    auto tmp = isolateFixture(fixture, "minsev");
    auto project = (tmp / "project").string();
    std::string config = project + "/lshaz.config.yaml";

    auto rAll = run(bin + " scan " + project + " --config " + config +
                    " --no-ir --format json --min-severity Informational");
    auto rHigh = run(bin + " scan " + project + " --config " + config +
                     " --no-ir --format json --min-severity High");

    int countAll = countOccurrences(rAll.out, "\"ruleID\"");
    int countHigh = countOccurrences(rHigh.out, "\"ruleID\"");
    check(countHigh <= countAll, "High filter reduces or maintains count");

    fs::remove_all(tmp);
}

// ===== Determinism test =====

void testDeterminism(const std::string &bin, const std::string &fixture) {
    std::cerr << "test: output determinism across runs\n";
    auto tmp = isolateFixture(fixture, "determ");
    auto project = (tmp / "project").string();
    std::string config = project + "/lshaz.config.yaml";

    std::string cmd = bin + " scan " + project + " --config " + config +
                      " --no-ir --format json";
    auto r1 = run(cmd);
    auto r2 = run(cmd);

    check(r1.exitCode == r2.exitCode, "exit codes match");

    // Strip timestamp for comparison.
    auto strip = [](std::string s) {
        auto pos = s.find("\"timestamp\"");
        if (pos != std::string::npos) {
            auto end = s.find(',', pos);
            if (end == std::string::npos) end = s.find('}', pos);
            if (end != std::string::npos) s.erase(pos, end - pos + 1);
        }
        return s;
    };

    check(strip(r1.out) == strip(r2.out),
          "JSON deterministic (modulo timestamp)");

    fs::remove_all(tmp);
}

// ===== Parallel determinism =====

void testParallelDeterminism(const std::string &bin, const std::string &fixture) {
    std::cerr << "test: parallel determinism (--jobs 4, 5 iterations)\n";
    auto tmp = isolateFixture(fixture, "pardet");
    auto project = (tmp / "project").string();
    std::string config = project + "/lshaz.config.yaml";

    auto strip = [](std::string s) {
        auto pos = s.find("\"timestamp\"");
        if (pos != std::string::npos) {
            auto end = s.find(',', pos);
            if (end == std::string::npos) end = s.find('}', pos);
            if (end != std::string::npos) s.erase(pos, end - pos + 1);
        }
        return s;
    };

    std::string cmd = bin + " scan " + project + " --config " + config +
                      " --no-ir --format json --jobs 4";
    auto baseline = run(cmd);
    std::string baseStripped = strip(baseline.out);

    bool allMatch = true;
    for (int i = 1; i < 5; ++i) {
        auto ri = run(cmd);
        if (strip(ri.out) != baseStripped) {
            allMatch = false;
            break;
        }
    }
    check(allMatch, "5 parallel runs produce identical output");

    fs::remove_all(tmp);
}

// ===== Config autodiscovery =====

void testConfigAutodiscovery(const std::string &bin, const std::string &fixture) {
    std::cerr << "test: config autodiscovery (no --config flag)\n";
    auto tmp = isolateFixture(fixture, "autoconf");
    auto project = (tmp / "project").string();

    // No --config flag. lshaz should find lshaz.config.yaml in project root.
    auto r = run(bin + " scan " + project + " --no-ir --format json");

    check(contains(r.err, "using config"), "autodiscovered lshaz.config.yaml");
    check(r.exitCode == 1, "exit 1 (findings)");

    // Hot-path rules should fire because config patterns are active.
    check(contains(r.out, "FL012") || contains(r.out, "FL020") ||
          contains(r.out, "FL050") || contains(r.out, "FL010"),
          "hot-path rules fire via autodiscovered config");

    fs::remove_all(tmp);
}

void testConfigAutodiscoveryAbsent(const std::string &bin, const std::string &fixture) {
    std::cerr << "test: config autodiscovery absent (no config file)\n";
    auto tmp = isolateFixture(fixture, "noconf");
    auto project = (tmp / "project").string();

    // Remove the config file.
    fs::remove(fs::path(project) / "lshaz.config.yaml");

    auto r = run(bin + " scan " + project + " --no-ir --format json");
    check(!contains(r.err, "using config"), "no config autodiscovered");
    // Should still produce some diagnostics (struct-level rules).
    check(r.exitCode == 0 || r.exitCode == 1, "valid exit code");

    fs::remove_all(tmp);
}

// ===== Exit code semantics =====

void testExitCodeClean(const std::string &bin, const std::string &fixture) {
    std::cerr << "test: exit code 0 when no findings (Critical-only filter)\n";
    auto tmp = isolateFixture(fixture, "clean");
    auto project = (tmp / "project").string();

    // Use min-severity Critical — may or may not have Critical findings.
    // The key contract: exit 0 = no findings, exit 1 = findings.
    auto r = run(bin + " scan " + project + " --no-ir --min-severity Critical");
    check(r.exitCode == 0 || r.exitCode == 1,
          "exit code is 0 or 1 (not error)");

    fs::remove_all(tmp);
}

} // anonymous namespace

int main() {
    std::string bin = lshazBin();
    std::string fixture = fixturePath();

    if (!fs::exists(bin)) {
        std::cerr << "FATAL: lshaz binary not found at: " << bin << "\n";
        return 1;
    }

    // CLI dispatch.
    testHelp(bin);
    testMissingTarget(bin);
    testNonexistentPath(bin);
    testUnknownOption(bin);

    if (fixture.empty() || !fs::exists(fixture)) {
        std::cerr << "FATAL: fixture not found at test/fixtures/hft_core\n";
        return 1;
    }

    // Compile DB resolution.
    testCMakeGeneration(bin, fixture);
    testExplicitCompileDB(bin, fixture);
    testDirectCompileDBPath(bin, fixture);

    // Hazard detection.
    testHazardDetectionWithConfig(bin, fixture);
    testMultipleTUs(bin, fixture);

    // Output formats.
    testJSONOutput(bin, fixture);
    testSARIFOutput(bin, fixture);
    testCLIOutput(bin, fixture);
    testOutputToFile(bin, fixture);

    // Filtering guardrails.
    testExcludeAllFiles(bin, fixture);
    testIncludeFilter(bin, fixture);
    testExcludeFilter(bin, fixture);
    testMaxFiles(bin, fixture);
    testCombinedFilters(bin, fixture);
    testMinSeverityFilter(bin, fixture);

    // Determinism.
    testDeterminism(bin, fixture);
    testParallelDeterminism(bin, fixture);

    // Config autodiscovery.
    testConfigAutodiscovery(bin, fixture);
    testConfigAutodiscoveryAbsent(bin, fixture);

    // Exit code semantics.
    testExitCodeClean(bin, fixture);

    std::cerr << "\n" << passed << " passed, " << failures << " failed\n";
    if (failures > 0) {
        std::cerr << "SCAN E2E TESTS FAILED\n";
        return 1;
    }
    std::cerr << "All scan E2E tests passed.\n";
    return 0;
}
