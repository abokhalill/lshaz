// Drives the scan subcommand end to end: compile DB autodiscovery, config
// driven hot-path classification, every output format, filtering, exit codes
// and determinism.
//
// Fixture is test/fixtures/hft_core, which carries no synthetic annotations;
// hot paths come from lshaz.config.yaml patterns. Needs the lshaz binary and
// cmake on PATH.

#include <unistd.h>
#include <sys/wait.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <iostream>
#include <cctype>
#include <set>
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

std::string canaryPath() {
    if (fs::exists("test/fixtures/canary"))
        return "test/fixtures/canary";
    return "";
}

// Collect every "FLnnn" appearing as a ruleID value.
void collectFiredRules(const std::string &json, std::set<std::string> &out) {
    const std::string key = "\"ruleID\":";
    for (size_t i = json.find(key); i != std::string::npos;
         i = json.find(key, i + key.size())) {
        size_t q = json.find('"', i + key.size());
        if (q == std::string::npos) break;
        size_t e = json.find('"', q + 1);
        if (e == std::string::npos) break;
        out.insert(json.substr(q + 1, e - q - 1));
    }
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

// Every registered rule must fire on some canary fixture. A rule that stops
// firing produces output identical to a clean scan, so nothing else catches
// it. The registry is enumerated through `explain --list` rather than a
// hardcoded list, so a new rule cannot ship without a canary.
void testEveryRuleHasCanary(const std::string &bin,
                            const std::string &hftFixture,
                            const std::string &canaryFixture) {
    std::cerr << "test: every registered rule fires on a canary\n";

    auto listed = run(bin + " explain --list");
    std::set<std::string> registered;
    for (size_t i = 0; (i = listed.out.find("FL", i)) != std::string::npos;
         i += 2) {
        if (i + 5 > listed.out.size()) break;
        std::string id = listed.out.substr(i, 5);
        if (std::isdigit(static_cast<unsigned char>(id[2])) &&
            std::isdigit(static_cast<unsigned char>(id[3])) &&
            std::isdigit(static_cast<unsigned char>(id[4])))
            registered.insert(id);
    }
    check(registered.size() >= 15, "explain --list enumerates the registry");

    std::set<std::string> fired;
    int idx = 0;
    for (const auto &fx : {hftFixture, canaryFixture}) {
        if (fx.empty()) continue;
        auto tmp = isolateFixture(fx, "canary" + std::to_string(idx++));
        auto r = run(bin + " scan " + (tmp / "project").string() +
                     " --no-ir --format json");
        collectFiredRules(r.out, fired);
        fs::remove_all(tmp);
    }

    std::vector<std::string> missing;
    for (const auto &id : registered)
        if (!fired.count(id))
            missing.push_back(id);

    if (!missing.empty()) {
        std::cerr << "    rules with no canary: ";
        for (const auto &m : missing) std::cerr << m << " ";
        std::cerr << "\n";
    }
    check(missing.empty(),
          "every registered rule fires on hft_core or canary");
}

// The gate above asks only whether a rule fired somewhere, and both fixtures
// were C++, so a rule matching C++ spellings alone stayed green while
// reporting nothing in C, which hides those rules on every C codebase.
void testCLanguageCanary(const std::string &bin,
                         const std::string &canaryFixture) {
    std::cerr << "test: language-specific rules fire on a C translation unit\n";
    if (canaryFixture.empty()) {
        check(false, "canary fixture present for the C-language gate");
        return;
    }
    auto tmp = isolateFixture(canaryFixture, "canaryc");
    auto r = run(bin + " scan " + (tmp / "project").string() +
                 " --no-ir --format json");
    fs::remove_all(tmp);

    // Each diagnostic emits ruleID before location.file, so the file
    // belonging to a ruleID is the first one before the next ruleID.
    std::set<std::string> firedInC;
    const std::string key = "\"ruleID\":";
    for (size_t i = r.out.find(key); i != std::string::npos;
         i = r.out.find(key, i + key.size())) {
        size_t q = r.out.find('"', i + key.size());
        if (q == std::string::npos) break;
        size_t e = r.out.find('"', q + 1);
        if (e == std::string::npos) break;
        std::string id = r.out.substr(q + 1, e - q - 1);

        size_t next = r.out.find(key, i + key.size());
        size_t f = r.out.find("\"file\":", e);
        if (f == std::string::npos || (next != std::string::npos && f > next))
            continue;
        size_t fq = r.out.find('"', f + 7);
        if (fq == std::string::npos) continue;
        size_t fe = r.out.find('"', fq + 1);
        if (fe == std::string::npos) continue;
        std::string file = r.out.substr(fq + 1, fe - fq - 1);
        if (file.size() > 2 && file.compare(file.size() - 2, 2, ".c") == 0)
            firedInC.insert(id);
    }

    check(!firedInC.empty(), "the C translation unit was analyzed at all");
    for (const char *id : {"FL012", "FL013"}) {
        std::string label = std::string(id) +
                            " fires on a C translation unit";
        check(firedInC.count(id) != 0, label.c_str());
    }
}

// arr[c->tid] carries the owner's id, so one thread can drive every slot:
// A per-connection array subscripted by an owner id is written from one
// thread only, so the subscript alone must not carry High.
// Both shapes sit in the canary so the grades are compared to each other.
void testStripeIndexIdentity(const std::string &bin,
                             const std::string &canaryFixture) {
    std::cerr << "test: owner-indexed striping grades below writer-indexed\n";
    if (canaryFixture.empty()) {
        check(false, "canary fixture present for the stripe-identity gate");
        return;
    }
    auto tmp = isolateFixture(canaryFixture, "stripeid");
    auto r = run(bin + " scan " + (tmp / "project").string() +
                 " --no-ir --format json");
    fs::remove_all(tmp);

    auto identityOf = [&](const std::string &symbol) -> std::string {
        auto at = r.out.find("\"symbol\": \"" + symbol + "\"");
        if (at == std::string::npos)
            at = r.out.find("\"symbol\":\"" + symbol + "\"");
        if (at == std::string::npos) return "<absent>";
        // structuralEvidence is a std::map, so keys are emitted in
        // alphabetical order and index_identity precedes symbol.
        auto k = r.out.rfind("\"index_identity\"", at);
        if (k == std::string::npos) return "<absent>";
        auto q = r.out.find('"', r.out.find(':', k));
        if (q == std::string::npos) return "<absent>";
        auto e = r.out.find('"', q + 1);
        if (e == std::string::npos) return "<absent>";
        return r.out.substr(q + 1, e - q - 1);
    };

    check(identityOf("g_thread_bytes") == "writer",
          "a subscript on the writer's own parameter reads as writer identity");
    check(identityOf("canary_clients_per_thread") == "owner",
          "a subscript through a handed-in object reads as owner identity");

    // Write forms other than assignment to a bare subscript. Each of these
    // was silently missed, and a miss is indistinguishable from a clean
    // scan without a named symbol to look for.
    check(identityOf("g_slot_via_ptr") == "writer",
          "a write through a pointer taken to a slot is a striped write");
    check(identityOf("g_slot_nested") == "writer",
          "a write to a member array inside a slot is a striped write");
    check(identityOf("g_slot_stride") == "writer",
          "an element stride that is not a line multiple straddles lines "
          "whatever the base alignment");

    // g_swept is padded and aligned correctly. Asserting both directions
    // keeps FL003 and FL004 from collapsing into each other.
    check(contains(r.out, "\"FL004\""),
          "a sweep over correctly padded per-thread slots is reported");
    check(contains(r.out, "\"symbol\": \"g_swept\""),
          "the swept array is named in the sweep finding");
    // Reading index_identity here would assert nothing: that field is
    // FL003's, and FL003 is supposed to be silent on a padded array.
    check(identityOf("g_swept") == "<absent>",
          "FL003 stays silent on slots that are padded apart");

    // A store invalidates the whole line, so a reader of a different field
    // on it pays the same miss a second writer would. FL002 required both
    // sides written and could not express this at all.
    check(contains(r.out, "read/write evidence"),
          "a stored field beside a field read by another function is "
          "reported without a second writer");

    // canary_xtu_cmd stores 'calls' in canary_c.c and reads the specs beside
    // it from canary.cpp. Neither TU holds both halves, so the map phase has
    // nothing to grade and this only exists if the reduce join ran.
    check(contains(r.out, "canary_xtu_cmd"),
          "a store and a read of one cache line in different TUs are joined "
          "in the reduce phase");
    check(contains(r.out, "\"cross_tu_line_sharing\": \"true\""),
          "the cross-TU line-sharing finding is labelled as such");

    // refresh_time stores a microsecond count divided down to seconds into a
    // shared global, from a function two callers reach. Both halves matter:
    // the map phase finds the shape, and only the merged call graph can say
    // the store runs more than once.
    check(contains(r.out, "\"FL005\""),
          "an unconditional store of a coarsened value into a shared global "
          "is reported");
    check(contains(r.out, "the store repeats"),
          "the reduce phase settles how often the store runs");
}

// The channel rides the IR pass, so every other canary run here misses it:
// they all pass --no-ir.
void testOptRemarkChannel(const std::string &bin,
                          const std::string &canaryFixture) {
    std::cerr << "test: compiler remarks reach findings on a hot function\n";
    if (canaryFixture.empty()) {
        check(false, "canary fixture present for the remark gate");
        return;
    }
    auto tmp = isolateFixture(canaryFixture, "remarks");
    auto r = run(bin + " scan " + (tmp / "project").string() +
                 " --format json");
    fs::remove_all(tmp);

    check(contains(r.out, "\"C002\""),
          "a licm remark on a hot function becomes a finding");
    check(contains(r.out, "canary_scale_into"),
          "the finding names the function the compiler reported");
    check(!contains(r.out, "Error while parsing"),
          "no remark container failed to parse");
}

// Every serious C codebase reaches libc through a wrapper, so a rule matching
// only the libc names sees almost none of its allocations.
void testAllocatorWrapperNames(const std::string &bin,
                               const std::string &canaryFixture) {
    std::cerr << "test: FL020 sees allocations through a project wrapper\n";
    if (canaryFixture.empty()) {
        check(false, "canary fixture present for the allocator gate");
        return;
    }
    auto tmp = isolateFixture(canaryFixture, "allocwrap");
    auto r = run(bin + " scan " + (tmp / "project").string() +
                 " --no-ir --format json --rule FL020");
    fs::remove_all(tmp);
    check(contains(r.out, "canary_alloc_buf"),
          "an allocator named only in config is detected");
}

void testMechanismClaimsBoundSeverity(const std::string &bin,
                                      const std::string &fixture,
                                      const std::string &canaryFixture) {
    std::cerr << "test: severity never outranks an established mechanism\n";
    // Both fixtures, because the ratchet is only as wide as what the corpus
    // emits: FL092 stayed unmigrated through a passing run because neither
    // fixture alone produced it. A gate catches what the corpus contains.
    auto tmp = isolateFixture(fixture, "mech");
    auto r = run(bin + " scan " + (tmp / "project").string() +
                 " --no-ir --format json");
    if (!canaryFixture.empty()) {
        auto tmp2 = isolateFixture(canaryFixture, "mech2");
        r.out += run(bin + " scan " + (tmp2 / "project").string() +
                     " --no-ir --format json").out;
        fs::remove_all(tmp2);
    }

    auto rank = [](const std::string &s) {
        if (s == "Critical") return 3;
        if (s == "High")     return 2;
        if (s == "Medium")   return 1;
        return 0;
    };
    auto strAfter = [](const std::string &s, const std::string &key,
                       size_t from) -> std::string {
        auto at = s.find(key, from);
        if (at == std::string::npos) return {};
        auto q = s.find('"', at + key.size());
        if (q == std::string::npos) return {};
        auto e = s.find('"', q + 1);
        if (e == std::string::npos) return {};
        return s.substr(q + 1, e - q - 1);
    };

    size_t checked = 0, violations = 0, unmigrated = 0;
    size_t refutedSurvivors = 0;
    for (size_t i = r.out.find("\"ruleID\":"); i != std::string::npos;
         i = r.out.find("\"ruleID\":", i + 1)) {
        size_t end = r.out.find("\"ruleID\":", i + 1);
        std::string obj = r.out.substr(
            i, end == std::string::npos ? std::string::npos : end - i);
        if (obj.find("\"mechanismClaims\"") == std::string::npos) {
            ++unmigrated;
            continue;
        }
        ++checked;

        int sev = rank(strAfter(obj, "\"severity\":", 0));

        // Ceiling is the highest grade any ESTABLISHED claim supports.
        // Unknown and refuted contribute nothing, and a refuted claim must
        // never reach the output at all: the reduce phase withdraws it.
        int ceiling = 0;
        for (size_t c = obj.find("\"state\":"); c != std::string::npos;
             c = obj.find("\"state\":", c + 1)) {
            const std::string st = strAfter(obj, "\"state\":", c);
            if (st == "refuted") ++refutedSurvivors;
            if (st != "established") continue;
            ceiling = std::max(ceiling, rank(strAfter(obj, "\"supports\":", c)));
        }
        if (sev > ceiling) {
            std::cerr << "    " << strAfter(obj, "\"ruleID\":", 0)
                      << " severity " << strAfter(obj, "\"severity\":", 0)
                      << " exceeds its established claims\n";
            ++violations;
        }
    }
    std::cerr << "    " << checked << " finding(s) with declared claims, "
              << unmigrated << " unmigrated\n";
    check(checked > 0, "rules declare mechanism claims");
    check(violations == 0, "no finding outranks its established claims");
    check(unmigrated == 0, "every emitted finding declares its mechanism");
    // A refuted gate withdraws the finding, so one cannot reach the output
    // still carrying the refutation that should have retired it.
    check(refutedSurvivors == 0,
          "no finding survives carrying a refuted gating precondition");
    fs::remove_all(tmp);
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

// A Config field that nothing reads is a knob the user sets and the docs
// advertise while nothing happens, and it looks exactly like a working one.
// allocSizeEscalation sat dead behind an FL020 comment, and jsonOutput was
// parsed, documented, and never consulted. Same species as the registry
// canary gate below: absence of effect is invisible without a check for it.
void testEveryConfigFieldIsRead() {
    std::cerr << "test: every Config field is read somewhere\n";
    const std::string hdr = "include/lshaz/core/config.h";
    if (!fs::exists(hdr)) {
        std::cerr << "    (not at repo root, skipping)\n";
        return;
    }
    std::string decl{std::istreambuf_iterator<char>(
                         *std::make_unique<std::ifstream>(hdr)),
                     std::istreambuf_iterator<char>()};
    auto structPos = decl.find("struct Config");
    check(structPos != std::string::npos, "Config struct located");
    decl = decl.substr(structPos);

    // Field names: the last identifier before '=' or ';' on a declaration
    // line. Comment lines and the method declarations are skipped.
    std::vector<std::string> fields;
    std::istringstream ls(decl);
    for (std::string line; std::getline(ls, line);) {
        auto hash = line.find("//");
        if (hash != std::string::npos) line = line.substr(0, hash);
        if (line.find('(') != std::string::npos) continue;   // methods
        auto term = line.find_first_of("=;");
        if (term == std::string::npos) continue;
        std::string lhs = line.substr(0, term);
        size_t e = lhs.find_last_not_of(" \t");
        if (e == std::string::npos) continue;
        size_t b = lhs.find_last_of(" \t*&", e);
        if (b == std::string::npos) continue;
        std::string name = lhs.substr(b + 1, e - b);
        if (name.empty() || !(isalpha(name[0]) || name[0] == '_')) continue;
        if (name == "Config" || name == "struct") continue;
        fields.push_back(name);
    }
    check(fields.size() > 20, "Config fields parsed");

    std::string corpus;
    for (const char *root : {"src", "include"}) {
        if (!fs::exists(root)) continue;
        for (auto &p : fs::recursive_directory_iterator(root)) {
            if (!p.is_regular_file()) continue;
            auto s = p.path().string();
            if (s.find("core/config.cpp") != std::string::npos ||
                s.find("core/config.h") != std::string::npos)
                continue;
            auto ext = p.path().extension().string();
            if (ext != ".cpp" && ext != ".h") continue;
            std::ifstream f(s);
            corpus.append(std::istreambuf_iterator<char>(f),
                          std::istreambuf_iterator<char>());
        }
    }

    std::vector<std::string> dead;
    for (const auto &f : fields) {
        bool seen = false;
        for (const char *pfx : {".", ">"}) {
            std::string needle = std::string(pfx) + f;
            size_t at = corpus.find(needle);
            while (at != std::string::npos && !seen) {
                char after = at + needle.size() < corpus.size()
                                 ? corpus[at + needle.size()] : ' ';
                if (!isalnum(after) && after != '_') seen = true;
                at = corpus.find(needle, at + 1);
            }
            if (seen) break;
        }
        if (!seen) dead.push_back(f);
    }
    if (!dead.empty()) {
        std::cerr << "    Config fields nothing reads: ";
        for (const auto &d : dead) std::cerr << d << " ";
        std::cerr << "\n";
    }
    check(dead.empty(), "no Config field is parsed and then ignored");
}

// json_output: true selects JSON, and --format still outranks it. "cli" is the
// default value of the flag, so the override has to key on whether --format
// was actually given rather than on its value.
void testJsonOutputConfigKey(const std::string &bin,
                             const std::string &fixture) {
    std::cerr << "test: json_output config key selects JSON, --format wins\n";
    auto tmp = isolateFixture(fixture, "jsoncfg");
    auto project = (tmp / "project").string();
    { std::ofstream f(project + "/lshaz.config.yaml"); f << "json_output: true\n"; }

    auto cfgOnly = run(bin + " scan " + project + " --no-ir");
    check(contains(cfgOnly.out, "\"schemaVersion\""),
          "json_output: true produces JSON without --format");

    auto overridden = run(bin + " scan " + project + " --no-ir --format cli");
    check(!contains(overridden.out, "\"schemaVersion\""),
          "--format cli outranks json_output: true");

    fs::remove_all(tmp);
}

// FL020's cross-thread-free conjunct. The allocation and the free sit in
// different TUs on purpose: that split is the whole reason the verdict has to
// come from the reduce phase, and a single-file repro would pass without
// exercising the join at all.
void testCrossThreadFreeConjunct(const std::string &bin) {
    std::cerr << "test: FL020 establishes cross-thread free across TUs\n";
    auto root = fs::temp_directory_path() /
                ("lshaz_xfree_" + std::to_string(getpid()));

    auto build = [&](const fs::path &dir, bool crossThread) {
        fs::create_directories(dir);
        { std::ofstream f(dir / "job.h");
          f << "#pragma once\n#include <stdlib.h>\n"
               "typedef struct { int id; char payload[512]; } Job;\n"
               "void enqueue(Job *j);\nJob *dequeue(void);\n"
               "void consume(Job *j);\n"; }
        { std::ofstream f(dir / "queue.c");
          f << "#include \"job.h\"\nstatic Job *s[1024];\n"
               "static unsigned h, t;\n"
               "void enqueue(Job *j) { s[h++ & 1023] = j; }\n"
               "Job *dequeue(void) { return s[t++ & 1023]; }\n"; }
        { std::ofstream f(dir / "consumer.c");
          f << "#include \"job.h\"\nvoid consume(Job *j) { free(j); }\n"
               "void *worker(void *a) { (void)a;\n";
          // Cross-thread: the worker drains and frees. Same-thread: it does
          // nothing and main frees, so the roles coincide.
          f << (crossThread
                    ? "  for (int i = 0; i < 1000000; i++) { Job *j = "
                      "dequeue(); if (j) consume(j); }\n"
                    : "");
          f << "  return 0;\n}\n"; }
        { std::ofstream f(dir / "producer.c");
          f << "#include \"job.h\"\n#include <pthread.h>\n"
               "void *worker(void *a);\n"
               "Job *make_job(int id) { Job *j = malloc(sizeof(Job));"
               " if (j) j->id = id; return j; }\n"
               "int main(void) { pthread_t t;"
               " pthread_create(&t, 0, worker, 0);\n"
               "  for (int i = 0; i < 1000000; i++) { Job *j = make_job(i);"
               " enqueue(j);";
          f << (crossThread ? "" : " consume(j);");
          f << " }\n  return 0; }\n"; }
        { std::ofstream f(dir / "lshaz.config.yaml");
          f << "hot_function_patterns:\n  - \"make_job\"\n  - \"consume\"\n"; }
        { std::ofstream f(dir / "compile_commands.json");
          f << "[";
          const char *srcs[] = {"producer.c", "consumer.c", "queue.c"};
          for (int i = 0; i < 3; ++i)
              f << (i ? "," : "") << "{\"directory\":\"" << dir.string()
                << "\",\"command\":\"cc -O2 -c " << srcs[i]
                << "\",\"file\":\"" << (dir / srcs[i]).string() << "\"}";
          f << "]\n"; }
    };

    build(root / "cross", true);
    build(root / "same", false);

    // Assert on the per-finding escalation, not the summary line: that line
    // reports the join's reach and prints the same phrase with a count of 0.
    auto cross = run(bin + " scan " + (root / "cross").string() + " --no-ir");
    check(contains(cross.out, "cross-TU: every allocation of 'Job'"),
          "disjoint alloc/free roles establish the conjunct");
    check(contains(cross.out, "[High] FL020"),
          "the allocating site outranks Medium once established");

    auto same = run(bin + " scan " + (root / "same").string() + " --no-ir");
    check(!contains(same.out, "cross-TU: every allocation of"),
          "same-thread free does not establish it");
    check(!contains(same.out, "[High] FL020"),
          "same-thread free stays capped");

    fs::remove_all(root);
}

// A cache that returns anything other than what a cold scan returns is worse
// than no cache, so the contract is equality, not hit rate. The header arm is
// the one that matters: keying on the TU alone would serve a stale record for
// every dependent TU after a header edit, and nothing downstream would notice.
void testTUCacheAgreesWithColdScan(const std::string &bin) {
    std::cerr << "test: cached scan matches cold scan, and headers invalidate\n";
    auto root = fs::temp_directory_path() /
                ("lshaz_cache_" + std::to_string(getpid()));
    auto cache = root / "cache";
    fs::create_directories(root);

    { std::ofstream f(root / "h.h");
      f << "#pragma once\n#include <stdlib.h>\n"
           "static inline void *wrap(size_t n) { return malloc(n); }\n"; }
    { std::ofstream f(root / "a.c");
      f << "#include \"h.h\"\n"
           "void run(void) { for (int i = 0; i < 1000; ++i)"
           " { void *p = wrap(8); (void)p; } }\n"
           "int main(void) { run(); return 0; }\n"; }
    { std::ofstream f(root / "compile_commands.json");
      f << "[{\"directory\":\"" << root.string()
        << "\",\"command\":\"cc -c a.c\",\"file\":\""
        << (root / "a.c").string() << "\"}]\n"; }

    const std::string args = " scan " + root.string() + " --no-ir --cache-dir " +
                             cache.string();
    auto cold = run(bin + args);
    check(contains(cold.err, "0 from cache"), "first scan populates nothing");
    auto warm = run(bin + args);
    check(contains(warm.err, "1 from cache"), "second scan is served");
    check(cold.out == warm.out, "cached scan output matches the cold scan");

    { std::ofstream f(root / "h.h");
      f << "#pragma once\n#include <stdlib.h>\n"
           "static inline void *wrap(size_t n) { return calloc(1, n); }\n"; }
    auto edited = run(bin + args);
    check(contains(edited.err, "0 from cache"),
          "editing a header the TU includes invalidates its entry");

    fs::remove_all(root);
}

// The prepass forks, so a fact added to ThreadRoleSummary and to merge() but
// not to the serializer is discarded at the shard boundary. That failed
// silently: correct at one job, empty in parallel, and the single-TU fixture
// that verified the feature took the sequential path and never noticed.
//
// Asserting the whole vocabulary line is identical across job counts catches
// the next one by construction, whatever kind of fact it is. Needs several
// TUs, or there is nothing to shard.
// The inert-rule line is what distinguishes "looked and found nothing" from
// "never ran", and it enumerated RuleRegistry only. Rules emitted in the
// reduce phase are not in the registry, so they were the one class the
// report could never speak for.
void testReducePhaseRulesAreAccountedFor(const std::string &bin,
                                         const std::string &hftFixture,
                                         const std::string &canaryFixture) {
    std::cerr << "test: reduce-phase rules appear in the inert-rule line\n";
    if (hftFixture.empty() || canaryFixture.empty()) {
        check(false, "both fixtures present for the inert-rule gate");
        return;
    }
    auto inertLine = [&](const std::string &fixture, const char *suffix) {
        auto tmp = isolateFixture(fixture, suffix);
        auto r = run(bin + " scan " + (tmp / "project").string() + " --no-ir");
        fs::remove_all(tmp);
        auto at = r.err.find("rule(s) produced no findings:");
        if (at == std::string::npos) return std::string("<absent>");
        return r.err.substr(at, r.err.find('\n', at) - at);
    };

    // FL003 finds nothing in hft_core, which spawns no threads, and fires on
    // the canary. Naming it in one and not the other is the whole contract.
    const std::string quiet = inertLine(hftFixture, "inerthft");
    check(contains(quiet, "FL003"),
          "a reduce-phase rule that found nothing is named as inert");
    check(!contains(inertLine(canaryFixture, "inertcan"), "FL003"),
          "a reduce-phase rule that fired is not named as inert");
}

// "do { ... } while(0)" is how C wraps a multi-statement macro, and it is a
// DoStmt in the AST like any other. Counted as a loop it makes a global
// written twice at startup look like one written in a loop, which is the
// difference between a lifecycle signal and sustained coherence traffic.
// Every atomic in a wrapper-using C codebase is written through such a
// macro, so this was not an edge case: it kept redisAsciiArt, which prints
// a banner once, graded as an allocation on a hot path.
void testMacroWrapperIsNotALoop(const std::string &bin) {
    std::cerr << "test: a do/while(0) macro wrapper is not counted as a loop\n";
    auto root = fs::temp_directory_path() /
                ("lshaz_dw0_" + std::to_string(getpid()));
    fs::create_directories(root);

    // Line numbers are the handle: FL040 reports the declaration site and
    // carries no symbol in its evidence.
    { std::ofstream f(root / "a.c");
      f << "#include <pthread.h>\n"                                  // 1
           "#define bump(v,n) do { (v) += (n); } while(0)\n"         // 2
           "static long macro_written;\n"                            // 3
           "static long loop_written;\n"                             // 4
           "static void *w1(void *a) { bump(macro_written, 1);\n"    // 5
           "  for (int i = 0; i < 1000; ++i) loop_written += i;\n"   // 6
           "  return a; }\n"                                         // 7
           "static void *w2(void *a) { bump(macro_written, 2);\n"    // 8
           "  loop_written = 0; return a; }\n"                       // 9
           "int main(void) {\n"
           "  pthread_t t[2];\n"
           "  pthread_create(&t[0],0,w1,0); pthread_create(&t[1],0,w2,0);\n"
           "  pthread_join(t[0],0); pthread_join(t[1],0);\n"
           "  return 0; }\n"; }
    { std::ofstream f(root / "compile_commands.json");
      f << "[{\"directory\":\"" << root.string()
        << "\",\"command\":\"cc -c a.c\",\"file\":\""
        << (root / "a.c").string() << "\"}]\n"; }

    auto r = run(bin + " scan " + root.string() + " --no-ir --rule FL040"
                 " --format json");
    auto loopWritesAtLine = [&](const std::string &line) {
        auto at = r.out.find("\"line\": " + line + ",");
        if (at == std::string::npos) return std::string("<absent>");
        auto k = r.out.find("\"global_loop_writes\"", at);
        if (k == std::string::npos) return std::string("<absent>");
        auto q = r.out.find('"', r.out.find(':', k));
        return r.out.substr(q + 1, r.out.find('"', q + 1) - q - 1);
    };
    // Two writes, both through the macro. Counted as loops this read as 2.
    check(loopWritesAtLine("3") == "0",
          "a write inside a do/while(0) macro is not a loop write");
    // The guard must fold only the degenerate condition, or it would trade
    // one blind spot for another and stop seeing real repetition.
    const std::string real = loopWritesAtLine("4");
    check(real != "0" && real != "<absent>",
          "a write inside a real loop is still a loop write");

    fs::remove_all(root);
}

// A project that needs a build before it can be scanned reports zero
// findings, which is what a clean project reports. B001 is the only thing
// that tells those apart, and it was dead: it searched the stored error for
// a "fatal error:" prefix that FormatDiagnostic does not emit, so it never
// matched and nothing failed. Nothing referenced B001 in any harness.
void testMissingHeaderIsReported(const std::string &bin) {
    std::cerr << "test: a project needing a build says so rather than "
                 "reporting clean\n";
    auto root = fs::temp_directory_path() /
                ("lshaz_b001_" + std::to_string(getpid()));
    fs::create_directories(root);

    const int kTUs = 4;   // B001 needs at least three
    for (int i = 0; i < kTUs; ++i) {
        std::ofstream f(root / ("a" + std::to_string(i) + ".c"));
        f << "#include \"generated_config.h\"\n"
             "int f" << i << "(void) { return CONFIG_VALUE; }\n";
    }
    { std::ofstream f(root / "compile_commands.json");
      f << "[";
      for (int i = 0; i < kTUs; ++i)
          f << (i ? "," : "") << "{\"directory\":\"" << root.string()
            << "\",\"command\":\"cc -c a" << i << ".c\",\"file\":\""
            << (root / ("a" + std::to_string(i) + ".c")).string() << "\"}";
      f << "]\n"; }

    auto scan = [&](const std::string &jobs) {
        return run(bin + " scan " + root.string() + " --no-ir --format json"
                   " --jobs " + jobs).out;
    };
    const std::string one = scan("1");
    check(contains(one, "\"B001\""),
          "a header missing from every TU is reported, not scanned past");
    check(contains(one, "generated_config.h"),
          "the report names the header that could not be found");
    // The header name is collected in a forked child. Anything the parent
    // needs has to cross the IPC boundary explicitly, and the symptom of
    // forgetting is a scan that is correct at --jobs 1 only.
    check(countOccurrences(one, "\"B001\"") ==
              countOccurrences(scan("4"), "\"B001\""),
          "the missing-header report survives the shard boundary");

    fs::remove_all(root);
}

void testVocabularyIsJobsInvariant(const std::string &bin) {
    std::cerr << "test: derived vocabulary is identical across job counts\n";
    auto root = fs::temp_directory_path() /
                ("lshaz_vjobs_" + std::to_string(getpid()));
    fs::create_directories(root);

    { std::ofstream f(root / "lk.h");
      f << "#pragma once\n#include <stdlib.h>\n"
           "typedef struct { volatile long *lock; } mtx_t;\n"
           "void spin_acq(mtx_t *m);\nvoid spin_rel(mtx_t *m);\n"
           "void *wrap_alloc(size_t n);\nvoid wrap_free(void *p);\n"; }
    { std::ofstream f(root / "lk.c");
      f << "#include \"lk.h\"\n"
           "void spin_acq(mtx_t *m) { for(;;){ if(__sync_bool_compare_and_swap("
           "m->lock,0,1)) return; } }\n"
           "void spin_rel(mtx_t *m) { __sync_bool_compare_and_swap("
           "m->lock,1,0); }\n"; }
    { std::ofstream f(root / "al.c");
      f << "#include \"lk.h\"\n"
           "void *wrap_alloc(size_t n) { return malloc(n); }\n"
           "void wrap_free(void *p) { free(p); }\n"; }
    { std::ofstream f(root / "use.c");
      f << "#include \"lk.h\"\nstatic mtx_t g;\n"
           "void run(void){ for(int i=0;i<100000;++i){ spin_acq(&g);"
           " void*p=wrap_alloc(8); wrap_free(p); spin_rel(&g); } }\n"
           "int main(void){ run(); return 0; }\n"; }
    { std::ofstream f(root / "compile_commands.json");
      f << "[";
      const char *srcs[] = {"lk.c", "al.c", "use.c"};
      for (int i = 0; i < 3; ++i)
          f << (i ? "," : "") << "{\"directory\":\"" << root.string()
            << "\",\"command\":\"cc -c " << srcs[i] << "\",\"file\":\""
            << (root / srcs[i]).string() << "\"}";
      f << "]\n"; }

    auto vocabLine = [&](const std::string &jobs) {
        auto r = run(bin + " scan " + root.string() + " --no-ir --jobs " + jobs);
        size_t i = r.err.find("name(s) derived");
        if (i == std::string::npos) return std::string("<absent>");
        size_t b = r.err.rfind("prescanned clean, ", i);
        return b == std::string::npos ? std::string("<absent>")
                                      : r.err.substr(b, i - b);
    };
    const std::string one = vocabLine("1");
    check(one != "<absent>", "the vocabulary line is reported");
    check(one == vocabLine("4"),
          "derived vocabulary survives the shard boundary");
    // Deliberately not named mtx_lock: that is C11's own spelling and would
    // match the seed set, proving nothing about the derivation.
    check(one.find("1 lock") != std::string::npos,
          "the spin lock pair is derived from its atomic, not from a name");

    fs::remove_all(root);
}

// ===== Compile DB resolution tests =====

// init must not report success when it produced no compile database: "ready,
// run lshaz scan" after "no build system found" sends the user at a scan that
// cannot read anything.
void testInitWithoutBuildSystem(const std::string &bin) {
    std::cerr << "test: init fails when it produced no compile database\n";
    auto tmp = fs::temp_directory_path() /
               ("lshaz_initnb_" + std::to_string(getpid()));
    fs::create_directories(tmp);
    { std::ofstream f(tmp / "m.c"); f << "int main(void){return 0;}\n"; }

    auto r = run(bin + " init " + tmp.string());
    check(r.exitCode != 0, "init reports failure with no build system");
    check(!contains(r.err, "ready"), "init does not claim ready");
    check(contains(r.err, "no compile_commands.json"),
          "init names what is missing");

    fs::remove_all(tmp);
}

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

    // FL013: explicit .load() spin and the implicit conversion-operator
    // form both fire; the __builtin_ia32_pause twin must not.
    check(countOccurrences(r.out, "\"FL013\"") >= 2,
          "FL013: explicit and implicit-conversion spins detected");
    check(contains(r.out, "spinAwaitImplicit"),
          "FL013: conversion-operator poll detected");
    check(contains(r.out, "spinAwaitReady") &&
              !contains(r.out, "spinAwaitReadyPaused"),
          "FL013: paused twin not flagged");

    // FL070: hot-referenced unaligned arena fires with alignment named
    // as the defect; the 2MB-aligned twin reports at floor.
    check(contains(r.out, "g_replayArena") &&
              contains(r.out, "lacks 2MB base alignment"),
          "FL070: unaligned hot arena flagged on alignment");
    check(contains(r.out, "hugepage-ready"),
          "FL070: aligned twin at mitigation-respect floor");

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

// Fixture: test/fixtures/thread_roles, SharedStats has its two atomic
// counters written by main (main.cpp) and a pthread worker (worker.cpp);
// LocalStats is the same layout with main-only writers. The escalation
// must attribute the first pair as disjoint and leave the control alone.
void testThreadRoleEscalation(const std::string &bin) {
    std::cerr << "test: cross-TU thread-role escalation\n";
    if (!fs::exists("test/fixtures/thread_roles")) {
        std::cerr << "  SKIP: fixture missing\n";
        return;
    }
    auto tmp = isolateFixture("test/fixtures/thread_roles", "throles");
    auto project = (tmp / "project").string();

    auto r = run(bin + " scan " + project + " --no-ir --format json");
    check(r.exitCode == 1, "exit 1 (findings)");
    check(contains(r.err, "thread entry point(s)"),
          "thread-role reduce reported");
    check(countOccurrences(r.out, "cross-TU thread-role attribution") == 1,
          "exactly one escalation (SharedStats, not the control)");
    check(contains(r.out, "'mainOps' written only from main-thread"),
          "main-side field attributed");
    check(contains(r.out, "'workerOps' only from worker-thread"),
          "worker-side field attributed across TUs");
    check(!contains(r.out, "'ctrlA' written only from"),
          "main-only control struct not escalated");

    // FL092: SharedStats lacks the idiom IsolatedCounter demonstrates.
    check(countOccurrences(r.out, "Unapplied In-Tree Mitigation") == 1,
          "exactly one FL092 (attributed struct without the idiom)");
    check(contains(r.out, "\"mitigated_exemplar\": \"IsolatedCounter\"") ||
              contains(r.out, "\"mitigated_exemplar\":\"IsolatedCounter\""),
          "FL092 names the in-tree exemplar");

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

    // Include *.cpp, exclude *main*, max 2 -> should get 2 of the 3 remaining.
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

// ===== Shard loss accounting =====

// A shard that dies takes its translation units with it. If the parent does
// not account for them, the scan reports the same thing a clean scan does:
// no findings, no failures, exit 0. Forcing the IPC write to fail is the
// cheapest reproduction of the whole class (the OOM killer is the realistic
// one). What is asserted is the accounting, not the specific failure.
void testLostShardIsNotACleanScan(const std::string &bin,
                                  const std::string &fixture) {
    std::cerr << "test: a lost shard is accounted, not silently dropped\n";
    auto tmp = isolateFixture(fixture, "shardloss");
    auto project = (tmp / "project").string();
    std::string config = project + "/lshaz.config.yaml";

    std::string scan = bin + " scan " + project + " --config " + config +
                       " --no-ir --jobs 2";

    auto clean = run(scan);
    auto killed = run("LSHAZ_FAULT_KILL_SHARD=0 " + scan);

    // The comparison is the point: the two runs must not look alike.
    check(contains(killed.err, "FAULT INJECTION"), "fault injection fired");
    check(killed.exitCode != 0, "lost shard does not exit 0");
    check(contains(killed.err, "unanalyzed"),
          "stderr names the shard's TUs as unanalyzed");
    check(contains(killed.err, "killed by signal"),
          "stderr gives the reason the shard was lost");

    // The defect this guards: without accounting, the killed shard's TUs are
    // counted as parsed, so both runs print the same "N/N parsed" with no
    // failures and exit alike. Assert the summaries actually differ.
    auto summary = [](const std::string &err) {
        auto pos = err.find(" TU(s) parsed");
        if (pos == std::string::npos) return std::string();
        auto begin = err.rfind('\n', pos);
        begin = (begin == std::string::npos) ? 0 : begin + 1;
        return err.substr(begin, err.find('\n', pos) - begin);
    };
    check(contains(summary(clean.err), "4/4"), "clean scan parses every TU");
    check(contains(summary(killed.err), "2/4") &&
          contains(summary(killed.err), "2 failed"),
          "lost shard's TUs are reported unparsed and failed");
    check(summary(clean.err) != summary(killed.err),
          "a lost shard is distinguishable from a clean scan");

    // Records are written per TU, so a shard that dies partway still hands
    // back what it finished. Without that, one fatal TU discards every TU the
    // shard already completed. The difference between 3/4 and 2/4 here was
    // every TU or none of them on a large project.
    auto midKill = run("LSHAZ_FAULT_KILL_SHARD=0:1 " + scan);
    check(contains(summary(midKill.err), "3/4") &&
          contains(summary(midKill.err), "1 failed"),
          "a mid-shard death loses only the TU it died on");
    check(contains(midKill.err, "1 recovered"),
          "stderr reports how much of the dead shard was recovered");

    // Same accounting, different cause. A cap too low to analyze anything is
    // the controllable stand-in for the TU that would otherwise OOM the host,
    // and the reason must name the cap so the operator knows which knob moved.
    auto starved = run(scan + " --memory-limit-mb 64");
    check(starved.exitCode != 0, "memory-starved shard does not exit 0");
    check(contains(starved.err, "memory cap"),
          "stderr attributes the loss to the memory cap, not a generic crash");
    check(contains(starved.err, "--memory-limit-mb"),
          "stderr names the knob that fixes it");
    check(contains(summary(starved.err), "failed"),
          "starved shard's TUs are reported failed");

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

    // Use min-severity Critical, may or may not have Critical findings.
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
    testEveryConfigFieldIsRead();
    testCrossThreadFreeConjunct(bin);
    testTUCacheAgreesWithColdScan(bin);
    testVocabularyIsJobsInvariant(bin);
    testMissingHeaderIsReported(bin);
    testMacroWrapperIsNotALoop(bin);
    testJsonOutputConfigKey(bin, fixture);
    testInitWithoutBuildSystem(bin);
    testCMakeGeneration(bin, fixture);
    testExplicitCompileDB(bin, fixture);
    testDirectCompileDBPath(bin, fixture);

    // Recall canary: registry completeness.
    testEveryRuleHasCanary(bin, fixture, canaryPath());
    testCLanguageCanary(bin, canaryPath());
    testStripeIndexIdentity(bin, canaryPath());
    testOptRemarkChannel(bin, canaryPath());
    testAllocatorWrapperNames(bin, canaryPath());
    testMechanismClaimsBoundSeverity(bin, fixture, canaryPath());
    testReducePhaseRulesAreAccountedFor(bin, fixture, canaryPath());

    // Hazard detection.
    testHazardDetectionWithConfig(bin, fixture);
    testMultipleTUs(bin, fixture);
    testThreadRoleEscalation(bin);

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

    // Loud failure.
    testLostShardIsNotACleanScan(bin, fixture);

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
