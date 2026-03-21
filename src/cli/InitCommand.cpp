// SPDX-License-Identifier: Apache-2.0
#include "InitCommand.h"

#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/Program.h>
#include <llvm/Support/raw_ostream.h>

#include <cstring>
#include <fstream>
#include <random>
#include <string>
#include <chrono>
#include <thread>

#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

namespace lshaz {

namespace {

enum class BuildSystem { CMake, Meson, Make, Unknown };

BuildSystem detectBuildSystem(const std::string &dir) {
    llvm::SmallString<256> p;

    p = llvm::StringRef(dir);
    llvm::sys::path::append(p, "CMakeLists.txt");
    if (llvm::sys::fs::exists(p))
        return BuildSystem::CMake;

    p = llvm::StringRef(dir);
    llvm::sys::path::append(p, "meson.build");
    if (llvm::sys::fs::exists(p))
        return BuildSystem::Meson;

    p = llvm::StringRef(dir);
    llvm::sys::path::append(p, "Makefile");
    if (llvm::sys::fs::exists(p))
        return BuildSystem::Make;

    p = llvm::StringRef(dir);
    llvm::sys::path::append(p, "GNUmakefile");
    if (llvm::sys::fs::exists(p))
        return BuildSystem::Make;

    return BuildSystem::Unknown;
}

bool hasCompileDB(const std::string &dir) {
    llvm::SmallString<256> p(dir);
    llvm::sys::path::append(p, "compile_commands.json");
    if (llvm::sys::fs::exists(p))
        return true;

    p = llvm::StringRef(dir);
    llvm::sys::path::append(p, "build");
    llvm::sys::path::append(p, "compile_commands.json");
    if (llvm::sys::fs::exists(p))
        return true;

    return false;
}

// Shell-escape a single argument for sh -c.
std::string shellQuote(const std::string &s) {
    std::string out = "'";
    for (char c : s) {
        if (c == '\'') out += "'\\''";
        else out += c;
    }
    out += "'";
    return out;
}

int runExternal(const std::string &program,
                const std::vector<std::string> &args,
                const std::string &cwd,
                const std::string &label = "",
                unsigned timeout = 120) {
    auto found = llvm::sys::findProgramByName(program);
    if (!found) {
        llvm::errs() << "lshaz init: '" << program << "' not found in PATH\n";
        return -1;
    }

    auto sh = llvm::sys::findProgramByName("sh");
    if (!sh) {
        llvm::errs() << "lshaz init: 'sh' not found\n";
        return -1;
    }

    std::string cmdline = "cd " + shellQuote(cwd) + " && exec " +
                          shellQuote(*found);
    for (const auto &a : args)
        cmdline += " " + shellQuote(a);

    bool isTTY = llvm::errs().is_displayed();
    std::string spinLabel = label.empty() ? program : label;

    // Fork so we can animate a spinner while the child runs.
    pid_t pid = fork();
    if (pid < 0) {
        llvm::errs() << "lshaz init: fork() failed: " << strerror(errno) << "\n";
        return -1;
    }

    if (pid == 0) {
        // Child: redirect stdout/stderr to /dev/null, exec via sh -c.
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execl(sh->c_str(), "sh", "-c", cmdline.c_str(), nullptr);
        _exit(127);
    }

    // Parent: animate spinner while waiting for child.
    static const char *spinFrames[] = {
        "\xe2\xa0\x8b", "\xe2\xa0\x99", "\xe2\xa0\xb9", "\xe2\xa0\xb8",
        "\xe2\xa0\xbc", "\xe2\xa0\xb4", "\xe2\xa0\xa6", "\xe2\xa0\xa7",
        "\xe2\xa0\x87", "\xe2\xa0\x8f"
    };
    constexpr unsigned numFrames = 10;
    unsigned frame = 0;
    auto startTime = std::chrono::steady_clock::now();

    if (!isTTY)
        llvm::errs() << "lshaz init: running " << spinLabel << "...\n";

    int status = 0;
    while (true) {
        pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid) break;
        if (w < 0) break;

        // Check timeout.
        auto elapsed = std::chrono::steady_clock::now() - startTime;
        auto secs = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
        if (static_cast<unsigned>(secs) >= timeout) {
            kill(pid, SIGTERM);
            waitpid(pid, &status, 0);
            if (isTTY) llvm::errs() << "\r\033[K";
            llvm::errs() << "lshaz init: " << spinLabel
                         << " timed out after " << timeout << "s\n";
            return -1;
        }

        if (isTTY) {
            llvm::errs() << "\r  " << spinFrames[frame % numFrames]
                         << "  " << spinLabel << "... ("
                         << secs << "s)";
            llvm::errs().flush();
            ++frame;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(80));
    }

    if (isTTY) llvm::errs() << "\r\033[K";

    int rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    return rc;
}

bool generateCMake(const std::string &dir, bool fullBuild) {
    llvm::errs() << "lshaz init: detected CMake project\n";
    llvm::SmallString<256> buildDir(dir);
    llvm::sys::path::append(buildDir, "build");
    llvm::sys::fs::create_directories(buildDir);

    int rc = runExternal("cmake", {
        "-S", dir,
        "-B", std::string(buildDir),
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"
    }, dir, "configuring CMake");

    // CMake often writes compile_commands.json before a late find_package
    // failure. Check regardless of exit code.
    llvm::SmallString<256> db(buildDir);
    llvm::sys::path::append(db, "compile_commands.json");
    bool haveDB = llvm::sys::fs::exists(db);

    if (rc != 0 && !haveDB) {
        llvm::errs() << "lshaz init: cmake configure failed and no "
                        "compile_commands.json was generated\n";
        return false;
    }
    if (rc != 0)
        llvm::errs() << "lshaz init: cmake configure had errors, but "
                        "compile_commands.json was generated\n";

    if (fullBuild) {
        llvm::errs() << "lshaz init: running full build to generate required "
                        "headers (--build)\n";
        int buildRc = runExternal("cmake", {
            "--build", std::string(buildDir), "--parallel"
        }, dir, "building (cmake --build)", 600);
        if (buildRc != 0)
            llvm::errs() << "lshaz init: build failed (exit " << buildRc
                         << "); some generated headers may be missing\n";
    }

    if (haveDB) {
        llvm::errs() << "lshaz init: generated " << db << "\n";
        return true;
    }
    return false;
}

bool generateMeson(const std::string &dir, bool fullBuild) {
    llvm::errs() << "lshaz init: detected Meson project\n";
    llvm::SmallString<256> buildDir(dir);
    llvm::sys::path::append(buildDir, "build");

    if (!llvm::sys::fs::is_directory(buildDir)) {
        int rc = runExternal("meson", {"setup", std::string(buildDir)}, dir, "configuring Meson");
        if (rc != 0) {
            llvm::errs() << "lshaz init: meson setup failed\n";
            return false;
        }
    }

    if (fullBuild) {
        llvm::errs() << "lshaz init: running full build to generate required "
                        "headers (--build)\n";
        int buildRc = runExternal("meson", {"compile", "-C", std::string(buildDir)},
                                  dir, "building (meson compile)", 600);
        if (buildRc != 0)
            llvm::errs() << "lshaz init: build failed (exit " << buildRc
                         << "); some generated headers may be missing\n";
    }

    llvm::SmallString<256> db(buildDir);
    llvm::sys::path::append(db, "compile_commands.json");
    if (llvm::sys::fs::exists(db)) {
        llvm::errs() << "lshaz init: found " << db << "\n";
        return true;
    }
    llvm::errs() << "lshaz init: meson build dir exists but compile_commands.json not found\n";
    return false;
}

bool generateBear(const std::string &dir) {
    llvm::errs() << "lshaz init: detected Makefile project\n"
                    "  Note: bear requires a full build; project dependencies "
                    "must be installed.\n";
    auto bear = llvm::sys::findProgramByName("bear");
    if (!bear) {
        llvm::errs() << "lshaz init: 'bear' not found. Install bear to "
                        "generate compile_commands.json from Make:\n"
                        "  apt install bear   # Debian/Ubuntu\n"
                        "  pacman -S bear     # Arch\n";
        return false;
    }

    int rc = runExternal("bear", {"--", "make", "-j"}, dir, "building with bear", 300);
    if (rc != 0) {
        llvm::errs() << "lshaz init: bear failed (exit " << rc << ")\n";
        return false;
    }

    llvm::SmallString<256> db(dir);
    llvm::sys::path::append(db, "compile_commands.json");
    if (llvm::sys::fs::exists(db)) {
        llvm::errs() << "lshaz init: generated " << db << "\n";
        return true;
    }
    return false;
}

bool writeStarterConfig(const std::string &dir) {
    llvm::SmallString<256> cfgPath(dir);
    llvm::sys::path::append(cfgPath, "lshaz.config.yaml");

    if (llvm::sys::fs::exists(cfgPath)) {
        llvm::errs() << "lshaz init: " << cfgPath << " already exists, skipping\n";
        return true;
    }

    std::error_code EC;
    llvm::raw_fd_ostream f(cfgPath, EC, llvm::sys::fs::OF_Text);
    if (EC) {
        llvm::errs() << "lshaz init: cannot write " << cfgPath
                     << ": " << EC.message() << "\n";
        return false;
    }

    f << "# lshaz configuration\n"
      << "# See: https://github.com/abokhalill/lshaz/blob/main/docs/configuration.md\n"
      << "\n"
      << "cache_line_bytes: 64\n"
      << "stack_frame_warn_bytes: 2048\n"
      << "\n"
      << "# Mark hot functions by pattern (fnmatch glob)\n"
      << "# hot_function_patterns:\n"
      << "#   - \"*::onMarketData*\"\n"
      << "#   - \"*::process*\"\n"
      << "\n"
      << "# hot_file_patterns:\n"
      << "#   - \"*/hot_path/*\"\n"
      << "\n"
      << "# Disable specific rules\n"
      << "# disabled_rules: []\n";

    llvm::errs() << "lshaz init: wrote " << cfgPath << "\n";
    return true;
}

// Probe a sample of TUs from the compile_commands.json to detect missing
// generated headers before the user runs a full scan. Reads the JSON,
// selects up to `maxProbes` entries at random, and runs the compiler with
// -fsyntax-only. Reports failures with the specific error.
void validateCompileDB(const std::string &dbPath, unsigned maxProbes = 5) {
    std::ifstream ifs(dbPath);
    if (!ifs) return;

    // Minimal extraction: collect (directory, file, arguments[0], full command).
    // We reconstruct the compiler invocation with -fsyntax-only.
    struct Entry {
        std::string directory;
        std::string file;
        std::string command; // raw "command" or reconstructed from "arguments"
    };

    std::vector<Entry> entries;
    std::string json((std::istreambuf_iterator<char>(ifs)),
                      std::istreambuf_iterator<char>());

    // Walk through top-level array objects by brace-counting.
    size_t pos = json.find('[');
    if (pos == std::string::npos) return;
    ++pos;

    auto extractStr = [&](const std::string &obj, const std::string &key) -> std::string {
        std::string needle = "\"" + key + "\": \"";
        auto p = obj.find(needle);
        if (p == std::string::npos) return {};
        p += needle.size();
        for (size_t i = p; i < obj.size(); ++i) {
            if (obj[i] == '\\') { ++i; continue; }
            if (obj[i] == '"') return obj.substr(p, i - p);
        }
        return {};
    };

    // Extract "arguments": [...] as a single shell-safe command string.
    auto extractArgs = [&](const std::string &obj) -> std::string {
        std::string needle = "\"arguments\": [";
        auto p = obj.find(needle);
        if (p == std::string::npos) return {};
        p += needle.size();
        std::string result;
        while (p < obj.size() && obj[p] != ']') {
            if (obj[p] == '"') {
                ++p;
                std::string arg;
                for (; p < obj.size() && obj[p] != '"'; ++p) {
                    if (obj[p] == '\\' && p + 1 < obj.size()) { arg += obj[++p]; continue; }
                    arg += obj[p];
                }
                if (p < obj.size()) ++p;
                if (!result.empty()) result += ' ';
                result += shellQuote(arg);
            } else {
                ++p;
            }
        }
        return result;
    };

    // Extract entries.
    int depth = 0;
    size_t objStart = std::string::npos;
    for (size_t i = pos; i < json.size(); ++i) {
        if (json[i] == '{') {
            if (depth == 0) objStart = i;
            ++depth;
        } else if (json[i] == '}') {
            --depth;
            if (depth == 0 && objStart != std::string::npos) {
                std::string obj = json.substr(objStart, i - objStart + 1);
                Entry e;
                e.directory = extractStr(obj, "directory");
                e.file = extractStr(obj, "file");
                e.command = extractStr(obj, "command");
                if (e.command.empty())
                    e.command = extractArgs(obj);
                if (!e.file.empty())
                    entries.push_back(std::move(e));
                objStart = std::string::npos;
            }
        } else if (json[i] == ']' && depth == 0) {
            break;
        }
    }

    if (entries.empty()) return;

    // Sample up to maxProbes entries.
    std::mt19937 rng(std::random_device{}());
    if (entries.size() > maxProbes) {
        std::shuffle(entries.begin(), entries.end(), rng);
        entries.resize(maxProbes);
    }

    // Resolve clang for syntax checking.
    std::string compiler;
    for (const char *name : {"clang", "clang-18", "clang-17", "clang-16", "cc"}) {
        auto found = llvm::sys::findProgramByName(name);
        if (found) { compiler = *found; break; }
    }
    if (compiler.empty()) return; // Can't validate without a compiler.

    unsigned failures = 0;
    for (const auto &e : entries) {
        // Build a -fsyntax-only command from the compile_commands.json entry.
        // Replace the compiler and output flags, keep includes and defines.
        std::string cmd;
        if (!e.command.empty()) {
            // "command" field: replace first token with our compiler, append -fsyntax-only.
            auto firstSpace = e.command.find(' ');
            if (firstSpace == std::string::npos) continue;
            cmd = compiler + " -fsyntax-only -Wno-everything " +
                  e.command.substr(firstSpace + 1);
            // Strip -o <file> to avoid writing output.
            for (;;) {
                auto oPos = cmd.find(" -o ");
                if (oPos == std::string::npos) break;
                auto valStart = oPos + 4;
                auto nextSpace = cmd.find(' ', valStart);
                cmd.erase(oPos, (nextSpace != std::string::npos ? nextSpace : cmd.size()) - oPos);
            }
        } else {
            continue;
        }

        // Run via sh -c in the entry's directory, capture stderr.
        auto shPath = llvm::sys::findProgramByName("sh");
        if (!shPath) continue;
        std::string shStr = *shPath;

        int pipefd[2];
        if (pipe(pipefd) < 0) continue;

        pid_t pid = fork();
        if (pid < 0) { close(pipefd[0]); close(pipefd[1]); continue; }

        if (pid == 0) {
            close(pipefd[0]);
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) { dup2(devnull, STDOUT_FILENO); close(devnull); }
            dup2(pipefd[1], STDERR_FILENO);
            close(pipefd[1]);
            if (chdir(e.directory.c_str()) != 0) _exit(127);
            execl(shStr.c_str(), "sh", "-c", cmd.c_str(), nullptr);
            _exit(127);
        }

        close(pipefd[1]);
        // Read child stderr (cap at 2KB).
        std::string errOutput;
        char buf[256];
        ssize_t n;
        while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) {
            if (errOutput.size() < 2048)
                errOutput.append(buf, std::min<size_t>(n, 2048 - errOutput.size()));
        }
        close(pipefd[0]);

        int status = 0;
        waitpid(pid, &status, 0);
        int rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;

        if (rc != 0) {
            ++failures;
            // Extract the "file not found" line if present.
            std::string hint;
            auto fatalPos = errOutput.find("fatal error:");
            if (fatalPos != std::string::npos) {
                auto lineEnd = errOutput.find('\n', fatalPos);
                hint = errOutput.substr(fatalPos,
                    lineEnd != std::string::npos ? lineEnd - fatalPos : std::string::npos);
            }
            llvm::errs() << "lshaz init: WARNING: sample TU failed to parse: "
                         << e.file << "\n";
            if (!hint.empty())
                llvm::errs() << "  " << hint << "\n";
        }
    }

    if (failures > 0)
        llvm::errs() << "lshaz init: " << failures << "/" << entries.size()
                     << " sample TU(s) failed — the project may need a full "
                        "build before scanning (generated headers)\n";
}

void printInitUsage() {
    llvm::errs()
        << "Usage: lshaz init [path] [options]\n"
        << "\n"
        << "Initialize a project for lshaz analysis.\n"
        << "Detects the build system, generates compile_commands.json,\n"
        << "and creates a starter lshaz.config.yaml.\n"
        << "\n"
        << "For CMake/Meson projects, only the configure step is run by\n"
        << "default. Use --build to also run a full build (needed when\n"
        << "the project uses configure_file() or custom_target() to\n"
        << "generate headers).\n"
        << "\n"
        << "Arguments:\n"
        << "  [path]           Project root (default: current directory)\n"
        << "\n"
        << "Options:\n"
        << "  -b, --build      Run a full build after configure (for generated headers)\n"
        << "  -f, --force      Regenerate compile_commands.json even if it exists\n"
        << "      --no-config  Skip lshaz.config.yaml generation\n"
        << "  -h, --help       Show this help\n";
}

} // anonymous namespace

int runInitCommand(int argc, const char **argv) {
    std::string target = ".";
    bool noConfig = false;
    bool force = false;
    bool fullBuild = false;

    for (int i = 0; i < argc; ++i) {
        if (std::strcmp(argv[i], "--help") == 0 ||
            std::strcmp(argv[i], "-h") == 0) {
            printInitUsage();
            return 0;
        }
        if (std::strcmp(argv[i], "--no-config") == 0) { noConfig = true; continue; }
        if (std::strcmp(argv[i], "--force") == 0 || std::strcmp(argv[i], "-f") == 0) { force = true; continue; }
        if (std::strcmp(argv[i], "--build") == 0 || std::strcmp(argv[i], "-b") == 0) { fullBuild = true; continue; }
        if (argv[i][0] == '-') {
            llvm::errs() << "lshaz init: unknown option '" << argv[i] << "'\n";
            printInitUsage();
            return 3;
        }
        target = argv[i];
    }

    if (!llvm::sys::fs::is_directory(target)) {
        llvm::errs() << "lshaz init: '" << target << "' is not a directory\n";
        return 3;
    }

    // Resolve to absolute path.
    llvm::SmallString<256> absTarget;
    llvm::sys::fs::real_path(target, absTarget);
    std::string dir = std::string(absTarget);

    // Step 1: compile_commands.json
    if (!force && hasCompileDB(dir)) {
        llvm::errs() << "lshaz init: compile_commands.json already exists "
                        "(use --force to regenerate)\n";
    } else {
        BuildSystem bs = detectBuildSystem(dir);
        bool ok = false;
        switch (bs) {
        case BuildSystem::CMake:  ok = generateCMake(dir, fullBuild);  break;
        case BuildSystem::Meson:  ok = generateMeson(dir, fullBuild);  break;
        case BuildSystem::Make:   ok = generateBear(dir);   break;
        case BuildSystem::Unknown:
            llvm::errs() << "lshaz init: no recognized build system found "
                            "(CMakeLists.txt, meson.build, or Makefile)\n";
            break;
        }
        if (!ok && bs != BuildSystem::Unknown) {
            llvm::errs() << "lshaz init: failed to generate compile_commands.json\n";
            return 1;
        }
    }

    // Step 2: validate compile_commands.json by probing sample TUs.
    {
        llvm::SmallString<256> dbPath(dir);
        llvm::sys::path::append(dbPath, "compile_commands.json");
        if (!llvm::sys::fs::exists(dbPath)) {
            dbPath = llvm::StringRef(dir);
            llvm::sys::path::append(dbPath, "build");
            llvm::sys::path::append(dbPath, "compile_commands.json");
        }
        if (llvm::sys::fs::exists(dbPath))
            validateCompileDB(std::string(dbPath));
    }

    // Step 3: starter config
    if (!noConfig)
        writeStarterConfig(dir);

    llvm::errs() << "\nlshaz init: ready. Run:\n"
                    "  lshaz scan " << dir << "\n";
    return 0;
}

} // namespace lshaz
