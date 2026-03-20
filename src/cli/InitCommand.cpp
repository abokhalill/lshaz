// SPDX-License-Identifier: Apache-2.0
#include "InitCommand.h"

#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/Program.h>
#include <llvm/Support/raw_ostream.h>

#include <cstring>
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

bool generateCMake(const std::string &dir) {
    llvm::errs() << "lshaz init: detected CMake project\n";
    llvm::SmallString<256> buildDir(dir);
    llvm::sys::path::append(buildDir, "build");
    llvm::sys::fs::create_directories(buildDir);

    int rc = runExternal("cmake", {
        "-S", dir,
        "-B", std::string(buildDir),
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"
    }, dir, "configuring CMake");

    if (rc != 0) {
        llvm::errs() << "lshaz init: cmake configure failed\n";
        return false;
    }

    // CMake's configure phase generates compile_commands.json but does not
    // execute configure_file() or add_custom_command() build steps. Without
    // the build phase, generated headers don't exist on disk.
    llvm::errs() << "lshaz init: running full build to generate required "
                    "headers... this may take a while\n";
    int buildRc = runExternal("cmake", {
        "--build", std::string(buildDir), "--parallel"
    }, dir, "building (cmake --build)", 600);
    if (buildRc != 0)
        llvm::errs() << "lshaz init: cmake build failed (exit " << buildRc
                     << "); generated headers may be missing\n";

    llvm::SmallString<256> db(buildDir);
    llvm::sys::path::append(db, "compile_commands.json");
    if (llvm::sys::fs::exists(db)) {
        llvm::errs() << "lshaz init: generated " << db << "\n";
        return true;
    }
    llvm::errs() << "lshaz init: cmake succeeded but compile_commands.json not found\n";
    return false;
}

bool generateMeson(const std::string &dir) {
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

    // Meson's configure phase (setup) generates compile_commands.json but does
    // not execute custom_target or configure_file steps. Without the build
    // phase, generated headers don't exist and TUs that #include them will
    // fail to parse.
    llvm::errs() << "lshaz init: running full build to generate required "
                    "headers... this may take a while\n";
    int buildRc = runExternal("meson", {"compile", "-C", std::string(buildDir)},
                              dir, "building (meson compile)", 600);
    if (buildRc != 0)
        llvm::errs() << "lshaz init: meson compile failed (exit " << buildRc
                     << "); generated headers may be missing\n";

    // Meson always generates compile_commands.json in the build dir.
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
    llvm::errs() << "lshaz init: detected Makefile project\n";
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

void printInitUsage() {
    llvm::errs()
        << "Usage: lshaz init [path] [options]\n"
        << "\n"
        << "Initialize a project for lshaz analysis.\n"
        << "Detects the build system, generates compile_commands.json,\n"
        << "and creates a starter lshaz.config.yaml.\n"
        << "\n"
        << "Arguments:\n"
        << "  [path]           Project root (default: current directory)\n"
        << "\n"
        << "Options:\n"
        << "  --no-config      Skip lshaz.config.yaml generation\n"
        << "  --force          Regenerate compile_commands.json even if it exists\n"
        << "  --help           Show this help\n";
}

} // anonymous namespace

int runInitCommand(int argc, const char **argv) {
    std::string target = ".";
    bool noConfig = false;
    bool force = false;

    for (int i = 0; i < argc; ++i) {
        if (std::strcmp(argv[i], "--help") == 0 ||
            std::strcmp(argv[i], "-h") == 0) {
            printInitUsage();
            return 0;
        }
        if (std::strcmp(argv[i], "--no-config") == 0) { noConfig = true; continue; }
        if (std::strcmp(argv[i], "--force") == 0) { force = true; continue; }
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
        case BuildSystem::CMake:  ok = generateCMake(dir);  break;
        case BuildSystem::Meson:  ok = generateMeson(dir);  break;
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

    // Step 2: starter config
    if (!noConfig)
        writeStarterConfig(dir);

    llvm::errs() << "\nlshaz init: ready. Run:\n"
                    "  lshaz scan " << dir << "\n";
    return 0;
}

} // namespace lshaz
