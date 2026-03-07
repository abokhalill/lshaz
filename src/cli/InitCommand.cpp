// SPDX-License-Identifier: Apache-2.0
#include "InitCommand.h"

#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/Program.h>
#include <llvm/Support/raw_ostream.h>

#include <cstring>
#include <string>

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
    const char *candidates[] = {
        "compile_commands.json",
        "build/compile_commands.json",
    };
    for (const char *c : candidates) {
        llvm::SmallString<256> p(dir);
        llvm::sys::path::append(p, c);
        if (llvm::sys::fs::exists(p))
            return true;
    }
    return false;
}

int runExternal(const std::string &program,
                const std::vector<std::string> &args,
                const std::string &cwd, unsigned timeout = 120) {
    auto found = llvm::sys::findProgramByName(program);
    if (!found) {
        llvm::errs() << "lshaz init: '" << program << "' not found in PATH\n";
        return -1;
    }

    std::vector<llvm::StringRef> argv;
    argv.push_back(*found);
    for (const auto &a : args)
        argv.push_back(a);

    llvm::SmallString<256> outFile, errFile;
    llvm::sys::path::system_temp_directory(true, outFile);
    errFile = outFile;
    llvm::sys::path::append(outFile, "lshaz-init.out");
    llvm::sys::path::append(errFile, "lshaz-init.err");

    std::optional<llvm::StringRef> redirects[] = {
        std::nullopt,
        llvm::StringRef(outFile),
        llvm::StringRef(errFile),
    };

    std::string execErr;
    bool failed = false;
    int rc = llvm::sys::ExecuteAndWait(
        *found, argv,
        /*Env=*/std::nullopt, redirects,
        timeout, /*MemoryLimit=*/0,
        &execErr, &failed);

    llvm::sys::fs::remove(outFile);
    llvm::sys::fs::remove(errFile);

    if (failed && !execErr.empty())
        llvm::errs() << "lshaz init: " << execErr << "\n";

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
    }, dir);

    if (rc != 0) {
        llvm::errs() << "lshaz init: cmake configure failed\n";
        return false;
    }

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
        int rc = runExternal("meson", {"setup", std::string(buildDir)}, dir);
        if (rc != 0) {
            llvm::errs() << "lshaz init: meson setup failed\n";
            return false;
        }
    }

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

    llvm::errs() << "lshaz init: running bear -- make ...\n";
    int rc = runExternal("bear", {"--", "make", "-j"}, dir, 300);
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
