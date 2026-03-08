// SPDX-License-Identifier: Apache-2.0
#include "FixCommand.h"

#include "lshaz/core/Config.h"
#include "lshaz/core/Version.h"
#include "lshaz/pipeline/ScanPipeline.h"

#include <clang/Tooling/CompilationDatabase.h>

#include <llvm/Support/FileSystem.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/raw_ostream.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace lshaz {
namespace {

void printFixUsage() {
    llvm::errs()
        << "Usage: lshaz fix <path> [options]\n"
        << "\n"
        << "Apply mechanical auto-remediation for fixable diagnostics.\n"
        << "\n"
        << "Options:\n"
        << "  --compile-db <path>   Path to compile_commands.json\n"
        << "  --config <path>       Path to lshaz.config.yaml\n"
        << "  --dry-run             Show patches without modifying files\n"
        << "  --rules <list>        Comma-separated rules to fix (default: FL001)\n"
        << "  --help                Show this help\n"
        << "\n"
        << "Supported rules:\n"
        << "  FL001  Cache Line Spanning Struct — adds alignas(64)\n"
        << "\n"
        << "Exit Codes:\n"
        << "  0  No fixable findings\n"
        << "  1  Fixes applied (or shown with --dry-run)\n"
        << "  3  Infrastructure failure\n";
}

struct FixArgs {
    std::string target;
    std::string compileDBPath;
    std::string configPath;
    bool dryRun = false;
    std::vector<std::string> rules = {"FL001"};
    std::vector<std::string> compilerFlags;
    bool help = false;
};

bool parseFixArgs(int argc, const char **argv, FixArgs &args) {
    auto consumeArg = [](int &i, int argc, const char **argv,
                         const char *flag, std::string &out) -> bool {
        if (std::strcmp(argv[i], flag) != 0) return false;
        if (i + 1 >= argc) {
            llvm::errs() << "lshaz fix: " << flag << " requires a value\n";
            return false;
        }
        out = argv[++i];
        return true;
    };

    for (int i = 0; i < argc; ++i) {
        if (std::strcmp(argv[i], "--") == 0) {
            for (++i; i < argc; ++i)
                args.compilerFlags.push_back(argv[i]);
            break;
        }
        if (std::strcmp(argv[i], "--help") == 0 ||
            std::strcmp(argv[i], "-h") == 0) {
            args.help = true;
            return true;
        }
        if (consumeArg(i, argc, argv, "--compile-db", args.compileDBPath)) continue;
        if (consumeArg(i, argc, argv, "--config", args.configPath)) continue;
        if (std::strcmp(argv[i], "--dry-run") == 0) { args.dryRun = true; continue; }
        {
            std::string rulesStr;
            if (consumeArg(i, argc, argv, "--rules", rulesStr)) {
                args.rules.clear();
                std::istringstream ss(rulesStr);
                std::string r;
                while (std::getline(ss, r, ','))
                    if (!r.empty()) args.rules.push_back(r);
                continue;
            }
        }
        if (argv[i][0] == '-') {
            llvm::errs() << "lshaz fix: unknown option '" << argv[i] << "'\n";
            return false;
        }
        if (args.target.empty()) {
            args.target = argv[i];
        } else {
            llvm::errs() << "lshaz fix: unexpected argument '" << argv[i] << "'\n";
            return false;
        }
    }
    return true;
}

// A pending edit for a single file at a specific line.
struct SourceEdit {
    std::string file;
    unsigned line;
    std::string ruleID;
    std::string description;
    // The original line content and replacement line content.
    std::string originalLine;
    std::string fixedLine;
};

// FL001 fix: insert alignas(64) before struct/class keyword.
bool generateFL001Fix(const Diagnostic &diag, SourceEdit &edit) {
    if (diag.location.file.empty() || diag.location.line == 0)
        return false;

    auto bufOrErr = llvm::MemoryBuffer::getFile(diag.location.file);
    if (!bufOrErr)
        return false;

    llvm::StringRef contents = (*bufOrErr)->getBuffer();
    llvm::SmallVector<llvm::StringRef, 0> lines;
    contents.split(lines, '\n', /*MaxSplit=*/-1, /*KeepEmpty=*/true);

    if (diag.location.line > lines.size())
        return false;

    llvm::StringRef srcLine = lines[diag.location.line - 1];
    std::string lineStr = srcLine.str();

    // Already has alignas — skip.
    if (lineStr.find("alignas") != std::string::npos)
        return false;

    // Find struct or class keyword to insert alignas before.
    auto insertBefore = [&](const std::string &keyword) -> bool {
        auto pos = lineStr.find(keyword);
        if (pos == std::string::npos) return false;
        // Verify it's a keyword boundary (not part of another word).
        if (pos > 0 && (std::isalnum(lineStr[pos - 1]) || lineStr[pos - 1] == '_'))
            return false;
        size_t end = pos + keyword.size();
        if (end < lineStr.size() && (std::isalnum(lineStr[end]) || lineStr[end] == '_'))
            return false;

        edit.file = diag.location.file;
        edit.line = diag.location.line;
        edit.ruleID = "FL001";
        edit.originalLine = lineStr;
        edit.fixedLine = lineStr.substr(0, pos) + "alignas(64) " + lineStr.substr(pos);
        edit.description = "Add alignas(64) to align struct to cache line boundary";
        return true;
    };

    if (insertBefore("struct")) return true;
    if (insertBefore("class")) return true;
    return false;
}

// Group edits by file, sorted by line descending (apply bottom-up to preserve line numbers).
void applyEdits(const std::vector<SourceEdit> &edits, bool dryRun) {
    std::map<std::string, std::vector<const SourceEdit *>> byFile;
    for (const auto &e : edits)
        byFile[e.file].push_back(&e);

    unsigned applied = 0;
    for (auto &[file, fileEdits] : byFile) {
        // Sort descending by line so earlier edits don't shift later ones.
        std::sort(fileEdits.begin(), fileEdits.end(),
                  [](const SourceEdit *a, const SourceEdit *b) {
                      return a->line > b->line;
                  });

        auto bufOrErr = llvm::MemoryBuffer::getFile(file);
        if (!bufOrErr) {
            llvm::errs() << "lshaz fix: cannot read '" << file << "'\n";
            continue;
        }

        llvm::StringRef contents = (*bufOrErr)->getBuffer();
        llvm::SmallVector<llvm::StringRef, 0> lines;
        contents.split(lines, '\n', /*MaxSplit=*/-1, /*KeepEmpty=*/true);

        for (const auto *edit : fileEdits) {
            if (edit->line == 0 || edit->line > lines.size()) continue;

            if (dryRun) {
                llvm::outs() << "--- " << file << ":" << edit->line
                             << " [" << edit->ruleID << "] "
                             << edit->description << "\n"
                             << "-  " << edit->originalLine << "\n"
                             << "+  " << edit->fixedLine << "\n\n";
            }

            lines[edit->line - 1] = llvm::StringRef(edit->fixedLine);
            ++applied;
        }

        if (!dryRun) {
            std::error_code EC;
            llvm::raw_fd_ostream out(file, EC, llvm::sys::fs::OF_Text);
            if (EC) {
                llvm::errs() << "lshaz fix: cannot write '" << file
                             << "': " << EC.message() << "\n";
                continue;
            }
            for (size_t i = 0; i < lines.size(); ++i) {
                if (i > 0) out << '\n';
                out << lines[i];
            }
        }
    }

    if (dryRun)
        llvm::errs() << "lshaz fix: " << applied << " fix(es) shown (dry run)\n";
    else
        llvm::errs() << "lshaz fix: " << applied << " fix(es) applied\n";
}

} // anonymous namespace

int runFixCommand(int argc, const char **argv) {
    FixArgs args;
    if (!parseFixArgs(argc, argv, args)) {
        printFixUsage();
        return 3;
    }
    if (args.help) {
        printFixUsage();
        return 0;
    }
    if (args.target.empty()) {
        llvm::errs() << "lshaz fix: missing target path\n\n";
        printFixUsage();
        return 3;
    }

    ScanPipeline pipeline([](const std::string &stage,
                             const std::string &detail) {
        llvm::errs() << "lshaz: [" << stage << "] " << detail << "\n";
    });

    ScanResult result;

    if (!args.compilerFlags.empty()) {
        // Single-file mode.
        if (!llvm::sys::fs::exists(args.target)) {
            llvm::errs() << "lshaz fix: source file '" << args.target
                         << "' not found\n";
            return 3;
        }
        llvm::SmallString<256> absSrc;
        llvm::sys::fs::real_path(args.target, absSrc);
        std::string srcPath(absSrc);

        clang::tooling::FixedCompilationDatabase fixedDB(".", args.compilerFlags);

        ScanRequest request;
        request.config = args.configPath.empty()
            ? Config::defaults()
            : Config::loadFromFile(args.configPath);
        request.ir.enabled = false;

        result = pipeline.executeWithDB(request, fixedDB, {srcPath});
    } else {
        // Directory mode.
        ScanRequest request;
        request.workingDirectory = args.target;
        request.compileDBPath = args.compileDBPath;
        request.config = args.configPath.empty()
            ? Config::defaults()
            : Config::loadFromFile(args.configPath);
        request.ir.enabled = false;
        request.trustBuildSystem = true;

        if (args.configPath.empty()) {
            llvm::SmallString<256> candidate(args.target);
            llvm::sys::path::append(candidate, "lshaz.config.yaml");
            if (llvm::sys::fs::exists(candidate)) {
                request.config = Config::loadFromFile(std::string(candidate));
                llvm::errs() << "lshaz: using config " << candidate << "\n";
            }
        }

        result = pipeline.execute(request);
    }

    // Filter to fixable rules.
    std::set<std::string> targetRules(args.rules.begin(), args.rules.end());
    std::vector<SourceEdit> edits;

    for (const auto &diag : result.diagnostics) {
        if (diag.suppressed) continue;
        if (targetRules.find(diag.ruleID) == targetRules.end()) continue;

        SourceEdit edit;
        bool generated = false;

        if (diag.ruleID == "FL001")
            generated = generateFL001Fix(diag, edit);

        if (generated)
            edits.push_back(std::move(edit));
    }

    if (edits.empty()) {
        llvm::errs() << "lshaz fix: no fixable findings\n";
        return 0;
    }

    applyEdits(edits, args.dryRun);
    return 1;
}

} // namespace lshaz
