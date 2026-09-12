// SPDX-License-Identifier: Apache-2.0
#include "lshaz/pipeline/abs_path_db.h"

#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Path.h>

namespace lshaz {

namespace {

// Flags whose next argument is a path (separated form).
//
// -include is deliberately absent: its argument resolves through the include
// search path, not the working directory, so making it absolute breaks any
// project that force-includes a generated config header found via -I.
bool isSeparatedPathFlag(llvm::StringRef arg) {
    return arg == "-I" || arg == "-isystem" || arg == "-iquote" ||
           arg == "-isysroot" || arg == "--sysroot" ||
           arg == "-o";
}

} // anonymous namespace

std::string
AbsolutePathCompilationDatabase::resolvePath(const std::string &path,
                                              const std::string &directory) {
    if (path.empty() || llvm::sys::path::is_absolute(path))
        return path;
    llvm::SmallString<256> resolved(directory);
    llvm::sys::path::append(resolved, path);
    llvm::sys::path::remove_dots(resolved, /*remove_dot_dot=*/true);
    return std::string(resolved);
}

clang::tooling::CompileCommand
AbsolutePathCompilationDatabase::resolveCommand(
    const clang::tooling::CompileCommand &cmd) {
    clang::tooling::CompileCommand resolved;
    resolved.Directory = cmd.Directory;
    resolved.Filename = resolvePath(cmd.Filename, cmd.Directory);
    resolved.Output = resolvePath(cmd.Output, cmd.Directory);
    resolved.Heuristic = cmd.Heuristic;

    const auto &args = cmd.CommandLine;
    resolved.CommandLine.reserve(args.size());

    for (size_t i = 0; i < args.size(); ++i) {
        const auto &arg = args[i];

        // argv[0], compiler path, keep as-is.
        if (i == 0) {
            resolved.CommandLine.push_back(arg);
            continue;
        }

        // Separated form: -I /some/path -> resolve the next argument.
        if (isSeparatedPathFlag(arg) && i + 1 < args.size()) {
            resolved.CommandLine.push_back(arg);
            ++i;
            resolved.CommandLine.push_back(
                resolvePath(args[i], cmd.Directory));
            continue;
        }

        // Joined form: -I../deps/hiredis -> split prefix, resolve path.
        // Handle -I, -isystem, -iquote, -include prefixes.
        bool handled = false;
        for (const char *prefix :
             {"-I", "-isystem", "-iquote", "-isysroot",
              "--sysroot="}) {
            llvm::StringRef sr(arg);
            llvm::StringRef pfx(prefix);
            if (sr.starts_with(pfx) && sr.size() > pfx.size()) {
                std::string path = sr.substr(pfx.size()).str();
                resolved.CommandLine.push_back(
                    std::string(pfx) + resolvePath(path, cmd.Directory));
                handled = true;
                break;
            }
        }
        if (handled)
            continue;

        // Source file argument (last non-flag argument, matches Filename).
        if (arg == cmd.Filename ||
            (!arg.empty() && arg[0] != '-' &&
             resolvePath(arg, cmd.Directory) == resolved.Filename)) {
            resolved.CommandLine.push_back(resolved.Filename);
            continue;
        }

        // -o output in joined form: -ofile.o
        if (llvm::StringRef(arg).starts_with("-o") && arg.size() > 2) {
            resolved.CommandLine.push_back(
                "-o" + resolvePath(arg.substr(2), cmd.Directory));
            continue;
        }

        // Everything else passes through unchanged.
        resolved.CommandLine.push_back(arg);
    }

    return resolved;
}

AbsolutePathCompilationDatabase::AbsolutePathCompilationDatabase(
    std::unique_ptr<clang::tooling::CompilationDatabase> inner)
    : inner_(std::move(inner)) {
    // Build the absolute path index and cached file list.
    auto origFiles = inner_->getAllFiles();
    allFiles_.reserve(origFiles.size());

    for (const auto &f : origFiles) {
        if (llvm::sys::path::is_absolute(f)) {
            allFiles_.push_back(f);
            continue;
        }
        // Look up the compile command to get the Directory for resolution.
        auto cmds = inner_->getCompileCommands(f);
        if (!cmds.empty()) {
            std::string abs = resolvePath(f, cmds.front().Directory);
            absToOrig_[abs] = f;
            allFiles_.push_back(std::move(abs));
        } else {
            allFiles_.push_back(f);
        }
    }
}

std::vector<clang::tooling::CompileCommand>
AbsolutePathCompilationDatabase::getCompileCommands(
    llvm::StringRef FilePath) const {
    // Try the inner DB with the path as given (handles both original
    // relative paths and absolute paths that the DB already knows about).
    auto cmds = inner_->getCompileCommands(FilePath);

    // If that failed and the caller used an absolute path, try the
    // reverse-mapped original relative path.
    if (cmds.empty()) {
        auto it = absToOrig_.find(FilePath.str());
        if (it != absToOrig_.end())
            cmds = inner_->getCompileCommands(it->second);
    }

    // Resolve all paths in the returned commands.
    std::vector<clang::tooling::CompileCommand> resolved;
    resolved.reserve(cmds.size());
    for (const auto &cmd : cmds)
        resolved.push_back(resolveCommand(cmd));
    return resolved;
}

std::vector<std::string>
AbsolutePathCompilationDatabase::getAllFiles() const {
    return allFiles_;
}

std::vector<clang::tooling::CompileCommand>
AbsolutePathCompilationDatabase::getAllCompileCommands() const {
    auto cmds = inner_->getAllCompileCommands();
    std::vector<clang::tooling::CompileCommand> resolved;
    resolved.reserve(cmds.size());
    for (const auto &cmd : cmds)
        resolved.push_back(resolveCommand(cmd));
    return resolved;
}

} // namespace lshaz
