// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <clang/Tooling/CompilationDatabase.h>
#include <llvm/Support/Path.h>

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace lshaz {

// Resolves every relative path in a CompilationDatabase (sources, include
// directories, outputs) to absolute at construction. ClangTool otherwise
// chdir()s to each compile command's Directory, and chdir is process-global:
// under parallel scans that races. Downstream code sees absolute paths only.
class AbsolutePathCompilationDatabase
    : public clang::tooling::CompilationDatabase {
public:
    /// Takes ownership of the underlying database.
    explicit AbsolutePathCompilationDatabase(
        std::unique_ptr<clang::tooling::CompilationDatabase> inner);

    std::vector<clang::tooling::CompileCommand>
    getCompileCommands(llvm::StringRef FilePath) const override;

    std::vector<std::string> getAllFiles() const override;

    std::vector<clang::tooling::CompileCommand>
    getAllCompileCommands() const override;

private:
    static clang::tooling::CompileCommand
    resolveCommand(const clang::tooling::CompileCommand &cmd);

    static std::string
    resolvePath(const std::string &path, const std::string &directory);

    std::unique_ptr<clang::tooling::CompilationDatabase> inner_;

    // Index: absolute path -> original relative path (for reverse lookup).
    std::unordered_map<std::string, std::string> absToOrig_;

    // Cached resolved file list.
    std::vector<std::string> allFiles_;
};

} // namespace lshaz
