#include "lshaz/pipeline/CompileDBResolver.h"

#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Path.h>

namespace lshaz {

std::vector<std::string> CompileDBResolver::candidatePaths(
        const std::string &projectRoot) {
    const char *subdirs[] = {
        "build",
        ".",
        "out",
        "cmake-build-debug",
        "cmake-build-release",
        "out/build",
        "build/debug",
        "build/release",
    };

    std::vector<std::string> paths;
    paths.reserve(std::size(subdirs));

    for (const char *sub : subdirs) {
        llvm::SmallString<256> p(projectRoot);
        llvm::sys::path::append(p, sub, "compile_commands.json");
        paths.push_back(std::string(p));
    }
    return paths;
}

std::string CompileDBResolver::discover(const std::string &projectRoot) {
    for (const auto &path : candidatePaths(projectRoot)) {
        if (llvm::sys::fs::exists(path))
            return path;
    }
    return {};
}

} // namespace lshaz
