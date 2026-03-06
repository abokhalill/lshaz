#include "lshaz/pipeline/RepoProvider.h"

#include <llvm/Support/FileSystem.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/Program.h>
#include <llvm/Support/raw_ostream.h>

#include <cstdlib>

namespace lshaz {

bool RepoProvider::isRemoteURL(const std::string &target) {
    return target.find("https://") == 0 ||
           target.find("http://") == 0 ||
           target.find("git@") == 0;
}

RepoAcquisition RepoProvider::acquire(const std::string &target,
                                       const std::string &ref,
                                       unsigned depth) {
    RepoAcquisition acq;

    if (!isRemoteURL(target)) {
        acq.localPath = target;
        return acq;
    }

    // Verify git is available.
    auto gitPath = llvm::sys::findProgramByName("git");
    if (!gitPath) {
        acq.error = "git not found on PATH; required for remote repo cloning";
        return acq;
    }

    // Create temp directory.
    llvm::SmallString<128> tmpDir;
    if (auto EC = llvm::sys::fs::createUniqueDirectory("lshaz-repo", tmpDir)) {
        acq.error = "failed to create temp directory: " + EC.message();
        return acq;
    }
    acq.tempDir = std::string(tmpDir);

    // Build git clone command.
    std::vector<llvm::StringRef> args;
    args.push_back(*gitPath);
    args.push_back("clone");

    std::string depthStr;
    if (depth > 0) {
        args.push_back("--depth");
        depthStr = std::to_string(depth);
        args.push_back(depthStr);
    }

    std::string branchFlag;
    if (!ref.empty()) {
        args.push_back("--branch");
        args.push_back(ref);
    }

    args.push_back("--single-branch");
    args.push_back(target);

    // Clone into a subdirectory named "repo" inside the temp dir.
    llvm::SmallString<256> repoDir(tmpDir);
    llvm::sys::path::append(repoDir, "repo");
    args.push_back(llvm::StringRef(repoDir));

    // Redirect stderr to a temp file for error capture.
    llvm::SmallString<256> errFile(tmpDir);
    llvm::sys::path::append(errFile, "git-clone.err");
    llvm::StringRef errRedirect(errFile);
    std::optional<llvm::StringRef> redirects[] = {
        std::nullopt, std::nullopt, errRedirect
    };

    std::string execErr;
    bool failed = false;
    int exitCode = llvm::sys::ExecuteAndWait(
        *gitPath, args,
        /*Env=*/std::nullopt, redirects,
        /*SecondsToWait=*/300, /*MemoryLimit=*/0,
        &execErr, &failed);

    if (exitCode != 0 || failed) {
        std::string msg = "git clone failed (exit " + std::to_string(exitCode) + ")";
        auto errBuf = llvm::MemoryBuffer::getFile(errFile);
        if (errBuf && !(*errBuf)->getBuffer().empty())
            msg += ": " + (*errBuf)->getBuffer().str();
        else if (!execErr.empty())
            msg += ": " + execErr;
        acq.error = msg;
        return acq;
    }

    acq.localPath = std::string(repoDir);
    acq.cloned = true;
    return acq;
}

void RepoProvider::cleanup(const RepoAcquisition &acq) {
    if (!acq.tempDir.empty())
        llvm::sys::fs::remove_directories(acq.tempDir);
}

} // namespace lshaz
