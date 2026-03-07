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

bool RepoProvider::isSafeURL(const std::string &url) {
    // Only HTTPS is safe for untrusted input. Reject:
    //   file://  — local filesystem exfiltration
    //   git://   — unauthenticated, MITM-able
    //   ssh://   — may trigger unexpected key prompts
    //   git@     — SSH shorthand, same concerns
    //   http://  — MITM-able, no transport security
    if (url.find("https://") != 0)
        return false;
    // Reject URLs with embedded credentials (user:pass@host).
    auto hostStart = url.find("://") + 3;
    auto atPos = url.find('@', hostStart);
    auto slashPos = url.find('/', hostStart);
    if (atPos != std::string::npos &&
        (slashPos == std::string::npos || atPos < slashPos))
        return false;
    // Reject URLs containing shell metacharacters.
    for (char c : url) {
        if (c == ';' || c == '|' || c == '&' || c == '$' ||
            c == '`' || c == '\n' || c == '\r')
            return false;
    }
    return true;
}

RepoAcquisition RepoProvider::acquire(const std::string &target,
                                       const std::string &ref,
                                       unsigned depth) {
    RepoAcquisition acq;

    if (!isRemoteURL(target)) {
        acq.localPath = target;
        return acq;
    }

    if (!isSafeURL(target)) {
        acq.error = "rejected URL: only HTTPS URLs without embedded "
                    "credentials or shell metacharacters are allowed";
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
