#pragma once

#include <string>

namespace lshaz {

struct RepoAcquisition {
    std::string localPath;     // Absolute path to cloned/local repo root
    std::string tempDir;       // Non-empty if we created a temp directory (caller must clean up)
    bool cloned = false;       // True if repo was cloned from a URL
    std::string error;         // Non-empty on failure
};

class RepoProvider {
public:
    // Returns true if the target looks like a remote URL (https:// or git@).
    static bool isRemoteURL(const std::string &target);

    // Acquire a repo: if target is a URL, clone into a temp directory.
    // If target is a local path, return it directly.
    // Options: ref (branch/tag/commit), depth (0 = full clone).
    static RepoAcquisition acquire(const std::string &target,
                                    const std::string &ref = "",
                                    unsigned depth = 1);

    // Remove temp directory created by acquire(). No-op if tempDir is empty.
    static void cleanup(const RepoAcquisition &acq);
};

} // namespace lshaz
