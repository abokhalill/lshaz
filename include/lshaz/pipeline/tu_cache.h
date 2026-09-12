// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace lshaz {

// Per-TU result cache, content-addressed.
//
// A stale entry is a false green, which costs more than the scan it saves, so
// validity is decided by hashing every file the TU actually read rather than
// by timestamps: mtime changes on checkout without the content changing, and
// fails to change when a file is restored.
//
// The dependency list comes from the previous run and is stored with the
// entry. That is the only way out of the ordering problem, since knowing which
// headers a TU reads requires parsing it.
class TUCache {
public:
    // Empty dir disables every operation, so callers need no second flag.
    explicit TUCache(std::string dir) : dir_(std::move(dir)) {}

    // Drop entries until the tree is under capBytes, oldest access first.
    // Called once per scan rather than per store: entries are content-keyed,
    // so a survivor is never wrong, only wasteful, and the cost of pruning is
    // not worth paying on the hot path. A large project writes gigabytes in
    // one scan, so without this a long-lived checkout grows without bound.
    static void prune(const std::string &dir, uint64_t capBytes);

    bool enabled() const { return !dir_.empty(); }
    unsigned hits() const { return hits_; }
    unsigned misses() const { return misses_; }

    // Everything outside the source text that changes a TU's verdict. A miss
    // here is cheap; a collision is silently wrong, so the tool version and
    // the config digest are both folded in.
    static std::string keyFor(const std::string &mainFile,
                              const std::vector<std::string> &command,
                              const std::string &configDigest);

    // Fills record and returns true only when every stored dependency still
    // hashes to what it did when the entry was written.
    bool lookup(const std::string &key, std::string &record);

    void store(const std::string &key,
               const std::vector<std::string> &deps,
               const std::string &record);

private:
    std::string path(const std::string &key) const;

    std::string dir_;
    unsigned hits_ = 0;
    unsigned misses_ = 0;
};

// Digest of the config fields a TU's analysis reads. Anything that changes a
// finding and is not the source text belongs here, or the cache serves results
// from a different question.
struct Config;
std::string configDigest(const Config &cfg);

} // namespace lshaz
