#pragma once

#include <string>
#include <unordered_set>
#include <vector>

namespace clang {
class Decl;
class FunctionDecl;
class Attr;
} // namespace clang

namespace faultline {

struct Config;

// Determines whether a given declaration resides on a hot path.
// Four mechanisms:
//   1. [[clang::annotate("faultline_hot")]] attribute on functions
//   2. Config-based function/file pattern matching
//   3. Perf/LBR profile: function name exceeds sample threshold
//   4. Manual markHot() calls during AST walk
class HotPathOracle {
public:
    explicit HotPathOracle(const Config &cfg);

    bool isHot(const clang::Decl *D) const;
    bool isFunctionHot(const clang::FunctionDecl *FD) const;

    void markHot(const clang::FunctionDecl *FD);

    // Load profile-derived hot function names (demangled qualified names).
    void loadProfileHotFunctions(std::unordered_set<std::string> names);

private:
    bool hasHotAnnotation(const clang::FunctionDecl *FD) const;
    bool matchesConfigPattern(const clang::FunctionDecl *FD) const;
    bool matchesProfileFunction(const clang::FunctionDecl *FD) const;

    const Config &config_;
    mutable std::unordered_set<const clang::FunctionDecl *> hotCache_;
    std::unordered_set<std::string> profileHotFunctions_;
};

} // namespace faultline
