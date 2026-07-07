// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "lshaz/core/Diagnostic.h"
#include "lshaz/ir/IRAnalyzer.h"

#include <vector>

namespace lshaz {

class DiagnosticRefiner {
public:
    // stackFrameWarnBytes: same threshold the AST rule (FL021) used —
    // suppression must not judge against a different bar than emission.
    explicit DiagnosticRefiner(const IRAnalyzer::ProfileMap &profiles,
                               uint64_t stackFrameWarnBytes = 2048);

    // Refine diagnostics in-place using IR evidence.
    // May adjust confidence, add escalations, or suppress false positives.
    void refine(std::vector<Diagnostic> &diagnostics) const;

private:
    void refineFL010(Diagnostic &diag) const;
    void refineFL011(Diagnostic &diag) const;
    void refineFL020(Diagnostic &diag) const;
    void refineFL021(Diagnostic &diag) const;
    void refineFL030(Diagnostic &diag) const;
    void refineFL031(Diagnostic &diag) const;
    void refineFL012(Diagnostic &diag) const;
    void refineFL090(Diagnostic &diag) const;
    void refineFL091(Diagnostic &diag) const;

    // Extract mangled function name from structural evidence.
    std::string extractFunctionName(const Diagnostic &diag) const;

    // Find best matching profile for a function name.
    const IRFunctionProfile *findProfile(const std::string &funcName) const;

    // Find profile by source location fallback (file suffix + line).
    const IRFunctionProfile *findProfileByLocation(
        const std::string &file, unsigned line) const;

    // Try name match, then source location fallback.
    const IRFunctionProfile *findProfileForDiag(const Diagnostic &diag) const;

    // Path suffix match: returns true if one path ends with the other's filename + dirs.
    static bool filePathSuffixMatch(const std::string &a, const std::string &b);

    const IRAnalyzer::ProfileMap &profiles_;
    uint64_t stackFrameWarnBytes_;
};

} // namespace lshaz
