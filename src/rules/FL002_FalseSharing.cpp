// SPDX-License-Identifier: Apache-2.0
#include "lshaz/core/Rule.h"
#include "lshaz/core/RuleRegistry.h"
#include "lshaz/core/HotPathOracle.h"
#include "lshaz/analysis/CacheLineMap.h"
#include "lshaz/analysis/EscapeAnalysis.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/DeclCXX.h>
#include <clang/Basic/SourceManager.h>

#include <sstream>

namespace lshaz {

class FL002_FalseSharing : public Rule {
public:
    std::string_view getID() const override { return "FL002"; }
    std::string_view getTitle() const override { return "False Sharing Candidate"; }
    Severity getBaseSeverity() const override { return Severity::Critical; }

    std::string_view getHardwareMechanism() const override {
        return "MESI invalidation ping-pong across cores due to shared "
               "cache line writes. Each write by one core forces invalidation "
               "of the line in all other cores' L1/L2, triggering RFO traffic.";
    }

    void analyze(const clang::Decl *D,
                 clang::ASTContext &Ctx,
                 const HotPathOracle & /*Oracle*/,
                 const Config &Cfg,
                 EscapeAnalysis &escape,
                 std::vector<Diagnostic> &out) override {

        const auto *RD = llvm::dyn_cast_or_null<clang::RecordDecl>(D);
        if (!RD || !RD->isCompleteDefinition())
            return;
        if (RD->isImplicit())
            return;
        if (const auto *CXXRD = llvm::dyn_cast<clang::CXXRecordDecl>(RD))
            if (CXXRD->isLambda())
                return;

        EscapeVerdict ev = escape.escapeVerdict(RD);
        if (!ev)
            return;

        CacheLineMap map(RD, Ctx, Cfg.cacheLineBytes, Cfg.atomicTypeNames);

        auto atomicPairs = map.atomicPairsOnSameLine();
        auto mutablePairs = map.mutablePairsOnSameLine();
        if (mutablePairs.empty())
            return;

        bool hasAtomicPairs = !atomicPairs.empty();
        auto fsCandidateLines = map.falseSharingCandidateLines();

        if (!hasAtomicPairs && map.totalAtomicFields() == 0)
            return;

        // Refcount-only structs: single atomic refcount field sharing a line
        // with immutable data.  No real false sharing.
        if (map.isRefcountOnly() && !hasAtomicPairs)
            return;

        Severity sev = hasAtomicPairs ? Severity::Critical : Severity::High;
        std::vector<std::string> escalations;

        constexpr size_t kMaxDetailedPairs = 5;
        constexpr size_t kMaxDetailedLines = 5;

        for (size_t i = 0; i < atomicPairs.size(); ++i) {
            if (i >= kMaxDetailedPairs) {
                escalations.push_back(
                    "and " + std::to_string(atomicPairs.size() - kMaxDetailedPairs) +
                    " more atomic pair(s) sharing cache lines");
                break;
            }
            const auto &pair = atomicPairs[i];
            escalations.push_back(
                "atomic fields '" + pair.a->name + "' and '" + pair.b->name +
                "' share line " + std::to_string(pair.lineIndex) +
                ": guaranteed cross-core invalidation on write");
        }

        for (size_t i = 0; i < fsCandidateLines.size(); ++i) {
            if (i >= kMaxDetailedLines) {
                escalations.push_back(
                    "and " + std::to_string(fsCandidateLines.size() - kMaxDetailedLines) +
                    " more cache line(s) with mixed write surface");
                break;
            }
            auto lineIdx = fsCandidateLines[i];
            const auto &bucket = map.buckets()[lineIdx];
            escalations.push_back(
                "line " + std::to_string(lineIdx) + ": " +
                std::to_string(bucket.atomicCount) + " atomic + " +
                std::to_string(bucket.mutableCount - bucket.atomicCount) +
                " non-atomic mutable field(s) — mixed write surface");
        }

        double confidence = 0.55;
        if (hasAtomicPairs)
            confidence = 0.88;
        else if (map.totalAtomicFields() > 0)
            confidence = 0.68;

        const auto &SM = Ctx.getSourceManager();
        auto loc = RD->getLocation();

        Diagnostic diag;
        diag.ruleID    = "FL002";
        diag.title     = "False Sharing Candidate";
        diag.severity  = sev;
        diag.confidence = confidence;
        diag.evidenceTier = hasAtomicPairs ? EvidenceTier::Proven : EvidenceTier::Likely;

        diag.location = resolveSourceLocation(loc, SM);

        std::ostringstream hw;
        hw << "Struct '" << RD->getNameAsString() << "' ("
           << map.recordSizeBytes() << "B, "
           << map.maxLinesSpanned() << " line(s)): "
           << mutablePairs.size() << " mutable field pair(s) share cache line(s) "
           << "with thread-escape evidence. Concurrent writes to co-located "
           << "fields trigger MESI invalidation per write.";
        diag.hardwareReasoning = hw.str();

        diag.structuralEvidence = {
            {"sizeof", std::to_string(map.recordSizeBytes()) + "B"},
            {"lines", std::to_string(map.maxLinesSpanned())},
            {"mutable_pairs_same_line", std::to_string(mutablePairs.size())},
            {"atomic_pairs_same_line", std::to_string(map.atomicPairsOnSameLine().size())},
            {"thread_escape", "true"},
            {"atomics", map.totalAtomicFields() > 0 ? "yes" : "no"},
            {"type_name", RD->getCanonicalDecl()->getQualifiedNameAsString()},
        };

        diag.mitigation =
            "Pad independently-written fields to separate 64B cache lines "
            "with alignas(64). Consider per-thread/per-core replicas.";

        diag.escalations = std::move(escalations);
        out.push_back(std::move(diag));
    }
};

LSHAZ_REGISTER_RULE(FL002_FalseSharing)

} // namespace lshaz
