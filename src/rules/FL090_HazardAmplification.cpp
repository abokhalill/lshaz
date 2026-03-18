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

class FL090_HazardAmplification : public Rule {
public:
    std::string_view getID() const override { return "FL090"; }
    std::string_view getTitle() const override { return "Hazard Amplification"; }
    Severity getBaseSeverity() const override { return Severity::Critical; }

    std::string_view getHardwareMechanism() const override {
        return "Multiple interacting latency multipliers on a single structure: "
               "cache line spanning + atomic contention + cross-thread sharing. "
               "Each hazard compounds under load. Coherence storms, store buffer "
               "saturation, and TLB pressure interact to produce tail latency.";
    }

    void analyze(const clang::Decl *D,
                 clang::ASTContext &Ctx,
                 const HotPathOracle & /*Oracle*/,
                 const Config &Cfg,
                 std::vector<Diagnostic> &out) override {

        const auto *RD = llvm::dyn_cast_or_null<clang::RecordDecl>(D);
        if (!RD || !RD->isCompleteDefinition())
            return;
        if (RD->isImplicit())
            return;
        if (const auto *CXXRD = llvm::dyn_cast<clang::CXXRecordDecl>(RD))
            if (CXXRD->isLambda())
                return;

        CacheLineMap map(RD, Ctx, Cfg.cacheLineBytes);
        EscapeAnalysis escape(Ctx);
        EscapeVerdict ev = escape.escapeVerdict(RD);

        bool multiLine    = map.maxLinesSpanned() >= 3;
        bool hasAtomics   = map.totalAtomicFields() > 0;

        unsigned signalCount = 0;
        if (multiLine)   ++signalCount;
        if (hasAtomics)  ++signalCount;
        if (ev.escapes)  ++signalCount;

        if (signalCount < 3)
            return;

        Severity sev = Severity::Critical;
        std::vector<std::string> escalations;

        unsigned atomicLines = 0;
        unsigned hotLines = 0;
        for (const auto &b : map.buckets()) {
            if (b.atomicCount > 0) ++atomicLines;
            if (b.mutableCount > 0) ++hotLines;
        }

        escalations.push_back(
            std::to_string(map.recordSizeBytes()) + "B across " +
            std::to_string(map.maxLinesSpanned()) + " cache lines");

        escalations.push_back(
            std::to_string(map.totalAtomicFields()) + " atomic field(s) on " +
            std::to_string(atomicLines) + " line(s): per-line RFO ownership transfer");

        escalations.push_back(
            "thread-escaping: coherence traffic amplified across participating cores");

        auto straddlers = map.straddlingFields();
        if (!straddlers.empty()) {
            escalations.push_back(
                std::to_string(straddlers.size()) +
                " field(s) straddle line boundaries: split load/store penalty "
                "compounds with coherence cost");
        }

        if (map.totalMutableFields() > 4) {
            escalations.push_back(
                std::to_string(map.totalMutableFields()) + " mutable fields across " +
                std::to_string(hotLines) + " line(s): wide write surface");
        }

        auto atomicPairs = map.atomicPairsOnSameLine();
        if (!atomicPairs.empty()) {
            escalations.push_back(
                std::to_string(atomicPairs.size()) +
                " atomic pair(s) share cache line(s): intra-line contention "
                "adds to cross-line RFO cost");
        }

        const auto &SM = Ctx.getSourceManager();
        auto loc = RD->getLocation();

        Diagnostic diag;
        diag.ruleID    = "FL090";
        diag.title     = "Hazard Amplification";
        diag.severity  = sev;
        diag.confidence = 0.70 + 0.18 * ev.contention; // [0.70, 0.88]
        diag.evidenceTier = EvidenceTier::Likely;

        diag.location = resolveSourceLocation(loc, SM);

        std::ostringstream hw;
        hw << "Struct '" << RD->getNameAsString() << "' ("
           << map.recordSizeBytes() << "B, "
           << map.maxLinesSpanned() << " lines) exhibits compound hazard: "
           << map.totalAtomicFields() << " atomic field(s) across "
           << atomicLines << " line(s) with thread-escape evidence. "
           << "Under multi-core contention, per-line RFO ownership transfer "
           << "and coherence invalidation interact across the full footprint. "
           << "[Assumes: struct is accessed concurrently from multiple cores under contention]";
        diag.hardwareReasoning = hw.str();

        diag.structuralEvidence = {
            {"struct", RD->getNameAsString()},
            {"sizeof", std::to_string(map.recordSizeBytes()) + "B"},
            {"cache_lines", std::to_string(map.maxLinesSpanned())},
            {"atomic_fields", std::to_string(map.totalAtomicFields())},
            {"atomic_lines", std::to_string(atomicLines)},
            {"mutable_fields", std::to_string(map.totalMutableFields())},
            {"straddling", std::to_string(straddlers.size())},
            {"thread_escape", "yes"},
            {"signal_count", std::to_string(signalCount)},
        };

        diag.mitigation =
            "Decompose into separate cache-line-aligned sub-structures. "
            "Isolate atomic fields with alignas(64) padding. "
            "Split hot (frequently written) and cold (rarely accessed) fields. "
            "Consider per-core replicas with periodic merge.";

        diag.escalations = std::move(escalations);
        out.push_back(std::move(diag));
    }
};

LSHAZ_REGISTER_RULE(FL090_HazardAmplification)

} // namespace lshaz
