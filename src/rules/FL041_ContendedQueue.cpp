// SPDX-License-Identifier: Apache-2.0
#include "lshaz/core/Rule.h"
#include "lshaz/core/RuleRegistry.h"
#include "lshaz/core/HotPathOracle.h"
#include "lshaz/analysis/CacheLineMap.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/DeclCXX.h>
#include <clang/Basic/SourceManager.h>

#include <algorithm>
#include <sstream>

namespace lshaz {

namespace {

// Case-insensitive substring search.
bool containsCI(const std::string &haystack, const char *needle) {
    std::string lower = haystack;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    return lower.find(needle) != std::string::npos;
}

} // anonymous namespace

class FL041_ContendedQueue : public Rule {
public:
    std::string_view getID() const override { return "FL041"; }
    std::string_view getTitle() const override { return "Contended Queue Pattern"; }
    Severity getBaseSeverity() const override { return Severity::High; }

    std::string_view getHardwareMechanism() const override {
        return "Head/tail index cache line bouncing in MPMC queues. "
               "Atomic head and tail on same cache line causes MESI "
               "invalidation on every enqueue/dequeue from different cores. "
               "Without padding, producer and consumer thrash the same line.";
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

        auto atomicPairs = map.atomicPairsOnSameLine();
        if (atomicPairs.empty())
            return;

        std::string structName = RD->getNameAsString();
        bool looksLikeQueue =
            containsCI(structName, "queue") ||
            containsCI(structName, "buffer") ||
            containsCI(structName, "ring") ||
            containsCI(structName, "channel") ||
            containsCI(structName, "spsc") ||
            containsCI(structName, "mpmc") ||
            containsCI(structName, "mpsc");

        bool hasHeadTail = false;
        for (const auto &f : map.fields()) {
            if (!f.isAtomic) continue;
            const auto &n = f.name;
            if (containsCI(n, "head") ||
                containsCI(n, "tail") ||
                containsCI(n, "read") ||
                containsCI(n, "write") ||
                containsCI(n, "push") ||
                containsCI(n, "pop") ||
                containsCI(n, "front") ||
                containsCI(n, "back") ||
                containsCI(n, "enqueue") ||
                containsCI(n, "dequeue") ||
                containsCI(n, "prod") ||
                containsCI(n, "cons")) {
                hasHeadTail = true;
            }
        }

        // Require at least one queue heuristic signal. Without it, atomic
        // pairs on the same line are already covered by FL002 (false sharing).
        if (!looksLikeQueue && !hasHeadTail)
            return;

        const auto &firstPair = atomicPairs.front();
        std::string field1 = firstPair.a->name;
        std::string field2 = firstPair.b->name;

        Severity sev = Severity::Critical;
        std::vector<std::string> escalations;

        escalations.push_back(
            "Structure appears to be a concurrent queue: head/tail "
            "atomic indices on same cache line guarantee producer-consumer "
            "cache line ping-pong");

        for (const auto &pair : atomicPairs) {
            escalations.push_back(
                "atomic fields '" + pair.a->name + "' and '" + pair.b->name +
                "' share line " + std::to_string(pair.lineIndex) +
                ": concurrent writes trigger MESI invalidation");
        }

        const auto &SM = Ctx.getSourceManager();
        auto loc = RD->getLocation();

        Diagnostic diag;
        diag.ruleID    = "FL041";
        diag.title     = "Contended Queue Pattern";
        diag.severity  = sev;
        diag.confidence = 0.82;
        diag.evidenceTier = EvidenceTier::Proven;

        if (loc.isValid()) {
            diag.location.file   = SM.getFilename(SM.getSpellingLoc(loc)).str();
            diag.location.line   = SM.getSpellingLineNumber(loc);
            diag.location.column = SM.getSpellingColumnNumber(loc);
        }

        std::ostringstream hw;
        hw << "Struct '" << structName << "' ("
           << map.recordSizeBytes() << "B, "
           << map.maxLinesSpanned() << " line(s)) has "
           << map.totalAtomicFields() << " atomic field(s) with '"
           << field1 << "' and '" << field2
           << "' on the same cache line. Under MPMC workload, every "
           << "enqueue/dequeue triggers cross-core RFO for the shared line.";
        diag.hardwareReasoning = hw.str();

        diag.structuralEvidence = {
            {"struct", structName},
            {"sizeof", std::to_string(map.recordSizeBytes()) + "B"},
            {"lines", std::to_string(map.maxLinesSpanned())},
            {"atomic_fields", std::to_string(map.totalAtomicFields())},
            {"atomic_pairs_same_line", std::to_string(atomicPairs.size())},
            {"queue_heuristic", looksLikeQueue ? "yes" : "no"},
            {"head_tail_names", hasHeadTail ? "yes" : "no"},
        };

        diag.mitigation =
            "Pad head and tail indices to separate 64B cache lines using "
            "alignas(64). Use per-core queues (SPSC) where possible. "
            "Consider cache-line-aware queue implementations.";

        diag.escalations = std::move(escalations);
        out.push_back(std::move(diag));
    }
};

LSHAZ_REGISTER_RULE(FL041_ContendedQueue)

} // namespace lshaz
