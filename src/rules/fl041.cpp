// SPDX-License-Identifier: Apache-2.0
#include "lshaz/core/rule.h"
#include "lshaz/core/registry.h"
#include "lshaz/core/hot_path.h"
#include "lshaz/analysis/cache_line.h"
#include "lshaz/analysis/escape.h"

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
        return "Head and tail index line bouncing. With both indices on one "
               "line, every enqueue invalidates every consumer's cached tail "
               "and the reverse, so producer and consumer trade the line "
               "instead of working. What padding buys does not transfer "
               "between parts: the gain is largest on a monolithic die and "
               "can be nothing at all within one chiplet, where co-locating "
               "the indices is free. Treat the monolithic figure as a ceiling "
               "on a chiplet part.";
    }

    void analyze(const clang::Decl *D,
                 clang::ASTContext &Ctx,
                 const HotPathOracle & /*Oracle*/,
                 const Config &Cfg,
                 const EscapeAnalysis &escape,
                 std::vector<Diagnostic> &out) override {

        const auto *RD = llvm::dyn_cast_or_null<clang::RecordDecl>(D);
        if (!RD || !RD->isCompleteDefinition())
            return;
        if (RD->isImplicit())
            return;
        if (const auto *CXXRD = llvm::dyn_cast<clang::CXXRecordDecl>(RD))
            if (CXXRD->isLambda())
                return;

        CacheLineMap map(RD, Ctx, Cfg.cacheLineBytes, Cfg.atomicTypeNames);

        // A ring whose head and tail are plain indices, one written by the
        // producer and one by the consumer, is the canonical contended queue.
        // Requiring atomics missed the exact shape this rule exists for.
        // Concurrency must still be established, so the plain path demands a
        // thread-escape verdict where the atomic path takes the atomics as
        // their own evidence.
        auto atomicPairs = map.atomicPairsOnSameLine();
        const bool fromAtomics = !atomicPairs.empty();
        if (!fromAtomics) {
            if (!escape.escapeVerdict(RD))
                return;
            atomicPairs = map.mutablePairsOnSameLine();
        }
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

        // "read"/"write" as substrings match bytes_read on every stats struct,
        // so plain indices need the queue shape itself: a head-like and a
        // tail-like index that are the co-located pair.
        auto endName = [](const std::string &n, bool headSide) {
            static const char *head[] = {"head", "front", "dequeue", "cons", "pop"};
            static const char *tail[] = {"tail", "back", "enqueue", "prod", "push"};
            for (const char *p : headSide ? head : tail)
                if (containsCI(n, p)) return true;
            return false;
        };
        std::vector<CacheLineMap::SharedLinePair> headTailPairs;
        for (const auto &p : atomicPairs) {
            if (p.intraArray) continue;
            if ((endName(p.a->name, true)  && endName(p.b->name, false)) ||
                (endName(p.a->name, false) && endName(p.b->name, true)))
                headTailPairs.push_back(p);
        }
        const bool pairIsHeadTail = !headTailPairs.empty();
        // The plain finding is about the head/tail pair, so it must carry
        // only that pair. Reporting every co-located pair here would attach
        // queue-index language to unrelated arrays sharing the same line.
        if (!fromAtomics && pairIsHeadTail)
            atomicPairs = headTailPairs;

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
        if (fromAtomics) {
            if (!looksLikeQueue && !hasHeadTail)
                return;
        } else if (!pairIsHeadTail) {
            // A queue-ish type name alone is not enough without atomics:
            // "buffer" and "cache" name plenty of non-queues.
            return;
        }

        const auto &firstPair = atomicPairs.front();
        std::string field1 = firstPair.a->name;
        std::string field2 = firstPair.b->name;

        Severity sev = Severity::Critical;
        std::vector<std::string> escalations;

        const char *kind = fromAtomics ? "atomic" : "plain";
        escalations.push_back(
            std::string("Structure appears to be a concurrent queue: head/tail ") +
            kind + " indices on same cache line guarantee producer-consumer "
            "cache line ping-pong");
        if (!fromAtomics)
            escalations.push_back(
                "indices are not atomic: single-writer-per-index needs no "
                "atomicity, so the coherence cost is unchanged, what is "
                "unproven is that producer and consumer run concurrently");

        for (const auto &pair : atomicPairs) {
            if (pair.intraArray)
                escalations.push_back(
                    std::string(kind) + " array '" + pair.a->name +
                    "' packs multiple indices per line " +
                    std::to_string(pair.lineIndex) +
                    ": concurrent writes trigger MESI invalidation");
            else
                escalations.push_back(
                    std::string(kind) + " fields '" + pair.a->name + "' and '" +
                    pair.b->name + "' share line " +
                    std::to_string(pair.lineIndex) +
                    ": concurrent writes trigger MESI invalidation");
        }

        const auto &SM = Ctx.getSourceManager();
        auto loc = RD->getLocation();

        Diagnostic diag;
        diag.ruleID    = "FL041";
        diag.title     = "Contended Queue Pattern";
        diag.severity  = sev;
        bool exactLayout = map.isCacheLineAligned();
        diag.confidence = exactLayout ? 0.82 : 0.76;
        // Naming plus co-location is weaker proof of concurrent use than
        // atomics are: same mechanism, same cost, less certainty.
        if (!fromAtomics)
            diag.confidence -= 0.14;
        diag.evidenceTier = (exactLayout && fromAtomics) ? EvidenceTier::Proven
                                                         : EvidenceTier::Likely;

        diag.location = resolveSourceLocation(loc, SM);

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
            {"type_name", RD->getCanonicalDecl()->getQualifiedNameAsString()},
        };

        diag.mitigation =
            "Pad head and tail indices to separate 64B cache lines using "
            "alignas(64). Use per-core queues (SPSC) where possible. "
            "Consider cache-line-aware queue implementations.";

        diag.escalations = std::move(escalations);
        diag.mechanismClaims = {
            {"head and tail indices occupy one line",
             "queue-shaped naming with the pair co-resident", true,
             Severity::Medium},
            {"producer/consumer ownership ping-pong on every operation",
             fromAtomics ? "atomic indices evidencing multi-writer intent"
                         : "a thread-escape verdict for the record",
             true, Severity::Critical},
        };
        out.push_back(std::move(diag));
    }
};

LSHAZ_REGISTER_RULE(FL041_ContendedQueue)

} // namespace lshaz
