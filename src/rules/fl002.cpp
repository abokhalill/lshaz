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

class FL002_FalseSharing : public Rule {
public:
    std::string_view getID() const override { return "FL002"; }
    std::string_view getTitle() const override { return "False Sharing Candidate"; }
    Severity getBaseSeverity() const override { return Severity::Critical; }

    std::string_view getHardwareMechanism() const override {
        return "MESI invalidation ping-pong. Two cores writing distinct "
               "fields on one line each force a Request-For-Ownership that "
               "invalidates the line in every other core's private cache: "
               "independent data, serialized by geometry. The cost needs the "
               "writes close enough in time to catch the line resident in a "
               "peer's L1, and only decays with spacing while both writers "
               "share a last-level cache. Across coherence domains it does "
               "not decay at all.";
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

        EscapeVerdict ev = escape.escapeVerdict(RD);
        if (!ev)
            return;

        CacheLineMap map(RD, Ctx, Cfg.cacheLineBytes, Cfg.atomicTypeNames);

        auto atomicPairs = map.atomicPairsOnSameLine();
        auto mutablePairs = map.mutablePairsOnSameLine();

        // An intra-array pair is co-residency alone, and co-residency is not
        // contention: padding arrays share lines by construction and are
        // never written. Require distinct writers actually reaching the
        // array before treating its elements as a contended pair.
        auto needsArrayWriters = [&](const CacheLineMap::SharedLinePair &p) {
            return p.intraArray &&
                   !escape.pairHasDistinctWriters(p.a->decl, p.a->decl);
        };
        mutablePairs.erase(std::remove_if(mutablePairs.begin(),
                                          mutablePairs.end(), needsArrayWriters),
                           mutablePairs.end());
        atomicPairs.erase(std::remove_if(atomicPairs.begin(), atomicPairs.end(),
                                         needsArrayWriters),
                          atomicPairs.end());
        if (mutablePairs.empty())
            return;

        bool hasAtomicPairs = !atomicPairs.empty();
        auto fsCandidateLines = map.falseSharingCandidateLines();

        // Write evidence is computed before the gate because it *is* the
        // gate for non-atomic records.
        enum { kNoWrites, kPartial, kWriterReader, kMultiWriter };
        int wev = kNoWrites;
        // Co-residency in space is not co-residency in time. Two threads
        // writing one line microseconds apart never find it in each other's
        // L1 and generate no coherence traffic at all.
        bool densePair = false;
        bool sparsePair = false;
        unsigned denseSites = 0;
        std::vector<std::string> writeEvidence;
        const auto &evPairs = hasAtomicPairs ? atomicPairs : mutablePairs;
        for (const auto &p : evPairs) {
            auto ea = escape.fieldWriteEvidence(p.a->decl);
            auto eb = escape.fieldWriteEvidence(p.b->decl);
            if (ea.loopWriteSites || eb.loopWriteSites) {
                densePair = true;
                denseSites += ea.loopWriteSites + eb.loopWriteSites;
            }
            // Sparse only when BOTH sides are proven sparse. One tight writer
            // is enough to keep the line moving.
            if (escape.fieldWritersAllOpaque(p.a->decl) &&
                escape.fieldWritersAllOpaque(p.b->decl))
                sparsePair = true;
            int level = kNoWrites;
            // For an intra-array pair a == b, this reduces to "this array is
            // written from >=2 functions", which is the correct question.
            if (ea.writeSites && eb.writeSites &&
                escape.pairHasDistinctWriters(p.a->decl, p.b->decl)) {
                level = kMultiWriter;
                if (wev < kMultiWriter) {
                    if (p.intraArray)
                        writeEvidence.push_back(
                            "write evidence: array '" + p.a->name + "' written "
                            "from " + std::to_string(ea.writerFunctions) +
                            " distinct function(s) across " +
                            std::to_string(ea.writeSites) +
                            " site(s) in this TU");
                    else
                        writeEvidence.push_back(
                            "write evidence: '" + p.a->name + "' (" +
                            std::to_string(ea.writeSites) + " site(s)/" +
                            std::to_string(ea.writerFunctions) + " fn(s)) and '" +
                            p.b->name + "' (" + std::to_string(eb.writeSites) +
                            " site(s)/" + std::to_string(eb.writerFunctions) +
                            " fn(s)) written from distinct functions in this TU");
                }
            } else if (const bool aStores =
                           ea.writeSites &&
                           escape.pairHasWriterAndDistinctReader(p.a->decl,
                                                                 p.b->decl),
                       bStores = eb.writeSites &&
                           escape.pairHasWriterAndDistinctReader(p.b->decl,
                                                                 p.a->decl);
                       aStores || bStores) {
                // One field stored, the other read from a function that is
                // not the writer. The store invalidates the line and the
                // reader re-fetches, which is the same coherence miss a
                // second writer pays.
                level = kWriterReader;
                if (wev < kWriterReader) {
                    const auto &wn = aStores ? p.a->name : p.b->name;
                    const auto &rn = aStores ? p.b->name : p.a->name;
                    auto rr = escape.fieldReadEvidence(
                        aStores ? p.b->decl : p.a->decl);
                    writeEvidence.push_back(
                        "read/write evidence: '" + wn + "' is stored while '" +
                        rn + "' on the same line is read from " +
                        std::to_string(rr.readerFunctions) +
                        " other function(s) across " +
                        std::to_string(rr.readSites) + " site(s) in this TU");
                }
            } else if (ea.writeSites || eb.writeSites) {
                level = kPartial;
            }
            wev = std::max(wev, level);
        }

        // Striped and role-partitioned fields are single-writer-per-slot, so
        // the dominant false-sharing idiom is deliberately non-atomic and a
        // gate on atomics scores zero against it. Gate on concurrent
        // independent writes: escape verdict plus distinct writers.
        const bool anyAtomics = hasAtomicPairs || map.totalAtomicFields() > 0;
        if (!anyAtomics && wev < kWriterReader)
            return;
        // Not gated on in-TU writes when atomics are present: write evidence
        // is per-TU, so a header-defined struct written from another TU shows
        // none. An atomic field is a declaration of intent to share and is
        // the signal that survives that blindness. Requiring writes here
        // would trade this rule's false-positive class for a cross-TU
        // false-negative class, which is the worse trade.

        // Refcount-only structs: single atomic refcount field sharing a line
        // with immutable data.  No real false sharing.
        if (map.isRefcountOnly() && !hasAtomicPairs)
            return;

        // proven only when bucketing is exact: alignment >= line size
        // pins every field to one shift. below that, co-location holds
        // for most-but-not-all base alignments the allocator may pick.
        bool exactLayout = map.isCacheLineAligned();

        // Explicit line alignment or a trailing pad-to-line says the author
        // already reasons in cache lines, and co-located atomics under that
        // idiom are usually single-writer by design. Structurally true, so
        // report it, but not at strike severity. FL041 is deliberately
        // exempt: head/tail naming implies the multi-writer roles for which
        // this idiom is itself the bug.
        bool deliberateLayout =
            exactLayout ||
            CacheLineMap::hasTrailingLinePad(RD, Ctx, Cfg.cacheLineBytes);

        Severity sev = hasAtomicPairs ? Severity::Critical : Severity::High;
        // A reader pays one miss per remote store; two writers trade the line
        // in both directions. Real, and not the same cost.
        if (wev == kWriterReader && sev > Severity::Medium)
            sev = Severity::Medium;
        std::vector<std::string> escalations;
        if (!anyAtomics)
            escalations.push_back(
                "no atomic fields: co-located plain fields written by "
                "distinct functions. The coherence cost is identical, what "
                "is unproven is that the writers run concurrently");
        if (deliberateLayout) {
            sev = Severity::Medium;
            escalations.push_back(
                "deliberate cache-line layout detected (explicit alignment "
                "or trailing line padding): co-located atomics are often "
                "single-writer by design, verify write ownership before "
                "acting");
        }

        // A mutex co-located with the data it guards is a deliberate and
        // benign layout: writes under that lock are already serialized, so
        // co-location adds no coherence cost beyond the lock's own line.
        // Per-field lock association is not available here, so this can be
        // proven neither way. Mark it rather than either suppressing the
        // finding or asserting a hazard.
        if (!anyAtomics && ev.hasSyncPrims) {
            sev = Severity::Medium;
            escalations.push_back(
                "record carries its own sync primitive: if these fields are "
                "written under that lock the co-location is benign, since "
                "the writes are already serialized. Lock coverage per field "
                "is not established here");
        }

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
            const std::string tail =
                exactLayout
                    ? ": guaranteed cross-core invalidation on write"
                    : ": cross-core invalidation on write (co-location "
                      "depends on allocation alignment; struct align < "
                      "line size)";
            if (pair.intraArray)
                escalations.push_back(
                    "atomic array '" + pair.a->name + "' packs " +
                    std::to_string(map.cacheLineBytes() /
                                   pair.a->accessGranuleBytes) +
                    " elements per line; writes to different indices share "
                    "line " + std::to_string(pair.lineIndex) + tail);
            else
                escalations.push_back(
                    "atomic fields '" + pair.a->name + "' and '" + pair.b->name +
                    "' share line " + std::to_string(pair.lineIndex) + tail);
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
                " non-atomic mutable field(s), mixed write surface");
        }

        // The strongest TU wins cross-TU dedup through confidence.
        // Severity is impact if real; confidence is how likely it is real.
        // A non-atomic record has the same mechanism and the same cost, and
        // weaker proof of concurrency, so it moves confidence, not severity.
        double confidence = 0.55;
        if (hasAtomicPairs)
            confidence = exactLayout ? 0.88 : 0.80;
        else if (map.totalAtomicFields() > 0)
            confidence = 0.68;
        else
            confidence = 0.60;

        escalations.insert(escalations.end(), writeEvidence.begin(),
                           writeEvidence.end());
        if (wev == kMultiWriter) {
            confidence = std::min(confidence + 0.06, 0.95);
        } else if (wev == kNoWrites) {
            // Writers may live in another TU; that TU's instance then
            // carries the evidence and outranks this one at dedup.
            if (sev == Severity::Critical)
                sev = Severity::High;
            confidence = std::max(confidence - 0.08, 0.50);
            escalations.push_back(
                "no write sites to the co-located fields observed in "
                "this TU: co-location is structural evidence only");
        }
        if (densePair) {
            escalations.push_back(
                "write density: " + std::to_string(denseSites) +
                " in-loop write site(s) to the flagged pair, spacing can "
                "reach the sub-microsecond range where coherence cost is real");
        }
        // Decay needs both writers under one last-level cache: across
        // domains the ownership transfer sits on the LOCK's critical path
        // and no gap hides it. Socket count is the wrong proxy on chiplets,
        // so an unknown topology declines to demote.
        unsigned domains = Cfg.coherenceDomains;
        if (domains == 0 && Cfg.numaSockets > 0) domains = Cfg.numaSockets;
        const bool decayApplies = domains == 1;
        if (sparsePair && !densePair && !decayApplies)
            escalations.push_back(
                "writers are sparse, but the target has more than one "
                "last-level-cache domain (or the count is unset): "
                "cross-domain sharing does not decay with spacing, so "
                "sparseness earns no demotion here. Set coherence_domains: 1 "
                "if both writers provably share an LLC");
        else if (sparsePair)
            escalations.push_back(
                "every writer of this pair calls out to a body this TU "
                "cannot see, and none writes in a loop: the writes are "
                "separated by a syscall or external call and are microseconds "
                "apart. Contended-RMW cost collapses as spacing grows under "
                "one last-level cache, so the co-location is real and the "
                "ping-pong is not");

        const auto &SM = Ctx.getSourceManager();
        auto loc = RD->getLocation();

        Diagnostic diag;
        diag.ruleID    = "FL002";
        diag.title     = "False Sharing Candidate";
        diag.severity  = sev;
        diag.confidence = confidence;
        diag.evidenceTier = (hasAtomicPairs && exactLayout)
                                ? EvidenceTier::Proven
                                : EvidenceTier::Likely;

        diag.location = resolveSourceLocation(loc, SM);

        std::ostringstream hw;
        hw << "Struct '" << RD->getNameAsString() << "' ("
           << map.recordSizeBytes() << "B, "
           << map.maxLinesSpanned() << " line(s)): "
           << mutablePairs.size() << " mutable field pair(s) share cache line(s) "
           << "with thread-escape evidence. Concurrent writes to co-located "
           << "fields trigger MESI invalidation per write.";
        diag.hardwareReasoning = hw.str();

        // Flagged pairs by name, so post processing can join them against
        // cross-TU writer attribution at pair granularity; a type-level
        // join could escalate on a pair this rule never flagged. Bounded
        // separately from the display cap: the join is for machines, and
        // large structs put the interesting pair deep in the list.
        constexpr size_t kMaxPairEvidence = 64;
        std::string pairFields;
        for (size_t i = 0; i < evPairs.size() && i < kMaxPairEvidence; ++i) {
            if (i) pairFields += ';';
            pairFields += evPairs[i].a->name + "|" + evPairs[i].b->name;
        }

        diag.structuralEvidence = {
            {"sizeof", std::to_string(map.recordSizeBytes()) + "B"},
            {"lines", std::to_string(map.maxLinesSpanned())},
            {"mutable_pairs_same_line", std::to_string(mutablePairs.size())},
            {"atomic_pairs_same_line", std::to_string(map.atomicPairsOnSameLine().size())},
            {"thread_escape", "true"},
            {"in_loop_write_sites", std::to_string(denseSites)},
            {"atomics", map.totalAtomicFields() > 0 ? "yes" : "no"},
            {"type_name", RD->getCanonicalDecl()->getQualifiedNameAsString()},
            {"pair_fields", pairFields},
            // Linker names of this type's global instances: the key a
            // runtime write-attribution trace is reported under.
            {"global_instances", escape.globalInstanceNames(RD)},
        };

        diag.mitigation =
            "Pad independently-written fields to separate 64B cache lines "
            "with alignas(64). Consider per-thread/per-core replicas.";

        diag.mechanismClaims = {
            {"co-located mutable fields share a line",
             "two mutable fields co-resident under some base alignment", ClaimState::Established,
             Severity::Medium},
            {"MESI invalidation ping-pong between cores",
             "distinct writers reaching the pair, or atomics evidencing "
             "multi-writer intent",
             claimFrom(hasAtomicPairs || wev == kMultiWriter),
             deliberateLayout ? Severity::Medium : Severity::Critical},
            // Gating: no temporal proximity, no mechanism.
            {"writes land close enough in time to catch the line resident "
             "in a peer core's L1",
             "no writer is separated from the next by an opaque call, on a "
             "target whose writers share one last-level cache, where "
             "coherence cost decays with spacing",
             claimFrom(!(sparsePair && !densePair && decayApplies)),
             (sparsePair && !densePair && decayApplies) ? Severity::Medium : sev,
             /*gating=*/true},
            // Not gated on ev.hasSharingRoute: it is a per-TU fact, and for a
            // header-declared record the TU defining the global is rarely the
            // TU reporting. The gate belongs in the reduce phase.
        };
        diag.escalations = std::move(escalations);
        out.push_back(std::move(diag));
    }
};

LSHAZ_REGISTER_RULE(FL002_FalseSharing)

} // namespace lshaz
