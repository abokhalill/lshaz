// SPDX-License-Identifier: Apache-2.0
#include "lshaz/core/rule.h"
#include "lshaz/core/registry.h"
#include "lshaz/core/hot_path.h"
#include "lshaz/core/config.h"
#include "lshaz/analysis/cache_line.h"
#include "lshaz/analysis/escape.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/DeclCXX.h>
#include <clang/Basic/SourceManager.h>

#include <sstream>

namespace lshaz {

class FL001_CacheLineSpanning : public Rule {
public:
    std::string_view getID() const override { return "FL001"; }
    std::string_view getTitle() const override { return "Cache Line Spanning Struct"; }
    Severity getBaseSeverity() const override { return Severity::High; }

    std::string_view getHardwareMechanism() const override {
        return "Footprint expansion. A record needing two lines where one "
               "would do doubles the cache it occupies, so an array of them "
               "outruns a given cache level at half the element count. Extra "
               "lines per access are not themselves a cost: touching two "
               "resident lines is as cheap as touching one. The variable is "
               "total footprint against cache size, which makes instance "
               "count matter as much as layout, and puts the threshold in the "
               "deployment's cache rather than in the record.";
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

        if (map.maxLinesSpanned() <= 1)
            return;

        uint64_t sizeBytes = map.recordSizeBytes();
        uint64_t lines = map.maxLinesSpanned();

        EscapeVerdict ev = escape.escapeVerdict(RD);

        Severity sev = Severity::High;
        std::vector<std::string> escalations;

        // Critical footprint is a property of SIZE, not placement: a
        // 104B object misaligned across boundaries touches 3 lines but
        // is fundamentally a 2-line object. minLines is what the object
        // occupies at any alignment; the worst case stays in the text.
        uint64_t minLines =
            (sizeBytes + Cfg.cacheLineBytes - 1) / Cfg.cacheLineBytes;

        // Coherence cost scales with the lines a writer touches, not the
        // object's span: a 504B struct whose written fields share one line
        // costs one line. Seeing no writes in this TU never demotes, since
        // writers may live elsewhere.
        unsigned writerLines = 0;
        for (const auto &b : map.buckets()) {
            for (const auto *f : b.fields) {
                if (f->decl &&
                    escape.fieldWriteEvidence(f->decl).writeSites > 0) {
                    ++writerLines;
                    break;
                }
            }
        }

        if (minLines >= 3) {
            if (writerLines == 0) {
                // Not Critical: seeing no writes is absence of evidence, not
                // evidence that the writes are clustered, so it must not
                // outrank the case where they were observed and counted.
                // Otherwise severity falls as evidence arrives, and the claim
                // needs writerLines >= 3 anyway.
                sev = Severity::High;
                escalations.push_back(
                    "occupies " + std::to_string(minLines) +
                    " cache lines at any alignment (worst case " +
                    std::to_string(lines) + "): elevated L1D eviction "
                    "pressure. No write sites observed in this TU, so the "
                    "span is assessed on footprint alone");
            } else if (writerLines >= 3) {
                sev = Severity::Critical;
                escalations.push_back(
                    "written fields occupy " + std::to_string(writerLines) +
                    " of " + std::to_string(minLines) +
                    " cache lines: each carries its own RFO traffic");
            } else {
                // Clustering the written fields is what removes the cost,
                // and this struct has already done it. Reporting the same
                // severity as a scattered one gives no credit for the work
                // and is how a tool stops being read.
                sev = Severity::High;
                escalations.push_back(
                    "occupies " + std::to_string(minLines) +
                    " cache lines but written fields touch only " +
                    std::to_string(writerLines) +
                    ": the remaining span is footprint, not coherence traffic");
            }
        }

        auto straddlers = map.straddlingFields();
        if (!straddlers.empty()) {
            for (const auto *f : straddlers) {
                escalations.push_back(
                    "field '" + f->name + "' straddles line boundary at offset " +
                    std::to_string(f->offsetBytes) + "B (" +
                    std::to_string(f->sizeBytes) + "B): split load/store penalty");
            }
        }

        if (map.totalAtomicFields() > 0) {
            unsigned atomicLines = 0;
            for (const auto &b : map.buckets()) {
                if (b.atomicCount > 0) ++atomicLines;
            }
            // Atomics spread across lines do not cost per access: touching two
            // resident lines measures the same as one. Separating them is also
            // FL002's prescribed fix, so escalating on it graded the remedy as
            // the hazard. What this signals is a wider record, and width only
            // costs once the instances outrun a cache level, which is a
            // working-set fact, not a layout one.
            if (map.totalAtomicFields() >= 2 && atomicLines >= 2 &&
                sev < Severity::High)
                sev = Severity::High;
            escalations.push_back(
                std::to_string(map.totalAtomicFields()) +
                " atomic field(s) across " + std::to_string(atomicLines) +
                " line(s): a wider record, costing once an array of them "
                "outruns cache, not per access");

            // Refcount-only structs: single atomic refcount with immutable
            // co-located data. demote; cache line spanning is real but
            // the coherence traffic is limited to refcount ops only.
            if (map.isRefcountOnly())
                sev = Severity::Medium;
        }

        // A sub-line object spans lines only under adverse placement;
        // single-line residency is the common runtime case. Whatever the
        // signals above said, the spanning mechanism cannot exceed Medium
        // here.
        if (sizeBytes <= Cfg.cacheLineBytes &&
            (sev == Severity::Critical || sev == Severity::High)) {
            sev = Severity::Medium;
            escalations.push_back(
                "sub-line object (" + std::to_string(sizeBytes) +
                "B <= " + std::to_string(Cfg.cacheLineBytes) +
                "B): spanning occurs only under adverse base placement");
        }

        // No escape evidence and no atomics -> speculative.
        if (!ev.escapes && map.totalAtomicFields() == 0) {
            sev = Severity::Medium;
        }
        // Escapes but low contention (shared_ptr/publication only,
        // no atomics/volatile/sync) -> demote. Coherence pressure is
        // theoretically possible but unlikely to be a hot path.
        else if (ev.escapes && ev.contention < 0.30 &&
                 map.totalAtomicFields() == 0) {
            sev = Severity::Medium;
            escalations.push_back(
                "low contention (" +
                std::to_string(static_cast<int>(ev.contention * 100)) +
                "%): escape via shared_ptr/publication only");
        }

        if (map.totalAtomicFields() > 0 &&
            (map.isCacheLineAligned() ||
             CacheLineMap::hasTrailingLinePad(RD, Ctx, Cfg.cacheLineBytes)) &&
            sev > Severity::Medium) {
            sev = Severity::Medium;
            escalations.push_back(
                "deliberate cache-line layout detected (explicit alignment "
                "or trailing line padding): verify write ownership before "
                "acting");
        }

        const auto &SM = Ctx.getSourceManager();
        auto loc = RD->getLocation();

        Diagnostic diag;
        diag.ruleID    = "FL001";
        diag.title     = "Cache Line Spanning Struct";
        diag.severity  = sev;
        if (!ev.escapes && map.totalAtomicFields() == 0) {
            diag.confidence = !straddlers.empty() ? 0.52 : 0.42;
            diag.evidenceTier = EvidenceTier::Likely;
        } else if (ev.contention < 0.30 && map.totalAtomicFields() == 0) {
            // Low-contention escape: slightly above non-escape.
            diag.confidence = !straddlers.empty() ? 0.55 : 0.45;
            diag.evidenceTier = EvidenceTier::Likely;
        } else {
            diag.confidence = (map.totalAtomicFields() > 0) ? 0.90 :
                              (!straddlers.empty() ? 0.82 : 0.72);
            diag.evidenceTier = EvidenceTier::Proven;
        }

        diag.location = resolveSourceLocation(loc, SM);

        std::ostringstream hw;
        hw << "Struct '" << RD->getNameAsString() << "' occupies "
           << sizeBytes << "B across " << lines << " cache line(s).";
        if (!straddlers.empty())
            hw << " " << straddlers.size()
               << " field(s) straddle line boundaries (split load/store).";
        if (map.totalAtomicFields() > 0)
            hw << " Atomic fields span multiple lines: each line requires "
               << "independent RFO ownership transfer.";
        diag.hardwareReasoning = hw.str();

        diag.structuralEvidence = {
            {"sizeof", std::to_string(sizeBytes) + "B"},
            {"lines_spanned", std::to_string(lines)},
            {"writer_lines", std::to_string(writerLines)},
            {"straddling_fields", std::to_string(straddlers.size())},
            {"atomic_fields", std::to_string(map.totalAtomicFields())},
            {"mutable_fields", std::to_string(map.totalMutableFields())},
            {"thread_escape", ev.escapes ? "true" : "false"},
            {"contention", std::to_string(static_cast<int>(ev.contention * 100)) + "%"},
            {"type_name", RD->getCanonicalDecl()->getQualifiedNameAsString()},
        };

        diag.mitigation =
            "Split hot/cold fields into separate structs. "
            "Consider AoS->SoA transformation. "
            "Apply alignas(64) to isolate write-heavy sub-structs.";

        diag.mechanismClaims = {
            {"L1D footprint: the object occupies several lines at once",
             "a record spanning more than one cache line", ClaimState::Established,
             Severity::High},
            {"per-line RFO transfer on write",
             "written fields spanning three or more lines",
             claimFrom(writerLines >= 3), Severity::Critical},
            {"split load/store across a line boundary",
             "a field whose access granule crosses the boundary",
             claimFrom(!straddlers.empty()), Severity::High},
        };
        diag.escalations = std::move(escalations);
        out.push_back(std::move(diag));
    }
};

LSHAZ_REGISTER_RULE(FL001_CacheLineSpanning)

} // namespace lshaz
