// SPDX-License-Identifier: Apache-2.0
#include "lshaz/core/rule.h"
#include "lshaz/core/registry.h"
#include "lshaz/core/hot_path.h"
#include "lshaz/analysis/cache_line.h"
#include "lshaz/analysis/escape.h"
#include "lshaz/core/ladder.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/DeclCXX.h>
#include <clang/Basic/SourceManager.h>

#include <sstream>

namespace lshaz {
namespace {

// Weakest first. The compounded hazards are established elsewhere, so all
// that separates these is whether an accessor was named.
enum class Rung : unsigned {
    RouteOnly,
    WriterNamed,
    Count,
};

} // namespace

class FL090_HazardAmplification : public Rule {
public:
    std::string_view getID() const override { return "FL090"; }
    std::string_view getTitle() const override { return "Hazard Amplification"; }
    Severity getBaseSeverity() const override { return Severity::Critical; }

    std::string_view getHardwareMechanism() const override {
        return "Several latency multipliers on one structure: per-line RFO "
               "ownership transfer, multi-line footprint, and cross-core "
               "sharing. They compound rather than add, because each "
               "additional occupied line is its own coherence unit and each "
               "additional sharer pays for every one of them.";
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
        EscapeVerdict ev = escape.escapeVerdict(RD);

        bool multiLine    = map.maxLinesSpanned() >= 3;
        bool escapeBeyondAtomics =
            ev.hasSyncPrims || ev.hasSharedOwner || ev.hasVolatile ||
            ev.hasSharingRoute;

        // A single atomic occupies one line at runtime however many buckets
        // alignment uncertainty smears it across. Amplification needs the RFO
        // surface itself to span lines; the same realizability test FL001
        // applies before its own Critical.
        unsigned atomicLines = 0;
        for (const auto &b : map.buckets())
            if (b.atomicCount > 0) ++atomicLines;
        bool multiLineAtomics = map.totalAtomicFields() >= 2 && atomicLines >= 2;

        unsigned signalCount = 0;
        if (multiLine)            ++signalCount;
        if (multiLineAtomics)     ++signalCount;
        if (escapeBeyondAtomics)  ++signalCount;

        if (signalCount < 3)
            return;

        // same demotion contract as FL001/FL002: the compound must not
        // outrank its mitigation-adjusted components.
        bool deliberateLayout =
            map.isCacheLineAligned() ||
            CacheLineMap::hasTrailingLinePad(RD, Ctx, Cfg.cacheLineBytes);

        Severity sev = Severity::Critical;
        std::vector<std::string> escalations;
        if (deliberateLayout) {
            sev = Severity::Medium;
            escalations.push_back(
                "deliberate cache-line layout detected (explicit alignment "
                "or trailing line padding): co-located atomics are often "
                "single-writer by design, verify write ownership before "
                "acting");
        }

        unsigned hotLines = 0;
        for (const auto &b : map.buckets())
            if (b.mutableCount > 0) ++hotLines;

        escalations.push_back(
            std::to_string(map.recordSizeBytes()) + "B across " +
            std::to_string(map.maxLinesSpanned()) + " cache lines");

        escalations.push_back(
            std::to_string(map.totalAtomicFields()) + " atomic field(s) on " +
            std::to_string(atomicLines) + " line(s): per-line RFO ownership transfer");

        // Named rather than asserted: which route establishes sharing is the
        // difference between a compound hazard and a large struct that
        // happens to contain an atomic.
        escalations.push_back(
            std::string("thread-escaping via ") +
            (ev.hasThreadWriters ? "writers on a spawned thread"
             : ev.hasPublication ? "publication to a thread or global"
             : ev.hasSyncPrims   ? "an embedded sync primitive"
             : ev.hasSharedOwner ? "shared ownership"
                                 : "volatile members") +
            ": coherence traffic amplified across participating cores");

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
        diag.confidence = rungRank(ev.escapesByRouteOnly() ? Rung::RouteOnly
                                                          : Rung::WriterNamed);
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
            {"type_name", RD->getCanonicalDecl()->getQualifiedNameAsString()},
        };

        diag.mitigation =
            "Decompose into separate cache-line-aligned sub-structures. "
            "Isolate atomic fields with alignas(64) padding. "
            "Split hot (frequently written) and cold (rarely accessed) fields. "
            "Consider per-core replicas with periodic merge.";

        diag.mechanismClaims = {
            {"per-line RFO transfer across the footprint",
             "atomics spanning >=2 lines and a sharing route independent of "
             "them",
             claimFrom(multiLineAtomics && escapeBeyondAtomics),
             deliberateLayout ? Severity::Medium : Severity::Critical},
        };
        diag.escalations = std::move(escalations);
        out.push_back(std::move(diag));
    }
};

LSHAZ_REGISTER_RULE(FL090_HazardAmplification)

} // namespace lshaz
