// SPDX-License-Identifier: Apache-2.0
#include "lshaz/analysis/layout_safety.h"
#include "lshaz/core/rule.h"
#include "lshaz/core/registry.h"
#include "lshaz/core/hot_path.h"
#include "lshaz/analysis/escape.h"
#include "lshaz/analysis/numa.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/DeclCXX.h>
#include <clang/AST/RecordLayout.h>
#include <clang/Basic/SourceManager.h>

#include <sstream>

namespace lshaz {

class FL060_NUMAUnfriendly : public Rule {
public:
    std::string_view getID() const override { return "FL060"; }
    std::string_view getTitle() const override { return "NUMA-Unfriendly Shared Structure"; }
    Severity getBaseSeverity() const override { return Severity::High; }

    std::string_view getHardwareMechanism() const override {
        return "On a multi-socket system memory is physically partitioned "
               "across NUMA nodes, and a remote access pays the interconnect "
               "on the critical path. Latency is the mechanism, not "
               "bandwidth: a single core cannot saturate either link, so it "
               "reads local and remote memory at the same rate. Placement and "
               "per-node replication help; widening the structure does not. "
               "The penalty is one cache-miss-sized step rather than an order "
               "of magnitude, so it cannot carry a top grade alone.";
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
        if (!canComputeRecordLayout(RD, Ctx))
            return;

        // On one socket there is no remote node, so this rule's entire
        // mechanism is null and reporting it would spend a reviewer's
        // attention on a penalty that cannot occur. Socket count is a
        // deployment property and unreadable from source, so the
        // tool takes it from config rather than guessing: 0 leaves the
        // assumption labelled in the output, as before.
        if (Cfg.numaSockets == 1)
            return;

        const auto &layout = Ctx.getASTRecordLayout(RD);
        uint64_t sizeBytes = layout.getSize().getQuantity();

        // NUMA risk is significant for structures that:
        // 1. Are large enough to span multiple cache lines (>= 256B)
        // 2. Show thread-escape evidence
        // 3. Contain mutable state
        if (sizeBytes < 256)
            return;

        EscapeVerdict ev = escape.escapeVerdict(RD);
        if (!ev)
            return;

        unsigned mutableCount = 0;
        bool hasAtomics = ev.hasAtomics;

        for (const auto *field : RD->fields()) {
            if (escape.isFieldMutable(field))
                ++mutableCount;
        }

        if (mutableCount == 0 && !hasAtomics)
            return;

        // Infer NUMA placement via first-touch policy analysis.
        NUMAPlacement placement = NUMATopology::classifyStruct(RD, Ctx);
        double hazardFactor = numaHazardFactor(placement);

        Severity sev = Severity::High;
        std::vector<std::string> escalations;

        uint64_t cacheLines = (sizeBytes + Cfg.cacheLineBytes - 1) / Cfg.cacheLineBytes;

        if (sizeBytes >= 4096) {
            sev = Severity::Critical;
            escalations.push_back(
                "sizeof >= 4KB: spans " + std::to_string(cacheLines) +
                " cache lines, guaranteed multi-page TLB footprint on "
                "remote NUMA node");
        }

        if (hasAtomics) {
            escalations.push_back(
                "Contains atomic fields: a cross-socket atomic RMW pays the "
                "interconnect on the critical path of the LOCK, and unlike "
                "same-socket sharing it does not decay with write spacing");
        }

        if (mutableCount > 8) {
            escalations.push_back(
                std::to_string(mutableCount) + " mutable fields: wide "
                "write surface amplifies remote store buffer pressure");
        }

        // Placement-based modulation.
        if (placement == NUMAPlacement::Explicit ||
            placement == NUMAPlacement::LocalInit) {
            // NUMA-aware allocation or thread-local: low risk.
            if (sev > Severity::Medium)
                sev = Severity::Medium;
            escalations.push_back(
                "numa-topology: placement=" +
                std::string(numaPlacementName(placement)) +
                ", reduced remote access risk");
        } else if (placement == NUMAPlacement::Interleaved) {
            escalations.push_back(
                "numa-topology: interleaved placement, "
                "balanced but still ~50% remote access");
        } else if (placement == NUMAPlacement::MainThread) {
            escalations.push_back(
                "numa-topology: first-touch on main thread (socket 0), "
                "remote for all worker threads on other sockets");
        } else if (placement == NUMAPlacement::AnyThread) {
            escalations.push_back(
                "numa-topology: allocated by arbitrary thread, "
                "unpredictable NUMA placement");
        }

        const auto &SM = Ctx.getSourceManager();
        auto loc = RD->getLocation();

        // Scale confidence by contention. Low-contention types (shared_ptr only)
        // are unlikely NUMA hotspots.
        double baseConfidence = hasAtomics ? 0.55 : 0.35;
        baseConfidence *= (0.5 + 0.5 * ev.contention); // floor at 50% of base

        Diagnostic diag;
        diag.ruleID    = "FL060";
        diag.title     = "NUMA-Unfriendly Shared Structure";
        diag.severity  = sev;
        diag.confidence = baseConfidence * hazardFactor;
        diag.evidenceTier = EvidenceTier::Speculative;

        diag.location = resolveSourceLocation(loc, SM);

        std::ostringstream hw;
        hw << "Struct '" << RD->getNameAsString() << "' (" << sizeBytes
           << "B, " << cacheLines << " cache lines) with "
           << mutableCount << " mutable field(s) and thread-escape evidence. "
           << "On multi-socket systems, at least one socket accesses this "
           << "structure via remote NUMA interconnect. A remote line fetch "
           << "costs one cache-miss-sized step over local, and the cost is "
           << "latency rather than bandwidth: one core reads both nodes at "
           << "the same rate. Atomic operations on remote lines additionally "
           << "pay ownership transfer to the remote home agent. "
           << "[Assumes: deployment target is multi-socket NUMA; single-socket systems are unaffected]";
        diag.hardwareReasoning = hw.str();

        diag.structuralEvidence = {
            {"struct", RD->getNameAsString()},
            {"sizeof", std::to_string(sizeBytes) + "B"},
            {"cache_lines", std::to_string(cacheLines)},
            {"mutable_fields", std::to_string(mutableCount)},
            {"atomics", hasAtomics ? "yes" : "no"},
            {"thread_escape", "yes"},
            {"numa_placement", std::string(numaPlacementName(placement))},
            {"type_name", RD->getCanonicalDecl()->getQualifiedNameAsString()},
        };

        diag.mitigation =
            "Use numa_alloc_onnode() or mbind() for NUMA-aware placement. "
            "Replicate structure per-socket with periodic synchronization. "
            "Split into read-mostly (replicated) and write-heavy (local) parts. "
            "Consider interleaved allocation for balanced access patterns.";

        diag.escalations = std::move(escalations);
        diag.mechanismClaims = {
            {"a large shared mutable structure with no placement control",
             "size past the threshold, thread escape, mutable state", true,
             Severity::Medium},
            // One cache-miss-sized step, not an order of magnitude, so it
            // cannot carry Critical on its own.
            {"remote-node access costing one cache-miss step over local",
             "a multi-socket deployment (numa_sockets >= 2)",
             Cfg.numaSockets >= 2, Severity::High},
        };
        out.push_back(std::move(diag));
    }
};

LSHAZ_REGISTER_RULE(FL060_NUMAUnfriendly)

} // namespace lshaz
