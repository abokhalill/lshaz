// SPDX-License-Identifier: Apache-2.0
#include "lshaz/analysis/LayoutSafety.h"
#include "lshaz/core/Rule.h"
#include "lshaz/core/RuleRegistry.h"
#include "lshaz/core/HotPathOracle.h"
#include "lshaz/analysis/EscapeAnalysis.h"
#include "lshaz/analysis/NUMATopology.h"

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
        return "On multi-socket systems, memory is physically partitioned across "
               "NUMA nodes. Accessing remote memory incurs ~100-300ns penalty vs "
               "~60-80ns local. Large shared mutable structures allocated without "
               "NUMA-aware placement will be accessed remotely by at least one socket.";
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
        if (!canComputeRecordLayout(RD, Ctx))
            return;

        const auto &layout = Ctx.getASTRecordLayout(RD);
        uint64_t sizeBytes = layout.getSize().getQuantity();

        // NUMA risk is significant for structures that:
        // 1. Are large enough to span multiple cache lines (>= 256B)
        // 2. Show thread-escape evidence
        // 3. Contain mutable state
        if (sizeBytes < 256)
            return;

        EscapeAnalysis escape(Ctx);
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
                "Contains atomic fields: cross-socket atomic RMW incurs "
                "interconnect round-trip (~200-400ns on QPI/UPI)");
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
           << "structure via remote NUMA interconnect. Each remote cache line "
           << "fetch adds ~100-300ns. Atomic operations on remote lines "
           << "require interconnect round-trip. "
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
        };

        diag.mitigation =
            "Use numa_alloc_onnode() or mbind() for NUMA-aware placement. "
            "Replicate structure per-socket with periodic synchronization. "
            "Split into read-mostly (replicated) and write-heavy (local) parts. "
            "Consider interleaved allocation for balanced access patterns.";

        diag.escalations = std::move(escalations);
        out.push_back(std::move(diag));
    }
};

LSHAZ_REGISTER_RULE(FL060_NUMAUnfriendly)

} // namespace lshaz
