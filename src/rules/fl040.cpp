// SPDX-License-Identifier: Apache-2.0
#include "lshaz/core/rule.h"
#include "lshaz/core/registry.h"
#include "lshaz/core/hot_path.h"
#include "lshaz/analysis/escape.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/DeclCXX.h>
#include <clang/AST/RecordLayout.h>
#include <clang/Basic/SourceManager.h>

#include <memory>
#include <sstream>

namespace lshaz {

class FL040_CentralizedGlobalState : public Rule {
public:
    std::string_view getID() const override { return "FL040"; }
    std::string_view getTitle() const override { return "Centralized Mutable Global State"; }
    Severity getBaseSeverity() const override { return Severity::High; }

    std::string_view getHardwareMechanism() const override {
        return "A line written by many cores serializes: per-operation cost "
               "grows roughly linearly with writer count, so aggregate "
               "throughput stays flat and extra cores buy nothing. That is "
               "the scalability collapse, and it needs the writes close "
               "together in time, since more writers keep the line contended "
               "longer and the cost vanishes once they are far enough apart. "
               "On a multi-socket target the remote access adds a separate "
               "and much smaller term than the contention itself.";
    }

    void analyze(const clang::Decl *D,
                 clang::ASTContext &Ctx,
                 const HotPathOracle & /*Oracle*/,
                 const Config & /*Cfg*/,
                 const EscapeAnalysis &escape,
                 std::vector<Diagnostic> &out) override {

        const auto *VD = llvm::dyn_cast_or_null<clang::VarDecl>(D);
        if (!VD)
            return;

        if (!escape.isGlobalSharedMutable(VD))
            return;

        clang::QualType QT = VD->getType();
        bool hasAtomics = false;

        // getAsRecordDecl, not getAsCXXRecordDecl: the latter is null for a
        // C struct, which would leave a C global holding _Atomic fields with
        // its concurrency claim unestablished.
        if (const auto *RD = QT->getAsRecordDecl())
            hasAtomics = escape.hasAtomicMembers(RD);

        // Also flag bare atomic globals.
        if (escape.isAtomicType(QT))
            hasAtomics = true;

        // Map phase: emit raw facts, defer write-once verdict to reduce.
        unsigned tuWriteCount = escape.getGlobalWriteCount(VD);
        bool hasInit = VD->hasInit() &&
                       !llvm::isa<clang::ImplicitValueInitExpr>(
                           VD->getInit()->IgnoreImplicit());

        // Tentative severity, reduce phase may reclassify.
        Severity sev = hasAtomics ? Severity::Critical : Severity::High;
        std::vector<std::string> escalations;

        if (hasAtomics) {
            escalations.push_back(
                "Contains atomic fields: confirmed multi-writer intent, "
                "guaranteed cross-core cache line contention");
        }

        // The NUMA and coherence mechanisms need concurrent writers. A
        // global written six times from startup configuration has neither,
        // and asserting them for it is a hardware claim the shape does not
        // support. Where concurrency cannot be established the finding is
        // reported at reduced severity saying so, rather than dropped:
        // writers may live in another TU, and unestablished is not absent.
        auto gw = escape.globalWriterEvidence(VD);
        const bool concurrentWriters =
            hasAtomics || (gw.writtenFromThreadEntry && gw.writerFunctions >= 2);
        if (!concurrentWriters) {
            if (sev == Severity::High)
                sev = Severity::Medium;
            escalations.push_back(
                gw.writerFunctions == 0
                    ? "no write sites in this TU: contention is assumed, not "
                      "observed"
                    : "written from " + std::to_string(gw.writerFunctions) +
                          " function(s) in this TU, none of them a thread "
                          "entry: concurrent access is assumed, not observed");
        } else if (!hasAtomics) {
            escalations.push_back(
                "written from " + std::to_string(gw.writerFunctions) +
                " function(s), at least one spawned as a thread: concurrent "
                "writes are evidenced, not assumed");
        }

        const auto &SM = Ctx.getSourceManager();
        auto loc = VD->getLocation();

        Diagnostic diag;
        diag.ruleID    = "FL040";
        diag.title     = "Centralized Mutable Global State";
        diag.severity  = sev;
        diag.confidence = hasAtomics ? 0.85 : 0.60;
        diag.evidenceTier = hasAtomics ? EvidenceTier::Likely
                                       : EvidenceTier::Speculative;

        diag.location = resolveSourceLocation(loc, SM);

        std::ostringstream hw;
        hw << "Global mutable variable '" << VD->getNameAsString()
           << "' (type: " << QT.getAsString() << "). "
           << "Accessible from any thread without confinement. ";
        if (concurrentWriters)
            hw << "Under multi-core write contention the line serialises: "
               << "per-operation cost grows about linearly with writer count, "
               << "so aggregate throughput stays flat and extra cores buy "
               << "nothing. That needs the writes close together in time, and "
               << "it vanishes once they are far enough apart, at a spacing "
               << "that grows with the number of writers. On a multi-socket "
               << "target remote access adds a separate and much smaller term "
               << "on top.";
        else
            hw << "Concurrent access is not established here, so the NUMA "
               << "and coherence penalties are potential rather than "
               << "demonstrated; the finding stands on centralization alone.";
        diag.hardwareReasoning = hw.str();

        diag.structuralEvidence = {
            {"var", VD->getNameAsString()},
            {"type", QT.getAsString()},
            {"storage", "global"},
            {"const", "no"},
            {"thread_local", "no"},
            {"atomics", hasAtomics ? "yes" : "no"},
            {"has_init", hasInit ? "yes" : "no"},
            {"tu_write_count", std::to_string(tuWriteCount)},
            {"tu_loop_writes",
             std::to_string(escape.getGlobalLoopWriteCount(VD))},
        };

        diag.mitigation =
            "Partition state per-thread or per-core. "
            "Inject via context object instead of global access. "
            "Use thread_local where possible. "
            "If read-mostly, consider RCU-style patterns.";

        diag.mechanismClaims = {
            {"centralized mutable state reachable from any thread",
             "a global, non-thread_local, mutable object", true,
             Severity::Medium},
            {"cross-core RFO transfer and remote NUMA access",
             "two or more writers, at least one on a spawned thread",
             concurrentWriters, Severity::Critical},
        };
        diag.escalations = std::move(escalations);
        out.push_back(std::move(diag));
    }

};

LSHAZ_REGISTER_RULE(FL040_CentralizedGlobalState)

} // namespace lshaz
