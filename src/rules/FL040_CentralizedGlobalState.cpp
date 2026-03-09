// SPDX-License-Identifier: Apache-2.0
#include "lshaz/core/Rule.h"
#include "lshaz/core/RuleRegistry.h"
#include "lshaz/core/HotPathOracle.h"
#include "lshaz/analysis/EscapeAnalysis.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/DeclCXX.h>
#include <clang/AST/RecordLayout.h>
#include <clang/Basic/SourceManager.h>

#include <sstream>

namespace lshaz {

class FL040_CentralizedGlobalState : public Rule {
public:
    std::string_view getID() const override { return "FL040"; }
    std::string_view getTitle() const override { return "Centralized Mutable Global State"; }
    Severity getBaseSeverity() const override { return Severity::High; }

    std::string_view getHardwareMechanism() const override {
        return "Global mutable state accessed from multiple cores causes "
               "NUMA remote memory access on multi-socket systems (~100-300ns "
               "penalty). Cache line contention on shared writes. "
               "Scalability collapse under core count increase.";
    }

    void analyze(const clang::Decl *D,
                 clang::ASTContext &Ctx,
                 const HotPathOracle & /*Oracle*/,
                 const Config & /*Cfg*/,
                 std::vector<Diagnostic> &out) override {

        const auto *VD = llvm::dyn_cast_or_null<clang::VarDecl>(D);
        if (!VD)
            return;

        EscapeAnalysis escape(Ctx);

        if (!escape.isGlobalSharedMutable(VD))
            return;

        // Trigger TU scan for write-site collection.
        escape.scanTranslationUnit(Ctx.getTranslationUnitDecl());

        clang::QualType QT = VD->getType();
        bool hasAtomics = false;
        bool isRecord = false;

        if (const auto *RD = QT->getAsCXXRecordDecl()) {
            isRecord = true;
            hasAtomics = escape.hasAtomicMembers(RD);
        }

        // Also flag bare atomic globals.
        if (escape.isAtomicType(QT))
            hasAtomics = true;

        bool writeOnce = escape.isWriteOnceGlobal(VD);

        Severity sev = Severity::High;
        std::vector<std::string> escalations;

        if (writeOnce) {
            // Write-once globals are initialized and never mutated at runtime.
            // Contention risk is negligible. Demote to Informational.
            sev = Severity::Informational;
            escalations.push_back(
                "write-once: initialized at declaration or assigned at most "
                "once in function bodies — negligible runtime contention");
        } else if (hasAtomics) {
            sev = Severity::Critical;
            escalations.push_back(
                "Contains atomic fields: confirmed multi-writer intent, "
                "guaranteed cross-core cache line contention");
        }

        const auto &SM = Ctx.getSourceManager();
        auto loc = VD->getLocation();

        Diagnostic diag;
        diag.ruleID    = "FL040";
        diag.title     = "Centralized Mutable Global State";
        diag.severity  = sev;
        diag.confidence = writeOnce ? 0.30 : (hasAtomics ? 0.85 : 0.60);
        diag.evidenceTier = writeOnce ? EvidenceTier::Speculative
                          : (hasAtomics ? EvidenceTier::Likely : EvidenceTier::Speculative);

        if (loc.isValid()) {
            diag.location.file   = SM.getFilename(SM.getSpellingLoc(loc)).str();
            diag.location.line   = SM.getSpellingLineNumber(loc);
            diag.location.column = SM.getSpellingColumnNumber(loc);
        }

        std::ostringstream hw;
        hw << "Global mutable variable '" << VD->getNameAsString()
           << "' (type: " << QT.getAsString() << "). "
           << "Accessible from any thread without confinement. "
           << "On multi-socket systems, remote NUMA access adds ~100-300ns. "
           << "Under multi-core write contention, cache line bouncing "
           << "degrades linearly with core count. "
           << "[Assumes: variable is accessed concurrently from multiple threads]";
        diag.hardwareReasoning = hw.str();

        diag.structuralEvidence = {
            {"var", VD->getNameAsString()},
            {"type", QT.getAsString()},
            {"storage", "global"},
            {"const", "no"},
            {"thread_local", "no"},
            {"atomics", hasAtomics ? "yes" : "no"},
            {"write_once", writeOnce ? "yes" : "no"},
        };

        diag.mitigation =
            "Partition state per-thread or per-core. "
            "Inject via context object instead of global access. "
            "Use thread_local where possible. "
            "If read-mostly, consider RCU-style patterns.";

        diag.escalations = std::move(escalations);
        out.push_back(std::move(diag));
    }
};

LSHAZ_REGISTER_RULE(FL040_CentralizedGlobalState)

} // namespace lshaz
