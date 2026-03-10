// SPDX-License-Identifier: Apache-2.0
#include "lshaz/core/Rule.h"
#include "lshaz/core/RuleRegistry.h"
#include "lshaz/core/HotPathOracle.h"
#include "lshaz/core/Config.h"
#include "lshaz/analysis/CacheLineMap.h"

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
        return "L1/L2 cache line footprint expansion. Increased eviction "
               "probability. Higher coherence traffic under multi-core writes.";
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

        if (map.linesSpanned() <= 1)
            return;

        uint64_t sizeBytes = map.recordSizeBytes();
        uint64_t lines = map.linesSpanned();

        Severity sev = Severity::High;
        std::vector<std::string> escalations;

        if (lines >= 3) {
            sev = Severity::Critical;
            escalations.push_back(
                "spans " + std::to_string(lines) +
                " cache lines: elevated L1D eviction pressure");
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
            sev = Severity::Critical;
            unsigned atomicLines = 0;
            for (const auto &b : map.buckets()) {
                if (b.atomicCount > 0) ++atomicLines;
            }
            escalations.push_back(
                std::to_string(map.totalAtomicFields()) +
                " atomic field(s) across " + std::to_string(atomicLines) +
                " line(s): RFO traffic on each distinct line");
        }

        const auto &SM = Ctx.getSourceManager();
        auto loc = RD->getLocation();

        Diagnostic diag;
        diag.ruleID    = "FL001";
        diag.title     = "Cache Line Spanning Struct";
        diag.severity  = sev;
        diag.confidence = (map.totalAtomicFields() > 0) ? 0.90 :
                          (!straddlers.empty() ? 0.82 : 0.72);
        diag.evidenceTier = EvidenceTier::Proven;

        if (loc.isValid()) {
            diag.location.file   = SM.getFilename(SM.getSpellingLoc(loc)).str();
            diag.location.line   = SM.getSpellingLineNumber(loc);
            diag.location.column = SM.getSpellingColumnNumber(loc);
        }

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
            {"straddling_fields", std::to_string(straddlers.size())},
            {"atomic_fields", std::to_string(map.totalAtomicFields())},
            {"mutable_fields", std::to_string(map.totalMutableFields())},
        };

        diag.mitigation =
            "Split hot/cold fields into separate structs. "
            "Consider AoS->SoA transformation. "
            "Apply alignas(64) to isolate write-heavy sub-structs.";

        diag.escalations = std::move(escalations);
        out.push_back(std::move(diag));
    }
};

LSHAZ_REGISTER_RULE(FL001_CacheLineSpanning)

} // namespace lshaz
