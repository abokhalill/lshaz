// SPDX-License-Identifier: Apache-2.0
#include "lshaz/core/rule.h"
#include "lshaz/core/registry.h"
#include "lshaz/core/hot_path.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Stmt.h>
#include <clang/Basic/SourceManager.h>

#include <algorithm>
#include <sstream>

namespace lshaz {

namespace {

struct BranchSite {
    clang::SourceLocation loc;
    unsigned depth;
    bool isSwitchStmt;
    unsigned switchCases; // only for switch
};

// A switch whose every arm returns a constant is a lookup, not a branch
// tree: the compiler emits a jump table into trivial stubs, or an indexed
// array of constants with no branch at all. Either way there is one indirect
// branch at most, and the cost does not scale with case count, so the
// mechanism this rule reports does not apply. A state-name lookup is the
// canonical shape; grading it as dispatch pressure invents a mechanism.
bool isConstantLookupSwitch(const clang::SwitchStmt *S,
                            clang::ASTContext &Ctx) {
    bool anyCase = false;
    for (const auto *sc = S->getSwitchCaseList(); sc;
         sc = sc->getNextSwitchCase()) {
        const clang::Stmt *body = sc->getSubStmt();
        // Fallthrough chains: walk to the first non-label statement.
        while (const auto *nested = llvm::dyn_cast_or_null<clang::SwitchCase>(body))
            body = nested->getSubStmt();
        const auto *ret = llvm::dyn_cast_or_null<clang::ReturnStmt>(body);
        if (!ret) return false;
        const clang::Expr *v = ret->getRetValue();
        if (!v) return false;
        v = v->IgnoreParenImpCasts();
        if (llvm::isa<clang::StringLiteral>(v)) { anyCase = true; continue; }
        if (v->isEvaluatable(Ctx)) { anyCase = true; continue; }
        return false;
    }
    return anyCase;
}

class BranchDepthVisitor : public clang::RecursiveASTVisitor<BranchDepthVisitor> {
public:
    BranchDepthVisitor(unsigned threshold, clang::ASTContext &Ctx)
        : threshold_(threshold), ctx_(Ctx) {}

    bool TraverseIfStmt(clang::IfStmt *S) {
        ++depth_;
        maxDepth_ = std::max(maxDepth_, depth_);

        if (depth_ >= threshold_) {
            sites_.push_back({S->getIfLoc(), depth_, false, 0});
        }

        bool r = clang::RecursiveASTVisitor<BranchDepthVisitor>::TraverseIfStmt(S);
        --depth_;
        return r;
    }

    bool VisitSwitchStmt(clang::SwitchStmt *S) {
        unsigned caseCount = 0;
        for (auto *sc = S->getSwitchCaseList(); sc; sc = sc->getNextSwitchCase())
            ++caseCount;

        if (caseCount >= 8 && !isConstantLookupSwitch(S, ctx_)) {
            sites_.push_back({S->getSwitchLoc(), depth_, true, caseCount});
        }
        return true;
    }

    const std::vector<BranchSite> &sites() const { return sites_; }
    unsigned maxDepth() const { return maxDepth_; }

private:
    unsigned threshold_;
    clang::ASTContext &ctx_;
    unsigned depth_ = 0;
    unsigned maxDepth_ = 0;
    std::vector<BranchSite> sites_;
};

} // anonymous namespace

class FL050_DeepConditionalTree : public Rule {
public:
    std::string_view getID() const override { return "FL050"; }
    std::string_view getTitle() const override { return "Deep Conditional Tree in Hot Path"; }
    Severity getBaseSeverity() const override { return Severity::Medium; }

    bool requiresHotPath() const override { return true; }
    bool withdrawnWhenNotHot() const override { return true; }

    std::string_view getHardwareMechanism() const override {
        return "Deeply nested conditionals and large switches widen the "
               "branch misprediction surface. A predicted branch is free, so "
               "target count does not matter: a predictable indirect branch "
               "costs the same at thousands of targets as at two, which rules "
               "out BTB capacity as the mechanism and case count as a "
               "severity signal. Cost requires the outcome to be "
               "data-dependent, which is a runtime property, hence Medium "
               "without a profile.";
    }

    void analyze(const clang::Decl *D,
                 clang::ASTContext &Ctx,
                 const HotPathOracle &Oracle,
                 const Config &Cfg,
                 const EscapeAnalysis & /*Escape*/,
                 std::vector<Diagnostic> &out) override {

        const auto *FD = llvm::dyn_cast_or_null<clang::FunctionDecl>(D);
        if (!FD || !FD->doesThisDeclarationHaveABody())
            return;

        if (!Oracle.isFunctionHot(FD))
            return;

        const unsigned threshold = Cfg.branchDepthWarn;

        BranchDepthVisitor visitor(threshold, Ctx);
        visitor.TraverseStmt(FD->getBody());

        if (visitor.sites().empty())
            return;

        const auto &SM = Ctx.getSourceManager();

        // Deduplicate: only emit for the deepest nesting point and large switches.
        bool emittedNested = false;

        for (const auto &site : visitor.sites()) {
            if (!site.isSwitchStmt && emittedNested)
                continue;

            Severity sev = Severity::Medium;
            std::vector<std::string> escalations;

            if (site.isSwitchStmt) {
                escalations.push_back(
                    "Switch with " + std::to_string(site.switchCases) +
                    " non-trivial arms: an indirect jump the predictor must "
                    "resolve, which costs only when the selector is "
                    "data-dependent");
            } else {
                if (site.depth >= 6) {
                    sev = Severity::High;
                    escalations.push_back(
                        "Nesting depth " + std::to_string(site.depth) +
                        ": high branch entropy, compounding misprediction cost");
                }
                emittedNested = true;
            }

            Diagnostic diag;
            diag.ruleID    = "FL050";
            diag.title     = "Deep Conditional Tree in Hot Path";
            diag.severity  = sev;
            diag.confidence = 0.50;
            diag.evidenceTier = EvidenceTier::Speculative;
            diag.functionName = FD->getQualifiedNameAsString();

            diag.location = resolveSourceLocation(site.loc, SM);

            std::ostringstream hw;
            if (site.isSwitchStmt) {
                hw << "switch statement with " << site.switchCases
                   << " cases in hot function '"
                   << FD->getQualifiedNameAsString()
                   << "'. Non-constexpr switch generates an indirect jump. "
                   << "The cost is misprediction, and it is flat in target "
                   << "count: a predictable indirect branch costs the same at "
                   << "thousands of targets as at two. Case count therefore "
                   << "does not indicate severity. "
                   << "[Requires: the selector varies unpredictably at runtime, "
                   << "not established statically]";
            } else {
                hw << "Conditional nesting depth " << site.depth
                   << " in hot function '" << FD->getQualifiedNameAsString()
                   << "'. Each nested branch is a prediction point. "
                   << "Deep trees create correlated misprediction chains "
                   << "that defeat pattern-based predictors. "
                   << "[Assumes: branch outcomes are not consistently predictable]";
            }
            diag.hardwareReasoning = hw.str();

            diag.structuralEvidence = {
                {"function", FD->getQualifiedNameAsString()},
                {"type", site.isSwitchStmt ? "switch" : "nested_if"},
                {"depth", std::to_string(site.depth)},
                {"max_depth", std::to_string(visitor.maxDepth())},
            };
            if (site.isSwitchStmt)
                diag.structuralEvidence["cases"] = std::to_string(site.switchCases);

            diag.mitigation =
                "Use table-driven dispatch. "
                "Flatten conditional logic with early returns. "
                "Precompute decision trees. "
                "Use __builtin_expect for predictable branches.";

            diag.escalations = std::move(escalations);
            diag.mechanismClaims = {
                {"branch prediction surface on a hot path",
                 "a deep nest or a large switch in a hot function", ClaimState::Established,
                 Severity::Medium},
                {"an indirect jump whose target the predictor must resolve",
                 "a switch whose arms are real work, not a constant lookup",
                 claimFrom(site.isSwitchStmt), Severity::High},
                {"correlated misprediction chains that defeat pattern "
                 "predictors",
                 "nesting depth at or beyond six",
                 claimFrom(!site.isSwitchStmt && site.depth >= 6),
                 Severity::High},
                {"branch outcomes vary unpredictably at run time",
                 "runtime branch-miss evidence for this site",
                 ClaimState::Unknown, Severity::Medium, /*gating=*/true},
            };
            out.push_back(std::move(diag));
        }
    }
};

LSHAZ_REGISTER_RULE(FL050_DeepConditionalTree)

} // namespace lshaz
