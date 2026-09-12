// SPDX-License-Identifier: Apache-2.0
#include "lshaz/core/rule.h"
#include "lshaz/core/registry.h"
#include "lshaz/core/hot_path.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/DeclCXX.h>
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Stmt.h>
#include <clang/Basic/SourceManager.h>

#include <sstream>

namespace lshaz {

namespace {

struct VCallSite {
    clang::SourceLocation loc;
    std::string methodName;
    std::string className;
    bool inLoop = false;
};

class VCallVisitor : public clang::RecursiveASTVisitor<VCallVisitor> {
public:
    bool VisitCXXMemberCallExpr(clang::CXXMemberCallExpr *E) {
        const auto *MD = E->getMethodDecl();
        if (!MD)
            return true;

        if (!MD->isVirtual())
            return true;

        // Skip calls on value-typed objects: the compiler will devirtualize.
        // Only pointer/reference receivers carry genuine indirect dispatch.
        const auto *obj = E->getImplicitObjectArgument();
        if (obj) {
            clang::QualType QT = obj->getType();
            if (!QT->isPointerType() && !QT->isReferenceType()) {
                return true;
            }
        }

        VCallSite site;
        site.loc = E->getBeginLoc();
        site.methodName = MD->getNameAsString();
        site.inLoop = inLoop_;
        if (const auto *parent = MD->getParent())
            site.className = parent->getQualifiedNameAsString();

        sites_.push_back(std::move(site));
        return true;
    }

    bool TraverseForStmt(clang::ForStmt *S) {
        ++inLoop_;
        bool r = clang::RecursiveASTVisitor<VCallVisitor>::TraverseForStmt(S);
        --inLoop_;
        return r;
    }

    bool TraverseWhileStmt(clang::WhileStmt *S) {
        ++inLoop_;
        bool r = clang::RecursiveASTVisitor<VCallVisitor>::TraverseWhileStmt(S);
        --inLoop_;
        return r;
    }

    bool TraverseDoStmt(clang::DoStmt *S) {
        ++inLoop_;
        bool r = clang::RecursiveASTVisitor<VCallVisitor>::TraverseDoStmt(S);
        --inLoop_;
        return r;
    }

    bool TraverseCXXForRangeStmt(clang::CXXForRangeStmt *S) {
        ++inLoop_;
        bool r = clang::RecursiveASTVisitor<VCallVisitor>::TraverseCXXForRangeStmt(S);
        --inLoop_;
        return r;
    }

    const std::vector<VCallSite> &sites() const { return sites_; }

private:
    std::vector<VCallSite> sites_;
    unsigned inLoop_ = 0;
};

} // anonymous namespace

class FL030_VirtualDispatch : public Rule {
public:
    std::string_view getID() const override { return "FL030"; }
    std::string_view getTitle() const override { return "Virtual Dispatch in Hot Path"; }
    Severity getBaseSeverity() const override { return Severity::High; }

    bool requiresHotPath() const override { return true; }
    bool withdrawnWhenNotHot() const override { return true; }

    std::string_view getHardwareMechanism() const override {
        return "An indirect branch through the vtable pointer, with two "
               "separable costs. The inlining barrier is always paid: the "
               "callee cannot be specialised into the caller. Misprediction "
               "is added only when the receiver type varies unpredictably, so "
               "a monomorphic site, or a predictable cycle over several "
               "types, costs what one type costs. Candidate-type count is not "
               "the signal; the dynamic distribution is, and it is not "
               "visible in the AST. The fixes differ: devirtualize (final, "
               "CRTP) for the barrier, type-partition the data for the "
               "misprediction.";
    }

    void analyze(const clang::Decl *D,
                 clang::ASTContext &Ctx,
                 const HotPathOracle &Oracle,
                 const Config & /*Cfg*/,
                 const EscapeAnalysis & /*Escape*/,
                 std::vector<Diagnostic> &out) override {

        const auto *FD = llvm::dyn_cast_or_null<clang::FunctionDecl>(D);
        if (!FD || !FD->doesThisDeclarationHaveABody())
            return;

        if (!Oracle.isFunctionHot(FD))
            return;

        VCallVisitor visitor;
        visitor.TraverseStmt(FD->getBody());

        const auto &SM = Ctx.getSourceManager();

        for (const auto &site : visitor.sites()) {
            Severity sev = Severity::High;
            std::vector<std::string> escalations;

            if (site.inLoop) {
                sev = Severity::Critical;
                // Frequency, not per-call cost. A loop over a homogeneous
                // container is the monomorphic case and the cheapest one there
                // is; what the loop multiplies is how often the lost inline is
                // paid, not the cost of each dispatch.
                escalations.push_back(
                    "Virtual call inside loop: the per-call cost is paid every "
                    "iteration, so the aggregate scales with trip count");
            }

            Diagnostic diag;
            diag.ruleID    = "FL030";
            diag.title     = "Virtual Dispatch in Hot Path";
            diag.severity  = sev;
            diag.confidence = 0.70;
            diag.evidenceTier = EvidenceTier::Likely;
            diag.functionName = FD->getQualifiedNameAsString();

            diag.location = resolveSourceLocation(site.loc, SM);

            std::ostringstream hw;
            hw << "Virtual call to '" << site.className << "::" << site.methodName
               << "' in hot function '" << FD->getQualifiedNameAsString()
               << "'. Requires vtable pointer dereference (potential L1D miss "
               << "if vtable is cold) followed by indirect branch. The cost "
               << "splits in two: the lost inline is always paid, while "
               << "misprediction is added only when the receiver type varies "
               << "unpredictably, so monomorphic dispatch costs the same at "
               << "eight candidate types as at one. "
               << "[Requires, for the larger term: polymorphic and "
               << "data-dependent receivers, not established statically]";
            diag.hardwareReasoning = hw.str();

            diag.structuralEvidence = {
                {"virtual_call", site.className + "::" + site.methodName},
                {"caller", FD->getQualifiedNameAsString()},
                {"in_loop", site.inLoop ? "yes" : "no"},
                {"hot_path", "true"},
            };

            diag.mitigation =
                "Use CRTP for static polymorphism. "
                "Use std::variant + std::visit for closed type sets. "
                "Use function pointers with known targets. "
                "Consider template-based dispatch.";

            diag.escalations = std::move(escalations);
            diag.mechanismClaims = {
                {"an inlining barrier: the callee cannot be specialised or "
                 "folded into the caller",
                 "a virtual call on a hot path", ClaimState::Established, Severity::High},
                {"the barrier is paid once per iteration, so cost scales with "
                 "trip count",
                 "the call sits inside a loop", claimFrom(site.inLoop != 0),
                 Severity::Critical},
                {"receiver type varies unpredictably, mispredicting the "
                 "indirect branch",
                 "runtime evidence that this site is megamorphic",
                 ClaimState::Unknown,
                 site.inLoop ? Severity::High : Severity::Medium,
                 /*gating=*/true},
            };
            out.push_back(std::move(diag));
        }
    }
};

LSHAZ_REGISTER_RULE(FL030_VirtualDispatch)

} // namespace lshaz
