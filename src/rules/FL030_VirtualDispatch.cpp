#include "lshaz/core/Rule.h"
#include "lshaz/core/RuleRegistry.h"
#include "lshaz/core/HotPathOracle.h"

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

    std::string_view getHardwareMechanism() const override {
        return "Indirect branch via vtable pointer. BTB (Branch Target Buffer) "
               "lookup required. Misprediction causes full pipeline flush "
               "(~14-20 cycle penalty on modern x86). Polymorphic call sites "
               "with multiple targets degrade BTB hit rate.";
    }

    void analyze(const clang::Decl *D,
                 clang::ASTContext &Ctx,
                 const HotPathOracle &Oracle,
                 const Config & /*Cfg*/,
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
                escalations.push_back(
                    "Virtual call inside loop: repeated indirect branch, "
                    "BTB capacity pressure, sustained pipeline flush risk");
            }

            Diagnostic diag;
            diag.ruleID    = "FL030";
            diag.title     = "Virtual Dispatch in Hot Path";
            diag.severity  = sev;
            diag.confidence = 0.70;
            diag.evidenceTier = EvidenceTier::Likely;
            diag.functionName = FD->getQualifiedNameAsString();

            if (site.loc.isValid()) {
                diag.location.file   = SM.getFilename(SM.getSpellingLoc(site.loc)).str();
                diag.location.line   = SM.getSpellingLineNumber(site.loc);
                diag.location.column = SM.getSpellingColumnNumber(site.loc);
            }

            std::ostringstream hw;
            hw << "Virtual call to '" << site.className << "::" << site.methodName
               << "' in hot function '" << FD->getQualifiedNameAsString()
               << "'. Requires vtable pointer dereference (potential L1D miss "
               << "if vtable is cold) followed by indirect branch. "
               << "BTB misprediction flushes the entire pipeline.";
            diag.hardwareReasoning = hw.str();

            std::ostringstream ev;
            ev << "virtual_call=" << site.className << "::" << site.methodName
               << "; caller=" << FD->getQualifiedNameAsString()
               << "; in_loop=" << (site.inLoop ? "yes" : "no")
               << "; hot_path=true";
            diag.structuralEvidence = ev.str();

            diag.mitigation =
                "Use CRTP for static polymorphism. "
                "Use std::variant + std::visit for closed type sets. "
                "Use function pointers with known targets. "
                "Consider template-based dispatch.";

            diag.escalations = std::move(escalations);
            out.push_back(std::move(diag));
        }
    }
};

LSHAZ_REGISTER_RULE(FL030_VirtualDispatch)

} // namespace lshaz
