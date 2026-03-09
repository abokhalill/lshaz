// SPDX-License-Identifier: Apache-2.0
#include "lshaz/core/Rule.h"
#include "lshaz/core/RuleRegistry.h"
#include "lshaz/core/HotPathOracle.h"
#include "lshaz/analysis/EscapeAnalysis.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/DeclCXX.h>
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/DeclTemplate.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/RecordLayout.h>
#include <clang/Basic/SourceManager.h>

#include <sstream>

namespace lshaz {

namespace {

struct AtomicWriteSite {
    clang::SourceLocation loc;
    std::string op;
    std::string varName;
    unsigned inLoop = 0;
};

bool isStdAtomicType(clang::QualType QT) {
    QT = QT.getCanonicalType().getNonReferenceType();
    if (QT->isAtomicType())
        return true;
    const clang::CXXRecordDecl *RD = nullptr;
    if (const auto *TST = QT->getAs<clang::TemplateSpecializationType>()) {
        if (auto TD = TST->getTemplateName().getAsTemplateDecl())
            RD = llvm::dyn_cast_or_null<clang::CXXRecordDecl>(
                TD->getTemplatedDecl());
    }
    if (!RD)
        RD = QT->getAsCXXRecordDecl();
    if (!RD)
        return false;
    std::string qn = RD->getQualifiedNameAsString();
    if (qn == "std::atomic" || qn == "std::atomic_ref")
        return true;
    // libstdc++ dispatches atomic member functions through std::__atomic_base<T>.
    // libc++ uses std::__1::__atomic_base<T>. Match these base classes.
    if (qn.find("__atomic_base") != std::string::npos)
        return true;
    if (const auto *CTSD =
            llvm::dyn_cast<clang::ClassTemplateSpecializationDecl>(RD)) {
        if (auto *TD = CTSD->getSpecializedTemplate()) {
            std::string tn = TD->getQualifiedNameAsString();
            if (tn == "std::atomic" || tn == "std::atomic_ref" ||
                tn.find("__atomic_base") != std::string::npos)
                return true;
        }
    }
    return false;
}

class AtomicWriteVisitor : public clang::RecursiveASTVisitor<AtomicWriteVisitor> {
public:
    bool VisitCXXMemberCallExpr(clang::CXXMemberCallExpr *E) {
        const auto *MD = E->getMethodDecl();
        if (!MD)
            return true;

        std::string name = MD->getNameAsString();

        // Write operations on atomics.
        static const char *writeOps[] = {
            "store", "exchange",
            "compare_exchange_weak", "compare_exchange_strong",
            "fetch_add", "fetch_sub", "fetch_and", "fetch_or", "fetch_xor"
        };

        bool isWrite = false;
        for (const auto *op : writeOps) {
            if (name == op) { isWrite = true; break; }
        }
        if (!isWrite)
            return true;

        const auto *obj = E->getImplicitObjectArgument();
        if (!obj)
            return true;

        if (!isStdAtomicType(obj->getType()))
            return true;

        std::string varName = "<unknown>";
        if (const auto *ME = llvm::dyn_cast<clang::MemberExpr>(
                obj->IgnoreImplicit()))
            varName = ME->getMemberDecl()->getNameAsString();
        else if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(
                     obj->IgnoreImplicit()))
            varName = DRE->getDecl()->getNameAsString();

        sites_.push_back({E->getBeginLoc(), name, varName, inLoop_});
        return true;
    }

    bool VisitCXXOperatorCallExpr(clang::CXXOperatorCallExpr *E) {
        if (E->getNumArgs() < 1)
            return true;

        if (!isStdAtomicType(E->getArg(0)->getType()))
            return true;

        auto op = E->getOperator();
        std::string opName;
        switch (op) {
            case clang::OO_PlusPlus:   opName = "operator++"; break;
            case clang::OO_MinusMinus: opName = "operator--"; break;
            case clang::OO_PlusEqual:  opName = "operator+="; break;
            case clang::OO_MinusEqual: opName = "operator-="; break;
            case clang::OO_AmpEqual:   opName = "operator&="; break;
            case clang::OO_PipeEqual:  opName = "operator|="; break;
            case clang::OO_CaretEqual: opName = "operator^="; break;
            case clang::OO_Equal:      opName = "operator="; break;
            default: return true;
        }

        sites_.push_back({E->getBeginLoc(), opName, "<atomic>", inLoop_});
        return true;
    }

    bool TraverseForStmt(clang::ForStmt *S) {
        ++inLoop_;
        bool r = clang::RecursiveASTVisitor<AtomicWriteVisitor>::TraverseForStmt(S);
        --inLoop_;
        return r;
    }
    bool TraverseWhileStmt(clang::WhileStmt *S) {
        ++inLoop_;
        bool r = clang::RecursiveASTVisitor<AtomicWriteVisitor>::TraverseWhileStmt(S);
        --inLoop_;
        return r;
    }
    bool TraverseDoStmt(clang::DoStmt *S) {
        ++inLoop_;
        bool r = clang::RecursiveASTVisitor<AtomicWriteVisitor>::TraverseDoStmt(S);
        --inLoop_;
        return r;
    }
    bool TraverseCXXForRangeStmt(clang::CXXForRangeStmt *S) {
        ++inLoop_;
        bool r = clang::RecursiveASTVisitor<AtomicWriteVisitor>::TraverseCXXForRangeStmt(S);
        --inLoop_;
        return r;
    }

    const std::vector<AtomicWriteSite> &sites() const { return sites_; }

private:
    std::vector<AtomicWriteSite> sites_;
    unsigned inLoop_ = 0;
};

} // anonymous namespace

class FL011_AtomicContention : public Rule {
public:
    std::string_view getID() const override { return "FL011"; }
    std::string_view getTitle() const override { return "Atomic Contention Hotspot"; }
    Severity getBaseSeverity() const override { return Severity::Critical; }

    std::string_view getHardwareMechanism() const override {
        return "Cache line ownership thrashing via MESI RFO (Read-For-Ownership). "
               "Each atomic write from a different core forces exclusive ownership "
               "transfer (~40-100ns cross-core, ~100-300ns cross-socket). "
               "Store buffer pressure from sustained atomic writes.";
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

        AtomicWriteVisitor visitor;
        visitor.TraverseStmt(FD->getBody());

        if (visitor.sites().empty())
            return;

        const auto &SM = Ctx.getSourceManager();
        unsigned writeCount = visitor.sites().size();

        // Only flag if there are multiple atomic writes (contention signal)
        // or writes inside loops (sustained pressure).
        bool hasLoopWrite = false;
        for (const auto &s : visitor.sites()) {
            if (s.inLoop) { hasLoopWrite = true; break; }
        }

        if (writeCount < 2 && !hasLoopWrite)
            return;

        // Emit one diagnostic per function summarizing the contention risk.
        Severity sev = Severity::Critical;
        std::vector<std::string> escalations;

        if (writeCount >= 3) {
            escalations.push_back(
                "3+ atomic writes per invocation: high store buffer pressure, "
                "sustained RFO traffic");
        }

        if (hasLoopWrite) {
            escalations.push_back(
                "Atomic write inside loop: per-iteration cache line ownership "
                "transfer, store buffer saturation risk");
        }

        auto loc = FD->getLocation();

        Diagnostic diag;
        diag.ruleID    = "FL011";
        diag.title     = "Atomic Contention Hotspot";
        diag.severity  = sev;
        diag.confidence = hasLoopWrite ? 0.65 : 0.50;
        diag.evidenceTier = EvidenceTier::Likely;
        diag.functionName = FD->getQualifiedNameAsString();

        if (loc.isValid()) {
            diag.location.file   = SM.getFilename(SM.getSpellingLoc(loc)).str();
            diag.location.line   = SM.getSpellingLineNumber(loc);
            diag.location.column = SM.getSpellingColumnNumber(loc);
        }

        std::ostringstream hw;
        hw << "Hot function '" << FD->getQualifiedNameAsString()
           << "' contains " << writeCount << " atomic write(s). "
           << "Under multi-core contention, each write triggers RFO "
           << "cache line transfer. Multiple writes compound store buffer "
           << "drain latency and coherence traffic. "
           << "[Assumes: multiple cores concurrently execute this function]";
        diag.hardwareReasoning = hw.str();

        std::string opsStr;
        for (size_t i = 0; i < visitor.sites().size(); ++i) {
            opsStr += visitor.sites()[i].op + "(" + visitor.sites()[i].varName + ")";
            if (i + 1 < visitor.sites().size()) opsStr += ", ";
        }
        diag.structuralEvidence = {
            {"function", FD->getQualifiedNameAsString()},
            {"atomic_writes", std::to_string(writeCount)},
            {"loop_writes", hasLoopWrite ? "yes" : "no"},
            {"ops", opsStr},
        };

        diag.mitigation =
            "Shard atomic state per-core to eliminate cross-core RFO. "
            "Batch updates to reduce write frequency. "
            "Redesign ownership model to single-writer pattern. "
            "Consider thread-local accumulation with periodic merge.";

        diag.escalations = std::move(escalations);
        out.push_back(std::move(diag));
    }
};

LSHAZ_REGISTER_RULE(FL011_AtomicContention)

} // namespace lshaz
