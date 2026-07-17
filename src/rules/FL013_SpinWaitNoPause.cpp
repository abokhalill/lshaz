// SPDX-License-Identifier: Apache-2.0
#include "lshaz/core/Rule.h"
#include "lshaz/core/RuleRegistry.h"
#include "lshaz/core/HotPathOracle.h"
#include "lshaz/analysis/EscapeAnalysis.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Stmt.h>
#include <clang/Basic/SourceManager.h>

#include <sstream>

namespace lshaz {

namespace {

// Does this expression read an atomic (std::atomic member call, C11
// _Atomic lvalue, __atomic_load builtin) or a volatile lvalue?
class PollReadFinder : public clang::RecursiveASTVisitor<PollReadFinder> {
public:
    bool found = false;
    bool casForm = false;
    std::string varName;

    bool VisitCXXMemberCallExpr(clang::CXXMemberCallExpr *E) {
        const auto *MD = E->getMethodDecl();
        if (!MD)
            return true;
        std::string name = MD->getNameAsString();
        bool isRead = name == "load";
        bool isCas = name == "compare_exchange_weak" ||
                     name == "compare_exchange_strong";
        if (!isRead && !isCas)
            return true;
        const auto *obj = E->getImplicitObjectArgument();
        if (!obj)
            return true;
        clang::QualType QT =
            obj->getType().getCanonicalType().getNonReferenceType();
        bool atomicObj = QT->isAtomicType();
        if (!atomicObj) {
            if (const auto *RD = QT->getAsCXXRecordDecl()) {
                std::string qn = RD->getQualifiedNameAsString();
                atomicObj = qn == "std::atomic" || qn == "std::atomic_ref" ||
                            qn.find("__atomic_base") != std::string::npos;
            }
        }
        if (!atomicObj)
            return true;
        found = true;
        casForm |= isCas;
        noteVar(obj->IgnoreImplicit());
        return true;
    }

    bool VisitCallExpr(clang::CallExpr *E) {
        const auto *FD = E->getDirectCallee();
        if (!FD || !FD->getIdentifier())
            return true;
        llvm::StringRef n = FD->getName();
        if (n.starts_with("__atomic_load") ||
            n.starts_with("__c11_atomic_load") || n == "atomic_load" ||
            n == "atomic_load_explicit") {
            found = true;
            if (E->getNumArgs() > 0)
                noteVar(E->getArg(0)->IgnoreParenImpCasts());
        }
        if (n.starts_with("__atomic_compare_exchange") ||
            n.starts_with("__c11_atomic_compare_exchange") ||
            n.starts_with("atomic_compare_exchange")) {
            found = true;
            casForm = true;
        }
        return true;
    }

    bool VisitImplicitCastExpr(clang::ImplicitCastExpr *E) {
        if (E->getCastKind() != clang::CK_LValueToRValue &&
            E->getCastKind() != clang::CK_AtomicToNonAtomic)
            return true;
        clang::QualType QT = E->getSubExpr()->getType();
        if (QT.getCanonicalType()->isAtomicType() ||
            QT.isVolatileQualified()) {
            found = true;
            noteVar(E->getSubExpr()->IgnoreParenImpCasts());
        }
        return true;
    }

private:
    void noteVar(const clang::Expr *E) {
        if (!varName.empty())
            return;
        if (const auto *UO = llvm::dyn_cast<clang::UnaryOperator>(E))
            if (UO->getOpcode() == clang::UO_AddrOf)
                E = UO->getSubExpr()->IgnoreParenImpCasts();
        if (const auto *ME = llvm::dyn_cast<clang::MemberExpr>(E))
            varName = ME->getMemberDecl()->getNameAsString();
        else if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(E))
            varName = DRE->getDecl()->getNameAsString();
    }
};

// Anything in the loop that de-speculates or deschedules: pause/yield
// family by name or builtin, or any inline asm (its semantics are
// opaque; cpu_relax() and hand-rolled pause both arrive as asm — the
// benefit of the doubt goes to the author).
class RelaxFinder : public clang::RecursiveASTVisitor<RelaxFinder> {
public:
    bool found = false;

    bool VisitCallExpr(clang::CallExpr *E) {
        const auto *FD = E->getDirectCallee();
        if (!FD)
            return true;
        if (FD->getBuiltinID() != 0) {
            if (const auto *II = FD->getIdentifier())
                if (II->getName() == "__builtin_ia32_pause") {
                    found = true;
                    return true;
                }
        }
        if (!FD->getIdentifier())
            return true;
        std::string qn = FD->getQualifiedNameAsString();
        llvm::StringRef n = FD->getName();
        if (n == "_mm_pause" || n == "sched_yield" || n == "pthread_yield" ||
            n == "nanosleep" || n == "usleep" || n == "sleep" ||
            n == "cpu_relax" || n == "futex" || n == "syscall" ||
            qn == "std::this_thread::yield" ||
            qn == "std::this_thread::sleep_for" ||
            qn == "std::this_thread::sleep_until")
            found = true;
        return true;
    }

    bool VisitGCCAsmStmt(clang::GCCAsmStmt *) {
        found = true;
        return true;
    }
};

struct SpinSite {
    clang::SourceLocation loc;
    std::string varName;
    bool casForm;
    unsigned bodyStmts;
};

unsigned countStmts(const clang::Stmt *S) {
    if (!S)
        return 0;
    if (const auto *CS = llvm::dyn_cast<clang::CompoundStmt>(S))
        return CS->size();
    return 1;
}

class SpinLoopVisitor : public clang::RecursiveASTVisitor<SpinLoopVisitor> {
public:
    std::vector<SpinSite> sites;

    bool VisitWhileStmt(clang::WhileStmt *S) {
        inspect(S->getCond(), S->getBody(), S->getWhileLoc());
        return true;
    }
    bool VisitDoStmt(clang::DoStmt *S) {
        inspect(S->getCond(), S->getBody(), S->getDoLoc());
        return true;
    }
    bool VisitForStmt(clang::ForStmt *S) {
        inspect(S->getCond(), S->getBody(), S->getForLoc());
        return true;
    }

private:
    void inspect(const clang::Expr *cond, const clang::Stmt *body,
                 clang::SourceLocation loc) {
        // Tight loops only: a large body is a work loop, not a spin;
        // flagging those is how a rule earns a mute.
        constexpr unsigned kMaxSpinBodyStmts = 4;
        unsigned bodyStmts = countStmts(body);
        if (bodyStmts > kMaxSpinBodyStmts)
            return;

        PollReadFinder poll;
        if (cond)
            poll.TraverseStmt(const_cast<clang::Expr *>(cond));
        // do { ... } while (!cas) keeps the poll in the condition; a
        // while(true) CAS retry keeps it in the body.
        if (!poll.found && body)
            poll.TraverseStmt(const_cast<clang::Stmt *>(body));
        if (!poll.found)
            return;

        RelaxFinder relax;
        if (cond)
            relax.TraverseStmt(const_cast<clang::Expr *>(cond));
        if (body && !relax.found)
            relax.TraverseStmt(const_cast<clang::Stmt *>(body));
        if (relax.found)
            return;

        sites.push_back({loc, poll.varName.empty() ? "<unknown>"
                                                   : poll.varName,
                         poll.casForm, bodyStmts});
    }
};

} // anonymous namespace

class FL013_SpinWaitNoPause : public Rule {
public:
    std::string_view getID() const override { return "FL013"; }
    std::string_view getTitle() const override {
        return "Spin-Wait Without Pause";
    }
    Severity getBaseSeverity() const override { return Severity::High; }

    std::string_view getHardwareMechanism() const override {
        return "A tight poll loop without PAUSE speculates loads far ahead; "
               "the other core's eventual write invalidates the line and the "
               "pipeline takes a memory-order machine clear (full flush, "
               "machine_clears.memory_ordering). The spinning logical core "
               "also monopolizes issue ports its SMT sibling needs. PAUSE "
               "de-speculates the loop and yields sibling bandwidth.";
    }

    void analyze(const clang::Decl *D,
                 clang::ASTContext &Ctx,
                 const HotPathOracle &Oracle,
                 const Config & /*Cfg*/,
                 EscapeAnalysis & /*Escape*/,
                 std::vector<Diagnostic> &out) override {

        const auto *FD = llvm::dyn_cast_or_null<clang::FunctionDecl>(D);
        if (!FD || !FD->doesThisDeclarationHaveABody())
            return;
        if (!Oracle.isFunctionHot(FD))
            return;

        SpinLoopVisitor visitor;
        visitor.TraverseStmt(FD->getBody());
        if (visitor.sites.empty())
            return;

        const auto &SM = Ctx.getSourceManager();
        for (const auto &s : visitor.sites) {
            Diagnostic diag;
            diag.ruleID = "FL013";
            diag.title = "Spin-Wait Without Pause";
            diag.severity = Severity::High;
            diag.confidence = s.casForm ? 0.62 : 0.75;
            diag.evidenceTier = EvidenceTier::Likely;
            diag.location = resolveSourceLocation(s.loc, SM);
            diag.functionName = FD->getQualifiedNameAsString();

            std::ostringstream hw;
            hw << "Tight loop polls '" << s.varName << "' ("
               << (s.casForm ? "CAS retry" : "load spin") << ", "
               << s.bodyStmts
               << " body stmt(s)) with no pause/yield/backoff. Every "
                  "cross-core invalidation of the polled line costs a "
                  "memory-order machine clear; the spin also starves the "
                  "SMT sibling's issue ports.";
            diag.hardwareReasoning = hw.str();

            diag.structuralEvidence = {
                {"polled", s.varName},
                {"form", s.casForm ? "cas-retry" : "load-spin"},
                {"body_stmts", std::to_string(s.bodyStmts)},
            };

            diag.mitigation =
                "Insert _mm_pause() (or std::this_thread::yield after a "
                "bounded spin count) in the loop; for long waits, park on "
                "a futex/condition variable instead of spinning.";

            out.push_back(std::move(diag));
        }
    }
};

LSHAZ_REGISTER_RULE(FL013_SpinWaitNoPause)

} // namespace lshaz
