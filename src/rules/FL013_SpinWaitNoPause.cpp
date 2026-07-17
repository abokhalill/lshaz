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
bool isAtomicObjType(clang::QualType QT) {
    QT = QT.getCanonicalType().getNonReferenceType();
    if (QT->isAtomicType())
        return true;
    if (const auto *RD = QT->getAsCXXRecordDecl()) {
        std::string qn = RD->getQualifiedNameAsString();
        return qn == "std::atomic" || qn == "std::atomic_ref" ||
               qn == "std::atomic_flag" ||
               qn.find("__atomic_base") != std::string::npos;
    }
    return false;
}

class PollReadFinder : public clang::RecursiveASTVisitor<PollReadFinder> {
public:
    bool found = false;
    bool casForm = false;
    // TAS spin (`while (lock.test_and_set())`) is doubly wrong: no
    // pause, and every iteration is an RFO write; contenders ping-pong
    // the line in Modified state where a test-and-test-and-set spins
    // read-only on a Shared copy.
    bool tasForm = false;
    std::vector<std::string> polledVars;

    bool VisitCXXMemberCallExpr(clang::CXXMemberCallExpr *E) {
        const auto *MD = E->getMethodDecl();
        if (!MD)
            return true;
        const auto *obj = E->getImplicitObjectArgument();
        if (!obj || !isAtomicObjType(obj->getType()))
            return true;

        // `while (flag)` desugars to a conversion-operator member call
        // (CXXConversionDecl, "operator bool"); the most common spin
        // form and invisible to name matching. atomic_flag's test /
        // test_and_set are the TAS spinlock idiom.
        std::string name = MD->getNameAsString();
        bool isRead = llvm::isa<clang::CXXConversionDecl>(MD) ||
                      name == "load" || name == "test";
        bool isCas = name == "compare_exchange_weak" ||
                     name == "compare_exchange_strong";
        bool isTas = name == "test_and_set";
        if (!isRead && !isCas && !isTas)
            return true;
        found = true;
        casForm |= isCas;
        tasForm |= isTas;
        noteVar(obj->IgnoreImplicit());
        return true;
    }

    // RMW-as-poll: `while (pending--)`, `while (!(seq += 0))` — atomic
    // operator overloads arrive as CXXOperatorCallExpr, a distinct node
    // class from both member calls above.
    bool VisitCXXOperatorCallExpr(clang::CXXOperatorCallExpr *E) {
        if (E->getNumArgs() < 1)
            return true;
        const auto *lhs = E->getArg(0);
        if (!isAtomicObjType(lhs->getType()))
            return true;
        found = true;
        noteVar(lhs->IgnoreImplicit());
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
        if (n.starts_with("atomic_flag_test_and_set") ||
            n.starts_with("__atomic_test_and_set")) {
            found = true;
            tasForm = true;
            if (E->getNumArgs() > 0)
                noteVar(E->getArg(0)->IgnoreParenImpCasts());
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
    // Every distinct polled variable, in source order; a compound
    // condition (`ready.load() && !abort.load()`) instruments both in
    // the experiment bundle, so the evidence must carry both.
    void noteVar(const clang::Expr *E) {
        std::string name;
        if (const auto *UO = llvm::dyn_cast<clang::UnaryOperator>(E))
            if (UO->getOpcode() == clang::UO_AddrOf)
                E = UO->getSubExpr()->IgnoreParenImpCasts();
        if (const auto *ME = llvm::dyn_cast<clang::MemberExpr>(E))
            name = ME->getMemberDecl()->getNameAsString();
        else if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(E))
            name = DRE->getDecl()->getNameAsString();
        if (name.empty())
            return;
        for (const auto &existing : polledVars)
            if (existing == name)
                return;
        polledVars.push_back(std::move(name));
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
        // umwait/tpause/monitor are the modern deliberate spin
        if (n == "_mm_pause" || n == "sched_yield" || n == "pthread_yield" ||
            n == "nanosleep" || n == "usleep" || n == "sleep" ||
            n == "cpu_relax" || n == "futex" || n == "syscall" ||
            n == "_umwait" || n == "_tpause" || n == "_umonitor" ||
            n == "_mm_monitor" || n == "_mm_mwait" ||
            n.starts_with("__builtin_ia32_umwait") ||
            n.starts_with("__builtin_ia32_tpause") ||
            n.starts_with("__builtin_ia32_monitor") ||
            n.starts_with("__builtin_ia32_mwait") ||
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
    std::vector<std::string> polledVars;
    bool casForm;
    bool tasForm;
    unsigned bodyStmts;
};

std::string joinVars(const std::vector<std::string> &vars) {
    if (vars.empty())
        return "<unknown>";
    std::string out;
    for (size_t i = 0; i < vars.size(); ++i) {
        if (i)
            out += ", ";
        out += vars[i];
    }
    return out;
}

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

        sites.push_back({loc, std::move(poll.polledVars), poll.casForm,
                         poll.tasForm, bodyStmts});
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
                 const Config &Cfg,
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

        // SMT off in BIOS voids the sibling-starvation half of the
        // mechanism; the machine clear survives. One mechanism, not
        // two = one severity notch, not silence.
        bool smt = Cfg.smtEnabled;

        const auto &SM = Ctx.getSourceManager();
        for (const auto &s : visitor.sites) {
            std::string polled = joinVars(s.polledVars);
            Diagnostic diag;
            diag.ruleID = "FL013";
            diag.title = "Spin-Wait Without Pause";
            diag.severity = smt ? Severity::High : Severity::Medium;
            // TAS spin outranks load spin: each iteration is an RFO
            // write, so contenders ping-pong the line in Modified state
            // where a TTAS spins read-only on a Shared copy.
            diag.confidence = s.tasForm ? 0.78 : s.casForm ? 0.62 : 0.75;
            diag.evidenceTier = EvidenceTier::Likely;
            diag.location = resolveSourceLocation(s.loc, SM);
            diag.functionName = FD->getQualifiedNameAsString();

            const char *form = s.tasForm ? "TAS spin"
                               : s.casForm ? "CAS retry"
                                           : "load spin";
            std::ostringstream hw;
            hw << "Tight loop polls '" << polled << "' (" << form << ", "
               << s.bodyStmts
               << " body stmt(s)) with no pause/yield/backoff. Every "
                  "cross-core invalidation of the polled line costs a "
                  "memory-order machine clear";
            if (s.tasForm)
                hw << "; each iteration is additionally an RFO write — "
                      "contenders trade the line in Modified state where "
                      "test-and-test-and-set would spin on a Shared copy";
            if (smt)
                hw << "; the spin also starves the SMT sibling's issue "
                      "ports";
            else
                hw << " (smt_enabled: false — sibling-starvation cost "
                      "excluded from this verdict)";
            hw << ".";
            diag.hardwareReasoning = hw.str();

            diag.structuralEvidence = {
                {"polled", polled},
                {"form", s.tasForm ? "tas-spin"
                         : s.casForm ? "cas-retry"
                                     : "load-spin"},
                {"body_stmts", std::to_string(s.bodyStmts)},
                {"smt_model", smt ? "on" : "off"},
            };

            diag.mitigation =
                s.tasForm
                    ? "Spin read-only on test() until clear, then "
                      "test_and_set (TTAS), with pause/umwait in the "
                      "read loop. If the bare TAS is the design: "
                      "// lshaz-suppress FL013."
                    : "_mm_pause() costs ~140 cycles of wake-up latency "
                      "on Skylake+-derived cores — for sub-microsecond "
                      "signaling prefer a bounded bare spin then "
                      "umwait/tpause where available, or yield/futex for "
                      "longer waits. If the bare spin is the design, say "
                      "so: // lshaz-suppress FL013.";

            out.push_back(std::move(diag));
        }
    }
};

LSHAZ_REGISTER_RULE(FL013_SpinWaitNoPause)

} // namespace lshaz
