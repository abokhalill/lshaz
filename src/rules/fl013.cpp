// SPDX-License-Identifier: Apache-2.0
#include "lshaz/core/rule.h"
#include "lshaz/analysis/atomics.h"
#include "lshaz/core/registry.h"
#include "lshaz/core/hot_path.h"
#include "lshaz/analysis/escape.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Stmt.h>
#include <clang/Basic/SourceManager.h>

#include <fnmatch.h>

#include <sstream>

namespace lshaz {

namespace {

// Does this expression read an atomic (std::atomic member call, C11
// _Atomic lvalue, __atomic_load builtin) or a volatile lvalue?
bool isAtomicObjType(clang::QualType QT,
                     const std::vector<std::string> &cfgAtomics) {
    // Before canonicalization: an opaque wrapper's spelling is all there is.
    // A kernel-style `while (atomic_read(&lock))` spin was invisible here
    // even with atomic_type_names set, because only CacheLineMap consumed it.
    if (isConfiguredAtomic(QT, cfgAtomics))
        return true;
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
    const std::vector<std::string> &cfgAtomics;
    explicit PollReadFinder(const std::vector<std::string> &a)
        : cfgAtomics(a) {}

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
        if (!obj || !isAtomicObjType(obj->getType(), cfgAtomics))
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

    // RMW-as-poll: `while (pending--)`, `while (!(seq += 0))`, atomic
    // operator overloads arrive as CXXOperatorCallExpr, a distinct node
    // class from both member calls above.
    bool VisitCXXOperatorCallExpr(clang::CXXOperatorCallExpr *E) {
        if (E->getNumArgs() < 1)
            return true;
        const auto *lhs = E->getArg(0);
        if (!isAtomicObjType(lhs->getType(), cfgAtomics))
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

    // AtomicExpr is not a CallExpr, so the arm above never sees a C11 or
    // GNU builtin. Matched on op spelling because the AO__ enumerators are
    // generated from Builtins.def and move between LLVM 16 and 18.
    bool VisitAtomicExpr(clang::AtomicExpr *E) {
        llvm::StringRef n = E->getOpAsString();
        if (E->isCmpXChg()) {
            casForm = true;
        } else if (n.ends_with("_test_and_set")) {
            tasForm = true;
        } else if (!n.ends_with("_load") && !n.ends_with("_load_n")) {
            return true;
        }
        found = true;
        noteVar(E->getPtr()->IgnoreParenImpCasts());
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
// opaque; cpu_relax() and hand-rolled pause both arrive as asm, the
// benefit of the doubt goes to the author).
class RelaxFinder : public clang::RecursiveASTVisitor<RelaxFinder> {
public:
    bool found = false;
    const std::vector<std::string> *extraPatterns = nullptr;

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
        // Bare-name wait/wait_for/wait_until on purpose: anything named wait
        // declares descheduling intent, and a custom one that bare-spins
        // gets flagged inside its body rather than at every call site.
        if (n == "_mm_pause" || n == "sched_yield" || n == "pthread_yield" ||
            n == "nanosleep" || n == "usleep" || n == "sleep" ||
            n == "cpu_relax" || n == "futex" || n == "syscall" ||
            n == "_umwait" || n == "_tpause" || n == "_umonitor" ||
            n == "_mm_monitor" || n == "_mm_mwait" ||
            n == "wait" || n == "wait_for" || n == "wait_until" ||
            n == "rte_pause" || n == "rte_delay_us" ||
            n == "rte_delay_us_block" ||
            n == "epoll_wait" || n == "epoll_pwait" || n == "ppoll" ||
            n == "poll" || n == "select" || n == "pselect" ||
            n.starts_with("__builtin_ia32_umwait") ||
            n.starts_with("__builtin_ia32_tpause") ||
            n.starts_with("__builtin_ia32_monitor") ||
            n.starts_with("__builtin_ia32_mwait") ||
            qn == "std::this_thread::yield" ||
            qn == "std::this_thread::sleep_for" ||
            qn == "std::this_thread::sleep_until") {
            found = true;
            return true;
        }
        // Bespoke backoff vocabularies (folly Sleeper, absl
        // SpinLockDelay, in-house Backoff::pause) are declared once in
        // config rather than chased by name here.
        if (extraPatterns)
            for (const auto &p : *extraPatterns)
                if (fnmatch(p.c_str(), n.str().c_str(), 0) == 0 ||
                    fnmatch(p.c_str(), qn.c_str(), 0) == 0) {
                    found = true;
                    return true;
                }
        return true;
    }

    bool VisitGCCAsmStmt(clang::GCCAsmStmt *) {
        found = true;
        return true;
    }
};

// break/return/goto that leaves THIS loop. Nested loops and switches own
// their own break, so their bodies are not searched.
class EarlyExitFinder : public clang::RecursiveASTVisitor<EarlyExitFinder> {
public:
    bool found = false;
    bool VisitBreakStmt(clang::BreakStmt *) { found = true; return true; }
    bool VisitReturnStmt(clang::ReturnStmt *) { found = true; return true; }
    bool VisitGotoStmt(clang::GotoStmt *) { found = true; return true; }
    bool TraverseForStmt(clang::ForStmt *) { return true; }
    bool TraverseWhileStmt(clang::WhileStmt *) { return true; }
    bool TraverseDoStmt(clang::DoStmt *) { return true; }
    bool TraverseCXXForRangeStmt(clang::CXXForRangeStmt *) { return true; }
    bool TraverseSwitchStmt(clang::SwitchStmt *) { return true; }
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
    const std::vector<std::string> *cfgAtomics = nullptr;
    const clang::ASTContext *ctx = nullptr;
    inline static const std::vector<std::string> kNoAtomics{};

    std::vector<SpinSite> sites;
    const std::vector<std::string> *relaxPatterns = nullptr;

    bool VisitWhileStmt(clang::WhileStmt *S) {
        inspect(S->getCond(), S->getBody(), S->getWhileLoc());
        return true;
    }
    bool VisitDoStmt(clang::DoStmt *S) {
        inspect(S->getCond(), S->getBody(), S->getDoLoc());
        return true;
    }
    bool VisitForStmt(clang::ForStmt *S) {
        // A counted loop exits on its induction variable whatever the poll
        // returns, so it is an aggregation sweep and not a wait. An early
        // exit puts termination back under the polled value: that is a
        // bounded retry and still spins. for(;;) has no increment and
        // reaches inspect() unchanged.
        if (S->getInc()) {
            EarlyExitFinder exit;
            if (S->getBody())
                exit.TraverseStmt(S->getBody());
            if (!exit.found)
                return true;
        }
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

        // A condition that folds to zero runs the body once. That is the
        // do/while(0) single-evaluation macro, and every atomicGet in a
        // C codebase is one.
        if (cond && ctx)
            if (auto v = cond->getIntegerConstantExpr(*ctx))
                if (v->isZero())
                    return;

        PollReadFinder poll(cfgAtomics ? *cfgAtomics : kNoAtomics);
        if (cond)
            poll.TraverseStmt(const_cast<clang::Expr *>(cond));
        // do { ... } while (!cas) keeps the poll in the condition; a
        // while(true) CAS retry keeps it in the body.
        if (!poll.found && body)
            poll.TraverseStmt(const_cast<clang::Stmt *>(body));
        if (!poll.found)
            return;

        RelaxFinder relax;
        relax.extraPatterns = relaxPatterns;
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

    bool requiresHotPath() const override { return true; }
    bool withdrawnWhenNotHot() const override { return true; }

    std::string_view getHardwareMechanism() const override {
        return "A tight poll loop without PAUSE speculates loads far ahead, "
               "and the other core's eventual write invalidates the line and "
               "costs the pipeline a memory-order machine clear, a full flush "
               "(machine_clears.memory_ordering). PAUSE de-speculates the "
               "loop. PAUSE is worth adding for the machine clear and not "
               "for sibling bandwidth: the spin slowing its SMT sibling is a "
               "separate claim, and this rule ships it unestablished.";
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

        SpinLoopVisitor visitor;
        visitor.relaxPatterns = &Cfg.relaxFunctionPatterns;
        visitor.cfgAtomics = &Cfg.atomicTypeNames;
        visitor.ctx = &Ctx;
        visitor.TraverseStmt(FD->getBody());
        if (visitor.sites.empty())
            return;

        // Deployment context only. The machine clear is the whole mechanism
        // and it does not care whether SMT is on; see the withdrawn
        // sibling-starvation claim below.
        bool smt = Cfg.smtEnabled;

        const auto &SM = Ctx.getSourceManager();
        for (const auto &s : visitor.sites) {
            std::string polled = joinVars(s.polledVars);
            Diagnostic diag;
            diag.ruleID = "FL013";
            diag.title = "Spin-Wait Without Pause";
            diag.severity = Severity::Medium;
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
                hw << "; each iteration is additionally an RFO write, "
                      "contenders trade the line in Modified state where "
                      "test-and-test-and-set would spin on a Shared copy";
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
                    : "PAUSE latency differs by roughly an order of "
                      "magnitude between vendors, so a fixed spin count does "
                      "not port. For sub-microsecond signaling prefer a "
                      "bounded bare spin then umwait/tpause where available, "
                      "or yield/futex for longer waits. If the bare spin is "
                      "the design, say so: // lshaz-suppress FL013.";

            diag.mechanismClaims = {
                {"memory-order machine clear when the peer's write lands",
                 "a tight poll loop with no pause or wait hint", true,
                 Severity::Medium},
                // Kept, unestablished, so the verdict names what was tested
                // and dropped rather than silently omitting it.
                {"sibling starvation: the spin holds issue slots the peer "
                 "needs to make the progress being waited on",
                 "a spinning sibling measurably slowing its peer, which did "
                 "not reproduce on either vendor measured", false,
                 Severity::High},
                {"RFO ping-pong with the line held Modified",
                 "the spin writes each iteration (TAS) rather than reading",
                 s.tasForm, Severity::High},
            };
            out.push_back(std::move(diag));
        }
    }
};

LSHAZ_REGISTER_RULE(FL013_SpinWaitNoPause)

} // namespace lshaz
