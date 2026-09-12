// SPDX-License-Identifier: Apache-2.0
#ifndef LSHAZ_ANALYSIS_LOOPSHAPE_H
#define LSHAZ_ANALYSIS_LOOPSHAPE_H

#include <clang/AST/ASTContext.h>
#include <clang/AST/Expr.h>
#include <clang/AST/Stmt.h>

#include <llvm/Support/Casting.h>

namespace lshaz {

// A loop whose controlling expression folds to zero does not repeat: the
// do/while(0) body runs exactly once, the while(0) body never.
inline const clang::Expr *loopCondition(const clang::Stmt *S) {
    if (const auto *D = llvm::dyn_cast_or_null<clang::DoStmt>(S))
        return D->getCond();
    if (const auto *W = llvm::dyn_cast_or_null<clang::WhileStmt>(S))
        return W->getCond();
    if (const auto *F = llvm::dyn_cast_or_null<clang::ForStmt>(S))
        return F->getCond();
    return nullptr;
}

inline bool conditionFoldsToZero(const clang::Expr *cond,
                                 const clang::ASTContext &Ctx) {
    if (!cond) return false;
    if (auto v = cond->getIntegerConstantExpr(Ctx))
        return v->isZero();
    return false;
}

// True when the statement is a loop in syntax only. Callers that count
// loop depth should not count these.
inline bool isDegenerateLoop(const clang::Stmt *S,
                             const clang::ASTContext &Ctx) {
    return conditionFoldsToZero(loopCondition(S), Ctx);
}

// Iterations attributed to a loop whose bound the source does not state.
//
// The Ball and Larus backedge heuristic puts a loop backedge at about 88%
// taken, which is roughly eight iterations; ten is the same order and
// rounder. Being wrong here scales a whole subtree by one factor, and every
// term the cost model consumes is a ratio, so a uniform error cancels.
constexpr uint64_t kDefaultTripCount = 10;

// How many times a loop body runs, when the source says so.
//
// Loop nesting depth is a four-value proxy for a quantity the source often
// states outright: `for (j = 0; j < 16; j++)` runs sixteen times and
// `for (i = 0; i < n; i++)` runs an unknown number. Treating both as one
// nesting level is why a cost model built on depth cannot rank.
//
// Returns 0 for "not derivable", which the caller replaces with its own
// default. Clang's constant evaluator folds the bound, so macros, enum
// constants, sizeof and constexpr all resolve.
inline uint64_t constantTripCount(const clang::Stmt *S,
                                  const clang::ASTContext &Ctx) {
    const auto *F = llvm::dyn_cast_or_null<clang::ForStmt>(S);
    if (!F || !F->getCond() || !F->getInc())
        return 0;

    // The induction variable and where it starts. Either a declaration in
    // the init clause or an assignment to an existing variable.
    const clang::VarDecl *iv = nullptr;
    llvm::APSInt start;
    if (const auto *DS = llvm::dyn_cast_or_null<clang::DeclStmt>(F->getInit())) {
        if (!DS->isSingleDecl())
            return 0;
        iv = llvm::dyn_cast<clang::VarDecl>(DS->getSingleDecl());
        if (!iv || !iv->getInit())
            return 0;
        auto v = iv->getInit()->getIntegerConstantExpr(Ctx);
        if (!v) return 0;
        start = *v;
    } else if (const auto *BO =
                   llvm::dyn_cast_or_null<clang::BinaryOperator>(F->getInit())) {
        if (BO->getOpcode() != clang::BO_Assign)
            return 0;
        const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(
            BO->getLHS()->IgnoreParenImpCasts());
        if (!DRE) return 0;
        iv = llvm::dyn_cast<clang::VarDecl>(DRE->getDecl());
        auto v = BO->getRHS()->getIntegerConstantExpr(Ctx);
        if (!iv || !v) return 0;
        start = *v;
    } else {
        return 0;
    }

    const auto refersToIV = [&](const clang::Expr *E) {
        const auto *DRE =
            llvm::dyn_cast_or_null<clang::DeclRefExpr>(E->IgnoreParenImpCasts());
        return DRE && DRE->getDecl() == iv;
    };

    const auto *cmp =
        llvm::dyn_cast<clang::BinaryOperator>(F->getCond()->IgnoreParenImpCasts());
    if (!cmp || !refersToIV(cmp->getLHS()))
        return 0;
    auto boundVal = cmp->getRHS()->getIntegerConstantExpr(Ctx);
    if (!boundVal)
        return 0;

    // The step, and whether the loop counts up or down.
    int64_t step = 0;
    if (const auto *UO = llvm::dyn_cast<clang::UnaryOperator>(F->getInc())) {
        if (!refersToIV(UO->getSubExpr())) return 0;
        if (UO->isIncrementOp()) step = 1;
        else if (UO->isDecrementOp()) step = -1;
        else return 0;
    } else if (const auto *CA = llvm::dyn_cast<clang::CompoundAssignOperator>(
                   F->getInc())) {
        if (!refersToIV(CA->getLHS())) return 0;
        auto s = CA->getRHS()->getIntegerConstantExpr(Ctx);
        if (!s) return 0;
        if (CA->getOpcode() == clang::BO_AddAssign) step = s->getExtValue();
        else if (CA->getOpcode() == clang::BO_SubAssign) step = -s->getExtValue();
        else return 0;
    } else {
        return 0;
    }
    if (step == 0)
        return 0;

    const int64_t from = start.getExtValue();
    const int64_t to = boundVal->getExtValue();
    int64_t span = 0;
    switch (cmp->getOpcode()) {
        case clang::BO_LT: span = to - from; break;
        case clang::BO_LE: span = to - from + 1; break;
        case clang::BO_GT: span = from - to; break;
        case clang::BO_GE: span = from - to + 1; break;
        case clang::BO_NE: span = step > 0 ? to - from : from - to; break;
        default: return 0;
    }
    // A loop counting away from its bound runs zero times, and the span
    // comes out non-positive when it does. Zero is "not derivable" to the
    // caller either way, which is the safe reading: a loop this analysis
    // cannot follow must not be priced as if it never runs.
    if (span <= 0)
        return 0;
    const int64_t stride = step > 0 ? step : -step;
    return static_cast<uint64_t>((span + stride - 1) / stride);
}

} // namespace lshaz

#endif // LSHAZ_ANALYSIS_LOOPSHAPE_H
