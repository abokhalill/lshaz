// SPDX-License-Identifier: Apache-2.0
#include "lshaz/analysis/DataFlowAnalyzer.h"

#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/DeclCXX.h>
#include <clang/AST/Stmt.h>
#include <clang/AST/StmtCXX.h>
#include <clang/Basic/SourceManager.h>

namespace lshaz {

namespace {

// Check if a call expression is a heap allocation.
bool isHeapAllocCall(const clang::CallExpr *CE) {
    const auto *callee = CE->getDirectCallee();
    if (!callee) return false;
    std::string name = callee->getQualifiedNameAsString();
    return name == "malloc" || name == "calloc" || name == "realloc" ||
           name == "aligned_alloc" || name == "posix_memalign" ||
           name == "std::make_shared" || name == "std::make_unique" ||
           name == "std::make_shared_for_overwrite" ||
           name == "std::make_unique_for_overwrite";
}

// Check if a call expression is an atomic load (member call).
bool isAtomicLoadCall(const clang::CXXMemberCallExpr *CE) {
    const auto *MD = CE->getMethodDecl();
    if (!MD) return false;
    std::string name = MD->getNameAsString();
    return name == "load" || name == "exchange" ||
           name == "compare_exchange_weak" ||
           name == "compare_exchange_strong" ||
           name == "fetch_add" || name == "fetch_sub" ||
           name == "fetch_and" || name == "fetch_or" ||
           name == "fetch_xor";
}

// Strip implicit casts and parens to get the underlying expression.
const clang::Expr *stripCasts(const clang::Expr *E) {
    while (E) {
        if (const auto *ICE = llvm::dyn_cast<clang::ImplicitCastExpr>(E))
            E = ICE->getSubExpr();
        else if (const auto *PE = llvm::dyn_cast<clang::ParenExpr>(E))
            E = PE->getSubExpr();
        else if (const auto *CE = llvm::dyn_cast<clang::CStyleCastExpr>(E))
            E = CE->getSubExpr();
        else
            break;
    }
    return E;
}

} // anonymous namespace

std::string DataFlowAnalyzer::varName(const clang::Expr *E) const {
    E = stripCasts(E);
    if (const auto *DRE = llvm::dyn_cast_or_null<clang::DeclRefExpr>(E)) {
        if (const auto *VD = llvm::dyn_cast<clang::VarDecl>(DRE->getDecl()))
            return VD->getNameAsString();
    }
    return {};
}

bool DataFlowAnalyzer::isHeapTainted(const clang::Expr *E,
                                      const DataFlowFacts &facts) const {
    std::string name = varName(E);
    return !name.empty() && facts.heapVars.count(name);
}

bool DataFlowAnalyzer::isAtomicTainted(const clang::Expr *E,
                                        const DataFlowFacts &facts) const {
    std::string name = varName(E);
    return !name.empty() && facts.atomicVars.count(name);
}

DataFlowFacts DataFlowAnalyzer::analyze(const clang::FunctionDecl *FD) {
    DataFlowFacts facts;
    if (!FD || !FD->doesThisDeclarationHaveABody())
        return facts;

    const clang::Stmt *body = FD->getBody();
    if (!body)
        return facts;

    // Pass 1: identify source bindings (alloc results, atomic loads).
    collectSources(body, facts);

    // Pass 2: track how tainted variables are used.
    trackUses(body, facts, 0);

    return facts;
}

void DataFlowAnalyzer::collectSources(const clang::Stmt *S,
                                       DataFlowFacts &facts) {
    if (!S) return;

    // VarDecl init with heap alloc or atomic load.
    if (const auto *DS = llvm::dyn_cast<clang::DeclStmt>(S)) {
        for (const auto *D : DS->decls()) {
            const auto *VD = llvm::dyn_cast<clang::VarDecl>(D);
            if (!VD || !VD->hasInit()) continue;

            const clang::Expr *init = stripCasts(VD->getInit());
            std::string name = VD->getNameAsString();

            // Check for new-expression.
            if (llvm::isa<clang::CXXNewExpr>(init)) {
                facts.heapVars.insert(name);
                continue;
            }

            // Check for heap alloc call (malloc, make_shared, etc.).
            if (const auto *CE = llvm::dyn_cast<clang::CallExpr>(init)) {
                if (isHeapAllocCall(CE)) {
                    facts.heapVars.insert(name);
                    continue;
                }
            }

            // Check for atomic load member call.
            if (const auto *MCE = llvm::dyn_cast<clang::CXXMemberCallExpr>(init)) {
                if (isAtomicLoadCall(MCE)) {
                    facts.atomicVars.insert(name);
                    continue;
                }
            }
        }
    }

    // Assignment: var = new/malloc/atomic.load()
    if (const auto *BO = llvm::dyn_cast<clang::BinaryOperator>(S)) {
        if (BO->getOpcode() == clang::BO_Assign) {
            std::string lhs = varName(BO->getLHS());
            if (!lhs.empty()) {
                const clang::Expr *rhs = stripCasts(BO->getRHS());
                if (llvm::isa<clang::CXXNewExpr>(rhs)) {
                    facts.heapVars.insert(lhs);
                } else if (const auto *CE = llvm::dyn_cast<clang::CallExpr>(rhs)) {
                    if (isHeapAllocCall(CE))
                        facts.heapVars.insert(lhs);
                } else if (const auto *MCE = llvm::dyn_cast<clang::CXXMemberCallExpr>(rhs)) {
                    if (isAtomicLoadCall(MCE))
                        facts.atomicVars.insert(lhs);
                }
            }
        }
    }

    for (auto it = S->child_begin(); it != S->child_end(); ++it) {
        if (*it) collectSources(*it, facts);
    }
}

void DataFlowAnalyzer::trackUses(const clang::Stmt *S, DataFlowFacts &facts,
                                   unsigned loopDepth) {
    if (!S) return;

    const auto &SM = ctx_.getSourceManager();

    // Track loop nesting.
    bool isLoop = llvm::isa<clang::ForStmt>(S) ||
                  llvm::isa<clang::WhileStmt>(S) ||
                  llvm::isa<clang::DoStmt>(S) ||
                  llvm::isa<clang::CXXForRangeStmt>(S);

    unsigned depth = isLoop ? loopDepth + 1 : loopDepth;

    // Check for heap-tainted variables used inside loops.
    if (depth > 0) {
        if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(S)) {
            if (isHeapTainted(DRE, facts)) {
                auto loc = DRE->getBeginLoc();
                if (loc.isValid()) {
                    unsigned line = SM.getSpellingLineNumber(loc);
                    auto it = facts.allocFlowsToLoop.find(line);
                    if (it == facts.allocFlowsToLoop.end() ||
                        it->second < depth)
                        facts.allocFlowsToLoop[line] = depth;
                }
            }
        }
    }

    // Check for atomic-tainted variables in branch conditions.
    if (const auto *If = llvm::dyn_cast<clang::IfStmt>(S)) {
        if (If->getCond() && isAtomicTainted(If->getCond(), facts)) {
            auto loc = If->getCond()->getBeginLoc();
            if (loc.isValid())
                facts.atomicFeedsBranch.insert(
                    SM.getSpellingLineNumber(loc));
        }
    }
    if (const auto *While = llvm::dyn_cast<clang::WhileStmt>(S)) {
        if (While->getCond() && isAtomicTainted(While->getCond(), facts)) {
            auto loc = While->getCond()->getBeginLoc();
            if (loc.isValid())
                facts.atomicFeedsBranch.insert(
                    SM.getSpellingLineNumber(loc));
        }
    }

    // Check for heap-tainted variables that escape:
    // 1. Passed as argument to a function call.
    if (const auto *CE = llvm::dyn_cast<clang::CallExpr>(S)) {
        for (unsigned i = 0; i < CE->getNumArgs(); ++i) {
            if (isHeapTainted(CE->getArg(i), facts)) {
                auto loc = CE->getArg(i)->getBeginLoc();
                if (loc.isValid())
                    facts.allocEscapes.insert(
                        SM.getSpellingLineNumber(loc));
            }
        }
    }

    // 2. Stored to a member (this->field = heapVar).
    if (const auto *BO = llvm::dyn_cast<clang::BinaryOperator>(S)) {
        if (BO->getOpcode() == clang::BO_Assign) {
            const clang::Expr *lhs = stripCasts(BO->getLHS());
            if (llvm::isa<clang::MemberExpr>(lhs) &&
                isHeapTainted(BO->getRHS(), facts)) {
                auto loc = BO->getBeginLoc();
                if (loc.isValid())
                    facts.allocEscapes.insert(
                        SM.getSpellingLineNumber(loc));
            }
        }
    }

    // 3. Returned from the function.
    if (const auto *RS = llvm::dyn_cast<clang::ReturnStmt>(S)) {
        if (RS->getRetValue() &&
            isHeapTainted(RS->getRetValue(), facts)) {
            auto loc = RS->getBeginLoc();
            if (loc.isValid())
                facts.allocEscapes.insert(
                    SM.getSpellingLineNumber(loc));
        }
    }

    for (auto it = S->child_begin(); it != S->child_end(); ++it) {
        if (*it) trackUses(*it, facts, depth);
    }
}

} // namespace lshaz
