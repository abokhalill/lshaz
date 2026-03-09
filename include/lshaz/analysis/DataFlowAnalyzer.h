// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace lshaz {

// Lightweight intra-procedural data-flow facts for a single function.
// Tracks how values produced by key operations (allocations, atomic loads)
// flow through the function body.
struct DataFlowFacts {
    // Heap allocation sites whose result flows into a loop body.
    // Key: source line of the allocation. Value: loop nesting depth.
    std::unordered_map<unsigned, unsigned> allocFlowsToLoop;

    // Heap allocation sites whose result escapes the function
    // (stored to a field, passed to a callee, returned).
    std::unordered_set<unsigned> allocEscapes;

    // Atomic load sites whose result feeds a branch condition
    // (indicates CAS retry loop or spin-wait pattern).
    std::unordered_set<unsigned> atomicFeedsBranch;

    // Variables that hold heap-allocated pointers (by VarDecl name).
    std::unordered_set<std::string> heapVars;

    // Variables that hold atomic load results (by VarDecl name).
    std::unordered_set<std::string> atomicVars;

    bool empty() const {
        return allocFlowsToLoop.empty() && allocEscapes.empty() &&
               atomicFeedsBranch.empty();
    }
};

// Performs lightweight intra-procedural data-flow analysis on a
// single function body. Does not build a full SSA/def-use graph;
// instead uses a single-pass AST walk with symbolic tracking.
class DataFlowAnalyzer {
public:
    explicit DataFlowAnalyzer(clang::ASTContext &Ctx) : ctx_(Ctx) {}

    // Analyze a function body and produce data-flow facts.
    DataFlowFacts analyze(const clang::FunctionDecl *FD);

private:
    // Pass 1: identify heap-alloc and atomic-load variable bindings.
    void collectSources(const clang::Stmt *S, DataFlowFacts &facts);

    // Pass 2: track uses of tainted variables.
    void trackUses(const clang::Stmt *S, DataFlowFacts &facts,
                   unsigned loopDepth);

    // Check if an expression refers to a tainted variable.
    bool isHeapTainted(const clang::Expr *E, const DataFlowFacts &facts) const;
    bool isAtomicTainted(const clang::Expr *E, const DataFlowFacts &facts) const;

    // Extract variable name from a DeclRefExpr if present.
    std::string varName(const clang::Expr *E) const;

    clang::ASTContext &ctx_;
};

} // namespace lshaz
