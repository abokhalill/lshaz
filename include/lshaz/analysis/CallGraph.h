// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <clang/AST/ASTContext.h>
#include <clang/AST/DeclCXX.h>

#include "lshaz/analysis/ThreadRoleSummary.h"

#include <set>
#include <string>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace lshaz {

// Lightweight per-TU call graph built from the Clang AST.
// Maps caller -> set of direct callees (resolved FunctionDecl pointers).
// Used for hot-path transitivity: if f() is hot and calls g(), g() is hot.
class CallGraph {
public:
    explicit CallGraph(clang::ASTContext &Ctx) : ctx_(Ctx) {}

    // Build the call graph from all function bodies in the TU.
    void buildFromTU(const clang::TranslationUnitDecl *TU);

    // Get direct callees of a function.
    const std::unordered_set<const clang::FunctionDecl *> &
    callees(const clang::FunctionDecl *Caller) const;

    // Get direct callers of a function.
    const std::unordered_set<const clang::FunctionDecl *> &
    callers(const clang::FunctionDecl *Callee) const;

    // Compute transitive callees from a set of root functions up to maxDepth.
    // Returns all functions reachable within maxDepth call edges.
    std::unordered_set<const clang::FunctionDecl *>
    transitiveCallees(
        const std::unordered_set<const clang::FunctionDecl *> &roots,
        unsigned maxDepth = 8) const;

    size_t numFunctions() const { return calleeMap_.size(); }
    size_t numEdges() const { return edgeCount_; }

    // Functions this TU passes to a thread-creation primitive. Collected
    // during the same CallExpr walk that builds the edges.
    const std::set<std::string> &threadEntryNames() const {
        return threadEntries_;
    }

    // Snapshot edges and entries as qualified names for cross-TU joining.
    // Name-keyed on purpose: C++ overload sets collapse to one node, which
    // can only widen a role mask, never fabricate disjointness.
    void snapshotForThreadRoles(ThreadRoleSummary &out) const;

private:
    void processFunction(const clang::FunctionDecl *FD);
    void resolveSpawnerEntries();

    clang::ASTContext &ctx_;

    // caller -> callees
    std::unordered_map<const clang::FunctionDecl *,
                       std::unordered_set<const clang::FunctionDecl *>>
        calleeMap_;

    // callee -> callers (reverse edges)
    std::unordered_map<const clang::FunctionDecl *,
                       std::unordered_set<const clang::FunctionDecl *>>
        callerMap_;

    size_t edgeCount_ = 0;

    std::set<std::string> threadEntries_;

    // Spawner wrappers (function -> forwarded param index) and observed
    // function-literal arguments, resolved TU-wide after buildFromTU.
    std::unordered_map<const clang::FunctionDecl *, unsigned> spawnerParams_;
    std::vector<std::tuple<const clang::FunctionDecl *, unsigned,
                           const clang::FunctionDecl *>> pendingLiteralFnArgs_;

    static const std::unordered_set<const clang::FunctionDecl *> empty_;
};

} // namespace lshaz
