// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <clang/AST/ASTContext.h>
#include <clang/AST/DeclCXX.h>

#include "lshaz/analysis/thread_role.h"

#include <map>
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

    // Max loop nesting at any call site of Callee inside Caller. 0 means
    // every call site is straight-line: entered once per entry to Caller.
    unsigned callSiteLoopDepth(const clang::FunctionDecl *Caller,
                               const clang::FunctionDecl *Callee) const;

    // Deepest loop nesting inside this function's own body. A leaf that
    // sweeps an array repeats without calling anything.
    unsigned ownLoopDepth(const clang::FunctionDecl *FD) const;

    // True when this function runs on several threads simultaneously: it is
    // reachable from a thread entry spawned in a loop or from more than one
    // site. Contention needs two cores, not two functions.
    bool runsOnManyThreads(const clang::FunctionDecl *FD) const {
        return FD && poolReachable_.count(FD->getCanonicalDecl()) > 0;
    }

    // Every function with a body seen in this TU.
    std::vector<const clang::FunctionDecl *> functions() const;

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
    // (caller, callee) -> max loop depth over that pair's call sites.
    std::map<std::pair<const clang::FunctionDecl *,
                       const clang::FunctionDecl *>, unsigned> edgeLoopDepth_;
    // Same pairs, executions per entry to the caller in milli-units, using
    // the source's own trip counts where it states them.
    std::map<std::pair<const clang::FunctionDecl *,
                       const clang::FunctionDecl *>, Milli> edgeFrequency_;
    std::unordered_map<const clang::FunctionDecl *, unsigned> ownLoopDepth_;
    std::unordered_map<const clang::FunctionDecl *, Milli> ownFrequency_;
    std::unordered_set<const clang::FunctionDecl *> poolEntryDecls_;
    std::unordered_set<const clang::FunctionDecl *> poolReachable_;

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

    std::set<std::string> threadEntries_;

    // Spawner wrappers (function -> forwarded param index) and observed
    // function-literal arguments, resolved TU-wide after buildFromTU.
    std::unordered_map<const clang::FunctionDecl *, unsigned> spawnerParams_;
    std::vector<std::tuple<const clang::FunctionDecl *, unsigned,
                           const clang::FunctionDecl *>> pendingLiteralFnArgs_;

    static const std::unordered_set<const clang::FunctionDecl *> empty_;
};

} // namespace lshaz
