// SPDX-License-Identifier: Apache-2.0
#include "lshaz/analysis/CallGraph.h"

#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/Decl.h>
#include <clang/AST/DeclCXX.h>
#include <clang/Basic/SourceManager.h>

#include <queue>

namespace lshaz {

const std::unordered_set<const clang::FunctionDecl *> CallGraph::empty_;

namespace {

// Resolve a thread-entry argument to the function it names, through
// parens, casts, and unary &.
const clang::FunctionDecl *entryArgToFunction(const clang::Expr *E) {
    if (!E) return nullptr;
    E = E->IgnoreParenImpCasts();
    if (const auto *UO = llvm::dyn_cast<clang::UnaryOperator>(E)) {
        if (UO->getOpcode() == clang::UO_AddrOf)
            E = UO->getSubExpr()->IgnoreParenImpCasts();
    }
    if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(E))
        return llvm::dyn_cast<clang::FunctionDecl>(DRE->getDecl());
    return nullptr;
}

class CallEdgeVisitor
    : public clang::RecursiveASTVisitor<CallEdgeVisitor> {
public:
    std::unordered_set<const clang::FunctionDecl *> callees;
    std::unordered_set<const clang::FunctionDecl *> threadEntries;
    // The fn-slot argument was a parameter of the enclosing function: the
    // enclosing function is a spawner wrapper (memcached's create_worker),
    // and function literals at that argument position of its call sites
    // are entries. Resolved TU-wide after all functions are processed.
    int spawnerParamIdx = -1;
    // (callee, argIdx, passed function) for every function-literal
    // argument observed, to resolve against detected spawners.
    std::vector<std::tuple<const clang::FunctionDecl *, unsigned,
                           const clang::FunctionDecl *>> literalFnArgs;

    bool VisitCallExpr(clang::CallExpr *CE) {
        const auto *Callee = CE->getDirectCallee();
        if (!Callee)
            return true;
        callees.insert(Callee->getCanonicalDecl());

        for (unsigned i = 0; i < CE->getNumArgs(); ++i)
            if (const auto *FD = entryArgToFunction(CE->getArg(i)))
                literalFnArgs.emplace_back(Callee->getCanonicalDecl(), i,
                                           FD->getCanonicalDecl());

        // pthread_create(&t, attr, fn, arg) / thrd_create(&t, fn, arg) /
        // std::async([policy,] fn, ...). Entry position varies per
        // primitive; std::async's optional launch policy is disambiguated
        // by which argument resolves to a function.
        llvm::StringRef name = Callee->getName();
        if (name == "pthread_create" && CE->getNumArgs() >= 3)
            addEntryOrSpawner(CE->getArg(2));
        else if (name == "thrd_create" && CE->getNumArgs() >= 2)
            addEntryOrSpawner(CE->getArg(1));
        else if (name == "async" && CE->getNumArgs() >= 1) {
            if (!addEntryOrSpawner(CE->getArg(0)) && CE->getNumArgs() >= 2)
                addEntryOrSpawner(CE->getArg(1));
        }
        return true;
    }

    bool VisitCXXConstructExpr(clang::CXXConstructExpr *CE) {
        const auto *CD = CE->getConstructor();
        if (!CD)
            return true;
        callees.insert(CD->getCanonicalDecl());

        // std::thread t(fn, args...) / std::jthread.
        const auto *RD = CD->getParent();
        if (RD && CE->getNumArgs() >= 1) {
            llvm::StringRef cls = RD->getName();
            if (cls == "thread" || cls == "jthread")
                addEntry(CE->getArg(0));
        }
        return true;
    }

private:
    bool addEntry(const clang::Expr *arg) {
        if (const auto *FD = entryArgToFunction(arg)) {
            threadEntries.insert(FD->getCanonicalDecl());
            return true;
        }
        return false;
    }

    bool addEntryOrSpawner(const clang::Expr *arg) {
        if (addEntry(arg))
            return true;
        if (!arg) return false;
        const auto *E = arg->IgnoreParenImpCasts();
        if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(E))
            if (const auto *PV =
                    llvm::dyn_cast<clang::ParmVarDecl>(DRE->getDecl()))
                spawnerParamIdx =
                    static_cast<int>(PV->getFunctionScopeIndex());
        return false;
    }
};

} // anonymous namespace

void CallGraph::buildFromTU(const clang::TranslationUnitDecl *TU) {
    if (!TU) return;

    const auto &SM = ctx_.getSourceManager();

    std::function<void(clang::DeclContext *)> visit =
        [&](clang::DeclContext *DC) {
            for (auto *D : DC->decls()) {
                if (auto *NS = llvm::dyn_cast<clang::NamespaceDecl>(D)) {
                    visit(NS);
                    continue;
                }
                if (auto *LS = llvm::dyn_cast<clang::LinkageSpecDecl>(D)) {
                    visit(LS);
                    continue;
                }
                if (auto *FD = llvm::dyn_cast<clang::FunctionDecl>(D)) {
                    if (FD->doesThisDeclarationHaveABody() &&
                        !FD->isDependentContext()) {
                        auto loc = FD->getLocation();
                        if (loc.isValid() &&
                            !SM.isInSystemHeader(SM.getSpellingLoc(loc)))
                            processFunction(FD);
                    }
                }
                if (auto *RD = llvm::dyn_cast<clang::CXXRecordDecl>(D)) {
                    if (RD->isCompleteDefinition() && !RD->isDependentType())
                        visit(RD);
                }
            }
        };

    visit(const_cast<clang::TranslationUnitDecl *>(TU));
    resolveSpawnerEntries();
}

void CallGraph::processFunction(const clang::FunctionDecl *FD) {
    const auto *canon = FD->getCanonicalDecl();
    if (calleeMap_.count(canon))
        return; // already processed

    CallEdgeVisitor visitor;
    visitor.TraverseStmt(const_cast<clang::Stmt *>(FD->getBody()));

    auto &targets = calleeMap_[canon];
    for (const auto *callee : visitor.callees) {
        targets.insert(callee);
        callerMap_[callee].insert(canon);
        ++edgeCount_;
    }
    for (const auto *entry : visitor.threadEntries)
        threadEntries_.insert(entry->getQualifiedNameAsString());
    if (visitor.spawnerParamIdx >= 0)
        spawnerParams_[canon] =
            static_cast<unsigned>(visitor.spawnerParamIdx);
    pendingLiteralFnArgs_.insert(pendingLiteralFnArgs_.end(),
                                 visitor.literalFnArgs.begin(),
                                 visitor.literalFnArgs.end());
}

void CallGraph::resolveSpawnerEntries() {
    // Spawner wrappers forward a parameter into a thread-create fn slot;
    // function literals at that argument position of their call sites are
    // entries.
    if (spawnerParams_.empty())
        return;
    for (const auto &[callee, argIdx, fn] : pendingLiteralFnArgs_) {
        auto it = spawnerParams_.find(callee);
        if (it != spawnerParams_.end() && it->second == argIdx)
            threadEntries_.insert(fn->getQualifiedNameAsString());
    }
}

void CallGraph::snapshotForThreadRoles(ThreadRoleSummary &out) const {
    out.threadEntries.insert(threadEntries_.begin(), threadEntries_.end());
    for (const auto &[caller, callees] : calleeMap_) {
        if (callees.empty())
            continue;
        auto &names = out.callEdges[caller->getQualifiedNameAsString()];
        for (const auto *callee : callees)
            names.insert(callee->getQualifiedNameAsString());
    }
}

const std::unordered_set<const clang::FunctionDecl *> &
CallGraph::callees(const clang::FunctionDecl *Caller) const {
    if (!Caller) return empty_;
    auto it = calleeMap_.find(Caller->getCanonicalDecl());
    return it != calleeMap_.end() ? it->second : empty_;
}

const std::unordered_set<const clang::FunctionDecl *> &
CallGraph::callers(const clang::FunctionDecl *Callee) const {
    if (!Callee) return empty_;
    auto it = callerMap_.find(Callee->getCanonicalDecl());
    return it != callerMap_.end() ? it->second : empty_;
}

std::unordered_set<const clang::FunctionDecl *>
CallGraph::transitiveCallees(
    const std::unordered_set<const clang::FunctionDecl *> &roots,
    unsigned maxDepth) const {

    std::unordered_set<const clang::FunctionDecl *> visited;
    std::queue<std::pair<const clang::FunctionDecl *, unsigned>> worklist;

    for (const auto *root : roots) {
        const auto *canon = root->getCanonicalDecl();
        if (visited.insert(canon).second)
            worklist.push({canon, 0});
    }

    while (!worklist.empty()) {
        auto [fn, depth] = worklist.front();
        worklist.pop();

        if (depth >= maxDepth)
            continue;

        for (const auto *callee : callees(fn)) {
            if (visited.insert(callee).second)
                worklist.push({callee, depth + 1});
        }
    }

    return visited;
}

} // namespace lshaz
