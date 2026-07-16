// SPDX-License-Identifier: Apache-2.0
#include "lshaz/analysis/CallGraph.h"
#include "lshaz/analysis/SymbolNames.h"

#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/Decl.h>
#include <clang/AST/DeclCXX.h>
#include <clang/Basic/SourceManager.h>
#include <llvm/ADT/SmallPtrSet.h>

#include <queue>

namespace lshaz {

const std::unordered_set<const clang::FunctionDecl *> CallGraph::empty_;

namespace {

// Resolve a thread-entry argument to the function it names, through
// parens, casts, and unary &. Member-function pointers resolve here too:
// &Engine::run is AddrOf over a DeclRefExpr to a CXXMethodDecl.
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

// Unwrap the temporary/copy scaffolding std::thread's by-value functor
// argument arrives in. Over-unwrapping a non-functor construct is
// harmless: the result simply matches neither lambda nor bind.
const clang::Expr *stripFunctorWrapping(const clang::Expr *E) {
    while (E) {
        E = E->IgnoreParenImpCasts();
        if (const auto *M =
                llvm::dyn_cast<clang::MaterializeTemporaryExpr>(E)) {
            E = M->getSubExpr();
            continue;
        }
        if (const auto *B = llvm::dyn_cast<clang::CXXBindTemporaryExpr>(E)) {
            E = B->getSubExpr();
            continue;
        }
        if (const auto *C = llvm::dyn_cast<clang::CXXConstructExpr>(E)) {
            if (C->getNumArgs() >= 1) {
                E = C->getArg(0);
                continue;
            }
        }
        break;
    }
    return E;
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
    // Lambdas become their own graph nodes; their bodies are deliberately
    // NOT traversed in the enclosing context, or every call and write in
    // a worker lambda would attribute to the spawner.
    struct LambdaRec {
        const clang::CXXMethodDecl *op;
        bool isThreadEntry;
    };
    std::vector<LambdaRec> lambdas;
    llvm::SmallPtrSet<const clang::LambdaExpr *, 4> entryLambdas;

    bool TraverseLambdaExpr(clang::LambdaExpr *LE) {
        // Capture initializers evaluate in the enclosing frame.
        for (auto *init : LE->capture_inits())
            if (init)
                TraverseStmt(init);
        if (const auto *Op = LE->getCallOperator())
            lambdas.push_back(LambdaRec{Op, entryLambdas.count(LE) > 0});
        return true;
    }

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
            if (!addEntryAnyOrSpawner(CE->getArg(0)) && CE->getNumArgs() >= 2)
                addEntryAnyOrSpawner(CE->getArg(1));
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
                addEntryAny(CE->getArg(0));
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

    // Function/member pointer, lambda, or std::bind(&C::f, ...).
    bool addEntryAny(const clang::Expr *arg) {
        if (addEntry(arg))
            return true;
        const auto *S = stripFunctorWrapping(arg);
        if (const auto *LE = llvm::dyn_cast_or_null<clang::LambdaExpr>(S)) {
            entryLambdas.insert(LE);
            return true;
        }
        if (const auto *BC = llvm::dyn_cast_or_null<clang::CallExpr>(S))
            if (const auto *BF = BC->getDirectCallee())
                if (BF->getName() == "bind" && BC->getNumArgs() >= 1)
                    return addEntry(BC->getArg(0));
        return false;
    }

    bool addEntryAnyOrSpawner(const clang::Expr *arg) {
        return addEntryAny(arg) || addEntryOrSpawner(arg);
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
        threadEntries_.insert(threadRoleNodeName(entry, ctx_));
    if (visitor.spawnerParamIdx >= 0)
        spawnerParams_[canon] =
            static_cast<unsigned>(visitor.spawnerParamIdx);
    pendingLiteralFnArgs_.insert(pendingLiteralFnArgs_.end(),
                                 visitor.literalFnArgs.begin(),
                                 visitor.literalFnArgs.end());

    // Lambda nodes. Entry lambdas get no creation edge; a spawner's role
    // must not leak into its worker. Non-entry lambdas keep one so hotness
    // still reaches their bodies. Edges before recursion: processFunction
    // mutates calleeMap_ and would invalidate `targets`.
    for (const auto &L : visitor.lambdas) {
        const auto *opCanon =
            llvm::cast<clang::CXXMethodDecl>(L.op->getCanonicalDecl());
        if (L.isThreadEntry) {
            threadEntries_.insert(threadRoleNodeName(L.op, ctx_));
        } else {
            calleeMap_[canon].insert(opCanon);
            callerMap_[opCanon].insert(canon);
            ++edgeCount_;
        }
    }
    for (const auto &L : visitor.lambdas)
        if (L.op->doesThisDeclarationHaveABody())
            processFunction(L.op);
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
            threadEntries_.insert(threadRoleNodeName(fn, ctx_));
    }
}

void CallGraph::snapshotForThreadRoles(ThreadRoleSummary &out) const {
    out.threadEntries.insert(threadEntries_.begin(), threadEntries_.end());
    for (const auto &[caller, callees] : calleeMap_) {
        if (callees.empty())
            continue;
        auto &names = out.callEdges[threadRoleNodeName(caller, ctx_)];
        for (const auto *callee : callees)
            names.insert(threadRoleNodeName(callee, ctx_));
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
