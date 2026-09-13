// SPDX-License-Identifier: Apache-2.0
#include "lshaz/analysis/call_graph.h"
#include "lshaz/analysis/loop_shape.h"
#include "lshaz/analysis/symbols.h"
#include "lshaz/core/cost.h"

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
// harmless: the result matches neither lambda nor bind.
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
    // Entries whose role runs on more than one thread at once.
    std::unordered_set<const clang::FunctionDecl *> poolEntries;
    std::unordered_set<const clang::FunctionDecl *> spawnSites;
    const clang::ASTContext *ctx = nullptr;
    // The fn-slot argument was a parameter of the enclosing function, so that
    // function is a spawner wrapper and function literals at the same argument
    // position of its call sites are entries. Resolved TU-wide once all
    // functions are processed.
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

    // Max loop nesting at any call site of each callee within this caller.
    // Repetition is what makes a miss steady-state rather than one-off, so
    // this is the structural signal hotness is derived from.
    std::unordered_map<const clang::FunctionDecl *, unsigned> calleeLoopDepth;
    unsigned loopDepth = 0;

    // How many times a call site runs per entry to this function, in milli.
    // Carrying the source's own trip counts is what lets a cost model rank
    // two findings that both sit one loop deep, where nesting depth calls
    // them equal. Saturating: an all-constant nest otherwise reaches numbers
    // the normaliser crushes everything else to zero against.
    static constexpr Milli kFreqCeiling = toMilli(1000000);
    std::unordered_map<const clang::FunctionDecl *, Milli> calleeFrequency;
    Milli frequency = kMilli;
    // Busiest point and deepest nesting anywhere in this body, call site or
    // not. A leaf that sweeps an array repeats on its own, and crediting only
    // call sites rates it as though it ran once.
    Milli ownFrequency = kMilli;
    unsigned ownLoopDepth = 0;

    // Statement counter for the phase partition. All call sites in one
    // full-expression share an index, which makes nested and sibling calls
    // mutually reaching: their evaluation order is unspecified anyway, and
    // an index that claimed otherwise would be the unsound direction.
    unsigned stmtIndex = 0;
    std::vector<unsigned> loopHeads;
    std::unordered_map<const clang::FunctionDecl *, CallPosition> calleePos;
    std::map<std::string, CallPosition> indirectPos;
    CallPosition spawnPos;
    bool anySpawn = false;
    bool orderUnknown = false;
    // signature -> functions whose address is taken under it. A function
    // cast to another type at the point its address is taken is recorded
    // under both, since that cast is how a thread entry usually reaches
    // pthread_create in C.
    std::map<std::string, std::set<const clang::FunctionDecl *>> addressTaken;
    llvm::SmallPtrSet<const clang::Stmt *, 16> calleeExprs;

    // Enclosing function, needed to name a forwarded parameter slot.
    const clang::FunctionDecl *self = nullptr;
    std::map<std::string, std::set<std::string>> fnSlotTargets;
    std::map<std::string, std::set<std::string>> fnSlotForwards;
    std::set<std::string> fnSlotOpaque;
    std::map<std::string, CallPosition> indirectSlotPos;
    std::set<const clang::FunctionDecl *> noReturn;
    bool hasReturn = false;
    std::map<const clang::FunctionDecl *, unsigned> callSites;
    std::map<const clang::FunctionDecl *, unsigned> unreachableAfter;

    bool VisitReturnStmt(clang::ReturnStmt *) {
        hasReturn = true;
        return true;
    }

    // Something after which the program does not reach the next statement:
    // __builtin_unreachable, or any function declared noreturn. Both spell
    // the same guarantee, and which one a codebase gets is not its choice.
    // redis picks between them on __GNUC__ >= 5, which Clang answers 4 to, so
    // matching only the builtin sees the assertion macro nowhere.
    static bool isUnreachableMarker(const clang::Stmt *S) {
        const auto *E = llvm::dyn_cast_or_null<clang::Expr>(S);
        if (!E) return false;
        const auto *CE =
            llvm::dyn_cast<clang::CallExpr>(E->IgnoreParenImpCasts());
        if (!CE) return false;
        const auto *C = CE->getDirectCallee();
        if (!C) return false;
        return C->isNoReturn() ||
               (C->getBuiltinID() != 0 &&
                C->getName() == "__builtin_unreachable");
    }

    void noteUnreachableAfter(const clang::Stmt *S) {
        const auto *E = llvm::dyn_cast_or_null<clang::Expr>(S);
        if (!E) return;
        const auto *CE =
            llvm::dyn_cast<clang::CallExpr>(E->IgnoreParenImpCasts());
        if (!CE) return;
        if (const auto *C = CE->getDirectCallee())
            ++unreachableAfter[C->getCanonicalDecl()];
    }

    // "f(...), __builtin_unreachable()" is how an assertion macro states that
    // f does not return when the function itself carries no attribute.
    bool VisitBinaryOperator(clang::BinaryOperator *BO) {
        if (BO->getOpcode() == clang::BO_Comma &&
            isUnreachableMarker(BO->getRHS()))
            noteUnreachableAfter(BO->getLHS());
        if (!BO->isAssignmentOp())
            return true;
        if (calleeSignature(BO->getLHS()->getType()).empty())
            return true;
        noteSlotWrite(slotKeyOf(BO->getLHS()), BO->getRHS());
        return true;
    }

    // Parameter index when an expression is a bare reference to one of the
    // enclosing function's own parameters.
    int paramIndexOf(const clang::Expr *E) const {
        if (!E) return -1;
        E = E->IgnoreParenImpCasts();
        if (const auto *UO = llvm::dyn_cast<clang::UnaryOperator>(E))
            if (UO->getOpcode() == clang::UO_AddrOf)
                E = UO->getSubExpr()->IgnoreParenImpCasts();
        const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(E);
        if (!DRE) return -1;
        const auto *PV = llvm::dyn_cast<clang::ParmVarDecl>(DRE->getDecl());
        if (!PV || !self) return -1;
        // Against the canonical decl, since the parameter belongs to the
        // definition and self is the first declaration whenever a prototype
        // exists, which for a function called across TUs is always.
        const auto *owner =
            llvm::dyn_cast<clang::FunctionDecl>(PV->getDeclContext());
        if (!owner || owner->getCanonicalDecl() != self->getCanonicalDecl())
            return -1;
        return static_cast<int>(PV->getFunctionScopeIndex());
    }

    // Which named place a function-pointer expression reads from or writes
    // to. Empty when it is a local, a return value, or an array element,
    // which then falls back to the callee signature.
    std::string slotKeyOf(const clang::Expr *E) const {
        if (!E || !ctx) return {};
        const int p = paramIndexOf(E);
        if (p >= 0)
            return "P:" + threadRoleNodeName(self, *ctx) + "|" +
                   std::to_string(p);
        E = E->IgnoreParenImpCasts();
        if (const auto *ME = llvm::dyn_cast<clang::MemberExpr>(E)) {
            const auto *FD = llvm::dyn_cast<clang::FieldDecl>(ME->getMemberDecl());
            if (!FD) return {};
            const auto *RD = FD->getParent();
            if (!RD) return {};
            return "F:" + RD->getCanonicalDecl()->getQualifiedNameAsString() +
                   "::" + FD->getNameAsString();
        }
        if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(E)) {
            const auto *VD = llvm::dyn_cast<clang::VarDecl>(DRE->getDecl());
            if (!VD) return {};
            if (VD->hasGlobalStorage())
                return "G:" + VD->getQualifiedNameAsString();
            // A local copied out of a struct before the loop that dispatches
            // through it. Without this the call reads as unattributable and
            // falls back to the signature, which on redis pairs a defrag
            // callback with a thread entry because both are void *(void *).
            if (self)
                return "L:" + threadRoleNodeName(self, *ctx) +
                       "::" + VD->getNameAsString();
        }
        return {};
    }

    // What a function pointer written into `slot` may hold.
    void noteSlotWrite(const std::string &slot, const clang::Expr *value) {
        if (slot.empty() || !value || !ctx) return;
        // "a ? a : fallback" is how a table fills an optional callback, and
        // reading the whole expression as unnameable makes the slot opaque
        // for the one pattern that names both of its values.
        if (const auto *CO = llvm::dyn_cast<clang::AbstractConditionalOperator>(
                value->IgnoreParenImpCasts())) {
            noteSlotWrite(slot, CO->getTrueExpr());
            noteSlotWrite(slot, CO->getFalseExpr());
            return;
        }
        if (const auto *FD = entryArgToFunction(value)) {
            fnSlotTargets[slot].insert(threadRoleNodeName(FD, *ctx));
            return;
        }
        // A null callee is never called, so storing one says nothing about
        // what the slot can dispatch to. The implicit form is the common one:
        // the semantic InitListExpr fills every field a designated
        // initializer left out, and reading those as unnameable makes every
        // partially-initialised callback table opaque.
        if (llvm::isa<clang::ImplicitValueInitExpr>(
                value->IgnoreParenImpCasts()) ||
            value->isNullPointerConstant(const_cast<clang::ASTContext &>(*ctx),
                                         clang::Expr::NPC_ValueDependentIsNull))
            return;
        const std::string from = slotKeyOf(value);
        if (!from.empty()) {
            fnSlotForwards[slot].insert(from);
            return;
        }
        fnSlotOpaque.insert(slot);
    }

    void noteFnArgs(const clang::FunctionDecl *callee,
                    const clang::CallExpr *CE) {
        if (!ctx || !callee) return;
        std::string calleeName;
        for (unsigned j = 0; j < CE->getNumArgs(); ++j) {
            const clang::Expr *A = CE->getArg(j);
            if (!A || calleeSignature(A->getType()).empty())
                continue;
            if (calleeName.empty())
                calleeName = threadRoleNodeName(callee, *ctx);
            noteSlotWrite("P:" + calleeName + "|" + std::to_string(j), A);
        }
    }

    bool VisitInitListExpr(clang::InitListExpr *ILE) {
        // Semantic form only. The syntactic form lists designated
        // initializers in written order, so pairing it with fields() maps
        // ".rewrite = f" onto whatever field happens to be third, and every
        // callback table in the tree reads as holding something unnameable.
        if (!ILE->isSemanticForm()) return true;
        const auto *RT = ILE->getType()->getAsRecordDecl();
        if (!RT) return true;
        unsigned i = 0;
        for (const auto *field : RT->fields()) {
            if (i >= ILE->getNumInits()) break;
            const clang::Expr *init = ILE->getInit(i++);
            if (!init || calleeSignature(field->getType()).empty())
                continue;
            noteSlotWrite("F:" +
                              RT->getCanonicalDecl()->getQualifiedNameAsString() +
                              "::" + field->getNameAsString(),
                          init);
        }
        return true;
    }

    bool VisitVarDecl(clang::VarDecl *VD) {
        if (!VD->hasInit() || calleeSignature(VD->getType()).empty())
            return true;
        if (VD->hasGlobalStorage()) {
            noteSlotWrite("G:" + VD->getQualifiedNameAsString(), VD->getInit());
        } else if (self && ctx) {
            noteSlotWrite("L:" + threadRoleNodeName(self, *ctx) +
                              "::" + VD->getNameAsString(),
                          VD->getInit());
        }
        return true;
    }

    // Outermost enclosing loop head, since a spawn in a nested loop reaches
    // back to the start of every loop containing it.
    unsigned reachFrom() const {
        return loopHeads.empty() ? stmtIndex : loopHeads.front();
    }

    void notePosition(CallPosition &p, bool &seen) {
        const CallPosition here{reachFrom(), stmtIndex};
        if (!seen) { p = here; seen = true; return; }
        p.merge(here);
    }

    void noteIndirect(const std::string &sig) {
        if (sig.empty())
            return;
        const CallPosition here{reachFrom(), stmtIndex};
        auto [it, fresh] = indirectPos.emplace(sig, here);
        if (!fresh) it->second.merge(here);
    }

    template <typename Node, typename Base>
    bool traverseLoop(Node *N, Base base) {
        // A do/while(0) macro wrapper is not repetition, and counting it
        // inflates the loop depth that hotness relaxation weighs.
        const unsigned step = (ctx && isDegenerateLoop(N, *ctx)) ? 0u : 1u;
        loopDepth += step;
        if (loopDepth > ownLoopDepth) ownLoopDepth = loopDepth;
        if (step) loopHeads.push_back(stmtIndex);

        // The source's own trip count where it states one, and the default
        // where it does not. Being wrong about the default scales a whole
        // subtree by one factor and every term the cost model consumes is a
        // ratio, so a uniform error cancels; being wrong by treating a
        // sixteen-iteration loop as a thousand-iteration one does not.
        const Milli saved = frequency;
        if (step) {
            uint64_t trips = ctx ? constantTripCount(N, *ctx) : 0;
            if (trips == 0) trips = kDefaultTripCount;
            frequency = milliMul(frequency, toMilli(static_cast<int64_t>(trips)));
            if (frequency > kFreqCeiling) frequency = kFreqCeiling;
            if (frequency > ownFrequency) ownFrequency = frequency;
        }
        bool r = (this->*base)(N);
        frequency = saved;
        if (step) loopHeads.pop_back();
        loopDepth -= step;
        return r;
    }

    bool TraverseCompoundStmt(clang::CompoundStmt *CS) {
        const clang::Stmt *prev = nullptr;
        for (auto *child : CS->body()) {
            if (prev && isUnreachableMarker(child))
                noteUnreachableAfter(prev);
            prev = child;
            ++stmtIndex;
            if (!TraverseStmt(child))
                return false;
        }
        return true;
    }

    // A backward jump reorders execution against the statement numbering, and
    // setjmp does the same from a caller's frame. Everything in such a body
    // reaches everything else, which is the sound reading of "we cannot say".
    bool VisitGotoStmt(clang::GotoStmt *GS) {
        const auto *L = GS->getLabel();
        if (!ctx || !L || !L->getStmt()) {
            orderUnknown = true;
            return true;
        }
        const auto &SM = ctx->getSourceManager();
        if (SM.isBeforeInTranslationUnit(L->getStmt()->getBeginLoc(),
                                         GS->getBeginLoc()))
            orderUnknown = true;
        return true;
    }

    bool VisitIndirectGotoStmt(clang::IndirectGotoStmt *) {
        orderUnknown = true;
        return true;
    }

    bool VisitDeclRefExpr(clang::DeclRefExpr *DRE) {
        if (calleeExprs.count(DRE))
            return true;
        if (const auto *FD =
                llvm::dyn_cast<clang::FunctionDecl>(DRE->getDecl())) {
            const std::string sig = calleeSignature(FD->getType());
            if (!sig.empty())
                addressTaken[sig].insert(FD->getCanonicalDecl());
        }
        return true;
    }

    bool VisitExplicitCastExpr(clang::ExplicitCastExpr *CE) {
        const auto *FD = entryArgToFunction(CE->getSubExpr());
        if (!FD)
            return true;
        const std::string sig = calleeSignature(CE->getTypeAsWritten());
        if (!sig.empty())
            addressTaken[sig].insert(FD->getCanonicalDecl());
        return true;
    }
    bool TraverseForStmt(clang::ForStmt *S) {
        return traverseLoop(S, &CallEdgeVisitor::baseTraverseFor);
    }
    bool TraverseWhileStmt(clang::WhileStmt *S) {
        return traverseLoop(S, &CallEdgeVisitor::baseTraverseWhile);
    }
    bool TraverseDoStmt(clang::DoStmt *S) {
        return traverseLoop(S, &CallEdgeVisitor::baseTraverseDo);
    }
    bool TraverseCXXForRangeStmt(clang::CXXForRangeStmt *S) {
        return traverseLoop(S, &CallEdgeVisitor::baseTraverseForRange);
    }
    bool baseTraverseFor(clang::ForStmt *S) {
        return clang::RecursiveASTVisitor<CallEdgeVisitor>::TraverseForStmt(S);
    }
    bool baseTraverseWhile(clang::WhileStmt *S) {
        return clang::RecursiveASTVisitor<CallEdgeVisitor>::TraverseWhileStmt(S);
    }
    bool baseTraverseDo(clang::DoStmt *S) {
        return clang::RecursiveASTVisitor<CallEdgeVisitor>::TraverseDoStmt(S);
    }
    bool baseTraverseForRange(clang::CXXForRangeStmt *S) {
        return clang::RecursiveASTVisitor<CallEdgeVisitor>::
            TraverseCXXForRangeStmt(S);
    }

    void noteEdge(const clang::FunctionDecl *callee) {
        callees.insert(callee);
        auto &d = calleeLoopDepth[callee];
        d = std::max(d, loopDepth);
        auto &f = calleeFrequency[callee];
        f = std::max(f, frequency);
        const CallPosition here{reachFrom(), stmtIndex};
        auto [it, inserted] = calleePos.emplace(callee, here);
        if (!inserted) it->second.merge(here);
        ++callSites[callee];
    }

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
        if (const auto *C = CE->getCallee())
            calleeExprs.insert(C->IgnoreParenImpCasts());
        const auto *Callee = CE->getDirectCallee();
        if (!Callee) {
            const clang::Expr *C = CE->getCallee();
            const std::string slot = slotKeyOf(C);
            if (!slot.empty()) {
                const CallPosition here{reachFrom(), stmtIndex};
                auto [it, fresh] = indirectSlotPos.emplace(slot, here);
                if (!fresh) it->second.merge(here);
            } else {
                noteIndirect(C ? calleeSignature(C->getType())
                               : std::string());
            }
            return true;
        }
        if (Callee->isNoReturn())
            noReturn.insert(Callee->getCanonicalDecl());
        noteFnArgs(Callee, CE);
        // A virtual call resolves at run time, so its target set is the
        // override set and not this declaration. It counts as indirect for
        // the spawn question and as a direct edge for every other.
        if (const auto *MD = llvm::dyn_cast<clang::CXXMethodDecl>(Callee))
            if (MD->isVirtual())
                noteIndirect(calleeSignature(MD->getType()));
        noteEdge(Callee->getCanonicalDecl());

        {
            const llvm::StringRef n = Callee->getName();
            if (n == "setjmp" || n == "_setjmp" || n == "sigsetjmp" ||
                n == "__sigsetjmp")
                orderUnknown = true;
        }

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
        // Where the thread is created, not which function it runs. A
        // pthread_create whose entry argument does not resolve still creates
        // the thread, and the phase partition turns on the creation alone.
        if (name == "pthread_create" || name == "thrd_create" ||
            name == "async")
            notePosition(spawnPos, anySpawn);
        return true;
    }

    bool VisitCXXConstructExpr(clang::CXXConstructExpr *CE) {
        const auto *CD = CE->getConstructor();
        if (!CD)
            return true;
        noteEdge(CD->getCanonicalDecl());

        // std::thread t(fn, args...) / std::jthread.
        const auto *RD = CD->getParent();
        if (RD && CE->getNumArgs() >= 1) {
            llvm::StringRef cls = RD->getName();
            if (cls == "thread" || cls == "jthread") {
                addEntryAny(CE->getArg(0));
                notePosition(spawnPos, anySpawn);
            }
        }
        return true;
    }

private:
    bool addEntry(const clang::Expr *arg) {
        if (const auto *FD = entryArgToFunction(arg)) {
            const auto *canon = FD->getCanonicalDecl();
            threadEntries.insert(canon);
            // Spawned inside a loop, or from more than one site: the role has
            // many live instances. One writer function then suffices for two
            // cores to contend, which is the whole thread-pool shape.
            if (loopDepth > 0 || !spawnSites.insert(canon).second)
                poolEntries.insert(canon);
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

    // Everything a pool entry reaches also runs on many threads at once.
    if (!poolEntryDecls_.empty()) {
        poolReachable_ = transitiveCallees(poolEntryDecls_);
        poolReachable_.insert(poolEntryDecls_.begin(), poolEntryDecls_.end());
    }
}

void CallGraph::processFunction(const clang::FunctionDecl *FD) {
    const auto *canon = FD->getCanonicalDecl();
    if (calleeMap_.count(canon))
        return; // already processed

    CallEdgeVisitor visitor;
    visitor.ctx = &ctx_;
    visitor.self = canon;
    visitor.TraverseStmt(const_cast<clang::Stmt *>(FD->getBody()));

    ownLoopDepth_[canon] = visitor.ownLoopDepth;
    ownFrequency_[canon] = visitor.ownFrequency;

    auto &targets = calleeMap_[canon];
    for (const auto *callee : visitor.callees) {
        targets.insert(callee);
        callerMap_[callee].insert(canon);
        auto it = visitor.calleeLoopDepth.find(callee);
        if (it != visitor.calleeLoopDepth.end())
            edgeLoopDepth_[{canon, callee}] = it->second;
        auto fit = visitor.calleeFrequency.find(callee);
        if (fit != visitor.calleeFrequency.end())
            edgeFrequency_[{canon, callee}] = fit->second;
        auto pit = visitor.calleePos.find(callee);
        if (pit != visitor.calleePos.end())
            edgePos_[{canon, callee}] = pit->second;
    }
    if (visitor.anySpawn)
        spawnPos_[canon] = visitor.spawnPos;
    if (!visitor.indirectPos.empty())
        indirectPos_[canon] = visitor.indirectPos;
    if (visitor.orderUnknown)
        orderUnknown_.insert(canon);
    for (const auto &[sig, fns] : visitor.addressTaken)
        addressTaken_[sig].insert(fns.begin(), fns.end());
    for (const auto &[slot, fns] : visitor.fnSlotTargets)
        fnSlotTargets_[slot].insert(fns.begin(), fns.end());
    for (const auto &[slot, srcs] : visitor.fnSlotForwards)
        fnSlotForwards_[slot].insert(srcs.begin(), srcs.end());
    fnSlotOpaque_.insert(visitor.fnSlotOpaque.begin(),
                         visitor.fnSlotOpaque.end());
    if (!visitor.indirectSlotPos.empty())
        indirectSlotPos_[canon] = visitor.indirectSlotPos;
    noReturn_.insert(visitor.noReturn.begin(), visitor.noReturn.end());
    for (const auto &[fn, n] : visitor.callSites) callSites_[fn] += n;
    for (const auto &[fn, n] : visitor.unreachableAfter)
        unreachableAfter_[fn] += n;
    if (visitor.hasReturn || !FD->getReturnType()->isVoidType())
        returning_.insert(canon);
    // The last statement of the top-level body, when it is a call in
    // statement position. A call nested inside an if leaves a path that falls
    // past it, so it is not a tail call and is deliberately not recorded.
    if (const auto *body =
            llvm::dyn_cast<clang::CompoundStmt>(FD->getBody())) {
        if (!body->body_empty())
            if (const auto *E = llvm::dyn_cast<clang::Expr>(body->body_back()))
                if (const auto *CE =
                        llvm::dyn_cast<clang::CallExpr>(E->IgnoreImplicit()))
                    if (const auto *C = CE->getDirectCallee())
                        tailCallee_[canon] = C->getCanonicalDecl();
    }
    for (const auto *entry : visitor.threadEntries)
        threadEntries_.insert(threadRoleNodeName(entry, ctx_));
    for (const auto *entry : visitor.poolEntries)
        poolEntryDecls_.insert(entry);
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
        if (it == spawnerParams_.end() || it->second != argIdx)
            continue;
        threadEntries_.insert(threadRoleNodeName(fn, ctx_));

        // The loop is around the *wrapper* call, not the pthread_create
        // inside it, so multiplicity has to be read one level out. Missing
        // this made every pool spawned through a helper -- which is most
        // production thread pools -- look single-instance.
        const auto &cs = callers(callee);
        bool repeated = cs.size() >= 2;
        for (const auto *c : cs)
            if (callSiteLoopDepth(c, callee) > 0) { repeated = true; break; }
        if (repeated)
            poolEntryDecls_.insert(fn->getCanonicalDecl());
    }
}

void CallGraph::snapshotForThreadRoles(ThreadRoleSummary &out) const {
    out.threadEntries.insert(threadEntries_.begin(), threadEntries_.end());
    for (const auto &[caller, callees] : calleeMap_) {
        if (callees.empty())
            continue;
        const std::string callerName = threadRoleNodeName(caller, ctx_);
        auto &names = out.callEdges[callerName];
        for (const auto *callee : callees) {
            const std::string calleeName = threadRoleNodeName(callee, ctx_);
            names.insert(calleeName);
            // Sparse: zero is both the default on the read side and the
            // overwhelming majority of call sites. Materialising it would put
            // an IPC entry on every edge in the program.
            auto fit = edgeFrequency_.find({caller, callee});
            if (fit != edgeFrequency_.end() && fit->second > kMilli) {
                auto &f = out.edgeFrequency[callerName][calleeName];
                if (fit->second > f) f = fit->second;
            }
            auto pit = edgePos_.find({caller, callee});
            if (pit != edgePos_.end()) {
                auto &dst = out.edgeOrder[callerName];
                auto [ins, fresh] = dst.emplace(calleeName, pit->second);
                if (!fresh) ins->second.merge(pit->second);
            }
            const unsigned d = callSiteLoopDepth(caller, callee);
            if (!d) continue;
            auto &cur = out.edgeLoopDepth[callerName][calleeName];
            if (d > cur) cur = d;
        }
    }
    for (const auto &[fn, p] : spawnPos_) {
        auto [it, fresh] =
            out.spawnPoints.emplace(threadRoleNodeName(fn, ctx_), p);
        if (!fresh) it->second.merge(p);
    }
    for (const auto &[fn, sigs] : indirectPos_) {
        auto &dst = out.indirectCalls[threadRoleNodeName(fn, ctx_)];
        for (const auto &[sig, p] : sigs) {
            auto [it, fresh] = dst.emplace(sig, p);
            if (!fresh) it->second.merge(p);
        }
    }
    for (const auto &[sig, fns] : addressTaken_) {
        auto &dst = out.addressTakenBySignature[sig];
        for (const auto *fn : fns)
            dst.insert(threadRoleNodeName(fn, ctx_));
    }
    for (const auto &[slot, fns] : fnSlotTargets_)
        out.fnSlotTargets[slot].insert(fns.begin(), fns.end());
    for (const auto &[slot, srcs] : fnSlotForwards_)
        out.fnSlotForwards[slot].insert(srcs.begin(), srcs.end());
    out.fnSlotOpaque.insert(fnSlotOpaque_.begin(), fnSlotOpaque_.end());
    for (const auto &[fn, slots] : indirectSlotPos_) {
        auto &dst = out.indirectSlotCalls[threadRoleNodeName(fn, ctx_)];
        for (const auto &[slot, p] : slots) {
            auto [it, fresh] = dst.emplace(slot, p);
            if (!fresh) it->second.merge(p);
        }
    }
    for (const auto *fn : noReturn_)
        out.noReturnFunctions.insert(threadRoleNodeName(fn, ctx_));
    for (const auto &[fn, tail] : tailCallee_)
        out.tailCallee[threadRoleNodeName(fn, ctx_)] =
            threadRoleNodeName(tail, ctx_);
    for (const auto *fn : returning_)
        out.returningFunctions.insert(threadRoleNodeName(fn, ctx_));
    for (const auto &[fn, n] : callSites_)
        out.callSiteCount[threadRoleNodeName(fn, ctx_)] += n;
    for (const auto &[fn, n] : unreachableAfter_)
        out.unreachableAfterCount[threadRoleNodeName(fn, ctx_)] += n;
    for (const auto *fn : orderUnknown_)
        out.orderUnknown.insert(threadRoleNodeName(fn, ctx_));
    // Own loop depth travels for every node, not only callers: a leaf that
    // spins is still the body the grade sharpens on.
    for (const auto *fn : functions()) {
        const std::string name = threadRoleNodeName(fn, ctx_);
        auto fit = ownFrequency_.find(fn);
        if (fit != ownFrequency_.end() && fit->second > kMilli) {
            auto &f = out.ownFrequency[name];
            if (fit->second > f) f = fit->second;
        }
        const unsigned d = ownLoopDepth(fn);
        if (!d) continue;
        auto &cur = out.ownLoopDepth[name];
        if (d > cur) cur = d;
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

namespace lshaz {

unsigned CallGraph::callSiteLoopDepth(const clang::FunctionDecl *Caller,
                                      const clang::FunctionDecl *Callee) const {
    auto it = edgeLoopDepth_.find({Caller, Callee});
    return it == edgeLoopDepth_.end() ? 0u : it->second;
}

unsigned CallGraph::ownLoopDepth(const clang::FunctionDecl *FD) const {
    auto it = ownLoopDepth_.find(FD);
    return it == ownLoopDepth_.end() ? 0u : it->second;
}

std::vector<const clang::FunctionDecl *> CallGraph::functions() const {
    std::vector<const clang::FunctionDecl *> out;
    out.reserve(calleeMap_.size());
    for (const auto &[fn, _] : calleeMap_)
        out.push_back(fn);
    return out;
}

} // namespace lshaz
