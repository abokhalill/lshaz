// SPDX-License-Identifier: Apache-2.0
#include "lshaz/analysis/striped_array.h"
#include "lshaz/analysis/symbols.h"
#include "lshaz/analysis/layout_safety.h"

#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/RecordLayout.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Basic/SourceManager.h>

#include <llvm/ADT/SmallPtrSet.h>

#include <fnmatch.h>

#include <algorithm>
#include <map>

namespace lshaz {

namespace {

// Deliberately narrow; thread_index_patterns carries per-project spellings.
bool nameIsThreadIdent(llvm::StringRef n,
                       const std::vector<std::string> &extra) {
    static constexpr llvm::StringLiteral kExact[] = {
        "tid", "thread_id", "thread_index", "thread_idx", "thread_num",
        "thd_id", "cur_tid", "running_tid", "core_id", "cpu_id", "shard_id",
        "gettid", "sched_getcpu", "omp_get_thread_num",
    };
    for (auto e : kExact)
        if (n.equals_insensitive(e)) return true;
    if (n.ends_with("_tid") || n.ends_with("_thread_id") ||
        n.ends_with("_thread_index"))
        return true;
    const std::string s = n.str();
    for (const auto &p : extra)
        if (fnmatch(p.c_str(), s.c_str(), 0) == 0) return true;
    return false;
}

bool isStdAtomicRecord(clang::QualType QT) {
    const clang::CXXRecordDecl *RD = nullptr;
    if (const auto *TST = QT->getAs<clang::TemplateSpecializationType>()) {
        if (auto TD = TST->getTemplateName().getAsTemplateDecl())
            RD = llvm::dyn_cast_or_null<clang::CXXRecordDecl>(
                TD->getTemplatedDecl());
    }
    if (!RD) RD = QT->getAsCXXRecordDecl();
    if (!RD) return false;
    std::string qn = RD->getQualifiedNameAsString();
    if (qn == "std::atomic" || qn == "std::atomic_ref") return true;
    if (const auto *CTSD =
            llvm::dyn_cast<clang::ClassTemplateSpecializationDecl>(RD))
        if (auto *TD = CTSD->getSpecializedTemplate()) {
            std::string tn = TD->getQualifiedNameAsString();
            return tn == "std::atomic" || tn == "std::atomic_ref";
        }
    return false;
}

const clang::ValueDecl *baseDeclOf(const clang::Expr *E) {
    E = E->IgnoreParenImpCasts();
    if (const auto *ME = llvm::dyn_cast<clang::MemberExpr>(E))
        return ME->getMemberDecl();
    if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(E))
        return DRE->getDecl();
    return nullptr;
}

// Descends through casts, address-of, deref, member access and subscripts
// to whichever DeclRefExpr the expression is rooted at.
const clang::Expr *peelToRoot(const clang::Expr *E) {
    while (E) {
        E = E->IgnoreParenImpCasts();
        if (const auto *UO = llvm::dyn_cast<clang::UnaryOperator>(E)) {
            if (UO->getOpcode() != clang::UO_AddrOf &&
                UO->getOpcode() != clang::UO_Deref)
                return E;
            E = UO->getSubExpr();
        } else if (const auto *ME = llvm::dyn_cast<clang::MemberExpr>(E)) {
            E = ME->getBase();
        } else if (const auto *ASE =
                       llvm::dyn_cast<clang::ArraySubscriptExpr>(E)) {
            E = ASE->getBase();
        } else {
            return E;
        }
    }
    return nullptr;
}

// Writes through a parameter, directly or by handing it on. An unseen body
// cannot be cleared, so only a visible one that does neither counts as
// read-only.
class ParamWriteFinder
    : public clang::RecursiveASTVisitor<ParamWriteFinder> {
public:
    explicit ParamWriteFinder(const clang::ValueDecl *P) : param(P) {}
    bool writes = false;

    bool VisitBinaryOperator(clang::BinaryOperator *B) {
        if (B->isAssignmentOp() && rootsAtParam(B->getLHS())) writes = true;
        return !writes;
    }
    bool VisitUnaryOperator(clang::UnaryOperator *U) {
        if (U->isIncrementDecrementOp() && rootsAtParam(U->getSubExpr()))
            writes = true;
        return !writes;
    }
    bool VisitAtomicExpr(clang::AtomicExpr *E) {
        if (rootsAtParam(E->getPtr())) writes = true;
        return !writes;
    }
    // Handing the pointer on puts the write out of view, which is not the
    // same as establishing there is none.
    bool VisitCallExpr(clang::CallExpr *CE) {
        for (const auto *A : CE->arguments())
            if (rootsAtParam(A)) { writes = true; break; }
        return !writes;
    }

private:
    bool rootsAtParam(const clang::Expr *E) const {
        const auto *root = peelToRoot(E);
        const auto *DRE = llvm::dyn_cast_or_null<clang::DeclRefExpr>(root);
        return DRE && DRE->getDecl()->getCanonicalDecl() == param;
    }
    const clang::ValueDecl *param;
};

bool isAtomicWriteBuiltin(llvm::StringRef n) {
    return n.starts_with("__atomic_") || n.starts_with("__c11_atomic_") ||
           n.starts_with("__sync_") || n.starts_with("atomic_fetch") ||
           n == "atomic_store" || n == "atomic_store_explicit" ||
           n == "atomic_exchange" || n == "atomic_exchange_explicit" ||
           n.starts_with("atomic_compare_exchange");
}

class UseVisitor : public clang::RecursiveASTVisitor<UseVisitor> {
public:
    clang::ASTContext &ctx;
    StripedArraySummary &out;
    const std::map<std::string, std::string> &aliases;
    const HotPathOracle &oracle;
    const Config &cfg;
    const clang::FunctionDecl *currentFn = nullptr;
    llvm::SmallPtrSet<const clang::ValueDecl *, 8> inductionVars;

    UseVisitor(clang::ASTContext &C, StripedArraySummary &o,
               const std::map<std::string, std::string> &al,
               const HotPathOracle &orc, const Config &c,
               const std::set<std::string> &entries)
        : ctx(C), out(o), aliases(al), oracle(orc), cfg(c),
          threadEntries(entries) {}

    const std::set<std::string> &threadEntries;
    // Locals carrying a thread identity forward. "long id = (long)arg" is the
    // canonical spelling and the cast erases nothing that matters.
    llvm::SmallPtrSet<const clang::VarDecl *, 8> identDerived;
    // Locals aimed at one slot by "T *p = &arr[id]".
    std::map<const clang::VarDecl *, const clang::ArraySubscriptExpr *>
        slotPointers;
    // Whether parameter i of a callee is only read, memoised because the
    // refutation walks that callee's whole body.
    std::map<std::pair<const clang::FunctionDecl *, unsigned>, bool>
        readOnlyParam;

    bool TraverseFunctionDecl(clang::FunctionDecl *FD) {
        if (!FD->doesThisDeclarationHaveABody())
            return RecursiveASTVisitor::TraverseFunctionDecl(FD);
        const auto *prev = currentFn;
        auto savedIdent = identDerived;
        auto savedSlots = slotPointers;
        identDerived.clear();
        slotPointers.clear();
        currentFn = FD;
        bool r = RecursiveASTVisitor::TraverseFunctionDecl(FD);
        currentFn = prev;
        identDerived = savedIdent;
        slotPointers = savedSlots;
        return r;
    }
    bool TraverseCXXMethodDecl(clang::CXXMethodDecl *MD) {
        return TraverseFunctionDecl(MD);
    }

    bool VisitVarDecl(clang::VarDecl *VD) {
        if (!VD || !VD->hasInit()) return true;
        if (inThreadEntry() && rootsAtEntryParam(VD->getInit()))
            identDerived.insert(VD->getCanonicalDecl());
        aimPointer(VD, VD->getInit());
        return true;
    }


    bool TraverseForStmt(clang::ForStmt *S) {
        auto added = pushInduction(S->getInit());
        bool r = RecursiveASTVisitor::TraverseForStmt(S);
        for (const auto *v : added) inductionVars.erase(v);
        return r;
    }

    // write forms; extracting the subscript from the write itself is
    // exact where a parent lookup on every subscript is not.
    bool VisitBinaryOperator(clang::BinaryOperator *B) {
        if (!B->isAssignmentOp()) return true;
        // Assigning the pointer re-aims it and writes no slot. Left to
        // noteWrite it would book the old target as written.
        if (const auto *VD = pointerVar(B->getLHS())) {
            aimPointer(VD, B->getRHS());
            return true;
        }
        noteWrite(B->getLHS());
        return true;
    }
    bool VisitUnaryOperator(clang::UnaryOperator *U) {
        if (!U->isIncrementDecrementOp()) return true;
        // p++ walks off the recorded slot rather than writing it.
        if (const auto *VD = pointerVar(U->getSubExpr())) {
            slotPointers.erase(VD);
            return true;
        }
        noteWrite(U->getSubExpr());
        return true;
    }
    bool VisitCallExpr(clang::CallExpr *CE) {
        const auto *FD = CE->getDirectCallee();
        if (!FD || !FD->getIdentifier() || CE->getNumArgs() == 0)
            return true;
        if (isAtomicWriteBuiltin(FD->getName())) {
            noteWrite(CE->getArg(0));
            return true;
        }
        // A slot handed over as a pointer to non-const is written by the
        // callee unless the callee is visible here and provably only
        // reads. This is what reaches memset(&slot[id], ...) and every
        // per-thread init helper, neither of which is an assignment.
        const unsigned n =
            std::min<unsigned>(CE->getNumArgs(), FD->getNumParams());
        for (unsigned i = 0; i < n; ++i) {
            clang::QualType pt = FD->getParamDecl(i)->getType();
            if (!pt->isPointerType() ||
                pt->getPointeeType().isConstQualified())
                continue;
            const clang::Expr *slot = slotAddressArg(CE->getArg(i));
            if (!slot || !resolveSlot(slot).first) continue;
            if (calleeOnlyReads(FD, i)) continue;
            noteWrite(slot);
        }
        return true;
    }
    // C11/GNU atomic builtins are AtomicExpr, not CallExpr, the shape
    // every atomicIncr-style macro lowers to.
    bool VisitAtomicExpr(clang::AtomicExpr *E) {
        switch (E->getOp()) {
        case clang::AtomicExpr::AO__c11_atomic_load:
        case clang::AtomicExpr::AO__atomic_load:
        case clang::AtomicExpr::AO__atomic_load_n:
        case clang::AtomicExpr::AO__opencl_atomic_load:
            return true;
        default:
            break;
        }
        noteWrite(E->getPtr());
        return true;
    }

    bool VisitCXXMemberCallExpr(clang::CXXMemberCallExpr *CE) {
        const auto *MD = CE->getMethodDecl();
        if (!MD) return true;
        llvm::StringRef n = MD->getName();
        if (n == "store" || n == "exchange" || n.starts_with("fetch_") ||
            n.starts_with("compare_exchange"))
            noteWrite(CE->getImplicitObjectArgument());
        return true;
    }

    // read side: loop-swept access is aggregation, never striping.
    bool VisitArraySubscriptExpr(clang::ArraySubscriptExpr *E) {
        if (!currentFn) return true;
        if (classify(E->getIdx()) != IndexProvenance::LoopInduction)
            return true;
        if (auto *s = siteFor(E)) {
            std::string an = threadRoleNodeName(currentFn, ctx);
            s->aggregators.insert(an);
            s->aggregatorTier = std::max(s->aggregatorTier, tierOf(an));
        }
        return true;
    }

private:
    std::vector<const clang::ValueDecl *> pushInduction(const clang::Stmt *init) {
        std::vector<const clang::ValueDecl *> added;
        if (const auto *DS = llvm::dyn_cast_or_null<clang::DeclStmt>(init))
            for (const auto *D : DS->decls())
                if (const auto *VD = llvm::dyn_cast<clang::VarDecl>(D))
                    if (inductionVars.insert(VD).second) added.push_back(VD);
        if (const auto *BO = llvm::dyn_cast_or_null<clang::BinaryOperator>(init))
            if (BO->isAssignmentOp())
                if (const auto *D = baseDeclOf(BO->getLHS()))
                    if (inductionVars.insert(D).second) added.push_back(D);
        return added;
    }

    StripedArraySite *siteFor(const clang::ArraySubscriptExpr *E) {
        const clang::ValueDecl *base = baseDeclOf(E->getBase());
        if (!base) return nullptr;
        std::string k = stripedKeyForDecl(base, ctx);
        auto it = out.find(k);
        if (it != out.end()) return &it->second;
        auto a = aliases.find(k);
        if (a == aliases.end()) return nullptr;
        it = out.find(a->second);
        return it == out.end() ? nullptr : &it->second;
    }

    // Every subscript on the path from the write down to the base, outermost
    // first. "stats[id].pad[0]" and "grid[id][j]" both put the striped
    // subscript under an outer one, and matching only the outermost resolved
    // the first to the inner member array and missed the striping entirely.
    void subscriptChain(
            const clang::Expr *E,
            std::vector<const clang::ArraySubscriptExpr *> &chain) {
        while (E) {
            E = E->IgnoreParenImpCasts();
            if (const auto *UO = llvm::dyn_cast<clang::UnaryOperator>(E)) {
                if (UO->getOpcode() == clang::UO_AddrOf) {
                    E = UO->getSubExpr();
                    continue;
                }
                if (UO->getOpcode() != clang::UO_Deref) return;
                return followPointer(UO->getSubExpr(), chain);
            }
            if (const auto *ME = llvm::dyn_cast<clang::MemberExpr>(E)) {
                if (ME->isArrow()) return followPointer(ME->getBase(), chain);
                E = ME->getBase();
                continue;
            }
            if (const auto *ASE =
                    llvm::dyn_cast<clang::ArraySubscriptExpr>(E)) {
                const auto *base = ASE->getBase()->IgnoreParenImpCasts();
                // Indexing an array stays inside it; indexing a pointer
                // lands wherever that pointer aims. A file-scope
                // "T *p = &arr[K]" is the one pointer whose target
                // collectAliases already settled, so try it before giving up.
                if (!base->getType()->isArrayType()) {
                    if (siteFor(ASE)) chain.push_back(ASE);
                    else              followPointer(base, chain);
                    return;
                }
                chain.push_back(ASE);
                E = base;
                continue;
            }
            if (llvm::isa<clang::DeclRefExpr>(E))
                return followPointer(E, chain);
            return;
        }
    }

    // Crossing a pointer indirection leaves the array: "slots[id]->field"
    // writes whatever the slot pointed at, not the slot. Only a pointer
    // this function already aimed at a slot carries the location through,
    // which is what makes "p = &arr[id]; p->field = x" a slot write.
    void followPointer(
            const clang::Expr *E,
            std::vector<const clang::ArraySubscriptExpr *> &chain) {
        const auto *VD = pointerVar(E);
        if (!VD) return;
        auto it = slotPointers.find(VD);
        if (it != slotPointers.end()) chain.push_back(it->second);
    }

    // The level of the chain that names a catalogued array under a
    // thread-identity index, if any.
    std::pair<StripedArraySite *, const clang::ArraySubscriptExpr *>
    resolveSlot(const clang::Expr *target) {
        if (!target || !currentFn) return {nullptr, nullptr};
        std::vector<const clang::ArraySubscriptExpr *> chain;
        subscriptChain(target, chain);
        for (const auto *E : chain) {
            auto *s = siteFor(E);
            if (s && classify(E->getIdx()) == IndexProvenance::ThreadIdent)
                return {s, E};
        }
        return {nullptr, nullptr};
    }

    // A pointer variable, for the two statements that move one rather than
    // write through it.
    const clang::VarDecl *pointerVar(const clang::Expr *E) const {
        const auto *DRE =
            llvm::dyn_cast<clang::DeclRefExpr>(E->IgnoreParenImpCasts());
        if (!DRE) return nullptr;
        const auto *VD = llvm::dyn_cast<clang::VarDecl>(DRE->getDecl());
        if (!VD || !VD->getType()->isPointerType()) return nullptr;
        return VD->getCanonicalDecl();
    }

    // "T *p = &arr[id]" aims p at one slot, and writing through p writes
    // that slot. Anything else the pointer is set to drops the record, so a
    // re-aimed or advanced pointer never carries a stale index.
    void aimPointer(const clang::VarDecl *VD, const clang::Expr *init) {
        if (!VD || !VD->getType()->isPointerType() || !init) return;
        const auto *canon = VD->getCanonicalDecl();
        std::vector<const clang::ArraySubscriptExpr *> chain;
        // The slot's address, not merely an expression mentioning it:
        // "listFirst(slots[worker])" reads the slot and yields a pointer
        // into the object it held, which aims nowhere near the array.
        if (const clang::Expr *slot = slotAddressArg(init))
            subscriptChain(slot, chain);
        if (chain.empty()) { slotPointers.erase(canon); return; }
        slotPointers[canon] = chain.front();
    }

    // A callee can only write a slot whose address it was handed: "&arr[id]",
    // or "arr[id]" where the element is itself an array and decays. Passing
    // "arr[id]" by value loads the slot and hands over whatever it held, so
    // the callee writes that object and never touches the array.
    const clang::Expr *slotAddressArg(const clang::Expr *A) const {
        while (A) {
            A = A->IgnoreParens();
            if (const auto *C = llvm::dyn_cast<clang::CastExpr>(A)) {
                if (C->getCastKind() == clang::CK_ArrayToPointerDecay)
                    return C->getSubExpr();
                if (C->getCastKind() == clang::CK_LValueToRValue) {
                    const auto *VD = pointerVar(C->getSubExpr());
                    return VD && slotPointers.count(VD) ? C->getSubExpr()
                                                        : nullptr;
                }
                A = C->getSubExpr();
                continue;
            }
            if (const auto *UO = llvm::dyn_cast<clang::UnaryOperator>(A))
                if (UO->getOpcode() == clang::UO_AddrOf)
                    return UO->getSubExpr();
            return nullptr;
        }
        return nullptr;
    }

    bool calleeOnlyReads(const clang::FunctionDecl *FD, unsigned i) {
        const auto key = std::make_pair(FD->getCanonicalDecl(), i);
        auto it = readOnlyParam.find(key);
        if (it != readOnlyParam.end()) return it->second;
        const clang::FunctionDecl *def = nullptr;
        bool ro = false;
        if (FD->hasBody(def) && def && i < def->getNumParams()) {
            ParamWriteFinder f(def->getParamDecl(i)->getCanonicalDecl());
            f.TraverseStmt(def->getBody());
            ro = !f.writes;
        }
        readOnlyParam.emplace(key, ro);
        return ro;
    }

    void noteWrite(const clang::Expr *target) {
        auto [s, E] = resolveSlot(target);
        if (!s) return;
        std::string wn = threadRoleNodeName(currentFn, ctx);
        s->stripedWriters.insert(wn);
        s->writerTier = std::max(s->writerTier, tierOf(wn));
        if (isTLSDerived(E->getIdx())) s->tlsIndexed = true;
        if (isHandedOverIndex(E->getIdx())) s->indexIsHandedOver = true;
        else                               s->indexIsOwnIdentity = true;
    }

    // Named-function tiers outrank oracle hotness: the oracle reaches
    // most functions through a file glob or transitive propagation,
    // which cannot distinguish a per-connection setup routine from the
    // per-command path in the same file. An explicit name is the more
    // specific statement and wins.
    uint8_t tierOf(const std::string &qualified) {
        std::string plain = currentFn->getNameAsString();
        auto hit = [&](const std::vector<std::string> &pats) {
            for (const auto &p : pats)
                if (fnmatch(p.c_str(), plain.c_str(), 0) == 0 ||
                    fnmatch(p.c_str(), qualified.c_str(), 0) == 0)
                    return true;
            return false;
        };
        if (hit(cfg.dispatchPathPatterns))
            return static_cast<uint8_t>(WriteFrequencyTier::Dispatch);
        if (hit(cfg.tickPathPatterns))
            return static_cast<uint8_t>(WriteFrequencyTier::Tick);
        if (oracle.isFunctionHot(currentFn))
            return static_cast<uint8_t>(WriteFrequencyTier::Hot);
        return static_cast<uint8_t>(WriteFrequencyTier::Unknown);
    }

    // arr[c->tid] carries the owner's id, so one thread can drive every
    // slot. arr[tid] and arr[sched_getcpu()] carry the writer's.
    bool isHandedOverIndex(const clang::Expr *idx) {
        return llvm::isa<clang::MemberExpr>(idx->IgnoreParenImpCasts());
    }

    bool isTLSDerived(const clang::Expr *idx) {
        idx = idx->IgnoreParenImpCasts();
        if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(idx))
            if (const auto *VD = llvm::dyn_cast<clang::VarDecl>(DRE->getDecl()))
                return VD->getTLSKind() != clang::VarDecl::TLS_None;
        return false;
    }

    // The enclosing function was handed to a thread primitive, so its
    // parameters are what the spawn passed it. That is the thread identity by
    // construction, whatever the parameter is named.
    // "F|i" from the prepass fixpoint: parameter i of F carries a thread
    // identity, however many calls from the entry it arrived through.
    bool identParam(const clang::ValueDecl *D) const {
        if (!currentFn) return false;
        const auto *PV = llvm::dyn_cast<clang::ParmVarDecl>(D);
        if (!PV || PV->getDeclContext() != currentFn) return false;
        return cfg.threadIdentParams.count(
                   threadRoleNodeName(currentFn, ctx) + "|" +
                   std::to_string(PV->getFunctionScopeIndex())) > 0;
    }

    bool inThreadEntry() const {
        return currentFn &&
               threadEntries.count(threadRoleNodeName(currentFn, ctx)) > 0;
    }

    // Through casts, arithmetic and member access, since a thread payload is
    // routinely a struct pointer whose field holds the index.
    bool rootsAtEntryParam(const clang::Stmt *S) const {
        if (!S) return false;
        if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(S)) {
            const auto *D = DRE->getDecl();
            if (llvm::isa<clang::ParmVarDecl>(D)) return true;
            if (const auto *VD = llvm::dyn_cast<clang::VarDecl>(D))
                return identDerived.count(VD->getCanonicalDecl()) > 0;
        }
        for (const auto *C : S->children())
            if (rootsAtEntryParam(C)) return true;
        return false;
    }

    IndexProvenance classify(const clang::Expr *idx) {
        idx = idx->IgnoreParenImpCasts();
        clang::Expr::EvalResult r;
        if (idx->EvaluateAsInt(r, ctx)) return IndexProvenance::ConstantIdx;

        if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(idx)) {
            const auto *D = DRE->getDecl();
            if (inductionVars.count(D)) return IndexProvenance::LoopInduction;
            if (const auto *VD = llvm::dyn_cast<clang::VarDecl>(D))
                if (VD->getTLSKind() != clang::VarDecl::TLS_None)
                    return IndexProvenance::ThreadIdent;
            if (nameIsThreadIdent(D->getName(), cfg.threadIndexPatterns))
                return IndexProvenance::ThreadIdent;
            // Structural, and it outranks the name list rather than extending
            // it: the canonical worker writes "long id = (long)arg" and no
            // spelling of "id" was ever going to be enumerable.
            if (const auto *VD = llvm::dyn_cast<clang::VarDecl>(D))
                if (inThreadEntry() &&
                    (llvm::isa<clang::ParmVarDecl>(D) ||
                     identDerived.count(VD->getCanonicalDecl())))
                    return IndexProvenance::ThreadIdent;
            // Identity that reached here through a call. A thread entry is
            // almost always a trampoline, so stopping at its own body saw one
            // shape and missed the worker it delegates to.
            if (identParam(D)) return IndexProvenance::ThreadIdent;
        }
        if (inThreadEntry() && rootsAtEntryParam(idx))
            return IndexProvenance::ThreadIdent;
        if (const auto *ME = llvm::dyn_cast<clang::MemberExpr>(idx))
            if (nameIsThreadIdent(ME->getMemberDecl()->getName(), cfg.threadIndexPatterns))
                return IndexProvenance::ThreadIdent;
        if (const auto *CE = llvm::dyn_cast<clang::CallExpr>(idx))
            if (const auto *F = CE->getDirectCallee())
                if (F->getIdentifier() && nameIsThreadIdent(F->getName(), cfg.threadIndexPatterns))
                    return IndexProvenance::ThreadIdent;
        return IndexProvenance::Unknown;
    }
};

} // anonymous namespace

std::string stripedKeyForDecl(const clang::ValueDecl *D,
                              clang::ASTContext &Ctx) {
    if (const auto *FD = llvm::dyn_cast<clang::FieldDecl>(D)) {
        const auto *P = FD->getParent();
        if (!P) return {};
        return P->getCanonicalDecl()->getQualifiedNameAsString() +
               "::" + FD->getNameAsString();
    }
    const auto *VD = llvm::dyn_cast<clang::VarDecl>(D);
    if (!VD || !VD->hasGlobalStorage()) return {};
    // internal linkage collides by name across TUs; the defining file
    // disambiguates. external linkage is unique on its own.
    std::string prefix;
    if (VD->getFormalLinkage() == clang::Linkage::Internal) {
        const auto &SM = Ctx.getSourceManager();
        auto loc = SM.getFileLoc(VD->getLocation());
        if (auto fe = SM.getFileEntryRefForID(SM.getFileID(loc)))
            prefix = fe->getName().str();
    }
    return prefix + "::" + VD->getQualifiedNameAsString();
}

void StripedArrayAnalysis::catalogue(const std::vector<clang::Decl *> &decls) {
    auto add = [&](const clang::ValueDecl *D, clang::QualType QT,
                   uint64_t alignBytes, bool fileStatic,
                   const std::string &typeName) {
        if (QT.isConstQualified()) return;
        const auto *CAT = ctx_.getAsConstantArrayType(QT);
        if (!CAT) return;
        const uint64_t n = CAT->getSize().getZExtValue();
        if (n < 2) return;
        clang::QualType elem = CAT->getElementType();
        if (!canComputeTypeSize(elem, ctx_)) return;
        // stride, not data size: indexing steps by the padded layout size.
        const uint64_t es = ctx_.getTypeSizeInChars(elem).getQuantity();
        if (es == 0) return;
        if (es >= cfg_.cacheLineBytes) {
            // A wider-than-line stride still shares a boundary line when it
            // is not a line multiple, and that holds for any base, so no
            // alignment has to be assumed. Three elements are needed to say
            // so: with two there is a single boundary, and a base can always
            // be found that puts it on a line start.
            if (strideStraddlesLines(es, cfg_.cacheLineBytes)) {
                if (n < 3) return;
            } else {
                // Adjacent slots never share, so FL003 stays silent, but
                // FL004 grades the sweep over exactly these. Bounded because
                // a per-thread slot is a counter or a small struct, and
                // without it every lookup table in the program is catalogued.
                constexpr uint64_t kMaxSlotLines = 4;
                if (es > kMaxSlotLines * cfg_.cacheLineBytes) return;
            }
        }

        std::string key = stripedKeyForDecl(D, ctx_);
        if (key.empty()) return;

        StripedArraySite s;
        s.key = key;
        s.displayName = D->getNameAsString();
        s.typeName = typeName;
        s.elemSizeBytes = es;
        s.elemCount = n;
        s.declAlignBytes = alignBytes;
        s.elementIsAtomic = elem.getCanonicalType()->isAtomicType() ||
                            isStdAtomicRecord(elem);
        s.elementIsVolatile = elem.isVolatileQualified();
        s.isFileStatic = fileStatic;
        const auto &SM = ctx_.getSourceManager();
        auto ploc = SM.getPresumedLoc(SM.getFileLoc(D->getLocation()));
        if (ploc.isValid()) { s.file = ploc.getFilename(); s.line = ploc.getLine(); }
        summary_.emplace(std::move(key), std::move(s));
    };

    for (auto *D : decls) {
        if (auto *VD = llvm::dyn_cast<clang::VarDecl>(D)) {
            // getDeclAlign is undefined on a dependent type and segfaults on
            // decltype in an uninstantiated template. add() checks the element
            // type, but that is too late: this argument is evaluated first.
            if (VD->hasGlobalStorage() && !VD->isConstexpr() &&
                canComputeTypeSize(VD->getType(), ctx_))
                add(VD, VD->getType(),
                    ctx_.getDeclAlign(VD).getQuantity(),
                    VD->getFormalLinkage() == clang::Linkage::Internal, {});
            continue;
        }
        const auto *RD = llvm::dyn_cast<clang::RecordDecl>(D);
        if (!RD || !RD->isCompleteDefinition()) continue;
        if (!canComputeRecordLayout(RD, ctx_)) continue;
        const std::string tn =
            RD->getCanonicalDecl()->getQualifiedNameAsString();
        const auto &layout = ctx_.getASTRecordLayout(RD);
        unsigned idx = 0;
        for (const auto *F : RD->fields()) {
            const uint64_t offBytes = layout.getFieldOffset(idx++) / 8;
            // field alignment within the record is what places the array
            // base; a line-aligned record with the array at a line
            // multiple is the only in-record head-alignment that counts.
            const uint64_t eff =
                (static_cast<uint64_t>(layout.getAlignment().getQuantity()) >=
                     cfg_.cacheLineBytes &&
                 offBytes % cfg_.cacheLineBytes == 0)
                    ? cfg_.cacheLineBytes
                    : ctx_.getTypeAlignInChars(F->getType()).getQuantity();
            add(F, F->getType(), eff, false, tn);
        }
    }
}

void StripedArrayAnalysis::collectAliases(
        const std::vector<clang::Decl *> &decls) {
    for (auto *D : decls) {
        auto *VD = llvm::dyn_cast<clang::VarDecl>(D);
        if (!VD || !VD->hasGlobalStorage() ||
            !VD->getType()->isPointerType())
            continue;
        const clang::Expr *init = VD->getAnyInitializer();
        if (!init) continue;
        init = init->IgnoreParenImpCasts();

        const clang::ValueDecl *target = nullptr;
        uint64_t originElems = 0;
        if (const auto *UO = llvm::dyn_cast<clang::UnaryOperator>(init)) {
            if (UO->getOpcode() != clang::UO_AddrOf) continue;
            const auto *sub = UO->getSubExpr()->IgnoreParenImpCasts();
            const auto *ASE = llvm::dyn_cast<clang::ArraySubscriptExpr>(sub);
            if (!ASE) continue;
            target = baseDeclOf(ASE->getBase());
            clang::Expr::EvalResult r;
            if (ASE->getIdx()->EvaluateAsInt(r, ctx_))
                originElems = r.Val.getInt().getZExtValue();
        } else if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(init)) {
            target = DRE->getDecl();   // array-to-pointer decay
        }
        if (!target) continue;

        auto it = summary_.find(stripedKeyForDecl(target, ctx_));
        if (it == summary_.end()) continue;
        aliases_[stripedKeyForDecl(VD, ctx_)] = it->first;
        if (originElems > 0 &&
            it->second.declAlignBytes >= cfg_.cacheLineBytes)
            it->second.hasHeadPaddingOffset = true;
    }
}

void StripedArrayAnalysis::collectUses(const clang::TranslationUnitDecl *TU) {
    if (summary_.empty() || !TU) return;
    UseVisitor v(ctx_, summary_, aliases_, oracle_, cfg_, threadEntries_);
    v.TraverseDecl(const_cast<clang::TranslationUnitDecl *>(TU));
}

} // namespace lshaz
