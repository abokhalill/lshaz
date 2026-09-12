// SPDX-License-Identifier: Apache-2.0
#include "lshaz/analysis/vocabulary.h"
#include "lshaz/analysis/loop_shape.h"
#include "lshaz/analysis/symbols.h"

#include <clang/AST/ASTConsumer.h>
#include <clang/AST/ASTContext.h>
#include <clang/AST/Attr.h>
#include <clang/AST/Decl.h>
#include <clang/AST/DeclCXX.h>
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Frontend/CompilerInstance.h>

#include <map>
#include <set>

namespace lshaz {

namespace {

// Nothing here matches a name. The reduce phase closes the allocator and freer
// sets over these edges from the libc seeds, which is what lets zmalloc,
// ngx_palloc, palloc and kmalloc be discovered rather than declared.
//
// Sites whose pointee type cannot be named are dropped, so FL020's conjunct
// fails closed rather than guessing.

// A locked read-modify-write written as inline assembly. A codebase whose
// shared-memory mutexes are hand-written "lock cmpxchgl" in an __asm__ block
// has neither an AtomicExpr nor a __sync_ builtin anywhere in the tree. These
// are ISA mnemonics fixed by Intel and ARM, and a lock-prefixed RMW is the
// coherence event FL012 grades rather than a proxy for it.
bool asmIsLockedRMW(llvm::StringRef a) {
    for (const char *m : {"cmpxchg", "xchg", "xadd", "lock bts", "lock btr",
                          "ldrex", "strex", "ldaxr", "stlxr", "casal", "cas ",
                          "swpal", "ldadd"})
        if (a.contains(m))
            return true;
    return false;
}

// Functions whose body performs one. A caller spinning on one of these is
// spinning on the RMW itself, which is the usual shape: the primitive is a
// static inline in a header and the loop is in the acquire wrapper.
class RMWPrimitiveFinder
    : public clang::RecursiveASTVisitor<RMWPrimitiveFinder> {
public:
    RMWPrimitiveFinder(clang::ASTContext &C, std::set<std::string> &out)
        : ctx_(C), out_(out) {}

    bool TraverseFunctionDecl(clang::FunctionDecl *FD) {
        if (!FD || !FD->doesThisDeclarationHaveABody())
            return true;
        const auto *saved = fn_;
        fn_ = FD;
        bool r = clang::RecursiveASTVisitor<
            RMWPrimitiveFinder>::TraverseFunctionDecl(FD);
        fn_ = saved;
        return r;
    }
    bool TraverseCXXMethodDecl(clang::CXXMethodDecl *MD) {
        return TraverseFunctionDecl(MD);
    }
    bool VisitGCCAsmStmt(clang::GCCAsmStmt *S) {
        const auto *lit = S->getAsmString();
        if (fn_ && lit && asmIsLockedRMW(lit->getString()))
            out_.insert(threadRoleNodeName(fn_, ctx_));
        return true;
    }
private:
    clang::ASTContext &ctx_;
    std::set<std::string> &out_;
    const clang::FunctionDecl *fn_ = nullptr;
};

class AllocOwnershipVisitor
    : public clang::RecursiveASTVisitor<AllocOwnershipVisitor> {
public:
    AllocOwnershipVisitor(clang::ASTContext &C, ThreadRoleSummary &out,
                          const std::set<std::string> &rmw)
        : ctx_(C), out_(out), rmw_(rmw) {}

    bool TraverseFunctionDecl(clang::FunctionDecl *FD) {
        if (!FD || !FD->doesThisDeclarationHaveABody())
            return true;
        const auto *savedFn = fn_;
        auto savedVars = std::move(varSource_);
        auto savedTaint = std::move(paramTainted_);
        auto savedIdent = std::move(identLocal_);
        varSource_.clear();
        paramTainted_.clear();
        identLocal_.clear();
        fn_ = FD;
        out_.definedFunctions.insert(threadRoleNodeName(FD, ctx_));
        bool r = clang::RecursiveASTVisitor<
            AllocOwnershipVisitor>::TraverseFunctionDecl(FD);
        fn_ = savedFn;
        varSource_ = std::move(savedVars);
        paramTainted_ = std::move(savedTaint);
        identLocal_ = std::move(savedIdent);
        return r;
    }
    bool TraverseCXXMethodDecl(clang::CXXMethodDecl *MD) {
        return TraverseFunctionDecl(MD);
    }

    using Base = clang::RecursiveASTVisitor<AllocOwnershipVisitor>;
    bool TraverseForStmt(clang::ForStmt *S) {
        const unsigned st = isDegenerateLoop(S, ctx_) ? 0u : 1u;
        loopDepth_ += st; bool r = Base::TraverseForStmt(S);
        loopDepth_ -= st; return r;
    }
    bool TraverseWhileStmt(clang::WhileStmt *S) {
        const unsigned st = isDegenerateLoop(S, ctx_) ? 0u : 1u;
        loopDepth_ += st; bool r = Base::TraverseWhileStmt(S);
        loopDepth_ -= st; return r;
    }
    bool TraverseDoStmt(clang::DoStmt *S) {
        const unsigned st = isDegenerateLoop(S, ctx_) ? 0u : 1u;
        loopDepth_ += st; bool r = Base::TraverseDoStmt(S);
        loopDepth_ -= st; return r;
    }

    // An atomic read-modify-write. Inside a loop it is an acquire spin; on its
    // own it is the release. Both are recorded against the parameter type they
    // operate on, and only the reduce phase decides, since the pairing needs
    // the whole program.
    bool VisitAtomicExpr(clang::AtomicExpr *E) {
        if (fn_ && isRMW(E->getOp()))
            noteSpin(E->getPtr(), nullptr);
        return true;
    }

    // new/delete need no inference: the operator is the allocator.
    bool VisitCXXNewExpr(clang::CXXNewExpr *E) {
        if (fn_)
            noteType(out_.allocatorsOfType, E->getAllocatedType());
        return true;
    }
    bool VisitCXXDeleteExpr(clang::CXXDeleteExpr *E) {
        if (fn_ && E->getArgument())
            noteType(out_.freersOfType, pointee(E->getArgument()->getType()));
        return true;
    }

    // T *p = G(...)
    bool VisitVarDecl(clang::VarDecl *VD) {
        if (!fn_ || !VD || !VD->hasInit())
            return true;
        if (mentionsParam(VD->getInit()))
            paramTainted_.insert(VD->getCanonicalDecl());
        if (int pi = paramIndexOf(VD->getInit()); pi >= 0)
            identLocal_[VD->getCanonicalDecl()] = pi;
        std::string g = calleeOf(VD->getInit());
        if (g.empty())
            return true;
        varSource_[VD->getCanonicalDecl()].insert(g);
        noteSite(out_.allocSitesByCallee, g, pointee(VD->getType()));
        return true;
    }

    // p = G(...). Outnumbers the declaration form in real C.
    bool VisitBinaryOperator(clang::BinaryOperator *BO) {
        if (!fn_ || !BO || BO->getOpcode() != clang::BO_Assign)
            return true;
        if (mentionsParam(BO->getRHS()))
            if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(
                    BO->getLHS()->IgnoreParenImpCasts()))
                if (const auto *VD =
                        llvm::dyn_cast<clang::VarDecl>(DRE->getDecl()))
                    paramTainted_.insert(VD->getCanonicalDecl());
        std::string g = calleeOf(BO->getRHS());
        if (g.empty())
            return true;
        noteSite(out_.allocSitesByCallee, g, pointee(BO->getLHS()->getType()));
        // An allocator wrapper routinely reassigns a variable declared from
        // an earlier call, so tracking only the declaration loses the source
        // that carries the alloc_size attribute.
        if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(
                BO->getLHS()->IgnoreParenImpCasts()))
            if (const auto *VD =
                    llvm::dyn_cast<clang::VarDecl>(DRE->getDecl()))
                varSource_[VD->getCanonicalDecl()].insert(g);
        return true;
    }

    // return G(...), and the factory form: T *p = G(...); ... return p;
    bool VisitReturnStmt(clang::ReturnStmt *RS) {
        if (!fn_ || !RS || !RS->getRetValue())
            return true;
        const clang::Expr *rv = RS->getRetValue()->IgnoreParenImpCasts();
        std::set<std::string> srcs;
        if (std::string g = calleeOf(rv); !g.empty())
            srcs.insert(std::move(g));
        else if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(rv))
            if (const auto *VD =
                    llvm::dyn_cast<clang::VarDecl>(DRE->getDecl())) {
                auto it = varSource_.find(VD->getCanonicalDecl());
                if (it != varSource_.end())
                    srcs = it->second;
            }
        // Several sources means several branches reached this return, and a
        // function allocates if any path through it does.
        //
        // Constructors are excluded. A generic allocator is type-agnostic by
        // construction, while a constructor that happens to allocate returns
        // its own type and its allocation is already a direct site in its
        // body. Propagating through both makes the closure transitively true
        // and useless, since almost anything reaches an allocator in a few
        // hops.
        const bool generic = fn_->getReturnType()
                                 .getCanonicalType()->isVoidPointerType();
        for (const auto &g : srcs) {
            if (generic)
                out_.returnForwards[threadRoleNodeName(fn_, ctx_)].insert(g);
            noteSite(out_.allocSitesByCallee, g, pointee(fn_->getReturnType()));
        }
        return true;
    }

    // G(x) with x a pointer. If x is one of this function's own parameters,
    // F is a release wrapper exactly when G is.
    bool VisitCallExpr(clang::CallExpr *E) {
        if (!fn_ || !E)
            return true;
        const auto *callee = E->getDirectCallee();
        if (!callee || !callee->getIdentifier())
            return true;
        std::string g = threadRoleNodeName(callee, ctx_);
        classifyDecl(callee, g);
        if (E->getNumArgs() < 1)
            return true;
        // GCC and Clang spell these identically and have for twenty years, so
        // matching the prefix is matching the compiler, not a codebase.
        if (callee->getBuiltinID() != 0) {
            llvm::StringRef bn = callee->getName();
            if ((bn.starts_with("__sync_") || bn.starts_with("__atomic_")) &&
                (bn.contains("compare") || bn.contains("exchange") ||
                 bn.contains("test_and_set") || bn.contains("lock_release") ||
                 bn.contains("fetch_")))
                noteSpin(E->getArg(0), E);
        }
        // Thread entries, so the identity fixpoint has a seed in the prepass.
        // Pass two's call graph knows these too, but it runs after the rules
        // that need the answer.
        if (g == "pthread_create" || g == "thrd_create") {
            const unsigned fnArg = (g == "pthread_create") ? 2u : 1u;
            if (E->getNumArgs() > fnArg)
                if (const auto *fref = llvm::dyn_cast<clang::DeclRefExpr>(
                        E->getArg(fnArg)->IgnoreParenImpCasts()))
                    if (const auto *FD = llvm::dyn_cast<clang::FunctionDecl>(
                            fref->getDecl()))
                        out_.threadEntries.insert(threadRoleNodeName(FD, ctx_));
        }
        // "F|i|G|j": this call hands F's parameter i to G's parameter j.
        for (unsigned j = 0; j < E->getNumArgs(); ++j) {
            // Integer arguments only. An identity used as an index is an
            // integer, and propagating into pointer parameters put memset's
            // first argument in the set, which can only ever be noise.
            if (!E->getArg(j)->getType()->isIntegerType()) continue;
            int src = paramIndexOf(E->getArg(j));
            if (src < 0) continue;
            out_.identArgFlow.insert(threadRoleNodeName(fn_, ctx_) + "|" +
                                     std::to_string(src) + "|" + g + "|" +
                                     std::to_string(j));
        }
        if (rmw_.count(g))
            for (unsigned i = 0; i < E->getNumArgs(); ++i)
                if (!paramRootType(E->getArg(i)).empty()) {
                    noteSpin(E->getArg(i), E);
                    break;
                }
        const clang::Expr *a0 = E->getArg(0)->IgnoreImpCasts();
        if (clang::QualType pt = pointee(a0->getType()); !pt.isNull())
            noteSite(out_.freeSitesByCallee, g, pt);
        // Any pointer argument, and the parameter may be reached through
        // arithmetic or a local: a wrapper that backs up to a header prefix
        // and frees that is performing the same release, and requiring a bare
        // parameter reference sees neither it nor the local it passes
        // through.
        bool relaxed = false, strict = false;
        for (unsigned i = 0; i < E->getNumArgs(); ++i) {
            const clang::Expr *a = E->getArg(i)->IgnoreImpCasts();
            if (!a->getType()->isPointerType())
                continue;
            if (!relaxed && mentionsParam(a))
                relaxed = true;
            if (!strict)
                if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(a))
                    strict = llvm::isa<clang::ParmVarDecl>(DRE->getDecl());
        }
        if (relaxed)
            out_.paramForwards[threadRoleNodeName(fn_, ctx_)].insert(g);
        if (strict)
            out_.strictParamForwards[threadRoleNodeName(fn_, ctx_)].insert(g);
        return true;
    }

private:
    // None of this depends on what the function is called. Clang spells
    // __attribute__((malloc)) as RestrictAttr, there is no MallocAttr, and it
    // synthesizes alloc_size onto libc even where the header omits it.
    void classifyDecl(const clang::FunctionDecl *FD, const std::string &n) {
        if (FD->getBuiltinID() != 0)
            out_.builtinCallees.insert(n);
        // Not the bare malloc attribute: glibc marks fopen and opendir that
        // way too, and they do return a fresh block, but this rule grades
        // caller-sized allocation.
        if (FD->hasAttr<clang::AllocSizeAttr>())
            out_.declaredAllocators.insert(n);
        for (const auto *OA : FD->specific_attrs<clang::OwnershipAttr>()) {
            if (OA->getOwnKind() == clang::OwnershipAttr::Returns)
                out_.declaredAllocators.insert(n);
            else if (OA->getOwnKind() == clang::OwnershipAttr::Takes)
                out_.declaredFreers.insert(n);
        }
        // The lock counterpart of alloc_size. Clang's thread-safety attributes
        // say a function acquires or releases a capability, which is the same
        // claim FL012 needs and is what an annotated codebase already tells the
        // compiler. A project carrying these needs no pthread seed to be
        // reached through, and no name in config.
        if (FD->hasAttr<clang::AcquireCapabilityAttr>() ||
            FD->hasAttr<clang::TryAcquireCapabilityAttr>() ||
            FD->hasAttr<clang::ExclusiveTrylockFunctionAttr>() ||
            FD->hasAttr<clang::SharedTrylockFunctionAttr>())
            out_.declaredLocks.insert(n);
        if (FD->hasAttr<clang::ReleaseCapabilityAttr>())
            out_.declaredUnlocks.insert(n);
    }

    // Which parameter of the current function an expression roots at, or -1.
    // Casts and arithmetic are transparent: "(long)arg" and "id - 1" both
    // carry the identity, and a payload struct's field does too.
    int paramIndexOf(const clang::Stmt *S) const {
        if (!S) return -1;
        if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(S)) {
            const auto *D = DRE->getDecl();
            if (const auto *PV = llvm::dyn_cast<clang::ParmVarDecl>(D)) {
                if (PV->getDeclContext() == fn_)
                    return static_cast<int>(PV->getFunctionScopeIndex());
                return -1;
            }
            if (const auto *VD = llvm::dyn_cast<clang::VarDecl>(D)) {
                auto it = identLocal_.find(VD->getCanonicalDecl());
                if (it != identLocal_.end()) return it->second;
            }
            return -1;
        }
        for (const auto *C : S->children())
            if (int r = paramIndexOf(C); r >= 0) return r;
        return -1;
    }

    // void* is the release side of the discipline the return path uses: a
    // function taking a typed pointer is doing its own work and merely happens
    // to release. Accepting those ran the closure away, since nearly every
    // function hands some pointer parameter to something that eventually frees.
    bool mentionsParam(const clang::Stmt *S) const {
        if (!S)
            return false;
        if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(S)) {
            const auto *D = DRE->getDecl();
            if (const auto *PV = llvm::dyn_cast<clang::ParmVarDecl>(D))
                return PV->getType().getCanonicalType()->isVoidPointerType();
            if (const auto *VD = llvm::dyn_cast<clang::VarDecl>(D))
                return paramTainted_.count(VD->getCanonicalDecl()) > 0;
        }
        for (const auto *C : S->children())
            if (mentionsParam(C))
                return true;
        return false;
    }

    static bool isRMW(clang::AtomicExpr::AtomicOp op) {
        switch (op) {
            case clang::AtomicExpr::AO__atomic_compare_exchange:
            case clang::AtomicExpr::AO__atomic_compare_exchange_n:
            case clang::AtomicExpr::AO__atomic_exchange:
            case clang::AtomicExpr::AO__atomic_exchange_n:
            case clang::AtomicExpr::AO__c11_atomic_compare_exchange_strong:
            case clang::AtomicExpr::AO__c11_atomic_compare_exchange_weak:
            case clang::AtomicExpr::AO__c11_atomic_exchange:
                return true;
            default:
                return false;
        }
    }

    // The parameter an atomic operand is rooted at, through field access,
    // address-of and indexing. A spin lock names its lock as a member of the
    // struct it was handed, not as the whole argument.
    std::string paramRootType(const clang::Expr *E) const {
        const clang::Expr *cur = E ? E->IgnoreParenImpCasts() : nullptr;
        while (cur) {
            if (const auto *UO = llvm::dyn_cast<clang::UnaryOperator>(cur)) {
                cur = UO->getSubExpr()->IgnoreParenImpCasts();
                continue;
            }
            if (const auto *ME = llvm::dyn_cast<clang::MemberExpr>(cur)) {
                cur = ME->getBase()->IgnoreParenImpCasts();
                continue;
            }
            if (const auto *AS =
                    llvm::dyn_cast<clang::ArraySubscriptExpr>(cur)) {
                cur = AS->getBase()->IgnoreParenImpCasts();
                continue;
            }
            break;
        }
        const auto *DRE = llvm::dyn_cast_or_null<clang::DeclRefExpr>(cur);
        if (!DRE || !llvm::isa<clang::ParmVarDecl>(DRE->getDecl()))
            return {};
        clang::QualType t = DRE->getDecl()->getType();
        if (auto p = pointee(t); !p.isNull())
            t = p;
        return typeKey(t);
    }

    // Which side a compare-exchange is depends on what it publishes, not on
    // whether a loop surrounds it: a release stores zero, an acquire stores the
    // owner. ngx_shmtx_trylock has no loop and is still an acquire, and grading
    // it as a release decrements FL012's nesting depth on a try.
    void noteSpin(const clang::Expr *operand, const clang::CallExpr *E) {
        // The operand's own type, independent of whether it roots at a
        // parameter: an atomic global is still an atomic.
        if (operand)
            if (std::string a = sugaredTypeName(pointee(operand->getType()));
                !a.empty())
                out_.atomicTypes.insert(a);
        std::string t = paramRootType(operand);
        if (t.empty())
            return;
        bool release = loopDepth_ == 0;
        if (E && E->getNumArgs() >= 3) {
            clang::Expr::EvalResult r;
            if (E->getArg(2)->EvaluateAsInt(r, ctx_))
                release = r.Val.getInt() == 0;
            else
                release = false;
        }
        (release ? out_.spinReleaseOfType : out_.spinAcquireOfType)[t]
            .insert(threadRoleNodeName(fn_, ctx_));
    }

    static clang::QualType pointee(clang::QualType QT) {
        if (QT.isNull())
            return {};
        const auto *PT = QT->getAs<clang::PointerType>();
        return PT ? PT->getPointeeType() : clang::QualType();
    }

    std::string calleeOf(const clang::Expr *E) const {
        const auto *CE = llvm::dyn_cast_or_null<clang::CallExpr>(
            E ? E->IgnoreParenImpCasts() : nullptr);
        if (!CE)
            return {};
        const auto *callee = CE->getDirectCallee();
        if (!callee || !callee->getIdentifier())
            return {};
        return threadRoleNodeName(callee, ctx_);
    }

    // The written name, not the canonical one. ngx_atomic_t canonicalizes to
    // unsigned long, and feeding that to the false-sharing rules would mark
    // every unsigned long field in the program atomic. Only a typedef or a
    // record qualifies, so a bare builtin operand contributes nothing.
    static std::string sugaredTypeName(clang::QualType QT) {
        if (QT.isNull())
            return {};
        QT = QT.getLocalUnqualifiedType();
        if (const auto *TT = QT->getAs<clang::TypedefType>())
            return TT->getDecl()->getName().str();
        if (const auto *RD = QT->getAsRecordDecl();
            RD && !RD->getName().empty())
            return RD->getCanonicalDecl()->getQualifiedNameAsString();
        return {};
    }

    std::string typeKey(clang::QualType QT) const {
        if (QT.isNull())
            return {};
        QT = QT.getCanonicalType().getUnqualifiedType();
        if (QT->isVoidType() || QT->isDependentType() || QT->isIncompleteType())
            return {};
        const auto *RD = QT->getAsRecordDecl();
        std::string n = RD ? RD->getCanonicalDecl()->getQualifiedNameAsString()
                           : QT.getAsString();
        return n;
    }

    void noteType(std::map<std::string, std::set<std::string>> &dst,
                  clang::QualType QT) {
        std::string n = typeKey(QT);
        if (!n.empty())
            dst[n].insert(threadRoleNodeName(fn_, ctx_));
    }

    void noteSite(std::map<std::string, std::set<std::string>> &dst,
                  const std::string &callee, clang::QualType QT) {
        std::string n = typeKey(QT);
        if (!n.empty())
            dst[callee].insert(threadRoleNodeName(fn_, ctx_) + "|" + n);
    }

    clang::ASTContext &ctx_;
    ThreadRoleSummary &out_;
    const clang::FunctionDecl *fn_ = nullptr;
    std::map<const clang::VarDecl *, std::set<std::string>> varSource_;
    std::set<const clang::VarDecl *> paramTainted_;
    std::map<const clang::VarDecl *, int> identLocal_;
    const std::set<std::string> &rmw_;
    unsigned loopDepth_ = 0;
};

class VocabularyConsumer : public clang::ASTConsumer {
public:
    explicit VocabularyConsumer(ThreadRoleSummary &out) : out_(out) {}

    void HandleTranslationUnit(clang::ASTContext &Ctx) override {
        if (Ctx.getDiagnostics().hasFatalErrorOccurred())
            return;
        collectAllocOwnership(Ctx, out_);
    }

private:
    ThreadRoleSummary &out_;
};

} // anonymous namespace

void collectAllocOwnership(clang::ASTContext &Ctx, ThreadRoleSummary &out) {
    // Which functions are RMW primitives has to be known before the main walk,
    // since a spin loop calls one rather than containing it.
    std::set<std::string> rmw;
    RMWPrimitiveFinder f(Ctx, rmw);
    f.TraverseDecl(Ctx.getTranslationUnitDecl());
    AllocOwnershipVisitor v(Ctx, out, rmw);
    v.TraverseDecl(Ctx.getTranslationUnitDecl());
}

void collectReadFiles(clang::CompilerInstance &CI,
                      std::vector<std::string> &out) {
    const auto &SM = CI.getSourceManager();
    std::set<std::string> uniq;
    for (auto it = SM.fileinfo_begin(); it != SM.fileinfo_end(); ++it) {
        llvm::StringRef n = it->first.getName();
        if (!n.empty())
            uniq.insert(n.str());
    }
    // The main file is not always among the fileinfos, and a cache entry that
    // does not depend on its own source is the worst possible entry.
    if (auto id = SM.getMainFileID(); id.isValid())
        if (const auto *fe = SM.getFileEntryForID(id))
            uniq.insert(fe->getName().str());
    out.assign(uniq.begin(), uniq.end());
}

std::unique_ptr<clang::ASTConsumer>
VocabularyAction::CreateASTConsumer(clang::CompilerInstance & /*CI*/,
                                    llvm::StringRef /*file*/) {
    return std::make_unique<VocabularyConsumer>(out_);
}

void VocabularyAction::EndSourceFileAction() {
    if (deps_)
        collectReadFiles(getCompilerInstance(), *deps_);
}

} // namespace lshaz
