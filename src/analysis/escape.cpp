// SPDX-License-Identifier: Apache-2.0
#include "lshaz/analysis/escape.h"
#include "lshaz/analysis/loop_shape.h"

#include "lshaz/analysis/atomics.h"
#include "lshaz/analysis/types.h"
#include "lshaz/analysis/symbols.h"
#include "lshaz/core/diagnostic.h"

#include <clang/AST/Decl.h>
#include <clang/AST/DeclCXX.h>
#include <clang/AST/DeclTemplate.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Type.h>

#include <functional>
#include <vector>

namespace lshaz {

EscapeAnalysis::EscapeAnalysis(clang::ASTContext &Ctx) : ctx_(Ctx) {}

namespace {

// Resolve through typedefs/aliases to the underlying CXXRecordDecl.
const clang::CXXRecordDecl *getUnderlyingRecord(clang::QualType QT) {
    QT = QT.getCanonicalType();
    QT = QT.getNonReferenceType();
    if (const auto *TST = QT->getAs<clang::TemplateSpecializationType>()) {
        if (auto TD = TST->getTemplateName().getAsTemplateDecl()) {
            if (auto *RD = llvm::dyn_cast_or_null<clang::CXXRecordDecl>(
                    TD->getTemplatedDecl()))
                return RD;
        }
    }
    return QT->getAsCXXRecordDecl();
}

bool isQualifiedNameOneOf(const clang::CXXRecordDecl *RD,
                          const std::initializer_list<const char *> &names) {
    if (!RD)
        return false;
    std::string qn = RD->getQualifiedNameAsString();
    for (const char *n : names)
        if (qn == n)
            return true;
    return false;
}

} // anonymous namespace

bool EscapeAnalysis::isAtomicType(clang::QualType QT) const {
    QT = peelArrays(QT);

    // Opaque wrappers named in config (atomic_t, ngx_atomic_t). Checked
    // first: the point of the option is that these types carry no other
    // evidence. Without it hasAtomicMembers, and so FL040 and FL060, were
    // blind on exactly the C codebases the option exists for.
    if (isConfiguredAtomic(QT, atomicTypeNames_))
        return true;

    // C11 _Atomic qualifier.
    if (QT.getCanonicalType()->isAtomicType())
        return true;

    // std::atomic<T>, match via template specialization.
    const clang::CXXRecordDecl *RD = getUnderlyingRecord(QT);
    if (isQualifiedNameOneOf(RD, {"std::atomic", "std::atomic_ref"}))
        return true;

    // ClassTemplateSpecializationDecl path for instantiated types.
    if (RD) {
        if (const auto *CTSD = llvm::dyn_cast<clang::ClassTemplateSpecializationDecl>(RD)) {
            if (auto *TD = CTSD->getSpecializedTemplate()) {
                std::string tn = TD->getQualifiedNameAsString();
                if (tn == "std::atomic" || tn == "std::atomic_ref")
                    return true;
            }
        }
    }

    return false;
}

bool EscapeAnalysis::isSyncType(clang::QualType QT) const {
    QT = peelArrays(QT);
    const clang::CXXRecordDecl *RD = getUnderlyingRecord(QT);
    if (isQualifiedNameOneOf(RD, {
            "std::mutex", "std::recursive_mutex",
            "std::shared_mutex", "std::timed_mutex",
            "std::recursive_timed_mutex", "std::shared_timed_mutex",
            "std::condition_variable", "std::condition_variable_any",
            "std::counting_semaphore", "std::binary_semaphore",
            "std::latch", "std::barrier"}))
        return true;

    // POSIX sync types (C structs, no CXXRecordDecl).
    std::string canon = QT.getCanonicalType().getAsString();
    for (const char *posix : {"pthread_mutex_t", "pthread_spinlock_t",
                              "pthread_rwlock_t", "pthread_cond_t",
                              "sem_t"})
        if (canon.find(posix) != std::string::npos)
            return true;

    return false;
}

bool EscapeAnalysis::hasAtomicMembers(const clang::RecordDecl *RD) const {
    if (!RD || !RD->isCompleteDefinition())
        return false;

    for (const auto *field : RD->fields()) {
        if (isAtomicType(field->getType()))
            return true;
    }

    // Check bases (C++ only).
    if (const auto *CXXRD = llvm::dyn_cast<clang::CXXRecordDecl>(RD)) {
        for (const auto &base : CXXRD->bases()) {
            if (const auto *baseRD = base.getType()->getAsCXXRecordDecl()) {
                if (hasAtomicMembers(baseRD))
                    return true;
            }
        }
    }

    return false;
}

bool EscapeAnalysis::hasSyncPrimitives(const clang::RecordDecl *RD) const {
    if (!RD || !RD->isCompleteDefinition())
        return false;

    for (const auto *field : RD->fields()) {
        if (isSyncType(field->getType()))
            return true;
    }

    if (const auto *CXXRD = llvm::dyn_cast<clang::CXXRecordDecl>(RD)) {
        for (const auto &base : CXXRD->bases()) {
            if (const auto *baseRD = base.getType()->getAsCXXRecordDecl()) {
                if (hasSyncPrimitives(baseRD))
                    return true;
            }
        }
    }

    return false;
}

EscapeVerdict EscapeAnalysis::escapeVerdict(const clang::RecordDecl *RD) const {
    EscapeVerdict v;
    if (!RD)
        return v;

    v.hasAtomics     = hasAtomicMembers(RD);
    v.hasSyncPrims   = hasSyncPrimitives(RD);
    v.hasSharedOwner = hasSharedOwnershipMembers(RD);
    v.hasVolatile    = hasVolatileMembers(RD);

    // Lazy, idempotent after first call.
    const_cast<EscapeAnalysis *>(this)->scanTranslationUnit(
        ctx_.getTranslationUnitDecl());
    v.hasPublication = hasPublicationEvidence(RD);
    v.hasThreadWriters = hasThreadEntryWriters(RD);
    v.hasGlobalInstance = hasGlobalInstance(RD);

    // Two cores can write one line only if they reach the same object. That
    // needs a shared instance AND a thread that touches it, either an
    // address crossing a thread boundary, or a file-scope object whose
    // writers run on threads. Stated once here because three rules were
    // each re-deriving it, and each got a different answer.
    v.hasSharingRoute = v.hasPublication || v.hasThreadWriters ||
                        (v.hasGlobalInstance && anyWriterOnThread(RD));

    v.escapes = v.hasAtomics || v.hasSyncPrims || v.hasSharedOwner ||
                v.hasVolatile || v.hasPublication || v.hasThreadWriters ||
                v.hasGlobalInstance;

    // Accessor count: how many functions in this TU touch the type?
    if (const auto *canon = llvm::dyn_cast<clang::RecordDecl>(RD->getCanonicalDecl())) {
        auto it = typeAccessorCounts_.find(canon);
        if (it != typeAccessorCounts_.end())
            v.accessorCount = it->second;
    }

    if (!v.escapes)
        return v;

    // Contention scoring: weights reflect coherence invalidation cost.
    // atomics > volatile > sync > shared_ptr > publication
    double score = 0.0;
    if (v.hasAtomics)     score += 0.40;
    if (v.hasVolatile)    score += 0.25;
    if (v.hasSyncPrims)   score += 0.15;
    if (v.hasSharedOwner) score += 0.10;
    if (v.hasPublication) score += 0.10;
    if (v.hasThreadWriters) score += 0.20;
    if (v.hasAtomics && v.hasSyncPrims)
        score += 0.15; // compound: lock + atomic = contended

    // Accessor count modulation: single-accessor = init-only pattern.
    // Many accessors = wider contention surface.
    if (v.accessorCount <= 1)
        score *= 0.5;
    else if (v.accessorCount >= 6)
        score = std::min(score * 1.2, 1.0);

    v.contention = score > 1.0 ? 1.0 : score;

    // Access pattern: atomics → RMW, volatile alone → read-heavy (MMIO/signal).
    if (v.hasAtomics)
        v.pattern = AccessPattern::ReadWrite;
    else if (v.hasVolatile && !v.hasSyncPrims)
        v.pattern = AccessPattern::ReadOnly;
    else if (v.hasSyncPrims)
        v.pattern = AccessPattern::ReadWrite;
    else if (v.hasSharedOwner || v.hasPublication)
        v.pattern = AccessPattern::ReadOnly;

    return v;
}

bool EscapeAnalysis::mayEscapeThread(const clang::RecordDecl *RD) const {
    return escapeVerdict(RD).escapes;
}

bool EscapeAnalysis::hasPublicationEvidence(const clang::RecordDecl *RD) const {
    if (!RD || publishedTypes_.empty())
        return false;
    const auto *canon = RD->getCanonicalDecl();
    if (!canon)
        return false;
    return publishedTypes_.count(canon->getQualifiedNameAsString()) > 0;
}

EscapeAnalysis::GlobalWriterEvidence
EscapeAnalysis::globalWriterEvidence(const clang::VarDecl *VD) const {
    GlobalWriterEvidence e;
    if (!VD) return e;
    auto it = globalWriters_.find(VD->getCanonicalDecl());
    if (it == globalWriters_.end()) return e;
    e.writerFunctions = static_cast<unsigned>(it->second.size());
    for (const auto *w : it->second)
        if (threadEntries_.count(w->getCanonicalDecl())) {
            e.writtenFromThreadEntry = true;
            break;
        }
    return e;
}

void EscapeAnalysis::markThreadEntry(const clang::Expr *E) {
    if (!E) return;
    E = E->IgnoreParenImpCasts();
    if (const auto *UO = llvm::dyn_cast<clang::UnaryOperator>(E))
        if (UO->getOpcode() == clang::UO_AddrOf)
            E = UO->getSubExpr()->IgnoreParenImpCasts();
    if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(E))
        if (const auto *FD = llvm::dyn_cast<clang::FunctionDecl>(DRE->getDecl()))
            threadEntries_.insert(FD->getCanonicalDecl());
}

// Any writer of any field runs on a thread -- entry itself, or a pool role.
// Deliberately drops hasThreadEntryWriters' ">= 2 writer functions" clause:
// one function running on N pool threads already puts two cores on the line,
// and requiring a second function is what hid the thread-pool shape.
bool EscapeAnalysis::anyWriterOnThread(const clang::RecordDecl *RD) const {
    if (!RD || (threadEntries_.empty() && poolRoleWriters_.empty()))
        return false;
    for (const auto *field : RD->fields()) {
        auto it = fieldWrites_.find(
            llvm::dyn_cast_or_null<clang::FieldDecl>(field->getCanonicalDecl()));
        if (it == fieldWrites_.end())
            continue;
        for (const auto *w : it->second.writers) {
            const auto *c = w->getCanonicalDecl();
            if (threadEntries_.count(c) || poolRoleWriters_.count(c))
                return true;
        }
    }
    return false;
}

// Shared because two functions write it and at least one of them runs on a
// spawned thread. Weaker than publication about *when* the writes overlap,
// which is why it moves confidence rather than severity downstream.
bool EscapeAnalysis::hasThreadEntryWriters(const clang::RecordDecl *RD) const {
    if (!RD || threadEntries_.empty())
        return false;
    std::unordered_set<const clang::FunctionDecl *> writers;
    bool onThread = false;
    for (const auto *field : RD->fields()) {
        auto it = fieldWrites_.find(
            llvm::dyn_cast_or_null<clang::FieldDecl>(field->getCanonicalDecl()));
        if (it == fieldWrites_.end())
            continue;
        for (const auto *w : it->second.writers) {
            writers.insert(w);
            if (threadEntries_.count(w->getCanonicalDecl()))
                onThread = true;
        }
    }
    return onThread && writers.size() >= 2;
}

namespace {
// getAsCXXRecordDecl() is null for a C struct, so any caller using it
// silently skipped all of C, which is most of what the tool is aimed at.
std::string recordKeyOf(clang::QualType QT) {
    QT = peelArrays(QT.getCanonicalType().getNonReferenceType());
    while (QT->isPointerType() || QT->isReferenceType())
        QT = peelArrays(QT->getPointeeType().getCanonicalType());
    if (const auto *RD = QT->getAsRecordDecl())
        if (const auto *canon = RD->getCanonicalDecl())
            return canon->getQualifiedNameAsString();
    return {};
}
} // namespace

void EscapeAnalysis::markPublished(clang::QualType QT) {
    if (std::string k = recordKeyOf(QT); !k.empty())
        publishedTypes_.insert(std::move(k));
}

void EscapeAnalysis::markGlobalInstance(clang::QualType QT,
                                        const std::string &varName) {
    std::string k = recordKeyOf(QT);
    if (k.empty())
        return;
    // The linker name is what a runtime trace reports, and the type name is
    // what a finding reports. Carrying both is what lets the two be joined
    // without re-deriving it from DWARF.
    if (!varName.empty())
        globalInstanceNames_[k].insert(varName);
    globalInstanceTypes_.insert(std::move(k));
}

std::string EscapeAnalysis::globalInstanceNames(
        const clang::RecordDecl *RD) const {
    if (!RD)
        return {};
    auto it = globalInstanceNames_.find(
        RD->getCanonicalDecl()->getQualifiedNameAsString());
    if (it == globalInstanceNames_.end())
        return {};
    std::string out;
    for (const auto &n : it->second) {
        if (!out.empty()) out += ';';
        out += n;
    }
    return out;
}

bool EscapeAnalysis::hasStandingWrites(const clang::RecordDecl *RD) const {
    if (!RD)
        return false;
    for (const auto *field : RD->fields()) {
        auto it = fieldWrites_.find(
            llvm::dyn_cast_or_null<clang::FieldDecl>(field->getCanonicalDecl()));
        if (it != fieldWrites_.end() && it->second.standingSites > 0)
            return true;
    }
    return false;
}

bool EscapeAnalysis::hasGlobalInstance(const clang::RecordDecl *RD) const {
    if (!RD || globalInstanceTypes_.empty())
        return false;
    const auto *canon = RD->getCanonicalDecl();
    return canon && globalInstanceTypes_.count(
                        canon->getQualifiedNameAsString()) > 0;
}

namespace {

// Visitor that collects types passed to thread-creation APIs.
class PublicationVisitor
    : public clang::RecursiveASTVisitor<PublicationVisitor> {
public:
    explicit PublicationVisitor(EscapeAnalysis &ea) : ea_(ea) {}

    bool VisitCXXConstructExpr(clang::CXXConstructExpr *E) {
        const auto *CD = E->getConstructor();
        if (!CD)
            return true;
        std::string parentName;
        if (const auto *CTSD =
                llvm::dyn_cast<clang::ClassTemplateSpecializationDecl>(
                    CD->getParent())) {
            if (auto *TD = CTSD->getSpecializedTemplate())
                parentName = TD->getQualifiedNameAsString();
        }
        if (parentName.empty())
            parentName = CD->getParent()->getQualifiedNameAsString();

        // std::thread, std::jthread constructor args are published.
        if (parentName == "std::thread" || parentName == "std::jthread") {
            for (unsigned i = 0; i < E->getNumArgs(); ++i) {
                ea_.markPublished(E->getArg(i)->getType());
                ea_.markThreadEntry(E->getArg(i));
            }
        }
        return true;
    }

    bool VisitCallExpr(clang::CallExpr *E) {
        if (const auto *callee = E->getDirectCallee()) {
            std::string name = callee->getQualifiedNameAsString();
            // std::async publishes all callable and argument types.
            if (name == "std::async") {
                for (unsigned i = 0; i < E->getNumArgs(); ++i) {
                    ea_.markPublished(E->getArg(i)->getType());
                    ea_.markThreadEntry(E->getArg(i));
                }
            }
            if (name == "pthread_create" && E->getNumArgs() >= 3)
                ea_.markThreadEntry(E->getArg(2));
        }
        return true;
    }

private:
    EscapeAnalysis &ea_;
};

} // anonymous namespace

void EscapeAnalysis::scanTranslationUnit(const clang::TranslationUnitDecl *TU) {
    if (tuScanned_ || !TU)
        return;
    tuScanned_ = true;

    // one recursive walk feeding every pass. the previous four loops
    // iterated TU->decls() top-level only: publication evidence, global
    // write counts (FL040's map input) and accessor counts were blind to
    // anything inside a namespace or a method body  i.e. most real C++.
    // CallGraph already recursed; the asymmetry was the bug.
    std::vector<const clang::VarDecl *> globals;
    std::vector<const clang::FunctionDecl *> bodies;
    std::function<void(const clang::DeclContext *)> walk =
        [&](const clang::DeclContext *DC) {
            for (const auto *D : DC->decls()) {
                if (const auto *NS = llvm::dyn_cast<clang::NamespaceDecl>(D)) {
                    walk(NS);
                } else if (const auto *LS =
                               llvm::dyn_cast<clang::LinkageSpecDecl>(D)) {
                    walk(LS);
                } else if (const auto *VD = llvm::dyn_cast<clang::VarDecl>(D)) {
                    globals.push_back(VD);
                } else if (const auto *FD =
                               llvm::dyn_cast<clang::FunctionDecl>(D)) {
                    if (FD->doesThisDeclarationHaveABody() &&
                        !FD->isDependentContext())
                        bodies.push_back(FD);
                } else if (const auto *RD =
                               llvm::dyn_cast<clang::CXXRecordDecl>(D)) {
                    if (RD->isCompleteDefinition() && !RD->isDependentType())
                        walk(RD);
                }
            }
        };
    walk(TU);

    // Pass 1: global/static mutable variable types. Kept separate from
    // pass 2 because they answer different questions. A file-scope instance
    // means threads that reach it reach the *same object* -- necessary for
    // false sharing, since per-request instances never collide. It does not
    // by itself mean any thread reaches it; that is pass 2's job. Merging
    // them made "is a global" indistinguishable from "is shared".
    for (const auto *VD : globals) {
        if (isGlobalSharedMutable(VD))
            markGlobalInstance(VD->getType(), VD->getNameAsString());
    }

    // Pass 2: thread-creation call sites across all function bodies.
    PublicationVisitor visitor(*this);
    for (const auto *FD : bodies)
        visitor.TraverseStmt(const_cast<clang::Stmt *>(FD->getBody()));

    // Pass 3: count write sites per global for write-once analysis.
    collectGlobalWriteSites(bodies);

    // Pass 4: count distinct functions accessing each record type.
    collectTypeAccessors(bodies);
}

bool EscapeAnalysis::isFieldMutable(const clang::FieldDecl *FD) const {
    if (!FD)
        return false;

    // Explicitly mutable keyword.
    if (FD->isMutable())
        return true;

    if (!FD->getType().isConstQualified())
        return true;

    return false;
}

bool EscapeAnalysis::isGlobalSharedMutable(const clang::VarDecl *VD) const {
    if (!VD)
        return false;

    // Must be global or static.
    if (!VD->hasGlobalStorage())
        return false;

    // Must not be const.
    if (VD->getType().isConstQualified())
        return false;

    // thread_local is not shared.
    if (VD->getTSCSpec() == clang::ThreadStorageClassSpecifier::TSCS_thread_local)
        return false;

    return true;
}

bool EscapeAnalysis::isSharedOwnershipType(clang::QualType QT) const {
    const clang::CXXRecordDecl *RD = getUnderlyingRecord(QT);
    if (isQualifiedNameOneOf(RD, {"std::shared_ptr", "std::weak_ptr"}))
        return true;

    if (RD) {
        if (const auto *CTSD = llvm::dyn_cast<clang::ClassTemplateSpecializationDecl>(RD)) {
            if (auto *TD = CTSD->getSpecializedTemplate()) {
                std::string tn = TD->getQualifiedNameAsString();
                if (tn == "std::shared_ptr" || tn == "std::weak_ptr")
                    return true;
            }
        }
    }

    return false;
}

bool EscapeAnalysis::hasSharedOwnershipMembers(const clang::RecordDecl *RD) const {
    if (!RD || !RD->isCompleteDefinition())
        return false;

    for (const auto *field : RD->fields()) {
        if (isSharedOwnershipType(field->getType()))
            return true;
    }

    if (const auto *CXXRD = llvm::dyn_cast<clang::CXXRecordDecl>(RD)) {
        for (const auto &base : CXXRD->bases()) {
            if (const auto *baseRD = base.getType()->getAsCXXRecordDecl()) {
                if (hasSharedOwnershipMembers(baseRD))
                    return true;
            }
        }
    }

    return false;
}

bool EscapeAnalysis::hasCallbackMembers(const clang::RecordDecl *RD) const {
    if (!RD || !RD->isCompleteDefinition())
        return false;

    for (const auto *field : RD->fields()) {
        if (field->getType()->isFunctionPointerType())
            return true;

        const clang::CXXRecordDecl *FRD = getUnderlyingRecord(field->getType());
        if (isQualifiedNameOneOf(FRD, {"std::function"}))
            return true;
        if (FRD) {
            if (const auto *CTSD = llvm::dyn_cast<clang::ClassTemplateSpecializationDecl>(FRD)) {
                if (auto *TD = CTSD->getSpecializedTemplate()) {
                    if (TD->getQualifiedNameAsString() == "std::function")
                        return true;
                }
            }
        }
    }

    return false;
}

bool EscapeAnalysis::hasVolatileMembers(const clang::RecordDecl *RD) const {
    if (!RD || !RD->isCompleteDefinition())
        return false;

    for (const auto *field : RD->fields()) {
        if (peelArrays(field->getType()).isVolatileQualified())
            return true;
    }

    if (const auto *CXXRD = llvm::dyn_cast<clang::CXXRecordDecl>(RD)) {
        for (const auto &base : CXXRD->bases()) {
            if (const auto *baseRD = base.getType()->getAsCXXRecordDecl()) {
                if (hasVolatileMembers(baseRD))
                    return true;
            }
        }
    }

    return false;
}

namespace {

// Counts writes to globals and record fields in one traversal. A write:
// LHS of assignment/compound-assignment, ++/-- operand, receiver of a
// non-const mutating atomic method, target of a C11/GNU atomic
// store/RMW. Constructor member-init lists excluded: init is not
// contention.
class GlobalWriteVisitor
    : public clang::RecursiveASTVisitor<GlobalWriteVisitor> {
public:
    using FieldWrites =
        std::unordered_map<const clang::FieldDecl *,
                           EscapeAnalysis::FieldWriteRecord>;

    using GlobalWriters =
        std::unordered_map<const clang::VarDecl *,
                           std::unordered_set<const clang::FunctionDecl *>>;

    std::unordered_map<const clang::VarDecl *, unsigned> &counts;
    std::unordered_map<const clang::VarDecl *, unsigned> &loopCounts;
    FieldWrites &fieldWrites;
    GlobalWriters &globalWriters;
    std::unordered_set<const clang::FunctionDecl *> &opaqueCallFns;
    const clang::ASTContext &ctx;
    const clang::FunctionDecl *currentFn = nullptr;
    unsigned loopDepth = 0;

    GlobalWriteVisitor(
        std::unordered_map<const clang::VarDecl *, unsigned> &c,
        std::unordered_map<const clang::VarDecl *, unsigned> &lc,
        FieldWrites &fw, GlobalWriters &gw,
        std::unordered_set<const clang::FunctionDecl *> &ocf,
        const clang::ASTContext &Ctx)
        : counts(c), loopCounts(lc), fieldWrites(fw), globalWriters(gw),
          opaqueCallFns(ocf), ctx(Ctx) {}

    // A syntactic loop that cannot repeat contributes no write rate. See
    // isDegenerateLoop: do/while(0) is how C wraps a macro.
    unsigned loopStep(const clang::Stmt *S) const {
        return isDegenerateLoop(S, ctx) ? 0u : 1u;
    }

    // write rate, not site count, is what coherence sees: a write under
    // any of these is repeatable per iteration.
    // Lambda bodies execute on invocation, not in the enclosing frame:
    // writes attribute to the lambda's own node (a worker lambda's writes
    // must not read as the spawner's) and enclosing loop depth does not
    // apply.
    bool TraverseLambdaExpr(clang::LambdaExpr *LE) {
        for (auto *init : LE->capture_inits())
            if (init && !TraverseStmt(init))
                return false;
        const auto *prevFn = currentFn;
        unsigned prevDepth = loopDepth;
        currentFn = LE->getCallOperator();
        loopDepth = 0;
        bool r = true;
        if (auto *Body = LE->getBody())
            r = TraverseStmt(Body);
        currentFn = prevFn;
        loopDepth = prevDepth;
        return r;
    }

    bool TraverseForStmt(clang::ForStmt *S) {
        const unsigned step = loopStep(S);
        loopDepth += step;
        bool r = RecursiveASTVisitor::TraverseForStmt(S);
        loopDepth -= step;
        return r;
    }
    bool TraverseWhileStmt(clang::WhileStmt *S) {
        const unsigned step = loopStep(S);
        loopDepth += step;
        bool r = RecursiveASTVisitor::TraverseWhileStmt(S);
        loopDepth -= step;
        return r;
    }
    bool TraverseDoStmt(clang::DoStmt *S) {
        const unsigned step = loopStep(S);
        loopDepth += step;
        bool r = RecursiveASTVisitor::TraverseDoStmt(S);
        loopDepth -= step;
        return r;
    }
    bool TraverseCXXForRangeStmt(clang::CXXForRangeStmt *S) {
        const unsigned step = loopStep(S);
        loopDepth += step;
        bool r = RecursiveASTVisitor::TraverseCXXForRangeStmt(S);
        loopDepth -= step;
        return r;
    }

    bool VisitBinaryOperator(clang::BinaryOperator *BO) {
        if (!BO->isAssignmentOp())
            return true;
        recordWrite(BO->getLHS());
        return true;
    }

    // Every member access that is not itself a store target. A compound
    // assignment reads and writes, and is deliberately booked only as a
    // write: it already trades the line, so counting it as a reader too
    // would let a field pair with itself.
    bool VisitMemberExpr(clang::MemberExpr *ME) {
        if (writeTargets.count(ME))
            return true;
        const auto *FD =
            llvm::dyn_cast<clang::FieldDecl>(ME->getMemberDecl());
        if (!FD) return true;
        auto &rec =
            fieldWrites[llvm::cast<clang::FieldDecl>(FD->getCanonicalDecl())];
        ++rec.readSites;
        if (rootsAtGlobal(ME->getBase()))
            ++rec.standingReadSites;
        else
            ++rec.handedReadSites;
        if (currentFn)
            rec.readers.insert(currentFn->getCanonicalDecl());
        return true;
    }

    bool VisitUnaryOperator(clang::UnaryOperator *UO) {
        if (UO->isIncrementDecrementOp())
            recordWrite(UO->getSubExpr());
        return true;
    }

    bool VisitCXXOperatorCallExpr(clang::CXXOperatorCallExpr *CE) {
        auto op = CE->getOperator();
        if (op >= clang::OO_Equal && op <= clang::OO_PipeEqual) {
            if (CE->getNumArgs() > 0)
                recordWrite(CE->getArg(0));
        }
        if (op == clang::OO_PlusPlus || op == clang::OO_MinusMinus) {
            if (CE->getNumArgs() > 0)
                recordWrite(CE->getArg(0));
        }
        return true;
    }

    bool VisitCXXMemberCallExpr(clang::CXXMemberCallExpr *CE) {
        const auto *MD = CE->getMethodDecl();
        // const gate: a user type with a method merely named 'store'
        // must not mint write evidence; atomic mutators are non-const.
        if (!MD || !MD->getIdentifier() || MD->isConst())
            return true;
        llvm::StringRef n = MD->getName();
        if (n == "store" || n == "exchange" || n.starts_with("fetch_") ||
            n.starts_with("compare_exchange"))
            recordWrite(CE->getImplicitObjectArgument());
        return true;
    }

    bool VisitAtomicExpr(clang::AtomicExpr *AE) {
        auto op = AE->getOp();
        if (op == clang::AtomicExpr::AO__c11_atomic_load ||
            op == clang::AtomicExpr::AO__atomic_load ||
            op == clang::AtomicExpr::AO__atomic_load_n ||
            op == clang::AtomicExpr::AO__c11_atomic_init)
            return true;
        recordWrite(AE->getPtr());
        return true;
    }

    bool VisitCallExpr(clang::CallExpr *CE) {
        const auto *callee = CE->getDirectCallee();
        // A body this TU cannot see (syscall, libc, cross-TU) dominates the
        // interval between two writes in the same function; what separates
        // a per-request counter from a per-iteration one. Indirect calls
        // count: same situation, less information.
        if (currentFn && (!callee || !callee->hasBody()))
            opaqueCallFns.insert(currentFn->getCanonicalDecl());
        if (!callee) return true;
        const auto *II = callee->getIdentifier();
        if (!II) return true;
        llvm::StringRef n = II->getName();
        if (n.starts_with("__sync_") && n != "__sync_synchronize" &&
            CE->getNumArgs() > 0)
            recordWrite(CE->getArg(0));
        return true;
    }

private:
    // Pre-order traversal reaches the assignment before its LHS, so a
    // MemberExpr already booked as a write is in here by the time
    // VisitMemberExpr sees it.
    std::unordered_set<const clang::MemberExpr *> writeTargets;

    void recordWrite(const clang::Expr *E) {
        if (!E) return;
        E = E->IgnoreParenImpCasts();
        // &member as an atomic-builtin target.
        if (const auto *UO = llvm::dyn_cast<clang::UnaryOperator>(E))
            if (UO->getOpcode() == clang::UO_AddrOf)
                E = UO->getSubExpr()->IgnoreParenImpCasts();
        // A write to arr[i] is a write to the field `arr`. Without this the
        // element writes of every striped counter resolve to nothing, and
        // the array reads as never written.
        while (const auto *ASE = llvm::dyn_cast<clang::ArraySubscriptExpr>(E))
            E = ASE->getBase()->IgnoreParenImpCasts();
        if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(E)) {
            if (const auto *VD = llvm::dyn_cast<clang::VarDecl>(DRE->getDecl())) {
                if (VD->hasGlobalStorage()) {
                    const auto *cv = VD->getCanonicalDecl();
                    ++counts[cv];
                    if (loopDepth > 0)
                        ++loopCounts[cv];
                    if (currentFn)
                        globalWriters[cv].insert(currentFn->getCanonicalDecl());
                }
            }
        }
        if (const auto *ME = llvm::dyn_cast<clang::MemberExpr>(E)) {
            if (const auto *FD =
                    llvm::dyn_cast<clang::FieldDecl>(ME->getMemberDecl())) {
                writeTargets.insert(ME);
                auto &rec = fieldWrites[llvm::cast<clang::FieldDecl>(
                    FD->getCanonicalDecl())];
                ++rec.sites;
                if (loopDepth > 0)
                    ++rec.loopSites;
                if (currentFn)
                    rec.writers.insert(currentFn->getCanonicalDecl());
                // Bounded, because a field stored from hundreds of places
                // needs no more than a handful to be joinable and the set
                // crosses the shard boundary. Ordered, so which ones survive
                // the cap is a property of the source.
                if (rec.writeSiteLocs.size() < 8) {
                    const auto &SM = ctx.getSourceManager();
                    auto loc = resolveSourceLocation(ME->getBeginLoc(), SM);
                    if (loc.line) {
                        const auto slash = loc.file.find_last_of('/');
                        rec.writeSiteLocs.insert(
                            (slash == std::string::npos
                                 ? loc.file
                                 : loc.file.substr(slash + 1)) +
                            ":" + std::to_string(loc.line));
                    }
                }
                // Reach separates sharing from handoff: `g_stats.hits++` names
                // a fixed object, `io->len = n` touches whatever was handed
                // in, and a queue hands each request to one owner. A writer
                // count cannot tell them apart.
                if (rootsAtGlobal(ME->getBase()))
                    rec.standingSites++;
                else
                    rec.handedSites++;
            }
            // Member access on a global: g.field = x counts as write to g.
            recordWrite(ME->getBase());
        }
    }

    // Walk a base expression to its root declaration: global storage means
    // standing access, a parameter means the object arrived from elsewhere.
    // A local is neither -- it is this thread's own object.
    static bool rootsAtGlobal(const clang::Expr *E) {
        while (E) {
            E = E->IgnoreParenImpCasts();
            if (const auto *UO = llvm::dyn_cast<clang::UnaryOperator>(E)) {
                E = UO->getSubExpr();
                continue;
            }
            if (const auto *ASE =
                    llvm::dyn_cast<clang::ArraySubscriptExpr>(E)) {
                E = ASE->getBase();
                continue;
            }
            if (const auto *ME2 = llvm::dyn_cast<clang::MemberExpr>(E)) {
                E = ME2->getBase();
                continue;
            }
            if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(E)) {
                const auto *VD =
                    llvm::dyn_cast<clang::VarDecl>(DRE->getDecl());
                return VD && VD->hasGlobalStorage() &&
                       !VD->getTLSKind();
            }
            return false;
        }
        return false;
    }
};

} // anonymous namespace

namespace {

class TypeAccessVisitor
    : public clang::RecursiveASTVisitor<TypeAccessVisitor> {
public:
    std::unordered_set<const clang::RecordDecl *> accessed;

    bool VisitMemberExpr(clang::MemberExpr *ME) {
        auto baseType = ME->getBase()->getType();
        if (baseType->isPointerType())
            baseType = baseType->getPointeeType();
        if (const auto *RD = baseType.getCanonicalType()->getAsRecordDecl())
            accessed.insert(static_cast<const clang::RecordDecl *>(
                RD->getCanonicalDecl()));
        return true;
    }
};

} // anonymous namespace

void EscapeAnalysis::collectTypeAccessors(
    const std::vector<const clang::FunctionDecl *> &bodies) {
    for (const auto *FD : bodies) {
        TypeAccessVisitor visitor;
        visitor.TraverseStmt(const_cast<clang::Stmt *>(FD->getBody()));
        for (const auto *RD : visitor.accessed)
            ++typeAccessorCounts_[RD];
    }
}

void EscapeAnalysis::collectGlobalWriteSites(
    const std::vector<const clang::FunctionDecl *> &bodies) {
    GlobalWriteVisitor visitor(globalWriteCounts_, globalLoopWriteCounts_,
                               fieldWrites_, globalWriters_, opaqueCallFns_,
                               ctx_);
    for (const auto *FD : bodies) {
        visitor.currentFn = FD;
        visitor.TraverseStmt(const_cast<clang::Stmt *>(FD->getBody()));
    }
}

EscapeAnalysis::FieldWriteEvidence
EscapeAnalysis::fieldWriteEvidence(const clang::FieldDecl *FD) const {
    if (!FD)
        return {};
    auto it = fieldWrites_.find(
        llvm::cast<clang::FieldDecl>(FD->getCanonicalDecl()));
    if (it == fieldWrites_.end())
        return {};
    return {it->second.sites,
            static_cast<unsigned>(it->second.writers.size()),
            it->second.loopSites};
}

EscapeAnalysis::FieldReadEvidence
EscapeAnalysis::fieldReadEvidence(const clang::FieldDecl *FD) const {
    if (!FD)
        return {};
    auto it = fieldWrites_.find(
        llvm::cast<clang::FieldDecl>(FD->getCanonicalDecl()));
    if (it == fieldWrites_.end())
        return {};
    return {it->second.readSites,
            static_cast<unsigned>(it->second.readers.size())};
}

bool EscapeAnalysis::pairHasWriterAndDistinctReader(
        const clang::FieldDecl *w, const clang::FieldDecl *r) const {
    if (!w || !r)
        return false;
    auto wi = fieldWrites_.find(llvm::cast<clang::FieldDecl>(
        w->getCanonicalDecl()));
    auto ri = fieldWrites_.find(llvm::cast<clang::FieldDecl>(
        r->getCanonicalDecl()));
    if (wi == fieldWrites_.end() || ri == fieldWrites_.end())
        return false;
    // A reader on the writer's own thread costs nothing: it finds the line
    // already Modified locally. The hazard needs the read to come from a
    // function the writer is not.
    for (const auto *rd : ri->second.readers)
        if (!wi->second.writers.count(rd))
            return true;
    return false;
}

bool EscapeAnalysis::fieldWritersAllOpaque(const clang::FieldDecl *FD) const {
    if (!FD)
        return false;
    auto it = fieldWrites_.find(
        llvm::cast<clang::FieldDecl>(FD->getCanonicalDecl()));
    if (it == fieldWrites_.end() || it->second.writers.empty())
        return false;   // nothing observed is not evidence of sparseness
    for (const auto *W : it->second.writers)
        if (!opaqueCallFns_.count(W))
            return false;   // one tight writer is enough to contend
    return true;
}

bool EscapeAnalysis::pairHasDistinctWriters(const clang::FieldDecl *A,
                                            const clang::FieldDecl *B) const {
    if (!A || !B)
        return false;
    auto ia = fieldWrites_.find(
        llvm::cast<clang::FieldDecl>(A->getCanonicalDecl()));
    auto ib = fieldWrites_.find(
        llvm::cast<clang::FieldDecl>(B->getCanonicalDecl()));
    if (ia == fieldWrites_.end() || ib == fieldWrites_.end())
        return false;
    const auto &wa = ia->second.writers;
    const auto &wb = ib->second.writers;
    if (wa.size() > 1 || wb.size() > 1)
        return true;
    if (!wa.empty() && !wb.empty() && *wa.begin() != *wb.begin())
        return true;
    for (const auto *w : wa)
        if (poolRoleWriters_.count(w)) return true;
    for (const auto *w : wb)
        if (poolRoleWriters_.count(w)) return true;
    return false;
}

void EscapeAnalysis::setPoolRoleFunctions(
        std::unordered_set<const clang::FunctionDecl *> fns) {
    poolRoleWriters_ = std::move(fns);
}

bool EscapeAnalysis::fieldHasPoolWriter(const clang::FieldDecl *FD) const {
    if (!FD || poolRoleWriters_.empty())
        return false;
    auto it = fieldWrites_.find(
        llvm::cast<clang::FieldDecl>(FD->getCanonicalDecl()));
    if (it == fieldWrites_.end())
        return false;
    for (const auto *w : it->second.writers)
        if (poolRoleWriters_.count(w)) return true;
    return false;
}

void EscapeAnalysis::appendFieldAccessNames(ThreadRoleSummary &out) const {
    for (const auto &[FD, rec] : fieldWrites_) {
        if (rec.writers.empty() && rec.readers.empty())
            continue;
        const auto *parent = FD->getParent();
        if (!parent)
            continue;
        std::string typeName =
            parent->getCanonicalDecl()->getQualifiedNameAsString();
        if (typeName.empty())
            continue;
        const std::string key = typeName + "::" + FD->getNameAsString();
        if (!rec.writers.empty()) {
            auto &writers = out.fieldWriters[key];
            for (const auto *w : rec.writers)
                writers.insert(threadRoleNodeName(w, ctx_));
        }
        if (!rec.readers.empty()) {
            auto &readers = out.fieldReaders[key];
            for (const auto *r : rec.readers)
                readers.insert(threadRoleNodeName(r, ctx_));
        }

        if (!rec.writeSiteLocs.empty())
            out.fieldWriteSites[key].insert(rec.writeSiteLocs.begin(),
                                            rec.writeSiteLocs.end());

        auto &fa = out.fieldAccess[key];
        fa.writeSites += rec.sites;
        fa.loopWriteSites += rec.loopSites;
        fa.standingWriteSites += rec.standingSites;
        fa.handedWriteSites += rec.handedSites;
        fa.readSites += rec.readSites;
        fa.standingReadSites += rec.standingReadSites;
        fa.handedReadSites += rec.handedReadSites;
    }
}

std::unordered_set<const clang::RecordDecl *>
EscapeAnalysis::accessedRecords() const {
    std::unordered_set<const clang::RecordDecl *> out;
    for (const auto &[FD, rec] : fieldWrites_) {
        (void)rec;
        if (const auto *parent = FD->getParent())
            out.insert(llvm::cast<clang::RecordDecl>(parent->getCanonicalDecl()));
    }
    return out;
}

unsigned EscapeAnalysis::getGlobalWriteCount(const clang::VarDecl *VD) const {
    if (!VD || !VD->hasGlobalStorage())
        return 0;
    auto it = globalWriteCounts_.find(VD->getCanonicalDecl());
    return (it != globalWriteCounts_.end()) ? it->second : 0;
}

unsigned EscapeAnalysis::getGlobalLoopWriteCount(
    const clang::VarDecl *VD) const {
    if (!VD || !VD->hasGlobalStorage())
        return 0;
    auto it = globalLoopWriteCounts_.find(VD->getCanonicalDecl());
    return (it != globalLoopWriteCounts_.end()) ? it->second : 0;
}

bool EscapeAnalysis::isWriteOnceGlobal(const clang::VarDecl *VD) const {
    if (!VD || !VD->hasGlobalStorage())
        return false;

    const auto *canon = VD->getCanonicalDecl();

    // Has a non-trivial initializer → one write at declaration.
    bool hasInit = VD->hasInit() && !llvm::isa<clang::ImplicitValueInitExpr>(
                                         VD->getInit()->IgnoreImplicit());

    auto it = globalWriteCounts_.find(canon);
    unsigned bodyCounts = (it != globalWriteCounts_.end()) ? it->second : 0;

    // Zero writes in function bodies + has initializer → write-once.
    if (hasInit && bodyCounts == 0)
        return true;

    // No initializer but exactly one write in function bodies → write-once.
    if (!hasInit && bodyCounts <= 1)
        return true;

    // Has initializer and exactly one write → could be re-initialization, but
    // still low contention. Accept as write-once.
    if (hasInit && bodyCounts <= 1)
        return true;

    return false;
}

EscapeSummary EscapeAnalysis::buildEscapeSummary(
    const std::vector<const clang::RecordDecl *> &records) const {
    EscapeSummary summary;
    for (const auto *RD : records) {
        if (!RD || !RD->isCompleteDefinition())
            continue;
        const auto *canon = RD->getCanonicalDecl();
        if (!canon)
            continue;
        std::string name = canon->getQualifiedNameAsString();
        if (name.empty())
            continue;

        TypeEscapeSignals &sig = summary[name];
        sig.hasAtomics     |= hasAtomicMembers(RD);
        sig.hasSyncPrims   |= hasSyncPrimitives(RD);
        sig.hasSharedOwner |= hasSharedOwnershipMembers(RD);
        sig.hasVolatile    |= hasVolatileMembers(RD);
        sig.hasPublication |= hasPublicationEvidence(RD);
        sig.hasThreadWriters |= hasThreadEntryWriters(RD);
        sig.hasGlobalInstance |= hasGlobalInstance(RD);
        sig.hasThreadBorneWriter |= anyWriterOnThread(RD);
        sig.hasStandingWrites |= hasStandingWrites(RD);

        auto it = typeAccessorCounts_.find(
            static_cast<const clang::RecordDecl *>(canon));
        if (it != typeAccessorCounts_.end())
            sig.accessorCount = it->second;
    }
    return summary;
}

} // namespace lshaz
