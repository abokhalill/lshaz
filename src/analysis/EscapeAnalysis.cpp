// SPDX-License-Identifier: Apache-2.0
#include "lshaz/analysis/EscapeAnalysis.h"

#include <clang/AST/Decl.h>
#include <clang/AST/DeclCXX.h>
#include <clang/AST/DeclTemplate.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Type.h>

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
    // C11 _Atomic qualifier.
    if (QT.getCanonicalType()->isAtomicType())
        return true;

    // std::atomic<T> — match via template specialization.
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

bool EscapeAnalysis::mayEscapeThread(const clang::RecordDecl *RD) const {
    if (!RD)
        return false;

    // Structural evidence.
    if (hasAtomicMembers(RD))
        return true;
    if (hasSyncPrimitives(RD))
        return true;
    if (hasSharedOwnershipMembers(RD))
        return true;
    if (hasVolatileMembers(RD))
        return true;

    // Lazy TU-wide publication path scan on first query.
    const_cast<EscapeAnalysis *>(this)->scanTranslationUnit(
        ctx_.getTranslationUnitDecl());
    if (hasPublicationEvidence(RD))
        return true;

    return false;
}

bool EscapeAnalysis::hasPublicationEvidence(const clang::RecordDecl *RD) const {
    if (!RD || publishedTypes_.empty())
        return false;
    const auto *canon = RD->getCanonicalDecl();
    if (!canon)
        return false;
    return publishedTypes_.count(canon->getQualifiedNameAsString()) > 0;
}

void EscapeAnalysis::markPublished(clang::QualType QT) {
    QT = QT.getCanonicalType().getNonReferenceType();
    // Strip pointer/reference layers.
    while (QT->isPointerType() || QT->isReferenceType())
        QT = QT->getPointeeType().getCanonicalType();
    if (const auto *RD = QT->getAsCXXRecordDecl()) {
        if (const auto *canon = RD->getCanonicalDecl())
            publishedTypes_.insert(canon->getQualifiedNameAsString());
    }
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
            for (unsigned i = 0; i < E->getNumArgs(); ++i)
                ea_.markPublished(E->getArg(i)->getType());
        }
        return true;
    }

    bool VisitCallExpr(clang::CallExpr *E) {
        if (const auto *callee = E->getDirectCallee()) {
            std::string name = callee->getQualifiedNameAsString();
            // std::async publishes all callable and argument types.
            if (name == "std::async") {
                for (unsigned i = 0; i < E->getNumArgs(); ++i)
                    ea_.markPublished(E->getArg(i)->getType());
            }
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

    // Pass 1: global/static mutable variable types.
    for (const auto *D : TU->decls()) {
        if (const auto *VD = llvm::dyn_cast<clang::VarDecl>(D)) {
            if (isGlobalSharedMutable(VD))
                markPublished(VD->getType());
        }
    }

    // Pass 2: thread-creation call sites across all function bodies.
    PublicationVisitor visitor(*this);
    for (auto *D : TU->decls()) {
        if (auto *FD = llvm::dyn_cast<clang::FunctionDecl>(D)) {
            if (FD->doesThisDeclarationHaveABody())
                visitor.TraverseStmt(FD->getBody());
        }
    }

    // Pass 3: count write sites per global for write-once analysis.
    collectGlobalWriteSites(TU);
}

bool EscapeAnalysis::isFieldMutable(const clang::FieldDecl *FD) const {
    if (!FD)
        return false;

    // Explicitly mutable keyword.
    if (FD->isMutable())
        return true;

    // Non-const qualified type.
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
        if (field->getType().isVolatileQualified())
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

// Counts write references to global variables within function bodies.
// A "write" is: LHS of assignment/compound-assignment, operand of
// increment/decrement, or passed as non-const pointer/reference argument.
class GlobalWriteVisitor
    : public clang::RecursiveASTVisitor<GlobalWriteVisitor> {
public:
    std::unordered_map<const clang::VarDecl *, unsigned> &counts;
    explicit GlobalWriteVisitor(
        std::unordered_map<const clang::VarDecl *, unsigned> &c)
        : counts(c) {}

    bool VisitBinaryOperator(clang::BinaryOperator *BO) {
        if (!BO->isAssignmentOp())
            return true;
        recordWrite(BO->getLHS());
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

private:
    void recordWrite(const clang::Expr *E) {
        if (!E) return;
        E = E->IgnoreParenImpCasts();
        if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(E)) {
            if (const auto *VD = llvm::dyn_cast<clang::VarDecl>(DRE->getDecl())) {
                if (VD->hasGlobalStorage())
                    ++counts[VD->getCanonicalDecl()];
            }
        }
        // Member access on a global: g.field = x counts as write to g.
        if (const auto *ME = llvm::dyn_cast<clang::MemberExpr>(E)) {
            recordWrite(ME->getBase());
        }
    }
};

} // anonymous namespace

void EscapeAnalysis::collectGlobalWriteSites(
    const clang::TranslationUnitDecl *TU) {
    GlobalWriteVisitor visitor(globalWriteCounts_);
    for (auto *D : TU->decls()) {
        if (auto *FD = llvm::dyn_cast<clang::FunctionDecl>(D)) {
            if (FD->doesThisDeclarationHaveABody())
                visitor.TraverseStmt(FD->getBody());
        }
    }
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

} // namespace lshaz
