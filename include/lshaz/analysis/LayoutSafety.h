#ifndef LSHAZ_ANALYSIS_LAYOUTSAFETY_H
#define LSHAZ_ANALYSIS_LAYOUTSAFETY_H

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/DeclCXX.h>
#include <clang/AST/Type.h>
#include <llvm/ADT/DenseMap.h>

namespace lshaz {

/// Per-TU cache for layout-safety queries. Keyed on canonical QualType
/// opaque pointer. Avoids redundant recursive type-tree walks when
/// multiple rules inspect the same types.
using LayoutSafetyCache = llvm::DenseMap<const void *, bool>;

namespace detail {

inline bool canComputeTypeSizeImpl(clang::QualType QT,
                                   clang::ASTContext &Ctx,
                                   LayoutSafetyCache *cache) {
    if (QT.isNull())
        return false;
    QT = QT.getCanonicalType();

    if (cache) {
        auto it = cache->find(QT.getAsOpaquePtr());
        if (it != cache->end())
            return it->second;
    }

    bool result = [&]() -> bool {
        if (QT->isDependentType() || QT->isIncompleteType())
            return false;
        if (QT->containsErrors())
            return false;
        if (QT->isUndeducedAutoType())
            return false;
        if (QT->isSizelessType())
            return false;
        if (QT->containsUnexpandedParameterPack())
            return false;
        if (QT->getAs<clang::UnresolvedUsingType>())
            return false;
        if (const auto *ArrT = Ctx.getAsArrayType(QT))
            return canComputeTypeSizeImpl(ArrT->getElementType(), Ctx, cache);
        if (const auto *RT = QT->getAs<clang::RecordType>()) {
            const auto *RD = RT->getDecl();
            if (!RD || RD->isInvalidDecl() || !RD->isCompleteDefinition())
                return false;
            if (RD->isDependentType())
                return false;
            for (const auto *field : RD->fields()) {
                if (!canComputeTypeSizeImpl(field->getType(), Ctx, cache))
                    return false;
            }
            if (const auto *CXXRD = llvm::dyn_cast<clang::CXXRecordDecl>(RD)) {
                for (const auto &base : CXXRD->bases()) {
                    if (!canComputeTypeSizeImpl(base.getType(), Ctx, cache))
                        return false;
                }
                for (const auto &vbase : CXXRD->vbases()) {
                    if (!canComputeTypeSizeImpl(vbase.getType(), Ctx, cache))
                        return false;
                }
            }
        }
        return true;
    }();

    if (cache)
        (*cache)[QT.getAsOpaquePtr()] = result;
    return result;
}

} // namespace detail

/// Cached variant — pass a LayoutSafetyCache that persists across calls
/// within a single TU for amortized O(1) per repeated type.
inline bool canComputeTypeSize(clang::QualType QT, clang::ASTContext &Ctx,
                               LayoutSafetyCache &cache) {
    return detail::canComputeTypeSizeImpl(QT, Ctx, &cache);
}

/// Uncached variant — backward compatible, allocates no external state.
inline bool canComputeTypeSize(clang::QualType QT, clang::ASTContext &Ctx) {
    return detail::canComputeTypeSizeImpl(QT, Ctx, nullptr);
}

/// Returns true if Clang can safely call getASTRecordLayout on this record.
inline bool canComputeRecordLayout(const clang::CXXRecordDecl *RD,
                                   clang::ASTContext &Ctx) {
    if (!RD || !RD->isCompleteDefinition())
        return false;
    if (RD->isDependentType() || RD->isInvalidDecl())
        return false;
    return canComputeTypeSize(Ctx.getRecordType(RD), Ctx);
}

} // namespace lshaz

#endif // LSHAZ_ANALYSIS_LAYOUTSAFETY_H
