// SPDX-License-Identifier: Apache-2.0
#include "lshaz/analysis/CacheLineMap.h"
#include "lshaz/analysis/LayoutSafety.h"

#include <clang/AST/Decl.h>
#include <clang/AST/DeclCXX.h>
#include <clang/AST/DeclTemplate.h>
#include <clang/AST/Type.h>

namespace lshaz {

CacheLineMap::CacheLineMap(const clang::RecordDecl *RD,
                           clang::ASTContext &Ctx,
                           uint64_t cacheLineBytes)
    : cacheLineBytes_(cacheLineBytes) {

    if (!canComputeRecordLayout(RD, Ctx))
        return;

    const auto &layout = Ctx.getASTRecordLayout(RD);
    sizeBytes_ = layout.getSize().getQuantity();
    linesSpanned_ = (sizeBytes_ + cacheLineBytes_ - 1) / cacheLineBytes_;

    collectFields(RD, Ctx, 0);
    buildBuckets();
}

bool CacheLineMap::isAtomicType(clang::QualType QT) {
    QT = QT.getCanonicalType();
    if (QT->isAtomicType())
        return true;

    // Resolve through typedefs/aliases to CXXRecordDecl.
    QT = QT.getNonReferenceType();
    const clang::CXXRecordDecl *RD = nullptr;
    if (const auto *TST = QT->getAs<clang::TemplateSpecializationType>()) {
        if (auto TD = TST->getTemplateName().getAsTemplateDecl())
            RD = llvm::dyn_cast_or_null<clang::CXXRecordDecl>(
                TD->getTemplatedDecl());
    }
    if (!RD)
        RD = QT->getAsCXXRecordDecl();

    if (!RD)
        return false;

    // Direct qualified name match.
    std::string qn = RD->getQualifiedNameAsString();
    if (qn == "std::atomic" || qn == "std::atomic_ref")
        return true;

    // ClassTemplateSpecializationDecl path for instantiated types.
    if (const auto *CTSD =
            llvm::dyn_cast<clang::ClassTemplateSpecializationDecl>(RD)) {
        if (auto *TD = CTSD->getSpecializedTemplate()) {
            std::string tn = TD->getQualifiedNameAsString();
            if (tn == "std::atomic" || tn == "std::atomic_ref")
                return true;
        }
    }

    return false;
}

bool CacheLineMap::isFieldMutable(const clang::FieldDecl *FD) {
    if (!FD)
        return false;
    if (FD->isMutable())
        return true;
    if (!FD->getType().isConstQualified())
        return true;
    return false;
}

void CacheLineMap::collectFields(const clang::RecordDecl *RD,
                                 clang::ASTContext &Ctx,
                                 uint64_t baseOffsetBytes) {
    if (!canComputeRecordLayout(RD, Ctx))
        return;

    const auto &layout = Ctx.getASTRecordLayout(RD);

    // Base subobjects (C++ only — C structs have no bases).
    if (const auto *CXXRD = llvm::dyn_cast<clang::CXXRecordDecl>(RD)) {
        for (const auto &base : CXXRD->bases()) {
            if (base.isVirtual())
                continue;
            const auto *baseRD = base.getType()->getAsCXXRecordDecl();
            if (!baseRD || !baseRD->isCompleteDefinition())
                continue;
            uint64_t baseOffset = layout.getBaseClassOffset(baseRD).getQuantity();
            collectFields(baseRD, Ctx, baseOffsetBytes + baseOffset);
        }

        // Virtual bases.
        for (const auto &vbase : CXXRD->vbases()) {
            const auto *baseRD = vbase.getType()->getAsCXXRecordDecl();
            if (!baseRD || !baseRD->isCompleteDefinition())
                continue;
            uint64_t baseOffset = layout.getVBaseClassOffset(baseRD).getQuantity();
            collectFields(baseRD, Ctx, baseOffsetBytes + baseOffset);
        }
    }

    // Direct fields.
    unsigned idx = 0;
    for (const auto *field : RD->fields()) {
        uint64_t offsetBits = layout.getFieldOffset(idx);
        uint64_t offsetBytes = offsetBits / 8;
        uint64_t absOffset = baseOffsetBytes + offsetBytes;

        if (!canComputeTypeSize(field->getType(), Ctx))
            continue;
        uint64_t fieldSize = Ctx.getTypeSizeInChars(field->getType()).getQuantity();

        uint64_t startLine = absOffset / cacheLineBytes_;
        uint64_t endByte = absOffset + fieldSize;
        uint64_t endLine = (endByte > 0) ? (endByte - 1) / cacheLineBytes_ : startLine;

        bool atomic = isAtomicType(field->getType());
        bool mutable_ = isFieldMutable(field);

        if (atomic) ++totalAtomics_;
        if (mutable_) ++totalMutables_;

        FieldLineEntry entry;
        entry.decl        = field;
        entry.name        = field->getNameAsString();
        entry.offsetBytes = absOffset;
        entry.sizeBytes   = fieldSize;
        entry.startLine   = startLine;
        entry.endLine     = endLine;
        entry.straddles   = (startLine != endLine);
        entry.isAtomic    = atomic;
        entry.isMutable   = mutable_;

        // Recurse into nested record types for sub-field granularity.
        auto qt = field->getType().getCanonicalType();
        if (const auto *nestedRD = qt->getAsRecordDecl()) {
            if (nestedRD->isCompleteDefinition() && !atomic) {
                collectFields(nestedRD, Ctx, absOffset);
            }
        }

        fields_.push_back(std::move(entry));
        ++idx;
    }
}

void CacheLineMap::buildBuckets() {
    if (linesSpanned_ == 0)
        return;

    buckets_.resize(linesSpanned_);
    for (uint64_t i = 0; i < linesSpanned_; ++i)
        buckets_[i].lineIndex = i;

    for (auto &f : fields_) {
        for (uint64_t line = f.startLine; line <= f.endLine && line < linesSpanned_; ++line) {
            buckets_[line].fields.push_back(&f);
            if (f.isAtomic)  ++buckets_[line].atomicCount;
            if (f.isMutable) ++buckets_[line].mutableCount;
        }
    }
}

std::vector<const FieldLineEntry *> CacheLineMap::straddlingFields() const {
    std::vector<const FieldLineEntry *> result;
    for (const auto &f : fields_) {
        if (f.straddles)
            result.push_back(&f);
    }
    return result;
}

std::vector<CacheLineMap::SharedLinePair>
CacheLineMap::mutablePairsOnSameLine() const {
    std::vector<SharedLinePair> result;
    for (const auto &bucket : buckets_) {
        for (size_t i = 0; i < bucket.fields.size(); ++i) {
            if (!bucket.fields[i]->isMutable)
                continue;
            for (size_t j = i + 1; j < bucket.fields.size(); ++j) {
                if (!bucket.fields[j]->isMutable)
                    continue;
                result.push_back({bucket.fields[i], bucket.fields[j],
                                  bucket.lineIndex});
            }
        }
    }
    return result;
}

std::vector<CacheLineMap::SharedLinePair>
CacheLineMap::atomicPairsOnSameLine() const {
    std::vector<SharedLinePair> result;
    for (const auto &bucket : buckets_) {
        for (size_t i = 0; i < bucket.fields.size(); ++i) {
            if (!bucket.fields[i]->isAtomic)
                continue;
            for (size_t j = i + 1; j < bucket.fields.size(); ++j) {
                if (!bucket.fields[j]->isAtomic)
                    continue;
                result.push_back({bucket.fields[i], bucket.fields[j],
                                  bucket.lineIndex});
            }
        }
    }
    return result;
}

std::vector<uint64_t> CacheLineMap::falseSharingCandidateLines() const {
    std::vector<uint64_t> result;
    for (const auto &bucket : buckets_) {
        if (bucket.atomicCount > 0 && bucket.mutableCount > bucket.atomicCount)
            result.push_back(bucket.lineIndex);
    }
    return result;
}

} // namespace lshaz
