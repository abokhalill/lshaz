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
    recordAlign_ = layout.getAlignment().getQuantity();
    if (recordAlign_ == 0)
        recordAlign_ = 1;

    // Best case: struct base is cache-line-aligned (offset 0 within line).
    linesSpanned_ = (sizeBytes_ + cacheLineBytes_ - 1) / cacheLineBytes_;

    // Worst case: struct base shifted to maximize cache line span.
    // The base can start at any multiple of recordAlign_ within a cache line.
    // The worst shift is the largest valid shift such that
    // (shift + sizeBytes_) crosses the most line boundaries.
    if (recordAlign_ >= cacheLineBytes_) {
        maxLinesSpanned_ = linesSpanned_;
    } else {
        uint64_t worstShift = cacheLineBytes_ - recordAlign_;
        maxLinesSpanned_ = (worstShift + sizeBytes_ + cacheLineBytes_ - 1) / cacheLineBytes_;
    }

    collectFields(RD, Ctx, 0);
    buildBuckets();
}

bool CacheLineMap::isAtomicType(clang::QualType QT) {
    // C-style volatile typedefs whose name contains "atomic" — covers
    // ngx_atomic_t (Nginx), atomic_t (Linux kernel), etc.  These are
    // volatile integers manipulated via compiler builtins (__sync_*,
    // __atomic_*) and represent real cross-process/cross-thread atomics.
    //
    // Gate: the canonical type must be volatile-qualified.  This avoids
    // false positives on non-volatile helper typedefs like
    // ngx_atomic_uint_t (plain uint64_t used as the underlying type).
    if (QT.getCanonicalType().isVolatileQualified()) {
        clang::QualType walk = QT;
        while (const auto *TDT = walk->getAs<clang::TypedefType>()) {
            std::string tdName = TDT->getDecl()->getNameAsString();
            std::string lower;
            lower.reserve(tdName.size());
            for (char c : tdName)
                lower.push_back(
                    static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
            if (lower.find("atomic") != std::string::npos)
                return true;
            walk = TDT->desugar();
        }
    }

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

        // Best case (base at cache line boundary): shift = 0.
        uint64_t startLine = absOffset / cacheLineBytes_;
        uint64_t endByte = absOffset + fieldSize;
        uint64_t endLine = (endByte > 0) ? (endByte - 1) / cacheLineBytes_ : startLine;

        // Worst case: base shifted by maximum valid offset within a cache line.
        // Valid shifts are multiples of recordAlign_ in [0, cacheLineBytes_).
        uint64_t worstShift = (recordAlign_ >= cacheLineBytes_)
            ? 0
            : cacheLineBytes_ - recordAlign_;
        uint64_t wStart = (absOffset + worstShift) / cacheLineBytes_;
        uint64_t wEndByte = absOffset + worstShift + fieldSize;
        uint64_t wEnd = (wEndByte > 0) ? (wEndByte - 1) / cacheLineBytes_ : wStart;

        // A field straddles if ANY valid base alignment causes it to span
        // a cache line boundary. Check all shifts in recordAlign_ steps.
        bool straddles = (startLine != endLine) || (wStart != wEnd);
        if (!straddles && recordAlign_ < cacheLineBytes_) {
            for (uint64_t shift = recordAlign_; shift < cacheLineBytes_;
                 shift += recordAlign_) {
                uint64_t sB = (absOffset + shift) / cacheLineBytes_;
                uint64_t eByte = absOffset + shift + fieldSize;
                uint64_t eL = (eByte > 0) ? (eByte - 1) / cacheLineBytes_ : sB;
                if (sB != eL) { straddles = true; break; }
            }
        }

        bool atomic = isAtomicType(field->getType());
        bool mutable_ = isFieldMutable(field);

        if (atomic) ++totalAtomics_;
        if (mutable_) ++totalMutables_;

        FieldLineEntry entry;
        entry.decl            = field;
        entry.name            = field->getNameAsString();
        entry.offsetBytes     = absOffset;
        entry.sizeBytes       = fieldSize;
        entry.startLine       = startLine;
        entry.endLine         = endLine;
        entry.worstStartLine  = wStart;
        entry.worstEndLine    = wEnd;
        entry.straddles       = straddles;
        entry.isAtomic        = atomic;
        entry.isMutable       = mutable_;

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
    if (maxLinesSpanned_ == 0)
        return;

    buckets_.resize(maxLinesSpanned_);
    for (uint64_t i = 0; i < maxLinesSpanned_; ++i)
        buckets_[i].lineIndex = i;

    for (auto &f : fields_) {
        // Union of best-case [startLine, endLine] and worst-case
        // [worstStartLine, worstEndLine]. A field belongs to every bucket
        // it could occupy under any valid struct base alignment.
        uint64_t lo = std::min(f.startLine, f.worstStartLine);
        uint64_t hi = std::max(f.endLine, f.worstEndLine);
        for (uint64_t line = lo; line <= hi && line < maxLinesSpanned_; ++line) {
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

bool CacheLineMap::isRefcountOnly() const {
    if (totalAtomics_ != 1)
        return false;

    // Find the single atomic field and check its name.
    for (const auto &f : fields_) {
        if (!f.isAtomic)
            continue;
        // Normalize to lowercase for comparison.
        std::string lower;
        lower.reserve(f.name.size());
        for (char c : f.name)
            lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));

        // Match common refcount field names.  Accept with or without
        // leading underscores / trailing underscores.
        // Strip leading/trailing underscores for matching.
        std::string_view sv(lower);
        while (!sv.empty() && sv.front() == '_') sv.remove_prefix(1);
        while (!sv.empty() && sv.back() == '_') sv.remove_suffix(1);

        if (sv == "ref" || sv == "refs" ||
            sv == "refcount" || sv == "refcnt" ||
            sv == "count" || sv == "cnt" ||
            sv == "nref" || sv == "nrefs" ||
            sv == "rc" || sv == "usecount" ||
            sv == "refcountandflags")
            return true;

        return false;
    }
    return false;
}

} // namespace lshaz
