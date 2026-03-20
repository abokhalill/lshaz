// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/DeclCXX.h>
#include <clang/AST/RecordLayout.h>

#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

namespace lshaz {

struct FieldLineEntry {
    const clang::FieldDecl *decl = nullptr;
    std::string name;
    uint64_t offsetBytes = 0;
    uint64_t sizeBytes   = 0;
    uint64_t startLine   = 0;   // 0-indexed cache line index (best case base alignment)
    uint64_t endLine     = 0;   // inclusive (best case)
    uint64_t worstStartLine = 0; // worst case: base shifted to maximize line index
    uint64_t worstEndLine   = 0; // worst case: inclusive
    bool straddles       = false; // field spans a line boundary under any valid base alignment
    bool isAtomic        = false;
    bool isMutable       = false;
};

struct CacheLineBucket {
    uint64_t lineIndex = 0;
    std::vector<const FieldLineEntry *> fields;
    unsigned atomicCount  = 0;
    unsigned mutableCount = 0;
};

// Per-record cache line occupancy model.
// Computes exact field-to-line mapping using ASTRecordLayout offsets,
// including nested sub-objects and base classes.
class CacheLineMap {
public:
    CacheLineMap(const clang::RecordDecl *RD,
                 clang::ASTContext &Ctx,
                 uint64_t cacheLineBytes = 64,
                 const std::vector<std::string> &atomicTypeNames = {});

    uint64_t recordSizeBytes() const { return sizeBytes_; }
    uint64_t linesSpanned() const { return linesSpanned_; }
    uint64_t maxLinesSpanned() const { return maxLinesSpanned_; }
    uint64_t cacheLineBytes() const { return cacheLineBytes_; }
    uint64_t recordAlign() const { return recordAlign_; }
    bool isCacheLineAligned() const { return recordAlign_ >= cacheLineBytes_; }

    const std::vector<FieldLineEntry> &fields() const { return fields_; }
    const std::vector<CacheLineBucket> &buckets() const { return buckets_; }

    // Fields that straddle a cache line boundary.
    std::vector<const FieldLineEntry *> straddlingFields() const;

    // Pairs of fields sharing a cache line where both are mutable.
    struct SharedLinePair {
        const FieldLineEntry *a;
        const FieldLineEntry *b;
        uint64_t lineIndex;
    };
    std::vector<SharedLinePair> mutablePairsOnSameLine() const;

    // Pairs of atomic fields sharing a cache line.
    std::vector<SharedLinePair> atomicPairsOnSameLine() const;

    // Lines with mixed atomic + non-atomic mutable fields (false sharing surface).
    std::vector<uint64_t> falseSharingCandidateLines() const;

    unsigned totalAtomicFields() const { return totalAtomics_; }
    unsigned totalMutableFields() const { return totalMutables_; }

    // Returns true if the struct has exactly one atomic field whose name
    // matches a reference-counting pattern (ref, refcount, count, etc.).
    // Such structs are typically COW/shared_ptr objects where the refcount
    // is the only mutable field and co-located immutable fields never cause
    // real false sharing.
    bool isRefcountOnly() const;

private:
    void collectFields(const clang::RecordDecl *RD,
                       clang::ASTContext &Ctx,
                       uint64_t baseOffsetBytes);
    void buildBuckets();

    bool isAtomicType(clang::QualType QT) const;
    static bool isFieldMutable(const clang::FieldDecl *FD);

    uint64_t cacheLineBytes_;
    uint64_t recordAlign_  = 1;
    uint64_t sizeBytes_    = 0;
    uint64_t linesSpanned_ = 0;
    uint64_t maxLinesSpanned_ = 0;
    unsigned totalAtomics_  = 0;
    unsigned totalMutables_ = 0;

    std::unordered_set<std::string> atomicTypeNames_;
    std::vector<FieldLineEntry> fields_;
    std::vector<CacheLineBucket> buckets_;
};

} // namespace lshaz
