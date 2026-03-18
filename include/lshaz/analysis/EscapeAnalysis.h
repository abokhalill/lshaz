// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <clang/AST/ASTContext.h>
#include <clang/AST/DeclCXX.h>
#include <clang/AST/Expr.h>
#include <clang/AST/Type.h>

#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace lshaz {

enum class AccessPattern : uint8_t {
    None       = 0,
    ReadOnly   = 1,
    WriteOnce  = 2,
    ReadWrite  = 3,
    WriteHeavy = 4, // worst coherence cost
};

// contention ∈ [0.0, 1.0]. 0 = no cross-thread sharing expected.
struct EscapeVerdict {
    bool escapes          = false;
    double contention     = 0.0;
    AccessPattern pattern = AccessPattern::None;

    bool hasAtomics       = false;
    bool hasSyncPrims     = false;
    bool hasSharedOwner   = false;
    bool hasVolatile      = false;
    bool hasPublication   = false;

    unsigned accessorCount = 0; // distinct functions touching this type in TU

    operator bool() const { return escapes; }
};

// Thread-escape analysis with both structural and interprocedural evidence.
// Conservative: if uncertain, assumes escape.
//
// Structural evidence (per-type):
//   1. std::atomic member fields
//   2. std::mutex / synchronization primitive members
//   3. std::shared_ptr / std::weak_ptr members
//   4. volatile members
//
// Publication evidence (TU-wide, collected via scanTranslationUnit):
//   5. Type passed to std::thread / std::jthread / std::async constructor
//   6. Type stored in a non-thread_local global/static mutable variable
//   7. Type used as pointee of std::shared_ptr in global scope
class EscapeAnalysis {
public:
    explicit EscapeAnalysis(clang::ASTContext &Ctx);

    // Run once per TU to collect interprocedural publication paths.
    void scanTranslationUnit(const clang::TranslationUnitDecl *TU);

    EscapeVerdict escapeVerdict(const clang::RecordDecl *RD) const;
    bool mayEscapeThread(const clang::RecordDecl *RD) const; // delegates to above

    bool isFieldMutable(const clang::FieldDecl *FD) const;
    bool hasAtomicMembers(const clang::RecordDecl *RD) const;
    bool hasSyncPrimitives(const clang::RecordDecl *RD) const;
    bool isGlobalSharedMutable(const clang::VarDecl *VD) const;

    bool isAtomicType(clang::QualType QT) const;
    bool isSyncType(clang::QualType QT) const;

    bool hasSharedOwnershipMembers(const clang::RecordDecl *RD) const;
    bool hasCallbackMembers(const clang::RecordDecl *RD) const;
    bool isSharedOwnershipType(clang::QualType QT) const;
    bool hasVolatileMembers(const clang::RecordDecl *RD) const;

    // Query publication evidence for a specific type (by canonical qualified name).
    bool hasPublicationEvidence(const clang::RecordDecl *RD) const;

    // Mark a type as published to a cross-thread context.
    void markPublished(clang::QualType QT);

    // Write-once analysis: a global assigned at most once (at declaration or
    // in an init function) is unlikely to cause runtime contention.
    // Requires prior scanTranslationUnit() call.
    bool isWriteOnceGlobal(const clang::VarDecl *VD) const;

private:

    clang::ASTContext &ctx_;

    // Canonical qualified names of types observed in publication paths.
    std::unordered_set<std::string> publishedTypes_;
    bool tuScanned_ = false;

    // Per-global write site count, populated by scanTranslationUnit.
    // Key: VarDecl canonical pointer. Value: number of write sites in TU
    // (excluding the initializer expression on the VarDecl itself).
    std::unordered_map<const clang::VarDecl *, unsigned> globalWriteCounts_;

    // Per-type: how many distinct functions access fields of this type.
    // Key: canonical RecordDecl*. Populated by scanTranslationUnit Pass 4.
    std::unordered_map<const clang::RecordDecl *, unsigned> typeAccessorCounts_;

    void collectGlobalWriteSites(const clang::TranslationUnitDecl *TU);
    void collectTypeAccessors(const clang::TranslationUnitDecl *TU);
};

} // namespace lshaz
