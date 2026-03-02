#pragma once

#include <clang/AST/ASTContext.h>
#include <clang/AST/DeclCXX.h>
#include <clang/AST/Expr.h>
#include <clang/AST/Type.h>

#include <string>
#include <unordered_set>

namespace faultline {

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

    // Does this record type contain evidence of cross-thread usage?
    // Consults both structural members and publication path evidence.
    bool mayEscapeThread(const clang::CXXRecordDecl *RD) const;

    bool isFieldMutable(const clang::FieldDecl *FD) const;
    bool hasAtomicMembers(const clang::CXXRecordDecl *RD) const;
    bool hasSyncPrimitives(const clang::CXXRecordDecl *RD) const;
    bool isGlobalSharedMutable(const clang::VarDecl *VD) const;

    bool isAtomicType(clang::QualType QT) const;
    bool isSyncType(clang::QualType QT) const;

    bool hasSharedOwnershipMembers(const clang::CXXRecordDecl *RD) const;
    bool hasCallbackMembers(const clang::CXXRecordDecl *RD) const;
    bool isSharedOwnershipType(clang::QualType QT) const;
    bool hasVolatileMembers(const clang::CXXRecordDecl *RD) const;

    // Query publication evidence for a specific type (by canonical qualified name).
    bool hasPublicationEvidence(const clang::CXXRecordDecl *RD) const;

    // Mark a type as published to a cross-thread context.
    void markPublished(clang::QualType QT);

private:

    clang::ASTContext &ctx_;

    // Canonical qualified names of types observed in publication paths.
    std::unordered_set<std::string> publishedTypes_;
    bool tuScanned_ = false;
};

} // namespace faultline
