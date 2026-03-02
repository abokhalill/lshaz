#include "faultline/analysis/NUMATopology.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/DeclCXX.h>
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Stmt.h>

namespace faultline {

namespace {

// Check if an initializer expression contains NUMA placement calls.
class NUMAHintVisitor : public clang::RecursiveASTVisitor<NUMAHintVisitor> {
public:
    bool found = false;

    bool VisitCallExpr(clang::CallExpr *E) {
        if (const auto *callee = E->getDirectCallee()) {
            std::string name = callee->getNameAsString();
            if (name == "numa_alloc_onnode" ||
                name == "numa_alloc_interleaved" ||
                name == "numa_alloc_local" ||
                name == "mbind" ||
                name == "set_mempolicy" ||
                name == "numa_tonode_memory" ||
                name == "numa_bind") {
                found = true;
                return false; // stop traversal
            }
        }
        return true;
    }
};

// Check if a variable's initializer involves thread creation context
// (std::thread, std::async, pthread_create).
class ThreadSpawnVisitor : public clang::RecursiveASTVisitor<ThreadSpawnVisitor> {
public:
    bool found = false;

    bool VisitCXXConstructExpr(clang::CXXConstructExpr *E) {
        if (const auto *CD = E->getConstructor()) {
            std::string parent = CD->getParent()->getQualifiedNameAsString();
            if (parent == "std::thread" || parent == "std::jthread") {
                found = true;
                return false;
            }
        }
        return true;
    }

    bool VisitCallExpr(clang::CallExpr *E) {
        if (const auto *callee = E->getDirectCallee()) {
            std::string name = callee->getQualifiedNameAsString();
            if (name == "std::async" || name == "pthread_create") {
                found = true;
                return false;
            }
        }
        return true;
    }
};

} // anonymous namespace

NUMAPlacement NUMATopology::classifyGlobalVar(const clang::VarDecl *VD,
                                               clang::ASTContext &Ctx) {
    if (!VD)
        return NUMAPlacement::Unknown;

    // Check for NUMA placement hints in initializer.
    if (hasNUMAPlacementHint(VD, Ctx))
        return NUMAPlacement::Explicit;

    // Thread-local storage: always local to the accessing thread's node.
    if (VD->getTLSKind() != clang::VarDecl::TLS_None)
        return NUMAPlacement::LocalInit;

    // Static local variables: initialized by first caller.
    // If in main() or constructor, likely main thread.
    if (VD->isStaticLocal()) {
        if (const auto *FD = llvm::dyn_cast_or_null<clang::FunctionDecl>(
                VD->getDeclContext())) {
            if (isMainThreadInitializer(FD))
                return NUMAPlacement::MainThread;
        }
        return NUMAPlacement::AnyThread;
    }

    // Global/namespace-scope variables: initialized before main() by
    // the main thread on socket 0 (Linux default first-touch).
    if (VD->hasGlobalStorage() && !VD->isStaticLocal())
        return NUMAPlacement::MainThread;

    return NUMAPlacement::Unknown;
}

NUMAPlacement NUMATopology::classifyStruct(const clang::CXXRecordDecl *RD,
                                            clang::ASTContext &Ctx) {
    if (!RD)
        return NUMAPlacement::Unknown;

    // Scan TU for global/static instances of this type.
    // If all instances are main-thread initialized, classify as MainThread.
    // If any are in worker-thread contexts, classify as AnyThread.
    bool foundGlobal = false;
    bool foundThreadLocal = false;

    auto structType = Ctx.getRecordType(RD).getCanonicalType();

    for (const auto *D : Ctx.getTranslationUnitDecl()->decls()) {
        const auto *VD = llvm::dyn_cast<clang::VarDecl>(D);
        if (!VD || !VD->hasGlobalStorage())
            continue;

        auto varType = VD->getType().getCanonicalType();

        // Direct type match.
        if (varType == structType) {
            if (VD->getTLSKind() != clang::VarDecl::TLS_None)
                foundThreadLocal = true;
            else
                foundGlobal = true;
        }

        // Pointer/reference to type.
        if (const auto *PT = varType->getAs<clang::PointerType>()) {
            if (PT->getPointeeType().getCanonicalType() == structType)
                foundGlobal = true;
        }
    }

    if (foundThreadLocal)
        return NUMAPlacement::LocalInit;
    if (foundGlobal)
        return NUMAPlacement::MainThread;

    // No global instances found — likely heap-allocated by worker threads.
    return NUMAPlacement::AnyThread;
}

bool NUMATopology::isMainThreadInitializer(const clang::FunctionDecl *FD) {
    if (!FD)
        return false;

    std::string name = FD->getNameAsString();

    // main() runs on the main thread by definition.
    if (name == "main")
        return true;

    // Common initialization function patterns.
    if (name == "init" || name == "initialize" || name == "setup" ||
        name == "Init" || name == "Initialize" || name == "Setup" ||
        name == "start" || name == "Start")
        return true;

    // Constructors of global objects run before main on the main thread.
    if (llvm::isa<clang::CXXConstructorDecl>(FD))
        return true;

    return false;
}

bool NUMATopology::hasNUMAPlacementHint(const clang::VarDecl *VD,
                                         clang::ASTContext & /*Ctx*/) {
    if (!VD)
        return false;

    // Check for NUMA-related annotations.
    for (const auto *A : VD->attrs()) {
        if (const auto *Ann = llvm::dyn_cast<clang::AnnotateAttr>(A)) {
            auto annStr = Ann->getAnnotation();
            if (annStr.contains("numa") || annStr.contains("NUMA"))
                return true;
        }
    }

    // Check initializer for NUMA API calls.
    if (const auto *init = VD->getInit()) {
        NUMAHintVisitor visitor;
        visitor.TraverseStmt(const_cast<clang::Expr *>(init));
        if (visitor.found)
            return true;
    }

    return false;
}

} // namespace faultline
