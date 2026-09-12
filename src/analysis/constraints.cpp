// SPDX-License-Identifier: Apache-2.0
//
// Points-to constraint generation. Emits per-TU partials only: a constraint
// names entities that survive a TU boundary, and the solve that turns them
// into a points-to relation runs once over every shard's output.

#include "lshaz/analysis/constraints.h"
#include "lshaz/core/diagnostic.h"

#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/RecordLayout.h>
#include <llvm/Support/Casting.h>

namespace lshaz {

namespace {

std::string qualified(const clang::FunctionDecl *FD) {
    return FD ? FD->getQualifiedNameAsString() : std::string("<tu>");
}

// A variable is both a node in the constraint graph and the storage that &v
// denotes, which is the usual flow-insensitive treatment and is why a local's
// name is reused for both roles.
std::string nodeOf(const clang::VarDecl *VD, const std::string &fn) {
    if (!VD) return obj::unresolved();
    if (VD->hasGlobalStorage())
        return obj::global(VD->getQualifiedNameAsString());
    return obj::stack(fn, VD->getNameAsString());
}

bool isAllocatorName(llvm::StringRef n,
                     const std::vector<std::string> &extra) {
    if (n == "malloc" || n == "calloc" || n == "realloc" ||
        n == "aligned_alloc" || n == "strdup" || n == "operator new" ||
        n == "operator new[]")
        return true;
    for (const auto &p : extra)
        if (n == p) return true;
    return false;
}

class ConstraintVisitor
    : public clang::RecursiveASTVisitor<ConstraintVisitor> {
public:
    ConstraintVisitor(clang::ASTContext &Ctx, MemorySummary &out,
                      const std::vector<std::string> &allocPatterns)
        : Ctx_(Ctx), out_(out), allocPatterns_(allocPatterns) {}

    bool TraverseFunctionDecl(clang::FunctionDecl *FD) {
        if (!FD || !FD->hasBody()) return true;
        const std::string prev = fn_;
        fn_ = qualified(FD);
        // A parameter's cell is named by (function, index), which is the same
        // name in the TU that compiles the call and the TU that compiles the
        // body. That is the whole reason this crosses a shard boundary.
        for (unsigned i = 0; i < FD->getNumParams(); ++i) {
            const auto *P = FD->getParamDecl(i);
            if (P && P->getType()->isPointerType())
                emit({Constraint::Kind::Copy, obj::stack(fn_, P->getNameAsString()),
                      obj::param(fn_, i), 0});
        }
        bool r = clang::RecursiveASTVisitor<ConstraintVisitor>::
            TraverseFunctionDecl(FD);
        fn_ = prev;
        return r;
    }

    bool TraverseCXXMethodDecl(clang::CXXMethodDecl *MD) {
        return TraverseFunctionDecl(MD);
    }

    bool VisitVarDecl(clang::VarDecl *VD) {
        if (!VD || !VD->hasInit() || !VD->getType()->isPointerType())
            return true;
        assign(nodeOf(VD, fn_), VD->getInit());
        return true;
    }

    bool VisitBinaryOperator(clang::BinaryOperator *BO) {
        if (!BO) return true;
        if (BO->isAssignmentOp()) {
            recordAccess(BO->getLHS(), /*isWrite=*/true);
            if (BO->getLHS()->getType()->isPointerType()) {
                if (const auto *lhsVar = varOf(BO->getLHS()))
                    assign(nodeOf(lhsVar, fn_), BO->getRHS());
                else if (const auto *me = memberOf(BO->getLHS()))
                    storeThrough(me, BO->getRHS());
            }
        }
        return true;
    }

    bool VisitMemberExpr(clang::MemberExpr *ME) {
        recordAccess(ME, /*isWrite=*/false);
        return true;
    }

    bool VisitCallExpr(clang::CallExpr *CE) {
        const auto *callee = CE->getDirectCallee();
        if (!callee) return true;
        const std::string target = qualified(callee);
        for (unsigned i = 0; i < CE->getNumArgs() && i < callee->getNumParams();
             ++i) {
            const clang::Expr *arg = CE->getArg(i)->IgnoreParenImpCasts();
            if (!arg->getType()->isPointerType()) continue;
            emitFrom(obj::param(target, i), arg);
        }
        return true;
    }

    bool VisitReturnStmt(clang::ReturnStmt *RS) {
        if (!RS || !RS->getRetValue() || fn_.empty()) return true;
        const clang::Expr *v = RS->getRetValue()->IgnoreParenImpCasts();
        if (v->getType()->isPointerType())
            emitFrom(obj::ret(fn_), v);
        return true;
    }

    bool VisitUnaryOperator(clang::UnaryOperator *UO) {
        if (UO && UO->getOpcode() == clang::UO_Deref)
            recordAccess(UO, /*isWrite=*/false);
        return true;
    }

#define LSHAZ_LOOP_BODY(Name, Type)                                            \
    bool Traverse##Name(clang::Type *S) {                                      \
        ++loopDepth_;                                                          \
        bool r =                                                               \
            clang::RecursiveASTVisitor<ConstraintVisitor>::Traverse##Name(S);  \
        --loopDepth_;                                                          \
        return r;                                                              \
    }
    LSHAZ_LOOP_BODY(ForStmt, ForStmt)
    LSHAZ_LOOP_BODY(WhileStmt, WhileStmt)
    LSHAZ_LOOP_BODY(DoStmt, DoStmt)
    LSHAZ_LOOP_BODY(CXXForRangeStmt, CXXForRangeStmt)
#undef LSHAZ_LOOP_BODY

private:
    void emit(Constraint c) {
        if (c.lhs.empty() || c.rhs.empty()) return;
        out_.constraints.insert(std::move(c));
    }

    static const clang::VarDecl *varOf(const clang::Expr *E) {
        if (!E) return nullptr;
        if (const auto *DRE =
                llvm::dyn_cast<clang::DeclRefExpr>(E->IgnoreParenImpCasts()))
            return llvm::dyn_cast<clang::VarDecl>(DRE->getDecl());
        return nullptr;
    }

    static const clang::MemberExpr *memberOf(const clang::Expr *E) {
        return E ? llvm::dyn_cast<clang::MemberExpr>(E->IgnoreParenImpCasts())
                 : nullptr;
    }

    uint64_t fieldOffset(const clang::FieldDecl *FD) const {
        if (!FD || FD->isBitField()) return 0;
        const auto *parent = FD->getParent();
        if (!parent || !parent->isCompleteDefinition()) return 0;
        return Ctx_.getASTRecordLayout(parent).getFieldOffset(
                   FD->getFieldIndex()) /
               8;
    }

    // The symbolic node a pointer expression denotes, or empty when the front
    // end cannot name one. Empty is not "unresolved": it means no constraint
    // is emitted at all, which leaves the solver's answer unaffected rather
    // than polluted.
    std::string nodeOfExpr(const clang::Expr *E) {
        E = E ? E->IgnoreParenImpCasts() : nullptr;
        if (!E) return {};
        if (const auto *VD = varOf(E)) return nodeOf(VD, fn_);
        if (const auto *ME = llvm::dyn_cast<clang::MemberExpr>(E)) {
            // A pointer field read is a load through the base.
            const std::string base = nodeOfExpr(ME->getBase());
            if (base.empty()) return {};
            const auto *FD = llvm::dyn_cast<clang::FieldDecl>(ME->getMemberDecl());
            const std::string tmp = base + ".#" + std::to_string(fieldOffset(FD));
            emit({Constraint::Kind::Load, tmp, base, fieldOffset(FD)});
            return tmp;
        }
        return {};
    }

    // lhs = <expr>
    void assign(const std::string &lhs, const clang::Expr *rhs) {
        if (lhs.empty()) return;
        emitFrom(lhs, rhs);
    }

    void emitFrom(const std::string &lhs, const clang::Expr *rhs) {
        rhs = rhs ? rhs->IgnoreParenImpCasts() : nullptr;
        if (!rhs || lhs.empty()) return;

        if (const auto *UO = llvm::dyn_cast<clang::UnaryOperator>(rhs)) {
            if (UO->getOpcode() == clang::UO_AddrOf) {
                const clang::Expr *sub = UO->getSubExpr()->IgnoreParenImpCasts();
                if (const auto *VD = varOf(sub)) {
                    emit({Constraint::Kind::AddrOf, lhs, nodeOf(VD, fn_), 0});
                    return;
                }
                if (const auto *ME = llvm::dyn_cast<clang::MemberExpr>(sub)) {
                    const std::string base = nodeOfExpr(ME->getBase());
                    const auto *FD =
                        llvm::dyn_cast<clang::FieldDecl>(ME->getMemberDecl());
                    if (!base.empty()) {
                        emit({Constraint::Kind::Copy, lhs, base, 0});
                        (void)FD;
                    }
                    return;
                }
            }
        }

        if (const auto *CE = llvm::dyn_cast<clang::CallExpr>(rhs)) {
            const auto *callee = CE->getDirectCallee();
            if (callee) {
                if (isAllocatorName(callee->getName(), allocPatterns_)) {
                    auto loc = resolveSourceLocation(CE->getBeginLoc(),
                                                     Ctx_.getSourceManager());
                    emit({Constraint::Kind::AddrOf, lhs,
                          obj::heap(loc.file, loc.line), 0});
                    return;
                }
                emit({Constraint::Kind::Copy, lhs, obj::ret(qualified(callee)),
                      0});
                return;
            }
        }

        const std::string node = nodeOfExpr(rhs);
        if (!node.empty())
            emit({Constraint::Kind::Copy, lhs, node, 0});
    }

    void storeThrough(const clang::MemberExpr *ME, const clang::Expr *rhs) {
        const std::string base = nodeOfExpr(ME->getBase());
        if (base.empty()) return;
        const auto *FD = llvm::dyn_cast<clang::FieldDecl>(ME->getMemberDecl());
        const std::string tmp = base + ".=" + std::to_string(fieldOffset(FD));
        emitFrom(tmp, rhs);
        emit({Constraint::Kind::Store, base, tmp, fieldOffset(FD)});
    }

    // One field touch, with the base left symbolic. Resolution happens in the
    // reduce phase because the constraint that settles a parameter is in the
    // caller's TU, which this shard may never compile.
    void recordAccess(const clang::Expr *E, bool isWrite) {
        const auto *ME = memberOf(E);
        if (!ME) return;
        const auto *FD = llvm::dyn_cast<clang::FieldDecl>(ME->getMemberDecl());
        if (!FD) return;

        const std::string base = nodeOfExpr(ME->getBase());
        if (base.empty()) {
            ++out_.unnameableAccesses;
            return;
        }

        auto loc = resolveSourceLocation(ME->getBeginLoc(),
                                         Ctx_.getSourceManager());
        PendingAccess a;
        a.base = base;
        a.offset = fieldOffset(FD);
        a.size = FD->isBitField()
                     ? 0
                     : Ctx_.getTypeSizeInChars(FD->getType()).getQuantity();
        a.function = fn_;
        a.site = loc.file + ":" + std::to_string(loc.line);
        a.isWrite = isWrite;
        a.inLoop = loopDepth_ > 0;
        a.fieldName = FD->getNameAsString();
        out_.accesses.push_back(std::move(a));
    }

    clang::ASTContext &Ctx_;
    MemorySummary &out_;
    const std::vector<std::string> &allocPatterns_;
    std::string fn_;
    unsigned loopDepth_ = 0;
};

} // namespace

MemorySummary buildMemorySummary(clang::ASTContext &Ctx,
                                 const std::vector<std::string> &allocPatterns) {
    MemorySummary out;
    ConstraintVisitor v(Ctx, out, allocPatterns);
    v.TraverseDecl(Ctx.getTranslationUnitDecl());
    return out;
}

} // namespace lshaz
