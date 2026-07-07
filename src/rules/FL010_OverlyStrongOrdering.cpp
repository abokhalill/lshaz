// SPDX-License-Identifier: Apache-2.0
#include "lshaz/core/Rule.h"
#include "lshaz/core/RuleRegistry.h"
#include "lshaz/core/HotPathOracle.h"
#include "lshaz/analysis/DataFlowAnalyzer.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/DeclCXX.h>
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/DeclTemplate.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Basic/SourceManager.h>

#include <sstream>

namespace lshaz {

namespace {

enum class AtomicOpClass { Load, Store, RMW };

struct SeqCstSite {
    clang::SourceLocation loc;
    std::string atomicOp;
    std::string varName;
    std::string ownerType; // canonical qualified name of the member's record
    AtomicOpClass opClass = AtomicOpClass::RMW;
    unsigned inLoop = 0;
};


// target of &x / &s->f / plain _Atomic lvalue: name + owning record.
static std::pair<std::string, std::string>
atomicTargetOf(const clang::Expr *E) {
    E = E->IgnoreParenImpCasts();
    if (const auto *UO = llvm::dyn_cast<clang::UnaryOperator>(E)) {
        if (UO->getOpcode() == clang::UO_AddrOf)
            E = UO->getSubExpr()->IgnoreParenImpCasts();
    }
    if (const auto *ME = llvm::dyn_cast<clang::MemberExpr>(E)) {
        std::string owner;
        if (const auto *FD = llvm::dyn_cast<clang::FieldDecl>(ME->getMemberDecl()))
            owner = FD->getParent()->getCanonicalDecl()
                        ->getQualifiedNameAsString();
        return {ME->getMemberDecl()->getNameAsString(), owner};
    }
    if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(E))
        return {DRE->getDecl()->getNameAsString(), {}};
    return {"<unknown>", {}};
}

bool isStdAtomicType(clang::QualType QT) {
    QT = QT.getCanonicalType().getNonReferenceType();
    if (QT->isAtomicType())
        return true;
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
    std::string qn = RD->getQualifiedNameAsString();
    if (qn == "std::atomic" || qn == "std::atomic_ref")
        return true;
    // libstdc++ dispatches atomic member functions through std::__atomic_base<T>.
    // libc++ uses std::__1::__atomic_base<T>. Match these base classes.
    if (qn.find("__atomic_base") != std::string::npos)
        return true;
    if (const auto *CTSD =
            llvm::dyn_cast<clang::ClassTemplateSpecializationDecl>(RD)) {
        if (auto *TD = CTSD->getSpecializedTemplate()) {
            std::string tn = TD->getQualifiedNameAsString();
            if (tn == "std::atomic" || tn == "std::atomic_ref" ||
                tn.find("__atomic_base") != std::string::npos)
                return true;
        }
    }
    return false;
}

// Detect memory_order_seq_cst usage on std::atomic member calls.
// seq_cst is the default when no order is specified, so we flag both
// explicit seq_cst and implicit (no argument) cases.
class SeqCstVisitor : public clang::RecursiveASTVisitor<SeqCstVisitor> {
public:
    explicit SeqCstVisitor(clang::ASTContext &Ctx) : ctx_(Ctx) {}

    bool VisitCXXMemberCallExpr(clang::CXXMemberCallExpr *E) {
        const auto *MD = E->getMethodDecl();
        if (!MD)
            return true;

        std::string methodName = MD->getNameAsString();

        // Filter to atomic operations.
        static const char *atomicOps[] = {
            "load", "store", "exchange",
            "compare_exchange_weak", "compare_exchange_strong",
            "fetch_add", "fetch_sub", "fetch_and", "fetch_or", "fetch_xor",
            "notify_one", "notify_all", "wait"
        };

        bool isAtomicOp = false;
        for (const auto *op : atomicOps) {
            if (methodName == op) {
                isAtomicOp = true;
                break;
            }
        }
        if (!isAtomicOp)
            return true;

        const auto *obj = E->getImplicitObjectArgument();
        if (!obj)
            return true;

        if (!isStdAtomicType(obj->getType()))
            return true;

        // Determine if seq_cst is used (explicit or implicit default).
        bool isSeqCst = true; // Default: no order arg = seq_cst.

        // std::memory_order enum values (C++11 [atomics.order]):
        //   relaxed=0, consume=1, acquire=2, release=3, acq_rel=4, seq_cst=5
        for (unsigned i = 0; i < E->getNumArgs(); ++i) {
            const auto *arg = E->getArg(i)->IgnoreImplicit();
            clang::QualType argType = arg->getType().getCanonicalType();

            // memory_order-typed args only; anything looser reads the
            // stored value as an ordering (store(0) -> "not seq_cst").
            bool isOrderArg = false;
            if (const auto *ET = argType->getAs<clang::EnumType>()) {
                if (const auto *ED = ET->getDecl()) {
                    isOrderArg = ED->getName() == "memory_order" ||
                                 ED->getName().starts_with("__memory_order");
                }
            }
            if (!isOrderArg)
                continue;

            // Prefer constant evaluation: handles constexpr, enums, literals.
            clang::Expr::EvalResult evalResult;
            if (arg->EvaluateAsInt(evalResult, ctx_)) {
                int64_t val = evalResult.Val.getInt().getExtValue();
                if (val != 5) { // != seq_cst
                    isSeqCst = false;
                    break;
                }
                continue;
            }

            // Fallback: match qualified name of referenced enumerator.
            if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(arg)) {
                std::string qn = DRE->getDecl()->getQualifiedNameAsString();
                if (qn.find("memory_order_relaxed") != std::string::npos ||
                    qn.find("memory_order_consume") != std::string::npos ||
                    qn.find("memory_order_acquire") != std::string::npos ||
                    qn.find("memory_order_release") != std::string::npos ||
                    qn.find("memory_order_acq_rel") != std::string::npos) {
                    isSeqCst = false;
                    break;
                }
            }
        }

        if (!isSeqCst)
            return true;

        // Extract variable name from the object expression.
        std::string varName = "<unknown>";
        std::string ownerType;
        if (const auto *ME = llvm::dyn_cast<clang::MemberExpr>(
                obj->IgnoreImplicit())) {
            varName = ME->getMemberDecl()->getNameAsString();
            if (const auto *FD2 =
                    llvm::dyn_cast<clang::FieldDecl>(ME->getMemberDecl()))
                ownerType = FD2->getParent()->getCanonicalDecl()
                                ->getQualifiedNameAsString();
        } else if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(
                       obj->IgnoreImplicit())) {
            varName = DRE->getDecl()->getNameAsString();
        }

        AtomicOpClass opClass = AtomicOpClass::RMW;
        if (methodName == "load")
            opClass = AtomicOpClass::Load;
        else if (methodName == "store")
            opClass = AtomicOpClass::Store;

        sites_.push_back({E->getBeginLoc(), methodName, varName,
                          std::move(ownerType), opClass, inLoop_});
        return true;
    }

    // Also catch operator overloads on atomics (++, --, +=, etc.)
    // These default to seq_cst.
    bool VisitCXXOperatorCallExpr(clang::CXXOperatorCallExpr *E) {
        if (E->getNumArgs() < 1)
            return true;

        if (!isStdAtomicType(E->getArg(0)->getType()))
            return true;

        auto op = E->getOperator();
        std::string opName;
        switch (op) {
            case clang::OO_PlusPlus:  opName = "operator++"; break;
            case clang::OO_MinusMinus: opName = "operator--"; break;
            case clang::OO_PlusEqual: opName = "operator+="; break;
            case clang::OO_MinusEqual: opName = "operator-="; break;
            case clang::OO_AmpEqual:  opName = "operator&="; break;
            case clang::OO_PipeEqual: opName = "operator|="; break;
            case clang::OO_CaretEqual: opName = "operator^="; break;
            default: return true;
        }

        sites_.push_back({E->getBeginLoc(), opName, "<atomic>", {},
                          AtomicOpClass::RMW, inLoop_});
        return true;
    }

    // C11/GNU atomics never pass through CXXMemberCallExpr: atomic_*()
    // macros and __atomic_* builtins are AtomicExpr; ++/--/=/op= on an
    // _Atomic lvalue are plain operators with implicit seq_cst; __sync_*
    // resolve to builtin CallExprs (full barrier). every C codebase was
    // invisible to this rule.
    bool VisitAtomicExpr(clang::AtomicExpr *E) {
        using AE = clang::AtomicExpr;
        auto op = E->getOp();
        if (op == AE::AO__c11_atomic_init)
            return true;
        AtomicOpClass opClass = AtomicOpClass::RMW;
        const char *opName = "atomic_rmw";
        switch (op) {
            case AE::AO__c11_atomic_load:
            case AE::AO__atomic_load:
            case AE::AO__atomic_load_n:
                opClass = AtomicOpClass::Load; opName = "atomic_load"; break;
            case AE::AO__c11_atomic_store:
            case AE::AO__atomic_store:
            case AE::AO__atomic_store_n:
                opClass = AtomicOpClass::Store; opName = "atomic_store"; break;
            default: break;
        }
        const clang::Expr *order = E->getOrder();
        clang::Expr::EvalResult r;
        if (!order || !order->EvaluateAsInt(r, ctx_))
            return true; // runtime-variable order: unprovable, skip
        if (r.Val.getInt().getExtValue() != 5)
            return true;
        auto [varName, owner] = atomicTargetOf(E->getPtr());
        sites_.push_back({E->getBeginLoc(), opName, varName,
                          std::move(owner), opClass, inLoop_});
        return true;
    }

    bool VisitUnaryOperator(clang::UnaryOperator *UO) {
        if (!UO->isIncrementDecrementOp() ||
            !UO->getSubExpr()->getType()->isAtomicType())
            return true;
        auto [varName, owner] = atomicTargetOf(UO->getSubExpr());
        sites_.push_back({UO->getBeginLoc(),
                          UO->isIncrementOp() ? "atomic++" : "atomic--",
                          varName, std::move(owner), AtomicOpClass::RMW,
                          inLoop_});
        return true;
    }

    bool VisitBinaryOperator(clang::BinaryOperator *BO) {
        if (!BO->isAssignmentOp() ||
            !BO->getLHS()->getType()->isAtomicType())
            return true;
        bool plain = BO->getOpcode() == clang::BO_Assign;
        auto [varName, owner] = atomicTargetOf(BO->getLHS());
        sites_.push_back({BO->getBeginLoc(),
                          plain ? "atomic=" : "atomic-op=", varName,
                          std::move(owner),
                          plain ? AtomicOpClass::Store : AtomicOpClass::RMW,
                          inLoop_});
        return true;
    }

    bool VisitCallExpr(clang::CallExpr *E) {
        const auto *callee = E->getDirectCallee();
        if (!callee)
            return true;
        // operators/ctors have no identifier; getName() would deref null
        const auto *II = callee->getIdentifier();
        if (!II)
            return true;
        llvm::StringRef name = II->getName();
        if (!name.starts_with("__sync_") ||
            name.starts_with("__sync_synchronize") ||
            name.starts_with("__sync_lock_release")) // release, not seq_cst
            return true;
        std::string varName = "<unknown>", owner;
        if (E->getNumArgs() > 0)
            std::tie(varName, owner) = atomicTargetOf(E->getArg(0));
        sites_.push_back({E->getBeginLoc(), name.str(), varName,
                          std::move(owner), AtomicOpClass::RMW, inLoop_});
        return true;
    }

    bool TraverseForStmt(clang::ForStmt *S) {
        ++inLoop_;
        bool r = clang::RecursiveASTVisitor<SeqCstVisitor>::TraverseForStmt(S);
        --inLoop_;
        return r;
    }
    bool TraverseWhileStmt(clang::WhileStmt *S) {
        ++inLoop_;
        bool r = clang::RecursiveASTVisitor<SeqCstVisitor>::TraverseWhileStmt(S);
        --inLoop_;
        return r;
    }
    bool TraverseDoStmt(clang::DoStmt *S) {
        ++inLoop_;
        bool r = clang::RecursiveASTVisitor<SeqCstVisitor>::TraverseDoStmt(S);
        --inLoop_;
        return r;
    }
    bool TraverseCXXForRangeStmt(clang::CXXForRangeStmt *S) {
        ++inLoop_;
        bool r = clang::RecursiveASTVisitor<SeqCstVisitor>::TraverseCXXForRangeStmt(S);
        --inLoop_;
        return r;
    }

    const std::vector<SeqCstSite> &sites() const { return sites_; }

private:
    clang::ASTContext &ctx_;
    std::vector<SeqCstSite> sites_;
    unsigned inLoop_ = 0;
};

} // anonymous namespace

class FL010_OverlyStrongOrdering : public Rule {
public:
    std::string_view getID() const override { return "FL010"; }
    std::string_view getTitle() const override { return "Overly Strong Atomic Ordering"; }
    Severity getBaseSeverity() const override { return Severity::High; }

    std::string_view getHardwareMechanism() const override {
        return "On x86-64 TSO: seq_cst stores lower to XCHG (implicit LOCK, "
               "store buffer drain). seq_cst loads lower to plain MOV (no "
               "additional cost over acquire). seq_cst RMW lowers to LOCK-prefixed "
               "instruction (same as acq_rel RMW). The actionable cost is on "
               "stores where release ordering would emit plain MOV.";
    }

    void analyze(const clang::Decl *D,
                 clang::ASTContext &Ctx,
                 const HotPathOracle &Oracle,
                 const Config &Cfg,
                 EscapeAnalysis & /*Escape*/,
                 std::vector<Diagnostic> &out) override {

        const auto *FD = llvm::dyn_cast_or_null<clang::FunctionDecl>(D);
        if (!FD || !FD->doesThisDeclarationHaveABody())
            return;

        if (!Oracle.isFunctionHot(FD))
            return;

        SeqCstVisitor visitor(Ctx);
        visitor.TraverseStmt(FD->getBody());

        if (visitor.sites().empty())
            return;

        // Intra-procedural data-flow: detect atomic results feeding branches.
        DataFlowAnalyzer dfa(Ctx);
        DataFlowFacts dfFacts = dfa.analyze(FD);

        const auto &SM = Ctx.getSourceManager();
        unsigned atomicCount = visitor.sites().size();
        bool isARM = (Cfg.targetArch == TargetArch::ARM64 ||
                      Cfg.targetArch == TargetArch::ARM64Apple);

        for (const auto &site : visitor.sites()) {
            // On x86-64 TSO, seq_cst loads are free (plain MOV, same as acquire).
            // On ARM64, seq_cst loads require LDAR which is costlier than relaxed.
            if (site.opClass == AtomicOpClass::Load && !isARM)
                continue;

            bool isStore = (site.opClass == AtomicOpClass::Store);
            bool isLoad = (site.opClass == AtomicOpClass::Load);

            // ARM64: all seq_cst ops have real fence cost vs weaker orderings.
            Severity sev;
            double confidence;
            if (isARM) {
                sev = isStore ? Severity::Critical : Severity::High;
                confidence = isStore ? 0.90 : 0.80;
            } else {
                sev = isStore ? Severity::High : Severity::Medium;
                confidence = isStore ? 0.85 : 0.55;
            }

            std::vector<std::string> escalations;

            if (site.inLoop && isStore) {
                sev = Severity::Critical;
                confidence = 0.92;
                if (isARM)
                    escalations.push_back(
                        "seq_cst store inside loop: DMB ISH + STR per iteration, "
                        "full barrier drain each cycle");
                else
                    escalations.push_back(
                        "seq_cst store inside loop: XCHG per iteration, "
                        "sustained store buffer drain");
            } else if (site.inLoop) {
                sev = Severity::High;
                if (isARM)
                    escalations.push_back(
                        "seq_cst " + std::string(isLoad ? "load" : "RMW") +
                        " inside loop: barrier per iteration on ARM64");
                else
                    escalations.push_back(
                        "seq_cst RMW inside loop: LOCK-prefixed op per iteration "
                        "(same cost as acq_rel on x86-64, but prevents compiler "
                        "reordering optimizations)");
            }

            if (atomicCount > 1) {
                escalations.push_back(
                    std::to_string(atomicCount) +
                    " seq_cst operations in function: cumulative serialization");
            }

            Diagnostic diag;
            diag.ruleID    = "FL010";
            diag.title     = "Overly Strong Atomic Ordering";
            diag.severity  = sev;
            diag.confidence = confidence;
            diag.evidenceTier = (isStore || isARM) ? EvidenceTier::Likely : EvidenceTier::Speculative;
            diag.functionName = FD->getQualifiedNameAsString();

            diag.location = resolveSourceLocation(site.loc, SM);

            std::ostringstream hw;
            if (isARM) {
                if (isStore) {
                    hw << "seq_cst store on '" << site.varName
                       << "' in '" << FD->getQualifiedNameAsString()
                       << "': lowers to DMB ISH + STR on ARM64 (full barrier "
                       << "before store). release ordering emits STLR "
                       << "(release-only, no preceding barrier).";
                } else if (isLoad) {
                    hw << "seq_cst load on '" << site.varName
                       << "' in '" << FD->getQualifiedNameAsString()
                       << "': lowers to LDAR + DMB ISH on ARM64 (acquire + "
                       << "trailing barrier). acquire ordering emits LDAR "
                       << "alone (no trailing barrier).";
                } else {
                    hw << "seq_cst " << site.atomicOp << " on '" << site.varName
                       << "' in '" << FD->getQualifiedNameAsString()
                       << "': lowers to LDAXR/STLXR loop + DMB ISH on ARM64. "
                       << "acq_rel RMW emits LDAXR/STLXR without trailing barrier.";
                }
            } else {
                if (isStore) {
                    hw << "seq_cst store on '" << site.varName
                       << "' in '" << FD->getQualifiedNameAsString()
                       << "': lowers to XCHG on x86-64 (implicit LOCK prefix, "
                       << "store buffer drain). release ordering would emit "
                       << "plain MOV with zero fence cost on TSO.";
                } else {
                    hw << "seq_cst " << site.atomicOp << " on '" << site.varName
                       << "' in '" << FD->getQualifiedNameAsString()
                       << "': lowers to LOCK-prefixed instruction on x86-64. "
                       << "On TSO, acq_rel RMW emits the same LOCK-prefixed op "
                       << "— no runtime cost difference, but seq_cst prevents "
                       << "compiler reordering across the operation.";
                }
            }
            diag.hardwareReasoning = hw.str();

            diag.structuralEvidence = {
                {"op", site.atomicOp},
                {"op_class", isLoad ? "load" : (isStore ? "store" : "rmw")},
                {"var", site.varName},
                {"ordering", "seq_cst"},
                {"function", FD->getQualifiedNameAsString()},
                {"in_loop", site.inLoop ? "yes" : "no"},
                {"total_seq_cst_in_func", std::to_string(atomicCount)},
                {"target_arch", isARM ? "arm64" : "x86-64"},
            };
            if (!site.ownerType.empty())
                diag.structuralEvidence["type_name"] = site.ownerType;

            if (isARM) {
                if (isStore) {
                    diag.mitigation =
                        "Use memory_order_release for stores where total order is "
                        "not required. On ARM64, release stores emit STLR (no "
                        "preceding DMB barrier), saving ~10-20ns per operation.";
                } else if (isLoad) {
                    diag.mitigation =
                        "Use memory_order_acquire for loads where total order is "
                        "not required. On ARM64, acquire loads emit LDAR without "
                        "trailing DMB barrier, saving ~10-20ns per operation.";
                } else {
                    diag.mitigation =
                        "Use memory_order_acq_rel for RMW if total order is not "
                        "required. On ARM64, this eliminates the trailing DMB ISH "
                        "barrier, reducing per-operation cost measurably.";
                }
            } else {
                if (isStore) {
                    diag.mitigation =
                        "Use memory_order_release for stores where total order is "
                        "not required. On x86-64 TSO, release stores emit plain MOV "
                        "(zero fence cost). Verify no downstream load depends on "
                        "SC total order before weakening.";
                } else {
                    diag.mitigation =
                        "Use memory_order_acq_rel for RMW if total order is not "
                        "required. On x86-64, runtime cost is identical (LOCK prefix "
                        "either way), but weaker ordering enables compiler "
                        "reordering optimizations around the operation.";
                }
            }

            // Data-flow: atomic result feeds branch condition.
            if (diag.location.line > 0 &&
                dfFacts.atomicFeedsBranch.count(diag.location.line)) {
                escalations.push_back(
                    "data-flow: atomic result feeds branch condition "
                    "(CAS retry loop or spin-wait pattern)");
                diag.structuralEvidence["feeds_branch"] = "yes";
            }

            diag.escalations = std::move(escalations);
            out.push_back(std::move(diag));
        }
    }
};

LSHAZ_REGISTER_RULE(FL010_OverlyStrongOrdering)

} // namespace lshaz
