// SPDX-License-Identifier: Apache-2.0
#include "lshaz/core/rule.h"
#include "lshaz/core/registry.h"
#include "lshaz/core/hot_path.h"
#include "lshaz/analysis/escape.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/ParentMapContext.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Basic/SourceManager.h>

#include <sstream>
#include <string>

namespace lshaz {

namespace {

// Walk a store target to its root. A global root means the store names a
// fixed object every thread reaches, which is what puts the line in other
// cores in the first place.
const clang::VarDecl *globalRoot(const clang::Expr *E) {
    while (E) {
        E = E->IgnoreParenImpCasts();
        if (const auto *UO = llvm::dyn_cast<clang::UnaryOperator>(E)) {
            E = UO->getSubExpr(); continue;
        }
        if (const auto *ASE = llvm::dyn_cast<clang::ArraySubscriptExpr>(E)) {
            E = ASE->getBase(); continue;
        }
        if (const auto *ME = llvm::dyn_cast<clang::MemberExpr>(E)) {
            E = ME->getBase(); continue;
        }
        if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(E)) {
            const auto *VD = llvm::dyn_cast<clang::VarDecl>(DRE->getDecl());
            return (VD && VD->hasGlobalStorage() && !VD->getTLSKind()) ? VD
                                                                      : nullptr;
        }
        return nullptr;
    }
    return nullptr;
}

// How many distinct inputs the stored expression collapses onto one output.
// A literal divisor or shift gives the factor; a predicate collapses onto
// two values, the weakest bound worth reporting.
uint64_t contractionFactor(const clang::Expr *E, clang::ASTContext &Ctx) {
    if (!E) return 0;
    E = E->IgnoreParenImpCasts();
    if (const auto *BO = llvm::dyn_cast<clang::BinaryOperator>(E)) {
        if (BO->isComparisonOp() || BO->isLogicalOp())
            return 2;
        if (BO->getOpcode() == clang::BO_Div ||
            BO->getOpcode() == clang::BO_Shr) {
            clang::Expr::EvalResult r;
            if (BO->getRHS()->EvaluateAsInt(r, Ctx)) {
                const llvm::APSInt v = r.Val.getInt();
                if (v.isStrictlyPositive()) {
                    uint64_t k = v.getZExtValue();
                    if (BO->getOpcode() == clang::BO_Div)
                        return k >= 2 ? k : 0;
                    return k < 63 ? (uint64_t{1} << k) : 0;
                }
            }
            return 0;
        }
        return std::max(contractionFactor(BO->getLHS(), Ctx),
                        contractionFactor(BO->getRHS(), Ctx));
    }
    if (const auto *UO = llvm::dyn_cast<clang::UnaryOperator>(E))
        if (UO->getOpcode() == clang::UO_LNot)
            return 2;
    if (const auto *CE = llvm::dyn_cast<clang::CastExpr>(E))
        return contractionFactor(CE->getSubExpr(), Ctx);
    return 0;
}

// The fix is already applied when an enclosing condition tests the
// destination. Matched by decl so `if (server.unixtime != t)` guards
// `server.unixtime = t` however the two are spelled.
class MentionsTarget : public clang::RecursiveASTVisitor<MentionsTarget> {
public:
    const clang::ValueDecl *target = nullptr;
    bool found = false;
    bool VisitMemberExpr(clang::MemberExpr *ME) {
        if (ME->getMemberDecl()->getCanonicalDecl() == target) found = true;
        return !found;
    }
    bool VisitDeclRefExpr(clang::DeclRefExpr *DRE) {
        if (DRE->getDecl()->getCanonicalDecl() == target) found = true;
        return !found;
    }
};

bool mentions(const clang::Stmt *S, const clang::ValueDecl *target) {
    if (!S) return false;
    MentionsTarget m;
    m.target = target;
    m.TraverseStmt(const_cast<clang::Stmt *>(S));
    return m.found;
}

// Any early exit ahead of the store bounds how often it runs, by a
// condition this rule cannot read. nginx returns on `tp->sec == sec` and
// then stores cached_gmtoff derived from the same second, so the store is
// already once-per-second while nothing tests cached_gmtoff itself.
// Requiring the condition to name the destination missed that and reported
// it. Any guarded predecessor is treated as a rate bound instead, which
// costs findings where the exit is unrelated and is the direction that does
// not invent them.
bool escapesEarlier(const clang::CompoundStmt *CS, const clang::Stmt *before) {
    for (const auto *child : CS->body()) {
        if (child == before) return false;
        const auto *IS = llvm::dyn_cast<clang::IfStmt>(child);
        if (!IS)
            continue;
        bool leaves = false;
        for (const auto *sub : IS->getThen()->children())
            if (llvm::isa_and_nonnull<clang::ReturnStmt>(sub) ||
                llvm::isa_and_nonnull<clang::BreakStmt>(sub) ||
                llvm::isa_and_nonnull<clang::ContinueStmt>(sub) ||
                llvm::isa_and_nonnull<clang::GotoStmt>(sub))
                leaves = true;
        if (llvm::isa<clang::ReturnStmt>(IS->getThen())) leaves = true;
        if (leaves) return true;
    }
    return false;
}

bool guardedByTarget(const clang::Stmt *S, const clang::ValueDecl *target,
                     clang::ASTContext &Ctx) {
    const clang::Stmt *cur = S;
    for (int depth = 0; cur && depth < 8; ++depth) {
        auto parents = Ctx.getParents(*cur);
        if (parents.empty()) return false;
        const clang::Stmt *p = parents[0].get<clang::Stmt>();
        if (!p) return false;
        const clang::Expr *cond = nullptr;
        if (const auto *IS = llvm::dyn_cast<clang::IfStmt>(p))
            cond = IS->getCond();
        else if (const auto *CO = llvm::dyn_cast<clang::ConditionalOperator>(p))
            cond = CO->getCond();
        if (cond && mentions(cond, target))
            return true;
        if (const auto *CS = llvm::dyn_cast<clang::CompoundStmt>(p))
            if (escapesEarlier(CS, cur))
                return true;
        cur = p;
    }
    return false;
}

struct Site {
    const clang::ValueDecl *decl = nullptr;
    const clang::VarDecl *root = nullptr;
    uint64_t factor = 0;
    bool isAtomic = false;
    clang::SourceLocation loc;
};

class StoreFinder : public clang::RecursiveASTVisitor<StoreFinder> {
public:
    explicit StoreFinder(clang::ASTContext &C) : Ctx(C) {}
    clang::ASTContext &Ctx;
    std::vector<Site> sites;

    bool VisitBinaryOperator(clang::BinaryOperator *BO) {
        if (BO->getOpcode() == clang::BO_Assign)
            record(BO->getLHS(), BO->getRHS(), BO, false);
        return true;
    }

    // C11 atomic_store_explicit is an AtomicExpr, not a call, and it is what
    // redis stores server.unixtime through. Matching assignments alone sees
    // nothing on the site this rule was built from.
    bool VisitAtomicExpr(clang::AtomicExpr *AE) {
        switch (AE->getOp()) {
        case clang::AtomicExpr::AO__c11_atomic_store:
        case clang::AtomicExpr::AO__atomic_store:
        case clang::AtomicExpr::AO__atomic_store_n:
            break;
        default:
            return true;
        }
        const auto *addr = AE->getPtr()->IgnoreParenImpCasts();
        if (const auto *UO = llvm::dyn_cast<clang::UnaryOperator>(addr))
            if (UO->getOpcode() == clang::UO_AddrOf)
                record(UO->getSubExpr(), AE->getVal1(), AE, true);
        return true;
    }

    // Builds routing the same macro through the GCC intrinsics reach it as a
    // call instead. Matched by name because the BI__atomic_store_n
    // enumerators are not exported from every LLVM this builds against.
    bool VisitCallExpr(clang::CallExpr *CE) {
        const auto *FD = CE->getDirectCallee();
        if (!FD || CE->getNumArgs() < 2)
            return true;
        const std::string n = FD->getNameAsString();
        if (n != "__atomic_store_n" && n != "__atomic_store")
            return true;
        const auto *addr = CE->getArg(0)->IgnoreParenImpCasts();
        if (const auto *UO = llvm::dyn_cast<clang::UnaryOperator>(addr))
            if (UO->getOpcode() == clang::UO_AddrOf)
                record(UO->getSubExpr(), CE->getArg(1), CE, true);
        return true;
    }

private:
    void record(const clang::Expr *lhs, const clang::Expr *rhs,
                const clang::Stmt *site, bool atomic) {
        lhs = lhs->IgnoreParenImpCasts();
        const clang::ValueDecl *decl = nullptr;
        if (const auto *ME = llvm::dyn_cast<clang::MemberExpr>(lhs))
            decl = ME->getMemberDecl();
        else if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(lhs))
            decl = llvm::dyn_cast<clang::ValueDecl>(DRE->getDecl());
        if (!decl || !globalRoot(lhs))
            return;
        uint64_t f = contractionFactor(rhs, Ctx);
        if (f < 2)
            return;
        const auto *canon = llvm::cast<clang::ValueDecl>(decl->getCanonicalDecl());
        if (guardedByTarget(site, canon, Ctx))
            return;
        sites.push_back({canon, globalRoot(lhs), f, atomic, lhs->getBeginLoc()});
    }
};

} // namespace

class FL005_RedundantSharedStore : public Rule {
public:
    std::string_view getID() const override { return "FL005"; }
    std::string_view getTitle() const override {
        return "Redundant Store to a Shared Line";
    }
    Severity getBaseSeverity() const override { return Severity::Medium; }
    bool requiresHotPath() const override { return true; }

    std::string_view getHardwareMechanism() const override {
        return "A store to a line other cores hold is a Request-For-Ownership "
               "whatever value it writes: the line is taken Exclusive and "
               "invalidated in every sharer, and each of them re-fetches on "
               "its next read. Storing a value that did not change pays that "
               "in full and buys nothing. Found on redis 8.9.241, whose "
               "updateCachedTimeWithUs stores server.unixtime, microseconds "
               "divided down to seconds, once per command: 52,304,853 stores "
               "in one 20s run, 22 of which changed the value, on the line "
               "carrying 12.3% of the process's HITM. Guarding the store "
               "removed that line from the profile. Note that it did not move "
               "throughput on that target, so the wasted traffic is certain "
               "and its endpoint value is not.";
    }

    void analyze(const clang::Decl *D,
                 clang::ASTContext &Ctx,
                 const HotPathOracle &Oracle,
                 const Config & /*Cfg*/,
                 const EscapeAnalysis &escape,
                 std::vector<Diagnostic> &out) override {

        const auto *FD = llvm::dyn_cast_or_null<clang::FunctionDecl>(D);
        if (!FD || !FD->doesThisDeclarationHaveABody())
            return;
        if (Oracle.hotnessSource(FD) == HotnessSource::None)
            return;

        StoreFinder finder(Ctx);
        finder.TraverseStmt(FD->getBody());
        if (finder.sites.empty())
            return;

        const auto &SM = Ctx.getSourceManager();
        const std::string fnName = FD->getQualifiedNameAsString();

        for (const auto &s : finder.sites) {
            if (SM.isInSystemHeader(s.loc))
                continue;

            const auto *field = llvm::dyn_cast<clang::FieldDecl>(s.decl);
            auto rev = field ? escape.fieldReadEvidence(field)
                             : EscapeAnalysis::FieldReadEvidence{};

            Diagnostic diag;
            diag.ruleID = "FL005";
            diag.title = "Redundant Store to a Shared Line";
            diag.severity = s.isAtomic ? Severity::Medium
                                       : Severity::Informational;
            diag.confidence = s.isAtomic ? 0.60 : 0.50;
            diag.evidenceTier = EvidenceTier::Likely;
            diag.location = resolveSourceLocation(s.loc, SM);
            diag.functionName = fnName;

            std::ostringstream hw;
            hw << "'" << s.decl->getNameAsString() << "' is stored "
               << "unconditionally, and its value collapses at least "
               << s.factor << " inputs onto one result, so at most one store "
               << "in " << s.factor << " changes it. The rest take the line "
               << "Exclusive and invalidate it in every core reading it, "
               << "leaving each of them to re-fetch a value identical to the "
               << "one it discarded.";
            diag.hardwareReasoning = hw.str();

            diag.structuralEvidence = {
                {"symbol", s.decl->getNameAsString()},
                {"global_root", s.root->getNameAsString()},
                {"contraction_factor", std::to_string(s.factor)},
                {"atomic_store", s.isAtomic ? "yes" : "no"},
                {"tu_reader_functions", std::to_string(rev.readerFunctions)},
                {"store_function", fnName},
            };
            if (field && field->getParent())
                diag.structuralEvidence["type_name"] =
                    field->getParent()->getCanonicalDecl()
                        ->getQualifiedNameAsString();

            diag.mitigation =
                "Read the location and store only when the value differs, or "
                "keep the last stored value in a thread-local so the guard "
                "does not touch the shared line either. The guard is a load "
                "that hits L1 while the line stays Shared; the store it "
                "replaces is an invalidation of every other core's copy.";

            diag.mechanismClaims = {
                {"the stored value changes far less often than the store runs",
                 "the value is a division, shift or predicate with a constant "
                 "factor", true, Severity::Informational},
                {"the store is not already guarded on the value changing",
                 "no enclosing condition tests the destination", true,
                 Severity::Medium},
                // Left for the reduce phase. A store in a function reached
                // once from main runs once, and a per-TU view cannot tell
                // that from a per-command one: the call graph that decides it
                // is only whole after every shard reports.
                {"the store runs more than once",
                 "the enclosing function is reached from a loop or from more "
                 "than one call site", false, Severity::Informational,
                 /*gating=*/true},
            };
            out.push_back(std::move(diag));
        }
    }
};

LSHAZ_REGISTER_RULE(FL005_RedundantSharedStore)

} // namespace lshaz
