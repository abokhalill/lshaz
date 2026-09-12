// SPDX-License-Identifier: Apache-2.0
#include "lshaz/core/rule.h"
#include "lshaz/core/registry.h"
#include "lshaz/core/hot_path.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/DeclCXX.h>
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Stmt.h>
#include <clang/Basic/SourceManager.h>

#include <sstream>

namespace lshaz {

namespace {

struct DispatchInfo {
    unsigned virtualCalls = 0;
    unsigned indirectCalls = 0;   // std::function operator()
    unsigned switchCases = 0;
    unsigned callees = 0;         // distinct function calls
    bool hasLoop = false;
};

class DispatchVisitor : public clang::RecursiveASTVisitor<DispatchVisitor> {
public:
    bool VisitCXXMemberCallExpr(clang::CXXMemberCallExpr *E) {
        if (const auto *MD = E->getMethodDecl()) {
            if (MD->isVirtual())
                ++info_.virtualCalls;
        }
        return true;
    }

    // Fan-out means transfers of control: each one costs a BTB entry and an
    // I-cache line at the callee. A compiler builtin costs neither, and an
    // AVX intrinsic is a CallExpr in the AST but a single instruction in the
    // object code, so counting them reads a hand-vectorised kernel as a wide
    // dispatcher.
    bool VisitCallExpr(clang::CallExpr *E) {
        if (const auto *FD = E->getDirectCallee()) {
            if (FD->getBuiltinID() != 0)
                return true;
            if (FD->hasAttr<clang::AlwaysInlineAttr>())
                return true;
        }
        ++info_.callees;
        return true;
    }

    bool VisitSwitchStmt(clang::SwitchStmt *S) {
        unsigned cases = 0;
        for (auto *sc = S->getSwitchCaseList(); sc; sc = sc->getNextSwitchCase())
            ++cases;
        info_.switchCases = std::max(info_.switchCases, cases);
        return true;
    }

    bool TraverseForStmt(clang::ForStmt *S) {
        info_.hasLoop = true;
        return clang::RecursiveASTVisitor<DispatchVisitor>::TraverseForStmt(S);
    }
    bool TraverseWhileStmt(clang::WhileStmt *S) {
        info_.hasLoop = true;
        return clang::RecursiveASTVisitor<DispatchVisitor>::TraverseWhileStmt(S);
    }
    bool TraverseCXXForRangeStmt(clang::CXXForRangeStmt *S) {
        info_.hasLoop = true;
        return clang::RecursiveASTVisitor<DispatchVisitor>::TraverseCXXForRangeStmt(S);
    }

    const DispatchInfo &info() const { return info_; }

private:
    DispatchInfo info_;
};

} // anonymous namespace

class FL061_CentralizedDispatcher : public Rule {
public:
    std::string_view getID() const override { return "FL061"; }
    std::string_view getTitle() const override { return "Centralized Dispatcher Bottleneck"; }
    Severity getBaseSeverity() const override { return Severity::High; }

    bool requiresHotPath() const override { return true; }
    bool withdrawnWhenNotHot() const override { return true; }

    std::string_view getHardwareMechanism() const override {
        return "A single fan-out point routes all message processing through "
               "one function. The cost is branch misprediction on the "
               "selector when it is data-dependent, which is what the "
               "conditional-depth rule already prices. Arm count itself is "
               "nearly free. Instruction-cache pressure applies only once the "
               "inlined arms exceed L1i, so a wide dispatcher of small arms "
               "costs little and a narrow one of large arms can cost more. "
               "Centralisation also prevents per-core locality of handler "
               "state, which is a separate argument from either.";
    }

    void analyze(const clang::Decl *D,
                 clang::ASTContext &Ctx,
                 const HotPathOracle &Oracle,
                 const Config & /*Cfg*/,
                 const EscapeAnalysis & /*Escape*/,
                 std::vector<Diagnostic> &out) override {

        const auto *FD = llvm::dyn_cast_or_null<clang::FunctionDecl>(D);
        if (!FD || !FD->doesThisDeclarationHaveABody())
            return;

        if (!Oracle.isFunctionHot(FD))
            return;

        DispatchVisitor visitor;
        visitor.TraverseStmt(FD->getBody());

        const auto &info = visitor.info();

        // Heuristic: centralized dispatcher has high fan-out.
        // Threshold: 5+ callees OR large switch OR 3+ virtual calls.
        bool isDispatcher = false;
        std::string reason;

        if (info.callees >= 8) {
            isDispatcher = true;
            reason = std::to_string(info.callees) + " call sites (high fan-out)";
        } else if (info.switchCases >= 6 && info.callees >= 3) {
            isDispatcher = true;
            reason = std::to_string(info.switchCases) + "-case switch with " +
                     std::to_string(info.callees) + " call sites";
        } else if (info.virtualCalls >= 3) {
            isDispatcher = true;
            reason = std::to_string(info.virtualCalls) +
                     " virtual dispatch sites (polymorphic fan-out)";
        }

        if (!isDispatcher)
            return;

        Severity sev = Severity::High;
        std::vector<std::string> escalations;

        if (info.hasLoop) {
            sev = Severity::Critical;
            escalations.push_back(
                "Dispatch loop: per-iteration fan-out amplifies I-cache "
                "and BTB pressure");
        }

        if (info.virtualCalls >= 3 && info.switchCases >= 4) {
            sev = Severity::Critical;
            escalations.push_back(
                "Mixed dispatch: switch + virtual calls compound "
                "branch misprediction surface");
        }

        const auto &SM = Ctx.getSourceManager();
        auto loc = FD->getLocation();

        Diagnostic diag;
        diag.ruleID    = "FL061";
        diag.title     = "Centralized Dispatcher Bottleneck";
        diag.severity  = sev;
        diag.confidence = 0.55;
        diag.evidenceTier = EvidenceTier::Speculative;
        diag.functionName = FD->getQualifiedNameAsString();

        diag.location = resolveSourceLocation(loc, SM);

        std::ostringstream hw;
        hw << "Hot function '" << FD->getQualifiedNameAsString()
           << "' exhibits centralized dispatcher pattern: " << reason
           << ". Single-point fan-out serializes all processing, "
           << "pressures I-cache with large dispatch body, and "
           << "creates BTB contention from multiple indirect targets. "
           << "[Assumes: dispatcher handles high fan-in from multiple callers at runtime]";
        diag.hardwareReasoning = hw.str();

        diag.structuralEvidence = {
            {"function", FD->getQualifiedNameAsString()},
            {"callees", std::to_string(info.callees)},
            {"virtual_calls", std::to_string(info.virtualCalls)},
            {"switch_cases", std::to_string(info.switchCases)},
            {"has_loop", info.hasLoop ? "yes" : "no"},
        };

        diag.mitigation =
            "Partition dispatch by message type to separate handlers. "
            "Use compile-time dispatch (templates, CRTP) where type set is closed. "
            "Shard by core to eliminate cross-core contention on dispatcher state. "
            "Consider table-driven dispatch with function pointer arrays.";

        // Counted in real transfers of control; see countsAsTransfer.
        diag.mechanismClaims = {
            {"I-cache and BTB footprint from wide fan-out",
             "a hot function with many real (non-builtin) call targets",
             ClaimState::Established, Severity::Medium},
            {"indirect target misprediction across polymorphic sites",
             "three or more virtual dispatch sites",
             claimFrom(info.virtualCalls >= 3), Severity::High},
            {"the fan-out is re-walked on every iteration",
             "the dispatch sits inside a loop", claimFrom(info.hasLoop),
             Severity::High},
        };
        diag.escalations = std::move(escalations);
        out.push_back(std::move(diag));
    }
};

LSHAZ_REGISTER_RULE(FL061_CentralizedDispatcher)

} // namespace lshaz
