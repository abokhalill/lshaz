// SPDX-License-Identifier: Apache-2.0
#include "lshaz/core/Rule.h"
#include "lshaz/core/RuleRegistry.h"
#include "lshaz/core/HotPathOracle.h"
#include "lshaz/analysis/EscapeAnalysis.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Basic/SourceManager.h>

#include <sstream>

namespace lshaz {

namespace {

// 2MB: the x86-64 hugepage unit, and >512 base pages; past L1 dTLB
// coverage. khugepaged collapses 2MB-aligned virtual extents only, so
// an unaligned region forfeits its edges: a 4MB array misaligned by a
// page backs 1 huge page instead of 2; exactly-2MB misaligned backs 0.
constexpr uint64_t kTLBSpanBytes = 2ull * 1024 * 1024;
constexpr uint64_t kMapHugetlb = 0x40000; // linux MAP_HUGETLB

uint64_t typeBytes(clang::ASTContext &Ctx, clang::QualType QT) {
    if (QT->isDependentType() || QT->isIncompleteType())
        return 0;
    return static_cast<uint64_t>(Ctx.getTypeSizeInChars(QT).getQuantity());
}

// Hot function bodies are the gate for global-array findings: a cold
// 5MB config buffer never page-walks anyone. Fire from the accessor,
// not the VarDecl; rules are stateless and the decl can't see its
// readers; dedup's canonical key collapses multiple hot accessors.
class HotGlobalRefVisitor
    : public clang::RecursiveASTVisitor<HotGlobalRefVisitor> {
public:
    clang::ASTContext &ctx;
    std::vector<const clang::VarDecl *> largeGlobals;

    explicit HotGlobalRefVisitor(clang::ASTContext &C) : ctx(C) {}

    bool VisitDeclRefExpr(clang::DeclRefExpr *E) {
        const auto *VD = llvm::dyn_cast<clang::VarDecl>(E->getDecl());
        if (!VD || !VD->hasGlobalStorage() || VD->isConstexpr())
            return true;
        if (VD->getType().isConstQualified())
            return true; // read-only data: still walkable but rarely strided hot; keep precision
        if (typeBytes(ctx, VD->getType()) < kTLBSpanBytes)
            return true;
        largeGlobals.push_back(VD);
        return true;
    }
};

struct AllocSite {
    clang::SourceLocation loc;
    uint64_t length;
    const char *api;
    // The argument that would exonerate the site (mmap flags, memalign
    // alignment) is not compile-time evaluable. Unprovable is a tier,
    // never a Medium assertion.
    const char *unprovableArg; // nullptr = fully evaluated, hazard proven
};

class AllocVisitor : public clang::RecursiveASTVisitor<AllocVisitor> {
public:
    clang::ASTContext &ctx;
    std::vector<AllocSite> sites;

    explicit AllocVisitor(clang::ASTContext &C) : ctx(C) {}

    bool VisitCallExpr(clang::CallExpr *E) {
        const auto *FD = E->getDirectCallee();
        if (!FD || !FD->getIdentifier())
            return true;
        llvm::StringRef n = FD->getName();

        auto cstInt = [&](unsigned idx, uint64_t &out) {
            if (idx >= E->getNumArgs())
                return false;
            clang::Expr::EvalResult r;
            if (!E->getArg(idx)->EvaluateAsInt(r, ctx))
                return false;
            out = r.Val.getInt().getZExtValue();
            return true;
        };

        if ((n == "mmap" || n == "mmap64") && E->getNumArgs() >= 4) {
            uint64_t len = 0, flags = 0;
            if (!cstInt(1, len) || len < kTLBSpanBytes)
                return true;
            if (!cstInt(3, flags)) {
                sites.push_back({E->getBeginLoc(), len, "mmap", "flags"});
                return true;
            }
            if (flags & kMapHugetlb)
                return true; // hugepages requested
            sites.push_back({E->getBeginLoc(), len, "mmap", nullptr});
        } else if (n == "posix_memalign" && E->getNumArgs() >= 3) {
            uint64_t align = 0, len = 0;
            if (!cstInt(2, len) || len < kTLBSpanBytes)
                return true;
            if (!cstInt(1, align)) {
                sites.push_back(
                    {E->getBeginLoc(), len, "posix_memalign", "alignment"});
                return true;
            }
            if (align >= kTLBSpanBytes)
                return true; // 2MB alignment: author already thinks in hugepages
            sites.push_back(
                {E->getBeginLoc(), len, "posix_memalign", nullptr});
        } else if (n == "aligned_alloc" && E->getNumArgs() >= 2) {
            uint64_t align = 0, len = 0;
            if (!cstInt(1, len) || len < kTLBSpanBytes)
                return true;
            if (!cstInt(0, align)) {
                sites.push_back(
                    {E->getBeginLoc(), len, "aligned_alloc", "alignment"});
                return true;
            }
            if (align >= kTLBSpanBytes)
                return true;
            sites.push_back(
                {E->getBeginLoc(), len, "aligned_alloc", nullptr});
        }
        return true;
    }
};

bool allocatorIsTHPAware(const Config &cfg) {
    return cfg.linkedAllocator == "jemalloc" ||
           cfg.linkedAllocator == "tcmalloc";
}

} // anonymous namespace

class FL070_TLBPressure : public Rule {
public:
    std::string_view getID() const override { return "FL070"; }
    std::string_view getTitle() const override { return "TLB Pressure"; }
    Severity getBaseSeverity() const override { return Severity::Medium; }

    std::string_view getHardwareMechanism() const override {
        return "A working set spanning more base pages than the dTLB "
               "covers (~64 L1 / ~1-2K L2 entries at 4KB) turns strided "
               "access into page walks — 4-level lookups, each a potential "
               "cache-miss chain (dtlb_load_misses.walk_completed). A 2MB "
               "hugepage entry covers 512x the reach; khugepaged can only "
               "collapse 2MB-aligned extents, so base alignment gates the "
               "whole mitigation.";
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
        const auto &SM = Ctx.getSourceManager();

        // Path 1: hot function strides a >=2MB global.
        if (Oracle.isFunctionHot(FD)) {
            HotGlobalRefVisitor globals(Ctx);
            globals.TraverseStmt(FD->getBody());
            for (const auto *VD : globals.largeGlobals) {
                uint64_t bytes = typeBytes(Ctx, VD->getType());
                uint64_t alignBytes = static_cast<uint64_t>(
                    Ctx.getDeclAlign(VD).getQuantity());
                bool hugeAligned = alignBytes >= kTLBSpanBytes;

                Diagnostic diag;
                diag.ruleID = "FL070";
                diag.title = "TLB Pressure";
                // Aligned = the author already thinks in hugepage units;
                // report at floor per the mitigation-respect contract.
                diag.severity =
                    hugeAligned ? Severity::Informational : Severity::Medium;
                diag.confidence = hugeAligned ? 0.35 : 0.65;
                diag.evidenceTier = EvidenceTier::Likely;
                diag.location =
                    resolveSourceLocation(VD->getLocation(), SM);
                diag.functionName = FD->getQualifiedNameAsString();

                std::ostringstream hw;
                hw << "Global '" << VD->getNameAsString() << "' ("
                   << (bytes / (1024 * 1024)) << "MB, " << (bytes / 4096)
                   << " base pages) is referenced from hot code";
                if (!hugeAligned)
                    hw << " and lacks 2MB base alignment — khugepaged "
                          "cannot collapse the unaligned edges, so THP "
                          "coverage is forfeited where it matters most";
                hw << ".";
                diag.hardwareReasoning = hw.str();

                diag.structuralEvidence = {
                    {"bytes", std::to_string(bytes)},
                    {"base_pages", std::to_string(bytes / 4096)},
                    {"align", std::to_string(alignBytes)},
                    {"kind", "hot-global"},
                    {"symbol", VD->getNameAsString()},
                };
                diag.mitigation =
                    hugeAligned
                        ? "Alignment is hugepage-ready; ensure THP is "
                          "enabled (or madvise(MADV_HUGEPAGE) the range "
                          "at startup)."
                        : "alignas(2*1024*1024) on the definition, then "
                          "madvise(MADV_HUGEPAGE)/THP. Alignment is the "
                          "gate: without it the kernel cannot collapse.";
                out.push_back(std::move(diag));
            }
        }

        // Path 2: allocation sites with provable sizes. Not hot-gated —
        // the mapping outlives the allocating function; grading carries
        // the uncertainty instead.
        AllocVisitor allocs(Ctx);
        allocs.TraverseStmt(FD->getBody());
        bool thpAllocator = allocatorIsTHPAware(Cfg);
        for (const auto &s : allocs.sites) {
            Diagnostic diag;
            diag.ruleID = "FL070";
            diag.title = "TLB Pressure";
            if (s.unprovableArg) {
                // The exonerating argument is dynamic: it may resolve
                // safe at runtime. Unprovable is a tier, not a warning.
                diag.severity = Severity::Informational;
                diag.confidence = 0.30;
                diag.evidenceTier = EvidenceTier::Speculative;
            } else {
                diag.severity =
                    thpAllocator ? Severity::Informational : Severity::Medium;
                diag.confidence = thpAllocator ? 0.40 : 0.65;
                diag.evidenceTier = EvidenceTier::Likely;
            }
            diag.location = resolveSourceLocation(s.loc, SM);
            diag.functionName = FD->getQualifiedNameAsString();

            std::ostringstream hw;
            hw << s.api << " of " << (s.length / (1024 * 1024))
               << "MB: " << (s.length / 4096)
               << " base-page dTLB entries vs "
               << (s.length / kTLBSpanBytes) << " hugepage entrie(s)";
            if (s.unprovableArg)
                hw << ". The " << s.unprovableArg
                   << " argument is not compile-time evaluable and may "
                      "resolve safe at runtime; verify there, this is a "
                      "pointer not a verdict";
            else if (thpAllocator)
                hw << ". Linked allocator (" << Cfg.linkedAllocator
                   << ") chunks large allocations 2MB-aligned and "
                      "THP-aware — residual risk is policy, not layout";
            hw << ".";
            diag.hardwareReasoning = hw.str();

            diag.structuralEvidence = {
                {"bytes", std::to_string(s.length)},
                {"base_pages", std::to_string(s.length / 4096)},
                {"kind", s.api},
                {"provable", s.unprovableArg ? s.unprovableArg
                                             : "fully-evaluated"},
            };
            diag.mitigation =
                "MAP_HUGETLB (reserved pool) or madvise(MADV_HUGEPAGE) "
                "after the map; 2MB-align the base either way.";
            out.push_back(std::move(diag));
        }
    }
};

LSHAZ_REGISTER_RULE(FL070_TLBPressure)

} // namespace lshaz
