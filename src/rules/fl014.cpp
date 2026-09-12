// SPDX-License-Identifier: Apache-2.0
#include "lshaz/core/rule.h"
#include "lshaz/core/registry.h"
#include "lshaz/core/hot_path.h"
#include "lshaz/core/config.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Basic/SourceManager.h>

#include <numeric>
#include <sstream>

namespace lshaz {

namespace {

struct MisalignedSite {
    clang::SourceLocation loc;
    std::string target;        // spelling of the atomic target type
    uint64_t widthBytes = 0;
    uint64_t baseAlign = 0;    // alignment of the underlying object, 0 unknown
    bool constantOffset = false;
    uint64_t offset = 0;
    bool splitsAlways = false; // crosses a line under every realizable shift
    bool splitsSometimes = false;
};

// Root of a chain of pointer arithmetic and casts, so a declared object's
// alignment can be recovered where there is one.
const clang::ValueDecl *rootDeclOf(const clang::Expr *E) {
    while (E) {
        E = E->IgnoreParenImpCasts();
        if (const auto *CE = llvm::dyn_cast<clang::CastExpr>(E)) {
            E = CE->getSubExpr();
        } else if (const auto *BO = llvm::dyn_cast<clang::BinaryOperator>(E)) {
            if (BO->getOpcode() != clang::BO_Add &&
                BO->getOpcode() != clang::BO_Sub)
                return nullptr;
            E = BO->getLHS()->getType()->isPointerType() ? BO->getLHS()
                                                         : BO->getRHS();
        } else if (const auto *DRE = llvm::dyn_cast<clang::DeclRefExpr>(E)) {
            return DRE->getDecl();
        } else if (const auto *UO = llvm::dyn_cast<clang::UnaryOperator>(E)) {
            if (UO->getOpcode() != clang::UO_AddrOf) return nullptr;
            E = UO->getSubExpr();
        } else {
            return nullptr;
        }
    }
    return nullptr;
}

class MisalignedAtomicVisitor
    : public clang::RecursiveASTVisitor<MisalignedAtomicVisitor> {
public:
    clang::ASTContext &ctx;
    uint64_t lineBytes;
    std::vector<MisalignedSite> sites;

    MisalignedAtomicVisitor(clang::ASTContext &C, uint64_t line)
        : ctx(C), lineBytes(line) {}

    bool VisitAtomicExpr(clang::AtomicExpr *E) {
        inspect(E->getPtr(), E->getBeginLoc());
        return true;
    }

    // __sync_* predate AtomicExpr and stay plain calls.
    bool VisitCallExpr(clang::CallExpr *E) {
        const auto *FD = E->getDirectCallee();
        if (!FD || !FD->getIdentifier() || E->getNumArgs() == 0)
            return true;
        if (FD->getName().starts_with("__sync_"))
            inspect(E->getArg(0), E->getBeginLoc());
        return true;
    }

private:
    // The compiler emits a native atomic whenever the pointer's type says the
    // access is aligned. A cast from a byte-granular base is the one shape
    // where that type is an assertion the source never justified: the packed
    // field case is diagnosed by Clang and lowered to libatomic instead.
    void inspect(const clang::Expr *ptr, clang::SourceLocation loc) {
        if (!ptr) return;
        const clang::Expr *stripped = ptr->IgnoreParenImpCasts();
        const auto *cast = llvm::dyn_cast<clang::ExplicitCastExpr>(stripped);
        if (!cast) return;

        clang::QualType dst = cast->getType();
        if (!dst->isPointerType()) return;
        clang::QualType target = dst->getPointeeType();
        if (target.isNull() || target->isIncompleteType()) return;

        clang::QualType src = cast->getSubExpr()->getType();
        if (!src->isPointerType()) return;
        clang::QualType srcPointee = src->getPointeeType();
        if (srcPointee.isNull() || srcPointee->isIncompleteType()) return;

        const uint64_t width = ctx.getTypeSizeInChars(target).getQuantity();
        const uint64_t srcAlign =
            ctx.getTypeAlignInChars(srcPointee).getQuantity();
        if (width <= 1 || srcAlign >= width)
            return;

        MisalignedSite s;
        s.loc = loc;
        s.target = target.getAsString();
        s.widthBytes = width;

        const clang::Expr *inner = cast->getSubExpr()->IgnoreParenImpCasts();
        if (const auto *BO = llvm::dyn_cast<clang::BinaryOperator>(inner)) {
            if (BO->getOpcode() == clang::BO_Add ||
                BO->getOpcode() == clang::BO_Sub) {
                const clang::Expr *off =
                    BO->getLHS()->getType()->isPointerType() ? BO->getRHS()
                                                             : BO->getLHS();
                clang::Expr::EvalResult r;
                if (off->EvaluateAsInt(r, ctx)) {
                    s.constantOffset = true;
                    s.offset = r.Val.getInt().getZExtValue() *
                               ctx.getTypeSizeInChars(srcPointee).getQuantity();
                }
            }
        }

        if (const auto *VD =
                llvm::dyn_cast_or_null<clang::VarDecl>(rootDeclOf(inner)))
            s.baseAlign = ctx.getDeclAlign(VD).getQuantity();

        // base+offset is aligned to gcd(align(base), offset). Where that
        // already covers the access the cast asserts nothing untrue, which is
        // most casts through a byte buffer.
        if (s.baseAlign && s.constantOffset &&
            std::gcd(s.baseAlign, s.offset ? s.offset : s.baseAlign) >= width)
            return;

        // Same realizable-shift sweep CacheLineMap uses: the base can sit at
        // any multiple of its own alignment inside a line.
        if (s.constantOffset && lineBytes) {
            const uint64_t step =
                s.baseAlign ? std::min(s.baseAlign, lineBytes) : lineBytes;
            bool all = true, any = false;
            for (uint64_t shift = 0; shift < lineBytes; shift += step) {
                const uint64_t at = (shift + s.offset) % lineBytes;
                if (at + width > lineBytes) any = true;
                else                        all = false;
            }
            s.splitsAlways = all && any;
            s.splitsSometimes = any;
        }
        sites.push_back(std::move(s));
    }
};

} // anonymous namespace

class FL014_MisalignedAtomic : public Rule {
public:
    std::string_view getID() const override { return "FL014"; }
    std::string_view getTitle() const override {
        return "Atomic on an Unprovably Aligned Address";
    }
    Severity getBaseSeverity() const override { return Severity::Critical; }

    std::string_view getHardwareMechanism() const override {
        return "An atomic whose address is cast from a byte-granular base "
               "asserts an alignment the source never established. On x86-64 "
               "a LOCK-prefixed operation spanning two cache lines cannot "
               "lock one line, so the core falls back to a serializing path "
               "costing orders of magnitude more than the aligned operation. "
               "The cost is borne by the issuing core and does not extend to "
               "unrelated cores on the socket. On ARM64 the "
               "exclusive and LSE atomics require natural alignment, so the "
               "same source raises an alignment fault and the process takes "
               "SIGBUS. A packed _Atomic field is a different shape: Clang "
               "diagnoses it under -Watomic-alignment and lowers it to a "
               "libatomic call, so it reaches neither path.";
    }

    void analyze(const clang::Decl *D,
                 clang::ASTContext &Ctx,
                 const HotPathOracle & /*Oracle*/,
                 const Config &Cfg,
                 const EscapeAnalysis & /*Escape*/,
                 std::vector<Diagnostic> &out) override {

        const auto *FD = llvm::dyn_cast_or_null<clang::FunctionDecl>(D);
        if (!FD || !FD->doesThisDeclarationHaveABody())
            return;

        MisalignedAtomicVisitor v(Ctx, Cfg.cacheLineBytes);
        v.TraverseStmt(FD->getBody());
        if (v.sites.empty())
            return;

        const bool isARM = Cfg.targetArch == TargetArch::ARM64 ||
                           Cfg.targetArch == TargetArch::ARM64Apple;
        const auto &SM = Ctx.getSourceManager();

        for (const auto &s : v.sites) {
            Diagnostic d;
            d.ruleID = "FL014";
            d.title = "Atomic on an Unprovably Aligned Address";
            d.functionName = FD->getQualifiedNameAsString();
            d.location = resolveSourceLocation(s.loc, SM);

            std::vector<std::string> esc;
            if (s.constantOffset)
                esc.push_back("byte offset " + std::to_string(s.offset) +
                              " into a base aligned to " +
                              (s.baseAlign ? std::to_string(s.baseAlign) + "B"
                                           : std::string("an unknown boundary")));
            else
                esc.push_back(
                    "offset is not compile-time evaluable, so alignment can be "
                    "neither proven nor refuted here; it may resolve safe at "
                    "runtime");

            if (s.splitsAlways) {
                d.severity = Severity::Critical;
                d.confidence = 0.90;
                d.evidenceTier = EvidenceTier::Proven;
                esc.push_back("the access crosses a " +
                              std::to_string(Cfg.cacheLineBytes) +
                              "B line under every realizable base alignment");
            } else if (s.splitsSometimes) {
                d.severity = Severity::Critical;
                d.confidence = 0.75;
                d.evidenceTier = EvidenceTier::Likely;
                esc.push_back("the access crosses a line under some realizable "
                              "base alignment; which one the allocator or "
                              "linker picks is not fixed here");
            } else {
                d.severity = Severity::Medium;
                d.confidence = 0.40;
                d.evidenceTier = EvidenceTier::Speculative;
                esc.push_back("no line crossing provable from this offset; the "
                              "finding rests on the cast alone");
            }

            std::ostringstream hw;
            hw << "Atomic access of " << s.widthBytes << "B ('" << s.target
               << "') through a pointer cast from a base with "
               << (s.baseAlign ? std::to_string(s.baseAlign) : std::string("1"))
               << "B alignment in '" << d.functionName << "'. ";
            if (isARM)
                hw << "On ARM64 the exclusive and LSE atomics fault on a "
                      "misaligned address, so this is a SIGBUS rather than a "
                      "slowdown.";
            else
                hw << "On x86-64 a LOCK-prefixed operation spanning two lines "
                      "serializes the issuing core, orders of magnitude "
                      "slower than the aligned operation.";
            d.hardwareReasoning = hw.str();

            d.structuralEvidence = {
                {"target_type", s.target},
                {"access_width", std::to_string(s.widthBytes)},
                {"base_align",
                 s.baseAlign ? std::to_string(s.baseAlign) : "unknown"},
                {"offset", s.constantOffset ? std::to_string(s.offset)
                                            : "not-constant"},
                {"splits", s.splitsAlways      ? "always"
                           : s.splitsSometimes ? "sometimes"
                                               : "unproven"},
                {"target_arch", isARM ? "arm64" : "x86-64"},
            };

            d.mitigation =
                isARM ? "Give the object the atomic's natural alignment "
                        "(alignas) or access it through a correctly typed "
                        "member. A misaligned exclusive access faults."
                      : "Give the object the atomic's natural alignment "
                        "(alignas) so the operation stays inside one line. "
                        "Where the layout is fixed by a wire format, copy to "
                        "an aligned local and operate there.";

            d.mechanismClaims = {
                {"the address carries an alignment the source never proved",
                 "an atomic cast from a base narrower than the access", true,
                 Severity::Medium},
                {isARM ? "alignment fault on a misaligned exclusive access"
                       : "the issuing core serializes on the split lock",
                 "the access crosses a cache line under a realizable base "
                 "alignment",
                 s.splitsSometimes, Severity::Critical},
            };
            d.escalations = std::move(esc);
            out.push_back(std::move(d));
        }
    }
};

LSHAZ_REGISTER_RULE(FL014_MisalignedAtomic)

} // namespace lshaz
