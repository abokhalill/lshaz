// SPDX-License-Identifier: Apache-2.0
#include "lshaz/core/rule.h"
#include "lshaz/analysis/loop_shape.h"
#include "lshaz/core/registry.h"
#include "lshaz/core/hot_path.h"
#include "lshaz/analysis/allocator.h"
#include "lshaz/analysis/data_flow.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/DeclCXX.h>
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/DeclTemplate.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Stmt.h>
#include <clang/Basic/SourceManager.h>

#include <fnmatch.h>
#include <map>
#include <set>

#include <sstream>
#include <string>

namespace lshaz {

namespace {

struct AllocSite {
    clang::SourceLocation loc;
    std::string kind; // "new", "delete", "malloc", "std::make_shared", etc.
    unsigned inLoop = 0;
    AllocatorClass allocClass = AllocatorClass::Unknown;
    long long constBytes = -1; // -1 when the request does not fold to a constant
    std::string typeName;      // pointee type, empty when it cannot be named
};

class AllocVisitor : public clang::RecursiveASTVisitor<AllocVisitor> {
public:
    AllocVisitor(clang::ASTContext &Ctx, const std::vector<std::string> &wrappers,
                 const std::set<std::string> &derived,
                 const std::set<std::string> &derivedFree)
        : ctx_(Ctx), wrappers_(wrappers), derived_(derived),
          derivedFree_(derivedFree) {}

    // T *p = malloc(n): the call's own type is void*, so the declaration is
    // where the allocated type is recoverable. Keyed by the call's location,
    // which is what the site records.
    bool VisitVarDecl(clang::VarDecl *VD) {
        if (!VD || !VD->hasInit())
            return true;
        const auto *CE = llvm::dyn_cast<clang::CallExpr>(
            VD->getInit()->IgnoreParenImpCasts());
        if (!CE)
            return true;
        clang::QualType QT = VD->getType();
        const auto *PT = QT.isNull() ? nullptr : QT->getAs<clang::PointerType>();
        if (!PT)
            return true;
        std::string n = typeKey(PT->getPointeeType());
        if (!n.empty())
            declTypes_[CE->getBeginLoc().getRawEncoding()] = n;
        return true;
    }

    bool VisitCXXNewExpr(clang::CXXNewExpr *E) {
        long long bytes = -1;
        clang::QualType t = E->getAllocatedType();
        if (!t.isNull() && !t->isDependentType() && !t->isIncompleteType()) {
            bytes = ctx_.getTypeSizeInChars(t).getQuantity();
            if (E->isArray()) {
                auto n = E->getArraySize();
                long long count = n ? constArg(*n) : -1;
                bytes = count >= 0 ? bytes * count : -1;
            }
        }
        sites_.push_back({E->getBeginLoc(), "operator new", inLoop_,
                          AllocatorClass::Unknown, bytes,
                          typeKey(E->getAllocatedType())});
        return true;
    }

    bool VisitCXXDeleteExpr(clang::CXXDeleteExpr *E) {
        sites_.push_back({E->getBeginLoc(), "operator delete", inLoop_});
        return true;
    }

    bool VisitCallExpr(clang::CallExpr *E) {
        if (const auto *callee = E->getDirectCallee()) {
            std::string name = callee->getQualifiedNameAsString();

            if (name == "malloc" || name == "calloc" || name == "realloc" ||
                name == "free" || name == "aligned_alloc" ||
                name == "posix_memalign" || matchesWrapper(name)) {
                sites_.push_back({E->getBeginLoc(), name, inLoop_,
                                  AllocatorClass::Unknown, requestBytes(E, name)});
            }

            if (name == "std::make_shared" || name == "std::make_unique" ||
                name == "std::make_shared_for_overwrite" ||
                name == "std::make_unique_for_overwrite") {
                sites_.push_back({E->getBeginLoc(), name, inLoop_});
            }
        }
        return true;
    }

    bool VisitCXXConstructExpr(clang::CXXConstructExpr *E) {
        if (const auto *CD = E->getConstructor()) {
            // Resolve template name through ClassTemplateSpecializationDecl.
            std::string templateName;
            if (const auto *CTSD = llvm::dyn_cast<clang::ClassTemplateSpecializationDecl>(
                    CD->getParent())) {
                if (auto *TD = CTSD->getSpecializedTemplate())
                    templateName = TD->getQualifiedNameAsString();
            }
            if (templateName.empty())
                templateName = CD->getParent()->getQualifiedNameAsString();

            static const char *heapAllocTypes[] = {
                "std::function",
                "std::shared_ptr",
                "std::vector", "std::map", "std::unordered_map",
                "std::list", "std::deque", "std::set", "std::unordered_set",
                "std::basic_string"
            };

            for (const auto *ht : heapAllocTypes) {
                if (templateName == ht) {
                    std::string label = std::string(ht) + " ctor";
                    sites_.push_back({E->getBeginLoc(), label, inLoop_});
                    break;
                }
            }

            // libstdc++ mangled string path.
            if (templateName == "std::__cxx11::basic_string")
                sites_.push_back({E->getBeginLoc(), "std::string ctor", inLoop_});
        }
        return true;
    }

    // Track loop nesting for escalation.
    bool TraverseForStmt(clang::ForStmt *S) {
        const unsigned st = isDegenerateLoop(S, ctx_) ? 0u : 1u;
        inLoop_ += st;
        bool r = clang::RecursiveASTVisitor<AllocVisitor>::TraverseForStmt(S);
        inLoop_ -= st;
        return r;
    }

    bool TraverseWhileStmt(clang::WhileStmt *S) {
        const unsigned st = isDegenerateLoop(S, ctx_) ? 0u : 1u;
        inLoop_ += st;
        bool r = clang::RecursiveASTVisitor<AllocVisitor>::TraverseWhileStmt(S);
        inLoop_ -= st;
        return r;
    }

    bool TraverseDoStmt(clang::DoStmt *S) {
        const unsigned st = isDegenerateLoop(S, ctx_) ? 0u : 1u;
        inLoop_ += st;
        bool r = clang::RecursiveASTVisitor<AllocVisitor>::TraverseDoStmt(S);
        inLoop_ -= st;
        return r;
    }

    bool TraverseCXXForRangeStmt(clang::CXXForRangeStmt *S) {
        const unsigned st = isDegenerateLoop(S, ctx_) ? 0u : 1u;
        inLoop_ += st;
        bool r = clang::RecursiveASTVisitor<AllocVisitor>::TraverseCXXForRangeStmt(S);
        inLoop_ -= st;
        return r;
    }

    // Types are attached after the walk: VisitVarDecl may run either side of
    // the call site it names, so the join cannot happen at push time.
    const std::vector<AllocSite> &sites() {
        for (auto &s : sites_)
            if (s.typeName.empty()) {
                auto it = declTypes_.find(s.loc.getRawEncoding());
                if (it != declTypes_.end())
                    s.typeName = it->second;
            }
        return sites_;
    }

private:
    // AllocatorTopology grades an unknown callee as the configured
    // allocator, which is what a wrapper resolves to.
    // Derived names come from the prepass and carry the codebase's own
    // spelling; the patterns remain for what structure cannot reach.
    bool matchesWrapper(const std::string &name) const {
        // Both sides: a release wrapper takes the same arena lock an
        // allocation does, which is why this rule's libc list already
        // carries free alongside malloc.
        if (derived_.count(name) || derivedFree_.count(name))
            return true;
        for (const auto &p : wrappers_)
            if (fnmatch(p.c_str(), name.c_str(), 0) == 0)
                return true;
        return false;
    }

    std::string typeKey(clang::QualType QT) const {
        if (QT.isNull())
            return {};
        QT = QT.getCanonicalType().getUnqualifiedType();
        if (QT->isVoidType() || QT->isDependentType() ||
            QT->isIncompleteType())
            return {};
        const auto *RD = QT->getAsRecordDecl();
        return RD ? RD->getCanonicalDecl()->getQualifiedNameAsString()
                  : QT.getAsString();
    }

    long long constArg(const clang::Expr *E) const {
        clang::Expr::EvalResult r;
        if (!E || !E->EvaluateAsInt(r, ctx_))
            return -1;
        return r.Val.getInt().getExtValue();
    }

    // Wrappers are deliberately absent: their signatures vary, and guessing
    // which parameter is the size would grade real allocations on a number
    // read from the wrong argument.
    long long requestBytes(const clang::CallExpr *E, llvm::StringRef name) const {
        unsigned n = E->getNumArgs();
        if (name == "malloc" && n >= 1)
            return constArg(E->getArg(0));
        if (name == "calloc" && n >= 2) {
            long long a = constArg(E->getArg(0)), b = constArg(E->getArg(1));
            return (a >= 0 && b >= 0) ? a * b : -1;
        }
        if ((name == "realloc" || name == "aligned_alloc") && n >= 2)
            return constArg(E->getArg(1));
        return -1;
    }

    clang::ASTContext &ctx_;
    const std::vector<std::string> &wrappers_;
    const std::set<std::string> &derived_;
    const std::set<std::string> &derivedFree_;
    std::vector<AllocSite> sites_;
    std::map<unsigned, std::string> declTypes_;
    unsigned inLoop_ = 0;
};

} // anonymous namespace

class FL020_HeapAllocHotPath : public Rule {
public:
    std::string_view getID() const override { return "FL020"; }
    std::string_view getTitle() const override { return "Heap Allocation in Hot Path"; }
    Severity getBaseSeverity() const override { return Severity::Critical; }

    bool requiresHotPath() const override { return true; }
    bool withdrawnWhenNotHot() const override { return true; }

    std::string_view getHardwareMechanism() const override {
        return "The allocate and free round trip is always paid, and grows "
               "with request size. Arena lock contention is not a general "
               "cost on top of it: same-thread alloc/free is flat in thread "
               "count, because a thread cache and per-thread arenas keep it "
               "off shared state. It appears when a block is freed by a "
               "thread other than the one that allocated it and returns to "
               "the owning arena, which costs several times the same-thread "
               "trip under glibc and is still worse than flat under "
               "jemalloc. Volume is not the signal; cross-thread ownership "
               "transfer is.";
    }

    void analyze(const clang::Decl *D,
                 clang::ASTContext &Ctx,
                 const HotPathOracle &Oracle,
                 const Config &Cfg,
                 const EscapeAnalysis & /*Escape*/,
                 std::vector<Diagnostic> &out) override {

        const auto *FD = llvm::dyn_cast_or_null<clang::FunctionDecl>(D);
        if (!FD || !FD->doesThisDeclarationHaveABody())
            return;

        if (!Oracle.isFunctionHot(FD))
            return;

        AllocVisitor visitor(Ctx, Cfg.allocatorFunctionPatterns,
                             Cfg.derivedAllocatorNames,
                             Cfg.derivedFreeNames);
        visitor.TraverseStmt(FD->getBody());

        // Intra-procedural data-flow analysis for precision.
        DataFlowAnalyzer dfa(Ctx);
        DataFlowFacts dfFacts = dfa.analyze(FD);

        // Classify allocation sites by allocator topology.
        AllocatorTopology topo;
        if (!Cfg.linkedAllocator.empty())
            topo.setLinkedAllocator(Cfg.linkedAllocator);

        const auto &SM = Ctx.getSourceManager();

        for (const auto &site : visitor.sites()) {
            AllocatorClass ac = topo.classify(site.kind);
            double sevFactor = allocatorSeverityFactor(ac);

            // Base severity modulated by allocator topology.
            Severity sev = Severity::Critical;
            if (sevFactor < 0.4)
                sev = Severity::Medium;
            else if (sevFactor < 0.8)
                sev = Severity::High;

            double confidence = 0.75 * sevFactor;
            if (confidence < 0.20)
                confidence = 0.20;
            if (confidence > 1.0)
                confidence = 1.0;

            std::vector<std::string> escalations;

            if (site.inLoop) {
                escalations.push_back(
                    "Allocation inside loop: per-iteration allocator pressure, "
                    "compounding TLB and fragmentation cost");
                // Loop escalation overrides topology demotion.
                if (sev < Severity::High)
                    sev = Severity::High;
            }

            // Above glibc's tcache_max the request misses the per-thread
            // cache and takes the arena path. tcmalloc and jemalloc draw
            // their boundary elsewhere, so only allocators not already
            // classified as thread-caching are graded on size.
            const bool overThreadCache =
                site.constBytes >= 0 &&
                static_cast<size_t>(site.constBytes) > Cfg.allocSizeEscalation &&
                ac != AllocatorClass::ThreadLocal &&
                ac != AllocatorClass::PoolSlab;
            if (overThreadCache) {
                escalations.push_back(
                    "Request of " + std::to_string(site.constBytes) +
                    "B exceeds the thread-cache boundary (" +
                    std::to_string(Cfg.allocSizeEscalation) +
                    "B): misses tcache for the arena path, 2.8x on glibc");
                if (sev < Severity::High)
                    sev = Severity::High;
            }

            if (ac == AllocatorClass::ThreadLocal) {
                escalations.push_back(
                    "allocator-topology: thread-local cache path (" +
                    Cfg.linkedAllocator + "), reduced contention risk");
            } else if (ac == AllocatorClass::PoolSlab) {
                escalations.push_back(
                    "allocator-topology: pool/slab allocator, minimal latency");
            } else if (ac == AllocatorClass::Syscall) {
                escalations.push_back(
                    "allocator-topology: mmap/brk syscall path, page fault risk");
            }

            Diagnostic diag;
            diag.ruleID    = "FL020";
            diag.title     = "Heap Allocation in Hot Path";
            diag.severity  = sev;
            diag.confidence = confidence;
            diag.evidenceTier = EvidenceTier::Likely;
            diag.functionName = FD->getQualifiedNameAsString();

            diag.location = resolveSourceLocation(site.loc, SM);

            std::ostringstream hw;
            hw << "'" << site.kind << "' in hot function '"
               << FD->getQualifiedNameAsString()
               << "'. Allocator class: " << allocatorClassName(ac)
               << ". ";
            if (ac == AllocatorClass::ThreadLocal) {
                // A thread-cache hit returns a previously freed chunk from a
                // per-thread free list: no lock is taken and no page is
                // mapped, so neither arena contention nor TLB pressure
                // applies. What remains is the call itself and the locality
                // loss against inline or stack storage.
                hw << "Thread-local cache hit expected (" << Cfg.linkedAllocator
                   << "): no arena lock and no new page mapping, so neither "
                   << "contention nor TLB reach is at issue here. The cost is "
                   << "the allocate/free round trip and the loss of locality "
                   << "against inline or stack storage, the returned chunk "
                   << "is typically cold in L1D.";
            } else if (ac == AllocatorClass::Syscall) {
                hw << "Large allocation triggers mmap syscall. "
                   << "Page fault jitter, TLB shootdown on munmap.";
            } else {
                hw << "May contend on allocator arena locks, "
                   << "trigger mmap/brk syscalls, fault new pages into the TLB, "
                   << "and fragment the heap reducing spatial locality.";
            }
            hw << " [Assumes: allocation frequency is high at runtime on this path]";
            diag.hardwareReasoning = hw.str();

            // Data-flow escalations.
            bool escapes = false;
            bool flowsToLoop = false;
            if (diag.location.line > 0) {
                escapes = dfFacts.allocEscapes.count(diag.location.line) > 0;
                flowsToLoop = dfFacts.allocFlowsToLoop.count(diag.location.line) > 0;
            }
            if (escapes) {
                escalations.push_back(
                    "data-flow: allocated pointer escapes function "
                    "(passed to callee, stored to field, or returned)");
                if (confidence < 0.85)
                    confidence = std::min(confidence + 0.10, 1.0);
            }
            if (flowsToLoop && !site.inLoop) {
                escalations.push_back(
                    "data-flow: allocation result flows into loop body");
                if (sev < Severity::High)
                    sev = Severity::High;
            }

            diag.severity = sev;
            diag.confidence = confidence;

            diag.structuralEvidence = {
                {"alloc_type", site.kind},
                {"allocator_class", std::string(allocatorClassName(ac))},
                {"function", FD->getQualifiedNameAsString()},
                {"in_loop", site.inLoop ? "yes" : "no"},
                {"allocated_type", site.typeName},
                {"hot_path", "true"},
                {"alloc_escapes", escapes ? "yes" : "no"},
                {"flows_to_loop", flowsToLoop ? "yes" : "no"},
            };

            diag.mitigation =
                "Preallocate buffers. Use arena/slab/pool allocators. "
                "Move allocation to cold initialization path. "
                "Reserve std::vector capacity upfront.";

            diag.escalations = std::move(escalations);
            diag.mechanismClaims = {
                {"allocate/free round trip, and locality lost against inline "
                 "or stack storage",
                 "an allocation on a hot path", ClaimState::Established, Severity::Medium},
                // Measured flat 1->3 threads for same-thread alloc/free, so
                // allocator class alone cannot establish contention.
                {"allocator arena lock contention",
                 "a free on a thread other than the allocating one, which "
                 "returns the block to another thread's arena",
                 ClaimState::Unknown, Severity::High},
                {"mmap syscall, page faults, TLB shootdown on munmap",
                 "an allocation above the mmap threshold",
                 claimFrom(ac == AllocatorClass::Syscall), Severity::Critical},
                {"the cost is paid on every iteration",
                 "the allocation sits inside a loop",
                 claimFrom(site.inLoop != 0),
                 Severity::High},
                // Established by the size alone: no runtime frequency
                // assumption stands behind it, unlike the round-trip claim.
                {"the request misses the thread cache and takes the arena "
                 "path, several times the thread-cache round trip",
                 "a constant request above the allocator's thread-cache "
                 "boundary",
                 claimFrom(overThreadCache), Severity::High},
                // Cross-thread free is the only term that reaches Critical,
                // and proving it needs alloc/free ownership across TUs, which
                // we cannot do yet. Unestablished so the grade says so.
                {"the block is freed by a thread other than the allocator, "
                 "costing 4-5x under jemalloc and up to 25x under glibc",
                 "alloc and free attributed to disjoint thread roles",
                 ClaimState::Unknown, Severity::High, /*gating=*/true},
            };
            out.push_back(std::move(diag));
        }
    }
};

LSHAZ_REGISTER_RULE(FL020_HeapAllocHotPath)

} // namespace lshaz
