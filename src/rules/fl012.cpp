// SPDX-License-Identifier: Apache-2.0
#include <fnmatch.h>

#include <set>
#include "lshaz/core/rule.h"
#include "lshaz/analysis/loop_shape.h"
#include "lshaz/core/registry.h"
#include "lshaz/core/hot_path.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/DeclCXX.h>
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/DeclTemplate.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Stmt.h>
#include <clang/Basic/SourceManager.h>

#include <sstream>

namespace lshaz {

namespace {

struct LockSite {
    clang::SourceLocation loc;
    std::string kind;     // "std::mutex::lock", "std::lock_guard", etc.
    bool isNested = false;
    unsigned inLoop = 0;
};

class LockVisitor : public clang::RecursiveASTVisitor<LockVisitor> {
public:
    LockVisitor(clang::ASTContext &Ctx,
                const std::vector<std::string> &lockPats,
                const std::vector<std::string> &unlockPats,
                const std::set<std::string> *derivedLock = nullptr,
                const std::set<std::string> *derivedUnlock = nullptr)
        : derivedLock_(derivedLock), derivedUnlock_(derivedUnlock), ctx_(Ctx),
          lockPats_(lockPats), unlockPats_(unlockPats) {}

    bool VisitCXXMemberCallExpr(clang::CXXMemberCallExpr *E) {
        const auto *MD = E->getMethodDecl();
        if (!MD)
            return true;

        std::string method = MD->getNameAsString();
        if (method != "lock" && method != "try_lock")
            return true;

        const auto *parent = MD->getParent();
        if (!parent)
            return true;

        std::string className = parent->getQualifiedNameAsString();
        static const char *mutexTypes[] = {
            "std::mutex", "std::recursive_mutex",
            "std::shared_mutex", "std::timed_mutex",
            "std::recursive_timed_mutex", "std::shared_timed_mutex"
        };
        bool isMutex = false;
        for (const auto *mt : mutexTypes) {
            if (className == mt) { isMutex = true; break; }
        }
        if (!isMutex)
            return true;

        bool nested = lockDepth_ > 0;
        sites_.push_back({E->getBeginLoc(), className + "::" + method, nested, inLoop_});
        ++lockDepth_;
        ++scopeLockIncrements_;
        return true;
    }

    // POSIX locks are free functions and arrive as CallExpr. The member-call
    // arm above cannot reach them at all: pthread_mutex_t is a union with no
    // methods, so nothing can name it as a member's parent.
    bool VisitCallExpr(clang::CallExpr *E) {
        const auto *FD = E->getDirectCallee();
        if (!FD || !FD->getIdentifier())
            return true;
        llvm::StringRef n = FD->getName();

        // Project wrappers first: a codebase reaching its mutexes through
        // ngx_shmtx_lock or LWLockAcquire has no pthread_ call to match.
        if (isUnlock(n)) {
            if (lockDepth_ > 0)
                --lockDepth_;
            return true;
        }
        if (isLock(n)) {
            sites_.push_back({E->getBeginLoc(), n.str(), lockDepth_ > 0,
                              inLoop_});
            ++lockDepth_;
            ++scopeLockIncrements_;
            return true;
        }

        if (!n.starts_with("pthread_"))
            return true;

        // RAII releases at scope exit, which TraverseCompoundStmt restores.
        // An explicit pair does not, so without this two sequential
        // lock/unlock pairs in one block report the second as nested.
        if (n == "pthread_mutex_unlock" || n == "pthread_spin_unlock" ||
            n == "pthread_rwlock_unlock") {
            if (lockDepth_ > 0)
                --lockDepth_;
            return true;
        }

        static const char *kAcquire[] = {
            "pthread_mutex_lock",         "pthread_mutex_trylock",
            "pthread_mutex_timedlock",    "pthread_spin_lock",
            "pthread_spin_trylock",       "pthread_rwlock_rdlock",
            "pthread_rwlock_wrlock",      "pthread_rwlock_tryrdlock",
            "pthread_rwlock_trywrlock",   "pthread_rwlock_timedrdlock",
            "pthread_rwlock_timedwrlock",
        };
        for (const char *a : kAcquire) {
            if (n != a)
                continue;
            sites_.push_back({E->getBeginLoc(), n.str(), lockDepth_ > 0,
                              inLoop_});
            ++lockDepth_;
            ++scopeLockIncrements_;
            break;
        }
        return true;
    }

    bool VisitCXXConstructExpr(clang::CXXConstructExpr *E) {
        const auto *CD = E->getConstructor();
        if (!CD)
            return true;

        std::string parent = CD->getParent()->getQualifiedNameAsString();

        // RAII lock wrappers. Resolve through template specializations.
        std::string resolvedName = parent;
        if (const auto *CTSD = llvm::dyn_cast<clang::ClassTemplateSpecializationDecl>(
                CD->getParent())) {
            if (auto *TD = CTSD->getSpecializedTemplate())
                resolvedName = TD->getQualifiedNameAsString();
        }
        if (resolvedName == "std::lock_guard" ||
            resolvedName == "std::unique_lock" ||
            resolvedName == "std::shared_lock" ||
            resolvedName == "std::scoped_lock") {

            bool nested = lockDepth_ > 0;
            sites_.push_back({E->getBeginLoc(), parent, nested, inLoop_});
            ++lockDepth_;
            ++scopeLockIncrements_;
        }
        return true;
    }

    bool TraverseCompoundStmt(clang::CompoundStmt *S) {
        unsigned savedDepth = lockDepth_;
        unsigned savedIncrements = scopeLockIncrements_;
        scopeLockIncrements_ = 0;
        bool r = clang::RecursiveASTVisitor<LockVisitor>::TraverseCompoundStmt(S);
        lockDepth_ = savedDepth;
        scopeLockIncrements_ = savedIncrements;
        return r;
    }

    bool TraverseForStmt(clang::ForStmt *S) {
        const unsigned st = isDegenerateLoop(S, ctx_) ? 0u : 1u;
        inLoop_ += st;
        bool r = clang::RecursiveASTVisitor<LockVisitor>::TraverseForStmt(S);
        inLoop_ -= st;
        return r;
    }
    bool TraverseWhileStmt(clang::WhileStmt *S) {
        const unsigned st = isDegenerateLoop(S, ctx_) ? 0u : 1u;
        inLoop_ += st;
        bool r = clang::RecursiveASTVisitor<LockVisitor>::TraverseWhileStmt(S);
        inLoop_ -= st;
        return r;
    }
    bool TraverseDoStmt(clang::DoStmt *S) {
        const unsigned st = isDegenerateLoop(S, ctx_) ? 0u : 1u;
        inLoop_ += st;
        bool r = clang::RecursiveASTVisitor<LockVisitor>::TraverseDoStmt(S);
        inLoop_ -= st;
        return r;
    }
    bool TraverseCXXForRangeStmt(clang::CXXForRangeStmt *S) {
        const unsigned st = isDegenerateLoop(S, ctx_) ? 0u : 1u;
        inLoop_ += st;
        bool r = clang::RecursiveASTVisitor<LockVisitor>::TraverseCXXForRangeStmt(S);
        inLoop_ -= st;
        return r;
    }

    const std::vector<LockSite> &sites() const { return sites_; }

private:
    static bool matches(const std::vector<std::string> &pats,
                        llvm::StringRef n) {
        std::string s = n.str();
        for (const auto &p : pats)
            if (fnmatch(p.c_str(), s.c_str(), 0) == 0)
                return true;
        return false;
    }

    // Derived names are exact; the pattern lists remain for wrappers the
    // prepass cannot reach, such as a spin lock built on atomics with no
    // POSIX call anywhere in its chain.
    bool isLock(llvm::StringRef n) const {
        return (derivedLock_ && derivedLock_->count(n.str())) ||
               matches(lockPats_, n);
    }
    bool isUnlock(llvm::StringRef n) const {
        return (derivedUnlock_ && derivedUnlock_->count(n.str())) ||
               matches(unlockPats_, n);
    }

    const std::set<std::string> *derivedLock_ = nullptr;
    const std::set<std::string> *derivedUnlock_ = nullptr;
    clang::ASTContext &ctx_;
    const std::vector<std::string> &lockPats_;
    const std::vector<std::string> &unlockPats_;
    std::vector<LockSite> sites_;
    unsigned inLoop_ = 0;
    unsigned lockDepth_ = 0;
    unsigned scopeLockIncrements_ = 0;
};

} // anonymous namespace

class FL012_LockHotPath : public Rule {
public:
    std::string_view getID() const override { return "FL012"; }
    std::string_view getTitle() const override { return "Lock in Hot Path"; }
    Severity getBaseSeverity() const override { return Severity::Critical; }

    bool requiresHotPath() const override { return true; }
    bool withdrawnWhenNotHot() const override { return true; }

    std::string_view getHardwareMechanism() const override {
        return "Threads serialize on a contended mutex, converting parallel "
               "execution into sequential. The lock word is itself a "
               "contended line, since the acquire is an atomic RMW, and it "
               "costs more than an atomic doing the same work. A futex sleep "
               "and context switch costs orders of magnitude more, but modern "
               "mutexes spin adaptively and block only when the critical "
               "section is long enough to make spinning wasteful, so that "
               "term belongs to the length of the section held rather than to "
               "the presence of a lock.";
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

        LockVisitor visitor(Ctx, Cfg.lockFunctionPatterns,
                            Cfg.unlockFunctionPatterns,
                            &Cfg.derivedLockNames, &Cfg.derivedUnlockNames);
        visitor.TraverseStmt(FD->getBody());

        const auto &SM = Ctx.getSourceManager();

        for (const auto &site : visitor.sites()) {
            Severity sev = (site.inLoop && site.isNested) ? Severity::Critical
                         : (site.inLoop || site.isNested) ? Severity::High
                                                          : Severity::Medium;
            std::vector<std::string> escalations;

            if (site.isNested) {
                escalations.push_back(
                    "Nested lock acquisition: widens the critical section and "
                    "serializes on two locks, before any contention");
            }

            if (site.inLoop) {
                escalations.push_back(
                    "Lock inside loop: the acquisition cost is paid every "
                    "iteration whether or not the lock is contended");
            }

            escalations.push_back(
                "the convoy cost, a futex wait and context switch, requires "
                "a second thread contending this lock, which is not "
                "established here; severity reflects acquisition frequency "
                "and critical-section width only");

            Diagnostic diag;
            diag.ruleID    = "FL012";
            diag.title     = "Lock in Hot Path";
            diag.severity  = sev;
            diag.confidence = 0.75;
            diag.evidenceTier = EvidenceTier::Likely;
            diag.functionName = FD->getQualifiedNameAsString();

            diag.location = resolveSourceLocation(site.loc, SM);

            std::ostringstream hw;
            hw << "'" << site.kind << "' in hot function '"
               << FD->getQualifiedNameAsString()
               << "'. Acquisition costs more than an atomic doing the same "
               << "work, since the LOCK-prefixed RMW on the lock word drains "
               << "the store buffer, and contention multiplies it. A futex "
               << "sleep costs orders of magnitude more, but glibc spins "
               << "adaptively before blocking, so that term is set by how "
               << "long the section is held and not by the lock "
               << "being on this path. "
               << "[Assumes: lock is contended under production load]";
            diag.hardwareReasoning = hw.str();

            diag.structuralEvidence = {
                {"lock_type", site.kind},
                {"function", FD->getQualifiedNameAsString()},
                {"nested", site.isNested ? "yes" : "no"},
                {"in_loop", site.inLoop ? "yes" : "no"},
            };

            diag.mitigation =
                "Use lock-free data structures. "
                "Adopt single-writer design pattern. "
                "Partition state to eliminate shared mutable access. "
                "Use try_lock with fallback to avoid blocking.";

            diag.mechanismClaims = {
                {"lock acquisition cost and critical-section width",
                 "a lock taken on a hot path", true,
                 (site.inLoop && site.isNested) ? Severity::Critical
                 : (site.inLoop || site.isNested) ? Severity::High
                                                  : Severity::Medium},
                {"lock convoy: futex wait and context switch",
                 "a second thread contending this lock", false,
                 Severity::Critical},
            };
            diag.escalations = std::move(escalations);
            out.push_back(std::move(diag));
        }
    }
};

LSHAZ_REGISTER_RULE(FL012_LockHotPath)

} // namespace lshaz
