// SPDX-License-Identifier: Apache-2.0
#include <fnmatch.h>
#include "lshaz/analysis/symbols.h"
#include "lshaz/analysis/vocabulary.h"
#include "lshaz/analysis/ast_consumer.h"
#include "lshaz/analysis/cache_line.h"
#include "lshaz/analysis/call_graph.h"
#include "lshaz/analysis/escape.h"
#include "lshaz/analysis/striped_array.h"
#include "lshaz/analysis/struct_layout.h"
#include "lshaz/core/registry.h"

#include <clang/AST/Decl.h>
#include <clang/AST/DeclGroup.h>
#include <clang/AST/DeclTemplate.h>
#include <clang/Basic/SourceManager.h>

#include <algorithm>
#include <unordered_set>

namespace lshaz {

namespace {

void collectOverriddenVirtuals(const std::vector<clang::Decl *> &decls,
                               ThreadRoleSummary &out) {
    for (const auto *D : decls) {
        const auto *RD = llvm::dyn_cast<clang::CXXRecordDecl>(D);
        if (!RD || !RD->isCompleteDefinition())
            continue;
        for (const auto *MD : RD->methods())
            for (const auto *Base : MD->overridden_methods())
                out.overriddenVirtuals.insert(
                    Base->getCanonicalDecl()->getQualifiedNameAsString());
    }
}

bool isInSystemHeader(const clang::Decl *D, const clang::SourceManager &SM) {
    auto loc = D->getLocation();
    if (loc.isInvalid())
        return true;
    return SM.isInSystemHeader(SM.getSpellingLoc(loc));
}

} // anonymous namespace

LshazASTConsumer::LshazASTConsumer(
    const Config &cfg,
    std::vector<Diagnostic> &diagnostics,
    EscapeSummary &escapeSummary,
    ThreadRoleSummary &threadRoles,
    StripedArraySummary &stripedArrays,
    ScanCoverage &coverage,
    const std::unordered_set<std::string> &profileHotFuncs)
    : config_(cfg), oracle_(cfg), diagnostics_(diagnostics),
      escapeSummary_(escapeSummary), threadRoles_(threadRoles),
      stripedArrays_(stripedArrays), coverage_(coverage) {
    if (!profileHotFuncs.empty())
        oracle_.loadProfileHotFunctions(profileHotFuncs);
}

void LshazASTConsumer::HandleTranslationUnit(clang::ASTContext &Ctx) {
    // Skip TUs that had fatal parse errors, partial ASTs contain
    // error-recovery types that crash Clang's layout computation.
    if (Ctx.getDiagnostics().hasFatalErrorOccurred())
        return;

    auto *TU = Ctx.getTranslationUnitDecl();
    const auto &SM = Ctx.getSourceManager();

    // Collect all non-system declarations, recursing into namespaces
    // and linkage-spec blocks (extern "C").
    std::vector<clang::Decl *> decls;
    std::function<void(clang::DeclContext *)> collect =
        [&](clang::DeclContext *DC) {
            for (auto *D : DC->decls()) {
                if (isInSystemHeader(D, SM))
                    continue;
                if (auto *NS = llvm::dyn_cast<clang::NamespaceDecl>(D)) {
                    collect(NS);
                    continue;
                }
                if (auto *LS = llvm::dyn_cast<clang::LinkageSpecDecl>(D)) {
                    collect(LS);
                    continue;
                }
                // Skip dependent or invalid decls, getASTRecordLayout
                // crashes on records with unresolved template parameters.
                if (D->isInvalidDecl())
                    continue;
                if (auto *RD = llvm::dyn_cast<clang::CXXRecordDecl>(D)) {
                    if (RD->isDependentType())
                        continue;
                }
                if (auto *FD = llvm::dyn_cast<clang::FunctionDecl>(D)) {
                    if (FD->isDependentContext())
                        continue;
                }

                decls.push_back(D);
                // Recurse into record decls for nested types.
                if (auto *RD = llvm::dyn_cast<clang::CXXRecordDecl>(D)) {
                    if (RD->isCompleteDefinition())
                        collect(RD);
                }
                // Recurse into class templates to visit implicit
                // specializations, without this, struct-level rules
                // never see instantiated template types.
                if (auto *CTD = llvm::dyn_cast<clang::ClassTemplateDecl>(D)) {
                    for (auto *Spec : CTD->specializations()) {
                        if (Spec->isCompleteDefinition() &&
                            !Spec->isInvalidDecl() &&
                            !isInSystemHeader(Spec, SM)) {
                            decls.push_back(Spec);
                            collect(Spec);
                        }
                    }
                }
            }
        };
    collect(TU);

    std::unordered_set<std::string> disabled(config_.disabledRules.begin(),
                                              config_.disabledRules.end());

    // First pass: seed hot-path oracle.
    for (auto *D : decls) {
        if (auto *FD = llvm::dyn_cast<clang::FunctionDecl>(D))
            oracle_.isFunctionHot(FD);
    }

    // Pass 1.5: build call graph and propagate hotness transitively.
    CallGraph cg(Ctx);
    cg.buildFromTU(TU);
    oracle_.propagateViaCallGraph(cg);
    // After propagation: an explicit signal must not be downgraded to an
    // inference, and record() keeps the strongest source anyway.
    if (config_.inferHotPaths) {
        oracle_.inferFromCodeShape(cg);
        // Everything the per-TU pass could not settle. Without this, a TU
        // holding no entry point answers "cold" for every function in it and
        // silently disables two thirds of the rule set there.
        oracle_.markCrossTUCandidates(cg);
    }

    // Counted after propagation, since that is when hotness is final.
    // Reported so a scan that examined a fraction of a codebase cannot be
    // mistaken for one that found nothing.
    for (auto *D : decls) {
        if (auto *FD = llvm::dyn_cast<clang::FunctionDecl>(D)) {
            if (!FD->hasBody())
                continue;
            ++coverage_.functionsSeen;
            if (oracle_.isFunctionHot(FD))
                ++coverage_.functionsHot;
        } else if (llvm::isa<clang::RecordDecl>(D)) {
            ++coverage_.recordsSeen;
        }
    }

    // Per-TU EscapeAnalysis, owned here, injected into rules.
    // This eliminates the ASTContext pointer-reuse cache invalidation
    // bug that caused FL040 non-determinism across forked children.
    EscapeAnalysis escape(Ctx);
    escape.setAtomicTypeNames(config_.atomicTypeNames);
    escape.scanTranslationUnit(TU);

    // Concurrency is a call-graph property, so it is injected rather than
    // rediscovered: which writers run on several threads at once decides
    // whether co-located fields can actually be written from two cores.
    {
        std::unordered_set<const clang::FunctionDecl *> pool;
        for (const auto *fn : cg.functions())
            if (cg.runsOnManyThreads(fn))
                pool.insert(fn);
        escape.setPoolRoleFunctions(std::move(pool));
    }

    // Second pass: run enabled rules.
    size_t diagsBefore = diagnostics_.size();
    const auto &rules = RuleRegistry::instance().rules();

    for (auto *D : decls) {
        const auto *FD = llvm::dyn_cast<clang::FunctionDecl>(D);
        const HotnessSource hs =
            FD ? oracle_.hotnessSource(FD) : HotnessSource::None;

        for (const auto &rule : rules) {
            if (disabled.count(std::string(rule->getID())))
                continue;
            const size_t before = diagnostics_.size();
            rule->analyze(D, Ctx, oracle_, config_, escape, diagnostics_);
            if (!rule->requiresHotPath() || hs == HotnessSource::None)
                continue;
            // Attached here rather than in each rule so a new hot-path rule
            // cannot forget it: the ceiling is a property of how hotness was
            // evidenced, not of the individual mechanism.
            for (size_t i = before; i < diagnostics_.size(); ++i) {
                // Recorded so the reduce phase can tell an unresolved
                // cross-TU candidate from a settled local verdict without
                // parsing the claim text back out.
                diagnostics_[i].hotness = static_cast<uint8_t>(hs);
                diagnostics_[i].mechanismClaims.push_back(
                    {std::string("this code runs often enough for the cost to "
                                 "recur (") + hotnessSourceName(hs) + ")",
                     "hotness established by profile or declaration, not "
                     "inferred from shape alone",
                     hs >= HotnessSource::Declared,
                     // Bound the grade the rule actually assigned, not the
                     // rule's base: rules escalate above base on evidence,
                     // and capping at base would erase those escalations.
                     hotnessSupportedSeverity(hs, diagnostics_[i].severity),
                     /*gating=*/true});
            }
        }
    }

    // Inline suppression: remove diagnostics with lshaz-suppress on their line
    // or the preceding line.  Format: // lshaz-suppress FL001,FL002
    auto isSuppressed = [&SM](const Diagnostic &diag) -> bool {
        if (diag.location.file.empty() || diag.location.line == 0)
            return false;
        auto fileRef = SM.getFileManager().getFileRef(diag.location.file);
        if (!fileRef)
            return false;
        auto fid = SM.translateFile(*fileRef);
        bool invalid = false;
        llvm::StringRef buf = SM.getBufferData(fid, &invalid);
        if (invalid || buf.empty())
            return false;

        // Check the diagnostic line and the line above it.
        for (unsigned checkLine = diag.location.line;
             checkLine >= 1 && checkLine >= diag.location.line - 1;
             --checkLine) {
            auto loc = SM.translateLineCol(fid, checkLine, 1);
            if (loc.isInvalid()) continue;
            unsigned offset = SM.getFileOffset(loc);
            auto eol = buf.find('\n', offset);
            llvm::StringRef line = buf.slice(offset,
                eol == llvm::StringRef::npos ? buf.size() : eol);
            auto pos = line.find("lshaz-suppress");
            if (pos == llvm::StringRef::npos) continue;
            llvm::StringRef tail = line.substr(pos + 14).ltrim();
            if (tail.empty())
                return true;  // bare suppress = suppress all
            // Parse comma-separated rule IDs.
            while (!tail.empty()) {
                auto [tok, rest] = tail.split(',');
                if (tok.trim() == diag.ruleID)
                    return true;
                tail = rest;
            }
        }
        return false;
    };

    auto it = std::remove_if(
        diagnostics_.begin() + static_cast<long>(diagsBefore),
        diagnostics_.end(), isSuppressed);
    diagnostics_.erase(it, diagnostics_.end());

    // Build per-TU escape summary for cross-TU aggregation.
    std::vector<const clang::RecordDecl *> records;
    for (auto *D : decls) {
        if (auto *RD = llvm::dyn_cast<clang::RecordDecl>(D))
            if (RD->isCompleteDefinition())
                records.push_back(RD);
    }
    escapeSummary_ = escape.buildEscapeSummary(records);

    // Layout-intent annotation for the FL092 precedent join. Alignment
    // reads Clang's cached record layout; no recomputation.
    const auto touched = escape.accessedRecords();
    for (const auto *RD : records) {
        auto it = escapeSummary_.find(
            RD->getCanonicalDecl()->getQualifiedNameAsString());
        if (it == escapeSummary_.end())
            continue;
        const auto &RL = Ctx.getASTRecordLayout(RD);
        bool aligned = static_cast<size_t>(
                           RL.getAlignment().getQuantity()) >=
                       config_.cacheLineBytes;
        if (aligned || CacheLineMap::hasTrailingLinePad(
                           RD, Ctx, config_.cacheLineBytes))
            it->second.hasDeliberateLayout = true;

        // Field extents for the reduce-phase read/write join. Restricted to
        // records this TU actually reaches: a record no TU touches has no
        // access to join against, and the map costs one pass per record per
        // TU either way.
        if (!touched.count(
                llvm::cast<clang::RecordDecl>(RD->getCanonicalDecl())))
            continue;
        CacheLineMap layout(RD, Ctx, config_.cacheLineBytes,
                            config_.atomicTypeNames);
        auto &sig = it->second;
        sig.recordAlignBytes = layout.recordAlign();
        for (const auto &f : layout.fields()) {
            if (!f.isMutable || f.name.empty())
                continue;
            // A bitfield's extent is the declared type's, not the bits it
            // owns, so every bitfield in a storage unit exports the same
            // byte range and pairs with its neighbours. They do share a
            // line, but they share a word, and no padding reaches that.
            if (f.decl && f.decl->isBitField())
                continue;
            const bool scalar = f.decl && f.decl->getType()->isScalarType() &&
                                !f.isAtomic && !f.decl->getType()->isPointerType();
            FieldExtent fx{f.offsetBytes, f.sizeBytes, f.isAtomic, scalar};
            if (f.decl)
                fx.declLine = resolveSourceLocation(f.decl->getLocation(), SM).line;
            sig.fieldExtents[f.name] = fx;
        }
        if (!sig.fieldExtents.empty()) {
            auto loc = resolveSourceLocation(RD->getLocation(), SM);
            sig.declFile = loc.file;
            sig.declLine = loc.line;
        }
    }

    // Thread-role facts for the cross-TU reduce: call edges + entries
    // from the graph already built for hotness, writer names from the
    // escape traversal. No additional TU walks.
    cg.snapshotForThreadRoles(threadRoles_);
    escape.appendFieldAccessNames(threadRoles_);
    collectOverriddenVirtuals(decls, threadRoles_);
    // Ownership facts come from the vocabulary prepass, which already walked
    // this TU for them. Collecting again here would be the second walk the
    // two-pass split exists to avoid.

    StripedArrayAnalysis striped(Ctx, config_, oracle_);
    striped.setThreadEntries(cg.threadEntryNames());
    striped.catalogue(decls);
    striped.collectAliases(decls);
    striped.collectUses(TU);
    stripedArrays_ = striped.summary();
}

} // namespace lshaz
