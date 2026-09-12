// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <clang/AST/ASTContext.h>
#include <clang/AST/DeclCXX.h>
#include <clang/AST/Expr.h>
#include <clang/AST/Type.h>

#include "lshaz/analysis/atomics.h"
#include "lshaz/analysis/escape_summary.h"
#include "lshaz/analysis/thread_role.h"

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace lshaz {

struct EscapeVerdict {
    bool escapes          = false;

    bool hasAtomics       = false;
    bool hasSyncPrims     = false;
    bool hasSharedOwner   = false;
    bool hasVolatile      = false;
    bool hasPublication   = false;
    // Written from >=2 functions, at least one of them spawned as a thread.
    // Publication needs an address to cross a thread boundary; a file-scope
    // object written directly from two thread bodies never does.
    bool hasThreadWriters = false;
    // A file-scope instance of this type exists: threads reaching it reach
    // the SAME object. Necessary for false sharing (per-request instances
    // never collide) but not sufficient -- some thread must actually reach
    // it, which is hasPublication/hasThreadWriters.
    bool hasGlobalInstance = false;
    // Threads can reach the SAME object: shared instance plus a thread that
    // touches it. The precondition false sharing actually needs.
    bool hasSharingRoute = false;

    unsigned accessorCount = 0; // distinct functions touching this type in TU

    // An address became reachable but nothing names a writer. Coherence cost
    // needs one, so this is a mechanism distinction and not a shade of doubt.
    bool escapesByRouteOnly() const {
        return escapes && !hasAtomics && !hasVolatile && !hasSyncPrims &&
               !hasThreadWriters;
    }

    // The signals that fired, for the evidence block.
    std::string escapeSignals() const;

    operator bool() const { return escapes; }
};

// Thread-escape analysis with both structural and interprocedural evidence.
//
// escapes is the disjunction of the seven signals below, so finding none
// leaves it false: it reads "one was found in this TU", not "this is shared".
// Deciding against sharing wants the merged TypeEscapeSignals instead.
//
// Structural evidence (per-type):
//   1. std::atomic member fields
//   2. std::mutex / synchronization primitive members
//   3. std::shared_ptr / std::weak_ptr members
//   4. volatile members
//
// Publication evidence (TU-wide, collected via scanTranslationUnit):
//   5. Type passed to std::thread / std::jthread / std::async constructor
//   6. Type stored in a non-thread_local global/static mutable variable
//   7. Type used as pointee of std::shared_ptr in global scope
class EscapeAnalysis {
public:
    explicit EscapeAnalysis(clang::ASTContext &Ctx);

    // Run once per TU to collect interprocedural publication paths.
    void scanTranslationUnit(const clang::TranslationUnitDecl *TU);

    EscapeVerdict escapeVerdict(const clang::RecordDecl *RD) const;

    bool isFieldMutable(const clang::FieldDecl *FD) const;
    bool hasAtomicMembers(const clang::RecordDecl *RD) const;
    bool hasSyncPrimitives(const clang::RecordDecl *RD) const;
    bool isGlobalSharedMutable(const clang::VarDecl *VD) const;

    bool isAtomicType(clang::QualType QT) const;

    // Opaque atomic wrappers named in config. Injected rather than passed
    // through every call so no rule can silently skip the option.
    void setAtomicTypeNames(std::vector<std::string> names) {
        atomicTypeNames_ = std::move(names);
    }
    bool isSyncType(clang::QualType QT) const;

    bool hasSharedOwnershipMembers(const clang::RecordDecl *RD) const;
    bool isSharedOwnershipType(clang::QualType QT) const;
    bool hasVolatileMembers(const clang::RecordDecl *RD) const;

    // Query publication evidence for a specific type (by canonical qualified name).
    bool hasPublicationEvidence(const clang::RecordDecl *RD) const;

    // Mark a type as published to a cross-thread context.
    void markPublished(clang::QualType QT);
    // Mark a type as having a file-scope instance. Deliberately distinct
    // from publication: one is "there is a single shared object", the other
    // is "a thread reaches it". Conflating them made every global look
    // shared and every C struct look neither.
    void markGlobalInstance(clang::QualType QT,
                            const std::string &varName = {});
    // ';'-separated linker names of this type's global instances,
    // so a runtime trace keyed on symbols can be joined to findings
    // keyed on types.
    std::string globalInstanceNames(const clang::RecordDecl *RD) const;
    void markThreadEntry(const clang::Expr *E);

    // Build per-type escape summary for cross-TU aggregation.
    // Requires prior scanTranslationUnit() call. Iterates all RecordDecls
    // in the TU and snapshots their escape signals.
    EscapeSummary buildEscapeSummary(
        const std::vector<const clang::RecordDecl *> &records) const;

    // Raw per-TU write count for a global. Does NOT include the initializer,
    // only explicit assignments/increments in function bodies within this TU.
    unsigned getGlobalWriteCount(const clang::VarDecl *VD) const;

    // Writes to the global inside a loop. One in-loop site can sustain
    // millions of RFOs/s; site count alone cannot see that.
    unsigned getGlobalLoopWriteCount(const clang::VarDecl *VD) const;

    // Concurrency evidence for a global: how many distinct functions write
    // it in this TU, and whether any of them is spawned as a thread. The
    // coherence and NUMA mechanisms need concurrent writers; a global
    // written six times from startup configuration has neither.
    struct GlobalWriterEvidence {
        unsigned writerFunctions = 0;
        bool writtenFromThreadEntry = false;
    };
    GlobalWriterEvidence globalWriterEvidence(const clang::VarDecl *VD) const;

    // Per-field write evidence within this TU: direct member mutation
    // (assignment, ++/--, atomic store/RMW forms) attributed to the
    // enclosing function. Constructor member-init lists deliberately
    // excluded: initialization is not contention.
    struct FieldWriteEvidence {
        unsigned writeSites = 0;
        unsigned writerFunctions = 0;
        // Over-approximates density: a loop body containing a syscall is
        // still sparse. Deliberate; this gates a conjunct, so erring toward
        // "dense" costs precision while erring the other way costs recall.
        unsigned loopWriteSites = 0;
    };
    FieldWriteEvidence fieldWriteEvidence(const clang::FieldDecl *FD) const;

    // A store invalidates the whole line, so a core that only reads another
    // field on it re-fetches. That reader pays the same coherence miss a
    // second writer would, which is why write/write is sufficient for the
    // hazard and not necessary, and why the read side has to be tracked.
    struct FieldReadEvidence {
        unsigned readSites = 0;
        unsigned readerFunctions = 0;
    };
    FieldReadEvidence fieldReadEvidence(const clang::FieldDecl *FD) const;

    // Union of one field's writers and the other's readers has >=2 members:
    // the line is stored by one function and read by a different one.
    bool pairHasWriterAndDistinctReader(const clang::FieldDecl *w,
                                        const clang::FieldDecl *r) const;

    // Every writer of this field is separated from its next write by a body
    // this TU cannot see: positive evidence of microsecond spacing, which a
    // writer count cannot supply. Absence proves nothing; a leaf setter has
    // no opaque call and may still be driven from a tight loop.
    bool fieldWritersAllOpaque(const clang::FieldDecl *FD) const;


    // Union of the two fields' writer functions has >=2 members: the
    // pair is written from more than one function in this TU. A single
    // common writer is the init-pattern signature.
    bool pairHasDistinctWriters(const clang::FieldDecl *A,
                                const clang::FieldDecl *B) const;

    // Functions that run on several threads at once (reachable from a thread
    // entry spawned in a loop or from multiple sites). Injected after the
    // call graph is built, since concurrency is a call-graph property.
    void setPoolRoleFunctions(
        std::unordered_set<const clang::FunctionDecl *> fns);

    bool hasGlobalInstance(const clang::RecordDecl *RD) const;
    bool anyWriterOnThread(const clang::RecordDecl *RD) const;

    // Some field of this record is written through a fixed, nameable object
    // rather than one passed in. Necessary for false sharing: a handed-over
    // object has one owner at a time however many threads touch it.
    bool hasStandingWrites(const clang::RecordDecl *RD) const;

    // Snapshot per-field writer and reader sets as names ("Type::field" ->
    // functions) into the TU's thread-role facts. Same key convention as
    // buildEscapeSummary: canonical qualified names.
    void appendFieldAccessNames(ThreadRoleSummary &out) const;

    // Records whose fields this TU reads or writes. Exporting a layout costs
    // a pass over the record, and one nothing touches has no access to join
    // against.
    std::unordered_set<const clang::RecordDecl *> accessedRecords() const;

    // Public so the TU-scan visitor (anonymous namespace) can populate it.
    struct FieldWriteRecord {
        unsigned sites = 0;
        // Writes reaching a fixed object by name (standing shared access)
        // versus writes to whatever the caller handed in (ownership moves
        // with the object). A queue produces the second; a global counter
        // block produces the first. Writer counts cannot tell them apart.
        unsigned standingSites = 0;
        unsigned handedSites   = 0;
        // Writes issued from inside a loop. Coherence cost tracks spacing
        // rather than site count, and collapses as the writes move apart.
        // Field-level twin of globalLoopWriteCounts_ (FL040).
        unsigned loopSites     = 0;
        std::unordered_set<const clang::FunctionDecl *> writers;
        // Where the stores are, as basename:line.
        //
        // A profiler reports the DWARF line of an inlined store and the
        // symbol of whatever it was inlined into, so a name-based join to a
        // hardware profile silently misses every static inline writer. The
        // line survives.
        std::set<std::string> writeSiteLocs;
        unsigned readSites = 0;
        // Reach on the read side, which the write side cannot always see. A
        // setter writing through its parameter makes every write look handed
        // while the readers name one global singleton, so only the reads
        // establish that both touch a single object.
        unsigned standingReadSites = 0;
        unsigned handedReadSites = 0;
        std::unordered_set<const clang::FunctionDecl *> readers;
    };

private:

    clang::ASTContext &ctx_;

    // Canonical qualified names of types observed in publication paths.
    std::unordered_set<std::string> publishedTypes_;
    bool tuScanned_ = false;

    // Per-global write site count, populated by scanTranslationUnit.
    // Key: VarDecl canonical pointer. Value: number of write sites in TU
    // (excluding the initializer expression on the VarDecl itself).
    std::unordered_map<const clang::VarDecl *, unsigned> globalWriteCounts_;
    std::unordered_map<const clang::VarDecl *, unsigned> globalLoopWriteCounts_;
    std::unordered_set<const clang::FunctionDecl *> opaqueCallFns_;

    // Per-type: how many distinct functions access fields of this type.
    // Key: canonical RecordDecl*. Populated by scanTranslationUnit Pass 4.
    std::unordered_map<const clang::RecordDecl *, unsigned> typeAccessorCounts_;

    // Per-field write sites and distinct writer functions. Key: canonical
    // FieldDecl*. Populated alongside globalWriteCounts_ (same traversal).
    std::unordered_map<const clang::FieldDecl *, FieldWriteRecord>
        fieldWrites_;

    // Functions spawned as threads in this TU. Publication (passing an
    // address across a thread boundary) is not the only way an object
    // becomes shared: a file-scope object written directly from two thread
    // bodies is shared without any address ever being passed anywhere, and
    // that is the striped-counter shape.
    std::unordered_set<const clang::FunctionDecl *> threadEntries_;
    std::unordered_set<const clang::FunctionDecl *> poolRoleWriters_;
    std::vector<std::string> atomicTypeNames_;
    std::set<std::string> globalInstanceTypes_;
    std::map<std::string, std::set<std::string>> globalInstanceNames_;
    bool hasThreadEntryWriters(const clang::RecordDecl *RD) const;

    // Which functions write each global, so rules can ask whether the
    // writers can actually run concurrently instead of assuming it.
    std::unordered_map<const clang::VarDecl *,
                       std::unordered_set<const clang::FunctionDecl *>>
        globalWriters_;

    void collectGlobalWriteSites(
        const std::vector<const clang::FunctionDecl *> &bodies);
    void collectTypeAccessors(
        const std::vector<const clang::FunctionDecl *> &bodies);
};

} // namespace lshaz
