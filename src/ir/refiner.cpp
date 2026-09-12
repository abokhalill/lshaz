// SPDX-License-Identifier: Apache-2.0
#include "lshaz/ir/refiner.h"

#include <llvm/IR/Instructions.h>

#include <algorithm>
#include <sstream>

namespace lshaz {

DiagnosticRefiner::DiagnosticRefiner(const IRAnalyzer::ProfileMap &profiles,
                                     uint64_t stackFrameWarnBytes)
    : profiles_(profiles), stackFrameWarnBytes_(stackFrameWarnBytes) {}

bool DiagnosticRefiner::filePathSuffixMatch(const std::string &a,
                                             const std::string &b) {
    const std::string &longer  = (a.size() >= b.size()) ? a : b;
    const std::string &shorter = (a.size() >= b.size()) ? b : a;

    if (shorter.empty())
        return false;

    if (longer == shorter)
        return true;

    if (longer.size() <= shorter.size())
        return false;

    auto pos = longer.size() - shorter.size();
    return longer.compare(pos, shorter.size(), shorter) == 0 &&
           longer[pos - 1] == '/';
}

std::string DiagnosticRefiner::extractFunctionName(const Diagnostic &diag) const {
    if (!diag.functionName.empty())
        return diag.functionName;

    // Fallback: look up from structuralEvidence map.
    for (const char *key : {"function", "caller"}) {
        auto it = diag.structuralEvidence.find(key);
        if (it != diag.structuralEvidence.end() && !it->second.empty())
            return it->second;
    }
    return {};
}

// AST qualified names carry no parameter list; demangled symbols always
// do ("foo::bar" vs "foo::bar(int)"). exact/suffix equality therefore
// never matched a demangled name and refinement silently degraded to the
// decl-line fallback, which only covers diagnostics anchored at the
// function declaration. match at a '::' boundary followed by end, '('
// or '<'.
static bool demangledMatches(const std::string &dn, const std::string &fn) {
    size_t p = 0;
    while ((p = dn.find(fn, p)) != std::string::npos) {
        bool bOK = p == 0 || (p >= 2 && dn[p - 1] == ':' && dn[p - 2] == ':');
        size_t e = p + fn.size();
        bool eOK = e == dn.size() || dn[e] == '(' || dn[e] == '<';
        if (bOK && eOK)
            return true;
        ++p;
    }
    return false;
}

const IRFunctionProfile *DiagnosticRefiner::findProfile(
    const std::string &funcName) const {
    if (funcName.empty())
        return nullptr;

    // Exact mangled name match.
    auto it = profiles_.find(funcName);
    if (it != profiles_.end())
        return &it->second;

    static constexpr std::string_view kAnonNS = "(anonymous namespace)::";
    std::string stripped = funcName;
    for (;;) {
        auto pos = stripped.find(kAnonNS);
        if (pos == std::string::npos) break;
        stripped.erase(pos, kAnonNS.size());
    }

    // among overloads, pick deterministically: exact demangled name wins,
    // then lowest mangled name; never hash-map iteration order.
    const IRFunctionProfile *best = nullptr;
    int bestRank = 3;
    for (const auto &[mangled, profile] : profiles_) {
        const auto &dn = profile.demangledName;
        int rank;
        if (dn == funcName)
            rank = 0;
        else if (demangledMatches(dn, funcName))
            rank = 1;
        else if (stripped != funcName && demangledMatches(dn, stripped))
            rank = 2;
        else
            continue;
        if (rank < bestRank ||
            (rank == bestRank && best &&
             mangled < best->mangledName)) {
            best = &profile;
            bestRank = rank;
        }
    }
    return best;
}

const IRFunctionProfile *DiagnosticRefiner::findProfileByLocation(
    const std::string &file, unsigned line) const {
    if (file.empty() || line == 0)
        return nullptr;

    for (const auto &[mangled, profile] : profiles_) {
        if (profile.sourceLine == line && !profile.sourceFile.empty() &&
            filePathSuffixMatch(file, profile.sourceFile))
            return &profile;
    }
    return nullptr;
}

const IRFunctionProfile *DiagnosticRefiner::findProfileForDiag(
    const Diagnostic &diag) const {
    auto funcName = extractFunctionName(diag);
    const auto *profile = findProfile(funcName);
    if (profile)
        return profile;
    return findProfileByLocation(diag.location.file, diag.location.line);
}

// What the optimizer left standing.
namespace {

constexpr std::string_view kSurvives = "the mechanism survives optimization";

void survives(Diagnostic &d, Severity supports, std::string observation) {
    d.addSettledGate(std::string(kSurvives),
                     "the construct is still present after optimization",
                     ClaimState::Established, supports, std::move(observation));
}

void eliminated(Diagnostic &d, Severity supports, std::string observation) {
    d.addSettledGate(std::string(kSurvives),
                     "the construct is still present after optimization",
                     ClaimState::Refuted, supports, std::move(observation));
}

} // namespace

void DiagnosticRefiner::refine(std::vector<Diagnostic> &diagnostics) const {
    for (auto &diag : diagnostics) {
        if (diag.ruleID == "FL010") refineFL010(diag);
        else if (diag.ruleID == "FL011") refineFL011(diag);
        else if (diag.ruleID == "FL012") refineFL012(diag);
        else if (diag.ruleID == "FL020") refineFL020(diag);
        else if (diag.ruleID == "FL021") refineFL021(diag);
        else if (diag.ruleID == "FL030") refineFL030(diag);
        else if (diag.ruleID == "FL031") refineFL031(diag);
        else if (diag.ruleID == "FL090") refineFL090(diag);
        else if (diag.ruleID == "FL091") refineFL091(diag);
    }
}

void DiagnosticRefiner::refineFL010(Diagnostic &diag) const {
    const auto *profile = findProfileForDiag(diag);
    if (!profile)
        return;

    const unsigned diagLine = diag.location.line;
    const std::string &diagFile = diag.location.file;

    std::string siteOp;
    for (const auto &ai : profile->atomics) {
        if (ai.sourceLine == 0 || ai.sourceLine != diagLine)
            continue;
        if (!(diagFile.empty() || ai.sourceFile.empty() ||
              filePathSuffixMatch(diagFile, ai.sourceFile)))
            continue;
        if (ai.ordering != static_cast<unsigned>(
                llvm::AtomicOrdering::SequentiallyConsistent))
            continue;
        switch (ai.op) {
            case IRAtomicInfo::Store:   siteOp = "store"; break;
            case IRAtomicInfo::RMW:     siteOp = "rmw"; break;
            case IRAtomicInfo::CmpXchg: siteOp = "cmpxchg"; break;
            case IRAtomicInfo::Fence:   siteOp = "fence"; break;
            default:                    siteOp = "atomic"; break;
        }
        break;
    }

    if (!siteOp.empty()) {
        survives(diag, diag.severity,
                 "seq_cst " + siteOp + " at line " + std::to_string(diagLine) +
                 " survives lowering");
        diag.evidenceTier = EvidenceTier::Proven;
    } else if (profile->seqCstCount > 0) {
        survives(diag, diag.severity,
                 std::to_string(profile->seqCstCount) +
                 " seq_cst instruction(s) in the function, no exact line");
    } else if (!profile->atomics.empty()) {
        // Atomics lowered here, none of them seq_cst. The ordering this rule
        // proposes weakening is the ordering the compiler already dropped.
        eliminated(diag, diag.severity,
                   "the function lowered " +
                   std::to_string(profile->atomics.size()) +
                   " atomic(s) and none is seq_cst");
    }

    if (profile->fenceCount > 0)
        diag.escalations.push_back(
            "IR: " + std::to_string(profile->fenceCount) +
            " explicit fence instruction(s)");
}

void DiagnosticRefiner::refineFL011(Diagnostic &diag) const {
    const auto *profile = findProfileForDiag(diag);
    if (!profile)
        return;

    unsigned writes = 0, inLoop = 0, sited = 0;
    for (const auto &ai : profile->atomics) {
        if (ai.op != IRAtomicInfo::Store && ai.op != IRAtomicInfo::RMW &&
            ai.op != IRAtomicInfo::CmpXchg)
            continue;
        ++writes;
        if (ai.isInLoop) ++inLoop;
        if (ai.sourceLine > 0) ++sited;
    }
    if (writes == 0)
        return;

    std::ostringstream obs;
    obs << writes << " atomic write instruction(s)";
    if (inLoop) obs << ", " << inLoop << " on a loop back edge";
    if (sited)  obs << ", " << sited << " with a debug-loc site";
    survives(diag, diag.severity, obs.str());
    if (sited > 0)
        diag.evidenceTier = EvidenceTier::Proven;
}

void DiagnosticRefiner::refineFL012(Diagnostic &diag) const {
    const auto *profile = findProfileForDiag(diag);
    if (!profile)
        return;

    bool mutexCall = false;
    for (const auto &csi : profile->allCalls) {
        if (csi.isIndirect) continue;
        if (csi.calleeName.find("pthread_mutex") != std::string::npos ||
            csi.calleeName.find("__gthread_mutex") != std::string::npos ||
            csi.calleeName.find("pthread_spin") != std::string::npos ||
            csi.calleeName.find("pthread_rwlock") != std::string::npos) {
            mutexCall = true;
            break;
        }
    }

    bool cmpxchg = false, sited = false;
    for (const auto &ai : profile->atomics) {
        if (ai.op != IRAtomicInfo::CmpXchg) continue;
        cmpxchg = true;
        if (ai.sourceLine == diag.location.line && diag.location.line > 0)
            sited = true;
    }

    if (!mutexCall && !cmpxchg)
        return;

    std::string what = mutexCall ? "a pthread_mutex call"
                                 : "an atomic cmpxchg (lock internals)";
    if (sited) {
        what += " at line " + std::to_string(diag.location.line);
        diag.evidenceTier = EvidenceTier::Proven;
    }
    survives(diag, diag.severity, what + " present in lowered IR");
}

void DiagnosticRefiner::refineFL020(Diagnostic &diag) const {
    const auto *profile = findProfileForDiag(diag);
    if (!profile)
        return;

    unsigned calls = 0, inLoop = 0;
    for (const auto &csi : profile->heapAllocCalls) {
        if (csi.isIndirect) continue;
        ++calls;
        if (csi.isInLoop) ++inLoop;
    }

    if (calls == 0) {
        // Inlining and escape analysis removed every allocation the rule was
        // reporting. There is no allocator call left to contend for an arena.
        eliminated(diag, diag.severity,
                   "no heap alloc or free call remains after inlining");
        return;
    }

    std::ostringstream obs;
    obs << calls << " heap alloc/free call(s) after inlining";
    if (inLoop) obs << ", " << inLoop << " in loop blocks";
    survives(diag, diag.severity, obs.str());
}

void DiagnosticRefiner::refineFL021(Diagnostic &diag) const {
    const auto *profile = findProfileForDiag(diag);
    if (!profile)
        return;

    const uint64_t frame = profile->totalAllocaBytes;
    if (frame == 0)
        return;   // no allocas recorded: the estimate stands unchallenged

    if (frame < stackFrameWarnBytes_) {
        // The rule graded an AST estimate; the real frame is below the same
        // bar it was emitted against.
        eliminated(diag, diag.severity,
                   "the lowered frame is " + std::to_string(frame) +
                   "B, below the " + std::to_string(stackFrameWarnBytes_) +
                   "B threshold the finding was emitted against");
        return;
    }

    std::ostringstream obs;
    obs << "lowered frame " << frame << "B from " << profile->allocas.size()
        << " alloca(s)";
    for (const auto &a : profile->allocas)
        if (a.sizeBytes >= 256) obs << " [" << a.name << "=" << a.sizeBytes << "B]";
    survives(diag, diag.severity, obs.str());
    diag.evidenceTier = EvidenceTier::Proven;
    diag.structuralEvidence["ir_frame"] = std::to_string(frame) + "B";
    diag.structuralEvidence["ir_allocas"] =
        std::to_string(profile->allocas.size());
}

void DiagnosticRefiner::refineFL030(Diagnostic &diag) const {
    const auto *profile = findProfileForDiag(diag);
    if (!profile)
        return;

    if (profile->indirectCallCount > 0) {
        survives(diag, diag.severity,
                 std::to_string(profile->indirectCallCount) +
                 " indirect call(s) remain after devirtualization");
    } else if (profile->directCallCount > 0) {
        // Every call in the function lowered to a direct one. There is no
        // indirect branch left to mispredict and no inline left to lose.
        eliminated(diag, diag.severity,
                   "every call devirtualized to a direct call");
    }
}

void DiagnosticRefiner::refineFL031(Diagnostic &diag) const {
    const auto *profile = findProfileForDiag(diag);
    if (!profile)
        return;

    if (profile->indirectCallCount > 0) {
        survives(diag, diag.severity,
                 std::to_string(profile->indirectCallCount) +
                 " indirect call(s): the type erasure was not eliminated");
    } else {
        eliminated(diag, diag.severity,
                   "no indirect call remains: the std::function was inlined "
                   "or devirtualized");
    }
}

void DiagnosticRefiner::refineFL090(Diagnostic &diag) const {
    // Struct-level, so there is no enclosing function to look up. The module
    // aggregate is context, not a verdict on this record, and is reported as
    // such rather than settling any claim.
    unsigned atomicWrites = 0, indirect = 0, fences = 0;
    for (const auto &[name, profile] : profiles_) {
        for (const auto &ai : profile.atomics)
            if (ai.op == IRAtomicInfo::Store || ai.op == IRAtomicInfo::RMW ||
                ai.op == IRAtomicInfo::CmpXchg)
                ++atomicWrites;
        indirect += profile.indirectCallCount;
        fences   += profile.fenceCount;
    }

    if (atomicWrites == 0 && fences == 0)
        return;
    std::ostringstream ss;
    ss << "IR module aggregate: " << atomicWrites << " atomic write(s), "
       << fences << " fence(s), " << indirect << " indirect call(s)";
    diag.escalations.push_back(ss.str());
}

void DiagnosticRefiner::refineFL091(Diagnostic &diag) const {
    refineFL090(diag);
}

} // namespace lshaz
