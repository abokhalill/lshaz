// SPDX-License-Identifier: Apache-2.0
#include "lshaz/ir/DiagnosticRefiner.h"
#include "lshaz/ir/ConfidenceModel.h"

#include <llvm/IR/Instructions.h>

#include <algorithm>
#include <sstream>

namespace lshaz {

DiagnosticRefiner::DiagnosticRefiner(const IRAnalyzer::ProfileMap &profiles)
    : profiles_(profiles) {}

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

const IRFunctionProfile *DiagnosticRefiner::findProfile(
    const std::string &funcName) const {
    if (funcName.empty())
        return nullptr;

    // Exact demangled name match.
    for (const auto &[mangled, profile] : profiles_) {
        if (profile.demangledName == funcName)
            return &profile;
    }

    // Qualified suffix match: "Foo::bar" matches "ns::Foo::bar".
    // Require match at a namespace boundary (preceded by '::' or at start).
    for (const auto &[mangled, profile] : profiles_) {
        const auto &dn = profile.demangledName;
        if (dn.size() > funcName.size()) {
            auto pos = dn.size() - funcName.size();
            if (dn.compare(pos, funcName.size(), funcName) == 0 &&
                pos >= 2 && dn[pos - 1] == ':' && dn[pos - 2] == ':')
                return &profile;
        }
    }

    // Exact mangled name match.
    auto it = profiles_.find(funcName);
    if (it != profiles_.end())
        return &it->second;

    // strip "(anonymous namespace)::" from
    // the AST name and retry suffix match against demangled IR names.
    static constexpr std::string_view kAnonNS = "(anonymous namespace)::";
    std::string stripped = funcName;
    for (;;) {
        auto pos = stripped.find(kAnonNS);
        if (pos == std::string::npos) break;
        stripped.erase(pos, kAnonNS.size());
    }
    if (stripped != funcName && !stripped.empty()) {
        for (const auto &[mangled, profile] : profiles_) {
            const auto &dn = profile.demangledName;
            if (dn.size() >= stripped.size()) {
                auto spos = dn.size() - stripped.size();
                if (dn.compare(spos, stripped.size(), stripped) == 0 &&
                    (spos == 0 || (spos >= 2 && dn[spos-1] == ':' && dn[spos-2] == ':')))
                    return &profile;
            }
        }
    }

    return nullptr;
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

    unsigned diagLine = diag.location.line;
    std::string diagFile = diag.location.file;

    // Site-level correlation: find IR atomics at the exact source line.
    bool siteConfirmed = false;
    std::string siteOpName;
    for (const auto &ai : profile->atomics) {
        if (ai.sourceLine == 0)
            continue;
        bool lineMatch = (ai.sourceLine == diagLine);
        bool fileMatch = diagFile.empty() || ai.sourceFile.empty() ||
                         filePathSuffixMatch(diagFile, ai.sourceFile);
        if (lineMatch && fileMatch) {
            bool isSeqCst = (ai.ordering ==
                static_cast<unsigned>(llvm::AtomicOrdering::SequentiallyConsistent));
            if (isSeqCst) {
                siteConfirmed = true;
                switch (ai.op) {
                    case IRAtomicInfo::Store:   siteOpName = "store"; break;
                    case IRAtomicInfo::RMW:     siteOpName = "rmw"; break;
                    case IRAtomicInfo::CmpXchg: siteOpName = "cmpxchg"; break;
                    case IRAtomicInfo::Fence:   siteOpName = "fence"; break;
                    default:                   siteOpName = "atomic"; break;
                }
                break;
            }
        }
    }

    if (siteConfirmed) {
        diag.confidence = std::clamp(
            diag.confidence + evidence::kSiteConfirmed,
            evidence::kFloor, evidence::kCeilingSiteProven);
        diag.evidenceTier = EvidenceTier::Proven;
        diag.escalations.push_back(
            "IR site-confirmed: seq_cst " + siteOpName +
            " at line " + std::to_string(diagLine) +
            " survives lowering");
    } else if (profile->seqCstCount > 0) {
        diag.confidence = std::clamp(
            diag.confidence + evidence::kFunctionConfirmed,
            evidence::kFloor, evidence::kCeilingModerate);
        diag.escalations.push_back(
            "IR confirmed: " + std::to_string(profile->seqCstCount) +
            " seq_cst instruction(s) in function (no exact line match)");
    } else if (!profile->atomics.empty()) {
        diag.confidence = std::clamp(
            diag.confidence + evidence::kOptimizedAway,
            evidence::kFloorOptimizedAway, evidence::kCeilingSiteProven);
        diag.escalations.push_back(
            "IR refinement: no seq_cst instructions emitted — "
            "compiler may have optimized ordering");
    }

    if (profile->fenceCount > 0) {
        diag.escalations.push_back(
            "IR confirmed: " + std::to_string(profile->fenceCount) +
            " explicit fence instruction(s)");
    }
}

void DiagnosticRefiner::refineFL011(Diagnostic &diag) const {
    const auto *profile = findProfileForDiag(diag);
    if (!profile)
        return;

    unsigned atomicWriteCount = 0;
    unsigned loopAtomics = 0;
    unsigned siteMatched = 0;
    for (const auto &ai : profile->atomics) {
        if (ai.op == IRAtomicInfo::Store || ai.op == IRAtomicInfo::RMW ||
            ai.op == IRAtomicInfo::CmpXchg) {
            ++atomicWriteCount;
            if (ai.isInLoop)
                ++loopAtomics;
            if (ai.sourceLine > 0)
                ++siteMatched;
        }
    }

    if (atomicWriteCount > 0) {
        diag.confidence = std::clamp(
            diag.confidence + evidence::kSiteConfirmed,
            evidence::kFloor, evidence::kCeilingFuncLevel);
        if (siteMatched > 0)
            diag.evidenceTier = EvidenceTier::Proven;

        std::ostringstream ss;
        ss << "IR confirmed: " << atomicWriteCount
           << " atomic write instruction(s)";
        if (loopAtomics > 0)
            ss << ", " << loopAtomics << " in loop back-edge blocks";
        if (siteMatched > 0)
            ss << " (" << siteMatched << " with debug-loc site mapping)";
        diag.escalations.push_back(ss.str());
    }
}

void DiagnosticRefiner::refineFL020(Diagnostic &diag) const {
    const auto *profile = findProfileForDiag(diag);
    if (!profile)
        return;

    unsigned heapCalls = 0;
    unsigned loopHeapCalls = 0;
    for (const auto &csi : profile->heapAllocCalls) {
        if (csi.isIndirect)
            continue;
        ++heapCalls;
        if (csi.isInLoop)
            ++loopHeapCalls;
    }

    if (heapCalls > 0) {
        diag.confidence = std::clamp(
            diag.confidence + evidence::kHeapSurvived,
            evidence::kFloor, evidence::kCeilingSiteProven);

        std::ostringstream ss;
        ss << "IR confirmed: " << heapCalls
           << " heap alloc/free call(s) after inlining";
        if (loopHeapCalls > 0)
            ss << ", " << loopHeapCalls << " in loop blocks";
        diag.escalations.push_back(ss.str());
    } else {
        diag.confidence = std::clamp(
            diag.confidence + evidence::kHeapEliminated,
            evidence::kFloorHeapEliminated, evidence::kCeilingSiteProven);
        diag.escalations.push_back(
            "IR refinement: no heap alloc calls found after inlining — "
            "allocation may have been optimized away");
    }
}

void DiagnosticRefiner::refineFL021(Diagnostic &diag) const {
    const auto *profile = findProfileForDiag(diag);
    if (!profile)
        return;

    uint64_t irStackSize = profile->totalAllocaBytes;
    constexpr uint64_t threshold = 2048;

    // IR-precise frame below threshold: suppress the AST-based diagnostic.
    if (irStackSize < threshold && irStackSize > 0) {
        diag.suppressed = true;
        diag.escalations.push_back(
            "IR suppressed: actual stack frame " + std::to_string(irStackSize) +
            "B (below " + std::to_string(threshold) +
            "B threshold) — AST estimate was inaccurate");
        return;
    }

    // Replace AST estimate with IR-precise value.
    std::ostringstream ss;
    ss << "IR confirmed: stack frame " << irStackSize
       << "B from " << profile->allocas.size() << " alloca(s)";

    // List large allocas.
    for (const auto &a : profile->allocas) {
        if (a.sizeBytes >= 256)
            ss << " [" << a.name << "=" << a.sizeBytes << "B]";
    }
    diag.escalations.push_back(ss.str());

    // Adjust confidence based on IR/AST agreement.
    uint64_t astEstimate = 0;
    auto estIt = diag.structuralEvidence.find("estimated_frame");
    if (estIt != diag.structuralEvidence.end()) {
        std::string val = estIt->second;
        if (!val.empty() && val.back() == 'B') val.pop_back();
        try { astEstimate = std::stoull(val); } catch (...) {}
    }

    if (irStackSize > 0) {
        diag.confidence = std::clamp(
            diag.confidence + evidence::kStackConfirmed,
            evidence::kFloor, evidence::kCeilingFuncLevel);
        diag.evidenceTier = EvidenceTier::Proven;

        diag.structuralEvidence["ir_frame"] = std::to_string(irStackSize) + "B";
        diag.structuralEvidence["ir_allocas"] = std::to_string(profile->allocas.size());

        if (astEstimate > 0 && irStackSize > astEstimate * 2) {
            diag.escalations.push_back(
                "IR stack frame (" + std::to_string(irStackSize) +
                "B) exceeds AST estimate (" + std::to_string(astEstimate) +
                "B) — compiler-generated temporaries or alignment padding");
        }
    }
}

void DiagnosticRefiner::refineFL030(Diagnostic &diag) const {
    const auto *profile = findProfileForDiag(diag);
    if (!profile)
        return;

    if (profile->indirectCallCount > 0) {
        diag.confidence = std::clamp(
            diag.confidence + evidence::kIndirectConfirmed,
            evidence::kFloor, evidence::kCeilingFuncLevel);

        std::ostringstream ss;
        ss << "IR confirmed: " << profile->indirectCallCount
           << " indirect call(s) remain after devirtualization";
        diag.escalations.push_back(ss.str());
    } else if (profile->directCallCount > 0) {
        diag.confidence = std::clamp(
            diag.confidence + evidence::kFullyDevirtualized,
            evidence::kFloorDevirtualized, evidence::kCeilingSiteProven);
        diag.escalations.push_back(
            "IR refinement: all calls devirtualized to direct — "
            "BTB pressure eliminated by compiler");
    }
}

void DiagnosticRefiner::refineFL031(Diagnostic &diag) const {
    const auto *profile = findProfileForDiag(diag);
    if (!profile)
        return;

    // std::function invocation compiles to an indirect call.
    if (profile->indirectCallCount > 0) {
        diag.confidence = std::clamp(
            diag.confidence + evidence::kIndirectConfirmed,
            evidence::kFloor, evidence::kCeilingFuncLevel);
        diag.escalations.push_back(
            "IR confirmed: " + std::to_string(profile->indirectCallCount) +
            " indirect call(s) — type-erased dispatch not eliminated");
    } else {
        diag.confidence = std::clamp(
            diag.confidence + evidence::kOptimizedAway,
            evidence::kFloorIndirectGone, evidence::kCeilingSiteProven);
        diag.escalations.push_back(
            "IR refinement: no indirect calls found — "
            "std::function may have been devirtualized or inlined");
    }
}

void DiagnosticRefiner::refineFL012(Diagnostic &diag) const {
    const auto *profile = findProfileForDiag(diag);
    if (!profile)
        return;

    unsigned diagLine = diag.location.line;

    bool hasMutexCall = false;
    bool hasAtomicCmpXchg = false;
    bool siteCorrelated = false;

    for (const auto &csi : profile->allCalls) {
        if (csi.isIndirect)
            continue;
        if (csi.calleeName.find("pthread_mutex") != std::string::npos ||
            csi.calleeName.find("__gthread_mutex") != std::string::npos ||
            csi.calleeName.find("pthread_spin") != std::string::npos ||
            csi.calleeName.find("pthread_rwlock") != std::string::npos)
            hasMutexCall = true;
    }
    for (const auto &ai : profile->atomics) {
        if (ai.op == IRAtomicInfo::CmpXchg) {
            hasAtomicCmpXchg = true;
            if (ai.sourceLine == diagLine && diagLine > 0)
                siteCorrelated = true;
        }
    }

    if (hasMutexCall || hasAtomicCmpXchg) {
        diag.confidence = std::clamp(
            diag.confidence + evidence::kLockConfirmed,
            evidence::kFloor, evidence::kCeilingFuncLevel);
        std::string detail;
        if (hasMutexCall) detail = "pthread_mutex call";
        else detail = "atomic cmpxchg (lock internals)";

        if (siteCorrelated) {
            diag.evidenceTier = EvidenceTier::Proven;
            detail += " at line " + std::to_string(diagLine);
        }
        diag.escalations.push_back(
            "IR confirmed: " + detail + " present in lowered IR");
    }
}

void DiagnosticRefiner::refineFL090(Diagnostic &diag) const {
    // FL090 is struct-level, not function-level. Scan all profiles for
    // aggregate IR signals that correlate with the compound hazard.
    unsigned totalAtomicWrites = 0;
    unsigned totalIndirectCalls = 0;
    unsigned totalFences = 0;

    for (const auto &[name, profile] : profiles_) {
        for (const auto &ai : profile.atomics) {
            if (ai.op == IRAtomicInfo::Store || ai.op == IRAtomicInfo::RMW ||
                ai.op == IRAtomicInfo::CmpXchg)
                ++totalAtomicWrites;
        }
        totalIndirectCalls += profile.indirectCallCount;
        totalFences += profile.fenceCount;
    }

    if (totalAtomicWrites > 0 || totalFences > 0) {
        std::ostringstream ss;
        ss << "IR aggregate: " << totalAtomicWrites << " atomic write(s), "
           << totalFences << " fence(s), "
           << totalIndirectCalls << " indirect call(s) across module";
        diag.escalations.push_back(ss.str());
    }
}

void DiagnosticRefiner::refineFL091(Diagnostic &diag) const {
    // FL091 synthesized interactions are struct-level; reuse FL090's
    // aggregate IR scan for corroborating atomic/fence/indirect evidence.
    refineFL090(diag);
}

} // namespace lshaz
