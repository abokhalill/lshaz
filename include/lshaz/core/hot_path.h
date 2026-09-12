// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "lshaz/core/severity.h"
#include "lshaz/analysis/thread_role.h"

#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace clang {
class Decl;
class FunctionDecl;
class Attr;
} // namespace clang

namespace lshaz {

class CallGraph;
struct Config;

// How a function came to be considered hot. Ordered weakest to strongest:
// an operator's explicit assertion and a real profile are evidence, a
// structural inference is a hypothesis the shape of the code supports.
// Rules must not treat these alike, see supportedCeiling().
enum class HotnessSource : uint8_t {
    None = 0,
    Candidate,        // externally visible, unresolved: only the merged
                      // call graph can say. 
    InferredShallow,  // reached from an entry through exactly one loop level
    InferredDeep,     // nested loops, or recursion (self-repetition)
    Declared,         // __attribute__((hot)) / annotate / config pattern
    Profiled,         // named by --perf-profile
};

// Determines whether a given declaration resides on a hot path.
//   1. [[clang::annotate("lshaz_hot")]] or __attribute__((hot))
//   2. Config-based function/file pattern matching
//   3. Perf/LBR profile: function name exceeds sample threshold
//   4. Structural inference: loop-depth-weighted reachability from the
//      TU's entry points, which needs no per-project configuration
class HotPathOracle {
public:
    explicit HotPathOracle(const Config &cfg);

    bool isHot(const clang::Decl *D) const;
    bool isFunctionHot(const clang::FunctionDecl *FD) const;

    // Why this function is hot. None when it is not.
    HotnessSource hotnessSource(const clang::FunctionDecl *FD) const;

    // A profile was supplied and does not name this function, yet config or
    // an attribute declares it hot.
    //
    // Declared and Profiled both impose no severity ceiling, so an assertion
    // the evidence does not corroborate would otherwise grade exactly like a
    // measurement, indefinitely and invisibly. This does not make the function
    // cold: absence from a sampled profile is weak evidence of absence, and
    // the cross-TU verdict is what withdraws findings. It removes the
    // declaration's claim to profile-grade authority and says why.
    bool profileContradictsDeclaration(const clang::FunctionDecl *FD) const;

    // Propagate hotness transitively through a call graph.
    // All functions reachable from currently-hot roots within maxDepth
    // call edges are marked hot.
    void propagateViaCallGraph(const CallGraph &cg, unsigned maxDepth = 8);

    // Derive hotness from code shape when nothing else supplies it. Seeded
    // from this TU's thread entries and main; a callee inherits its caller's
    // hotness plus the loop nesting at the call site, and recursion counts as
    // self-repetition. Per-TU, so a function looped over from elsewhere needs
    // inferGlobalHotness over the merged graph.
    void inferFromCodeShape(const CallGraph &cg);

    // Mark every externally-visible function this pass could not settle. A
    // TU without main or a thread entry seeds nothing, which silently
    // disabled every hot-path rule inside it; a candidate lets the rule run
    // and defers the verdict to the reduce phase instead of answering "cold"
    // from facts this TU does not have. Internal-linkage functions are left
    // alone: unreachable from a local entry, they cannot be entered from
    // another TU except through an escaping function pointer.
    void markCrossTUCandidates(const CallGraph &cg);

    // Load profile-derived hot function names (demangled qualified names).
    void loadProfileHotFunctions(std::unordered_set<std::string> names);

private:
    bool hasHotAnnotation(const clang::FunctionDecl *FD) const;
    bool matchesConfigPattern(const clang::FunctionDecl *FD) const;
    bool matchesProfileFunction(const clang::FunctionDecl *FD) const;
    void record(const clang::FunctionDecl *FD, HotnessSource src) const;

    const Config &config_;
    mutable std::unordered_set<const clang::FunctionDecl *> hotCache_;
    mutable std::unordered_map<const clang::FunctionDecl *, HotnessSource>
        sources_;
    std::unordered_set<std::string> profileHotFunctions_;
};

const char *hotnessSourceName(HotnessSource s);

// A hot-path rule's mechanism claim rests on the code actually running often.
// An inference establishes shape, not execution: it justifies looking, not a
// grade that implies measured cost. Rules pass their own base severity and
// get back what the evidence for hotness can carry.
Severity hotnessSupportedSeverity(HotnessSource s, Severity base);

// Reduce-phase hotness over the merged call graph, keyed by the same
// qualified names the per-TU pass uses. Same loop-depth-weighted relaxation
// as inferFromCodeShape, run once on facts no single TU has. Deterministic:
// ordered inputs and a bounded fixed point, so the result does not depend on
// shard count or completion order.
std::map<std::string, HotnessSource>
inferGlobalHotness(const ThreadRoleSummary &facts,
                   const std::vector<std::string> &mainPatterns);

} // namespace lshaz
