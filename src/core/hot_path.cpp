// SPDX-License-Identifier: Apache-2.0
#include "lshaz/core/hot_path.h"
#include "lshaz/core/config.h"
#include "lshaz/analysis/call_graph.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Attr.h>
#include <clang/AST/Decl.h>
#include <clang/AST/DeclCXX.h>
#include <clang/Basic/SourceManager.h>

#include <fnmatch.h>

#include <vector>

namespace lshaz {

HotPathOracle::HotPathOracle(const Config &cfg) : config_(cfg) {}

bool HotPathOracle::isHot(const clang::Decl *D) const {
    if (const auto *FD = llvm::dyn_cast_or_null<clang::FunctionDecl>(D))
        return isFunctionHot(FD);
    return false;
}

bool HotPathOracle::isFunctionHot(const clang::FunctionDecl *FD) const {
    if (!FD)
        return false;

    const auto *canon = FD->getCanonicalDecl();
    if (hotCache_.count(canon))
        return true;

    if (matchesProfileFunction(FD)) {
        record(canon, HotnessSource::Profiled);
        return true;
    }
    if (hasHotAnnotation(FD) || matchesConfigPattern(FD)) {
        record(canon, HotnessSource::Declared);
        return true;
    }

    return false;
}

void HotPathOracle::record(const clang::FunctionDecl *FD,
                           HotnessSource src) const {
    hotCache_.insert(FD);
    auto &cur = sources_[FD];
    if (src > cur) cur = src;   // strongest evidence wins
}

HotnessSource HotPathOracle::hotnessSource(
        const clang::FunctionDecl *FD) const {
    if (!FD) return HotnessSource::None;
    auto it = sources_.find(FD->getCanonicalDecl());
    return it == sources_.end() ? HotnessSource::None : it->second;
}

const char *hotnessSourceName(HotnessSource s) {
    switch (s) {
        case HotnessSource::Profiled:        return "profile";
        case HotnessSource::Declared:        return "declared";
        case HotnessSource::InferredDeep:    return "inferred-deep";
        case HotnessSource::InferredShallow: return "inferred-shallow";
        case HotnessSource::Candidate:       return "cross-tu-candidate";
        case HotnessSource::None:            break;
    }
    return "none";
}

Severity hotnessSupportedSeverity(HotnessSource s, Severity base) {
    auto demote = [](Severity v, unsigned steps) {
        int r = static_cast<int>(v) - static_cast<int>(steps);
        return r < static_cast<int>(Severity::Informational)
                   ? Severity::Informational
                   : static_cast<Severity>(r);
    };
    switch (s) {
        // An operator naming the path, or a profile that saw it execute,
        // imposes no bound: whatever the rule graded, including escalations
        // above its own base, stands. Returning `base` here would silently
        // cap every escalation.
        case HotnessSource::Profiled:
        case HotnessSource::Declared:
            return Severity::Critical;
        // Unresolved. Bounded like the weakest real grade so a finding that
        // somehow reaches output unresolved understates rather than
        // overstates; the reduce phase normally rewrites this.
        case HotnessSource::Candidate:
            return demote(base, 2);
        // Nested loops or recursion: repetition is structurally certain,
        // its magnitude is not.
        case HotnessSource::InferredDeep:
            return demote(base, 1);
        // One loop level from an entry. Enough to look, not to assert cost.
        case HotnessSource::InferredShallow:
            return demote(base, 2);
        case HotnessSource::None:
            break;
    }
    return Severity::Informational;
}

void HotPathOracle::loadProfileHotFunctions(
    std::unordered_set<std::string> names) {
    profileHotFunctions_ = std::move(names);
}

bool HotPathOracle::matchesProfileFunction(
    const clang::FunctionDecl *FD) const {
    if (profileHotFunctions_.empty())
        return false;
    // Match by qualified name (demangled form).
    std::string qualName = FD->getQualifiedNameAsString();
    if (profileHotFunctions_.count(qualName))
        return true;
    // Match by bare name (perf symbols often lack namespace).
    std::string name = FD->getNameAsString();
    if (profileHotFunctions_.count(name))
        return true;
    return false;
}

bool HotPathOracle::hasHotAnnotation(const clang::FunctionDecl *FD) const {
    for (const auto *A : FD->attrs()) {
        // [[clang::annotate("lshaz_hot")]]
        if (const auto *Ann = llvm::dyn_cast<clang::AnnotateAttr>(A)) {
            if (Ann->getAnnotation() == "lshaz_hot")
                return true;
        }
        // __attribute__((hot)), GCC/Clang standard hot attribute
        if (llvm::isa<clang::HotAttr>(A))
            return true;
    }
    return false;
}

bool HotPathOracle::matchesConfigPattern(const clang::FunctionDecl *FD) const {
    std::string qualName = FD->getQualifiedNameAsString();

    for (const auto &pat : config_.hotFunctionPatterns) {
        if (fnmatch(pat.c_str(), qualName.c_str(), 0) == 0)
            return true;
    }

    const auto &SM = FD->getASTContext().getSourceManager();
    auto loc = FD->getLocation();
    if (loc.isValid()) {
        std::string filename = SM.getFilename(SM.getSpellingLoc(loc)).str();
        for (const auto &pat : config_.hotFilePatterns) {
            if (fnmatch(pat.c_str(), filename.c_str(), 0) == 0)
                return true;
        }
    }

    return false;
}

void HotPathOracle::propagateViaCallGraph(const CallGraph &cg,
                                           unsigned maxDepth) {
    // Snapshot current hot roots (avoid iterator invalidation).
    std::unordered_set<const clang::FunctionDecl *> roots(hotCache_);

    if (roots.empty())
        return;

    auto reachable = cg.transitiveCallees(roots, maxDepth);
    for (const auto *fn : reachable) {
        // Reached from a declared/profiled root: inherits that standing.
        record(fn, HotnessSource::Declared);
    }
}

void HotPathOracle::inferFromCodeShape(const CallGraph &cg) {
    // Seeds: functions this TU hands to a thread primitive, plus main. A
    // thread body is a steady-state loop by construction in server code.
    const auto &entryNames = cg.threadEntryNames();
    std::unordered_map<const clang::FunctionDecl *, unsigned> depth;
    std::vector<const clang::FunctionDecl *> work;

    // Seeds are entries only. A function's own loop nesting says it is
    // expensive per call; it says nothing about being called often, and
    // conflating the two marks every initializer hot.
    for (const auto *fn : cg.functions()) {
        const std::string qn = fn->getQualifiedNameAsString();
        if (fn->isMain() || entryNames.count(qn) ||
            entryNames.count(fn->getNameAsString())) {
            depth[fn] = 0;
            work.push_back(fn);
        }
    }
    if (work.empty())
        return;

    // Relax to a fixed point. Values are bounded by kMaxDepth and only
    // increase, so a cycle (recursion) settles instead of diverging.
    constexpr unsigned kMaxDepth = 4;
    while (!work.empty()) {
        const auto *caller = work.back();
        work.pop_back();
        const unsigned d = depth[caller];
        for (const auto *callee : cg.callees(caller)) {
            unsigned nd = d + cg.callSiteLoopDepth(caller, callee);
            // A call into an already-hot region is repetition even without a
            // loop here: recursion re-enters the same body.
            if (callee == caller && nd == d) nd = d + 1;
            if (nd > kMaxDepth) nd = kMaxDepth;
            auto it = depth.find(callee);
            if (it != depth.end() && it->second >= nd)
                continue;
            depth[callee] = nd;
            work.push_back(callee);
        }
    }

    for (const auto &[fn, d] : depth) {
        const unsigned own = cg.ownLoopDepth(fn);
        // Repetition on the way in, or repetition once here. Requiring the
        // former alone made the same hazard visible or invisible depending on
        // where it was written: an allocation in a helper called from a loop
        // graded hot, while the identical allocation inlined into that loop
        // body graded cold, because the enclosing function was entered once.
        if (d == 0 && own == 0) continue;
        // Own loop nesting is still only cost per call, so it sharpens the
        // grade rather than establishing it. A function reached once whose own
        // loop is the only repetition stays at the weakest grade.
        const unsigned graded = d + (own >= 2 ? 1u : 0u);
        record(fn, graded >= 2 ? HotnessSource::InferredDeep
                               : HotnessSource::InferredShallow);
    }
}

void HotPathOracle::markCrossTUCandidates(const CallGraph &cg) {
    for (const auto *fn : cg.functions()) {
        const auto *canon = fn->getCanonicalDecl();
        if (hotCache_.count(canon))
            continue;                       // already settled, and stronger
        // Internal linkage with no local entry reaching it is genuinely
        // cold: no other TU can name it. Anything externally visible may be
        // called from a loop this TU cannot see.
        if (!fn->isExternallyVisible())
            continue;
        record(canon, HotnessSource::Candidate);
    }
}

std::map<std::string, HotnessSource>
inferGlobalHotness(const ThreadRoleSummary &facts,
                   const std::vector<std::string> &mainPatterns) {
    std::map<std::string, HotnessSource> out;

    // Same seeds as the per-TU pass, drawn from every TU at once: thread
    // entries wherever they were spawned, plus the program entry points.
    std::map<std::string, unsigned> depth;
    std::vector<std::string> work;
    auto seed = [&](const std::string &fn) {
        if (depth.count(fn)) return;
        depth[fn] = 0;
        work.push_back(fn);
    };
    for (const auto &e : facts.threadEntries) seed(e);
    // inferFromCodeShape seeds fn->isMain() per TU; without the same seed
    // here a program that spawns no threads has no globally hot function at
    // all, and every hot-path rule is silently inert on it.
    seed("main");
    for (const auto &p : mainPatterns) seed(p);

    if (work.empty())
        return out;

    constexpr unsigned kMaxDepth = 4;
    // Reuses propagateViaCallGraph's reach bound; a second one would be arbitrary.
    constexpr unsigned kFarCallDistance = 8;
    while (!work.empty()) {
        const std::string caller = work.back();
        work.pop_back();
        const unsigned d = depth[caller];
        auto edges = facts.callEdges.find(caller);
        if (edges == facts.callEdges.end())
            continue;
        auto depthsIt = facts.edgeLoopDepth.find(caller);
        for (const auto &callee : edges->second) {
            unsigned site = 0;
            if (depthsIt != facts.edgeLoopDepth.end()) {
                auto s = depthsIt->second.find(callee);
                if (s != depthsIt->second.end()) site = s->second;
            }
            unsigned nd = d + site;
            if (callee == caller && nd == d) nd = d + 1;   // recursion repeats
            if (nd > kMaxDepth) nd = kMaxDepth;
            auto it = depth.find(callee);
            if (it != depth.end() && it->second >= nd)
                continue;
            depth[callee] = nd;
            work.push_back(callee);
        }
    }

    // Depth proves repetition; distance says how thinly it spreads, since a
    // loop's budget splits across its whole callee subtree. Without this one
    // loop marks everything downstream hot.
    std::map<std::string, unsigned> dist;
    {
        std::vector<std::string> q;
        for (const auto &e : facts.threadEntries) { dist[e] = 0; q.push_back(e); }
        // Same seed set as the depth pass above. Omitting main left every
        // function in a thread-free program at the unmeasured default, so the
        // spreading discount never applied there.
        if (!dist.count("main")) { dist["main"] = 0; q.push_back("main"); }
        for (const auto &p : mainPatterns)
            if (!dist.count(p)) { dist[p] = 0; q.push_back(p); }
        for (size_t head = 0; head < q.size(); ++head) {
            const std::string cur = q[head];
            const unsigned nd = dist[cur] + 1;
            auto edges = facts.callEdges.find(cur);
            if (edges == facts.callEdges.end()) continue;
            for (const auto &callee : edges->second) {
                auto it = dist.find(callee);
                if (it != dist.end() && it->second <= nd) continue;
                dist[callee] = nd;
                q.push_back(callee);
            }
        }
    }

    for (const auto &[fn, d] : depth) {
        unsigned own = 0;
        auto o = facts.ownLoopDepth.find(fn);
        if (o != facts.ownLoopDepth.end()) own = o->second;
        // Must match inferFromCodeShape's admission test exactly. The reduce
        // phase confirms or drops what the map phase proposed, so a stricter
        // rule here deletes findings the map was right to raise.
        if (d == 0 && own == 0) continue;
        unsigned graded = d + (own >= 2 ? 1u : 0u);

        // Demote, never drop: still worth seeing, not worth asserting.
        auto dit = dist.find(fn);
        const unsigned callDist = dit == dist.end() ? kFarCallDistance
                                                    : dit->second;
        if (callDist > kFarCallDistance && graded > 1) graded = 1;

        out[fn] = graded >= 2 ? HotnessSource::InferredDeep
                              : HotnessSource::InferredShallow;
    }
    return out;
}

} // namespace lshaz
