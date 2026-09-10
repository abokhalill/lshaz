// SPDX-License-Identifier: Apache-2.0
#include "lshaz/core/evidence.h"

namespace lshaz {

std::string_view evidenceFamilyName(EvidenceFamily f) {
    switch (f) {
        case EvidenceFamily::Coherence:        return "coherence";
        case EvidenceFamily::BranchMispredict: return "branch-mispredict";
        case EvidenceFamily::DataTLB:          return "data-tlb";
        case EvidenceFamily::InstructionTLB:   return "instruction-tlb";
        case EvidenceFamily::CacheMiss:        return "cache-miss";
        case EvidenceFamily::Cycles:           return "cycles";
        case EvidenceFamily::None:             break;
    }
    return "none";
}

EvidenceFamily evidenceFamilyFromName(std::string_view name) {
    for (auto f : {EvidenceFamily::Coherence, EvidenceFamily::BranchMispredict,
                   EvidenceFamily::DataTLB, EvidenceFamily::InstructionTLB,
                   EvidenceFamily::CacheMiss, EvidenceFamily::Cycles})
        if (evidenceFamilyName(f) == name)
            return f;
    return EvidenceFamily::None;
}

const std::vector<RuleEvidence> &ruleEvidence() {
    static const std::vector<RuleEvidence> kMap = {
        // c2c gives these a per-line verdict. The family is still recorded
        // so a target profiled with nothing but a counter gets one too.
        {"FL002", EvidenceFamily::Coherence, true,
         "a store invalidating a line a peer core holds"},
        {"FL003", EvidenceFamily::Coherence, true,
         "per-thread slots sharing a line"},
        {"FL004", EvidenceFamily::Coherence, true,
         "a sweep downgrading every slot owner out of Modified"},
        {"FL005", EvidenceFamily::Coherence, true,
         "a store that repeats a value already on the line"},
        {"FL006", EvidenceFamily::Coherence, true,
         "one field stored by one role and read by another"},
        {"FL011", EvidenceFamily::Coherence, true,
         "an atomic read-modify-write taking the line Modified"},
        {"FL040", EvidenceFamily::Coherence, true,
         "many cores writing one line"},
        {"FL041", EvidenceFamily::Coherence, true,
         "a queue's head and tail traded between producer and consumer"},

        // The mispredict retires in the function holding the branch, so
        // per-symbol attribution is exact here.
        {"FL050", EvidenceFamily::BranchMispredict, true,
         "a data-dependent branch the predictor cannot learn"},
        {"FL030", EvidenceFamily::BranchMispredict, true,
         "an indirect call whose target varies"},
        {"FL031", EvidenceFamily::BranchMispredict, true,
         "an indirect call through a type-erased wrapper"},
        {"FL061", EvidenceFamily::BranchMispredict, true,
         "a dispatcher's indirect branch"},

        {"FL070", EvidenceFamily::DataTLB, true,
         "a working set spanning more pages than the TLB holds"},
        {"FL060", EvidenceFamily::DataTLB, true,
         "pages faulted on one node and read from another"},

        {"FL001", EvidenceFamily::CacheMiss, true,
         "a record spanning more lines than it needs"},
        {"FL021", EvidenceFamily::CacheMiss, true,
         "a stack frame displacing live lines"},

        // These three spend their time inside malloc, the mutex and the
        // futex, not in the caller we named. Nothing to look up per symbol,
        // so they are counted and left unjudged rather than scored as
        // misses on the rules most likely to be right.
        {"FL020", EvidenceFamily::Cycles, false,
         "cycles inside the allocator, attributed to the allocator"},
        {"FL012", EvidenceFamily::Cycles, false,
         "cycles inside the lock and the futex path"},
        {"FL013", EvidenceFamily::Cycles, false,
         "cycles spun before the wait succeeds"},

        // Claims about emitted code, not about a run. An unnecessary fence
        // costs what it costs whether or not anything contended, and no
        // counter tells you an address was only accidentally aligned.
        {"FL010", EvidenceFamily::None, false,
         "an ordering stronger than the algorithm needs"},
        {"FL014", EvidenceFamily::None, false,
         "an atomic whose address alignment is not provable"},

        // Borrowed mechanisms. These synthesise from other findings.
        {"FL090", EvidenceFamily::None, false,
         "inherited from the hazards it amplifies"},
        {"FL091", EvidenceFamily::None, false,
         "inherited from its constituents"},
        {"FL092", EvidenceFamily::None, false,
         "inherited from the component hazard"},
        {"B001", EvidenceFamily::None, false, "a build fact, not a run fact"},
        {"C002", EvidenceFamily::None, false,
         "a compiler decision, visible in the remark rather than in a count"},
    };
    return kMap;
}

const RuleEvidence *evidenceForRule(std::string_view id) {
    for (const auto &e : ruleEvidence())
        if (e.id == id)
            return &e;
    return nullptr;
}

} // namespace lshaz
