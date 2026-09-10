// SPDX-License-Identifier: Apache-2.0
#include "lshaz/core/emitters.h"

namespace lshaz {

const std::vector<EmitterDoc> &nonRuleEmitters() {
    static const std::vector<EmitterDoc> kDocs = {
        {"FL003", "Per-Thread Array False Sharing", Severity::High,
         "N slots indexed by thread identity pack floor(line/elemSize) to a "
         "cache line, so slots i and j written by different cores trade that "
         "line in Modified state on every update. Adjacent slots avoid this "
         "only when the element stride is a line multiple; a stride that is "
         "not shares a boundary line wherever the array lands, whatever the "
         "base alignment."},
        {"FL004", "Aggregation Sweep Over Per-Thread Slots", Severity::High,
         "A loop reading every per-thread slot takes each line in Shared, "
         "downgrading its owner out of Modified, and that owner pays an "
         "Exclusive re-acquire on its next write. The cost is two coherence "
         "transactions per line swept, per call. Padding cannot fix it and "
         "makes it worse: separating writers from each other does nothing "
         "about a reader that touches every line, and padding raises the "
         "line count."},
        {"FL006", "Cross-Thread Read of a Recurrently Written Field",
         Severity::High,
         "One field, stored by one thread role and read by another. Each "
         "store takes the line in Modified state and invalidates every core "
         "holding it Shared, so each of those cores pays a cross-core "
         "transfer on its next read instead of an L1 hit: one transfer per "
         "reading core per store. Distinct from false sharing in the fix as "
         "well as the shape. Padding relocates the cost and does not remove "
         "it, because the readers want the value the writer stores; only "
         "cutting the store rate or the reader count does. Emitted in the "
         "reduce phase because it needs the merged access set and the "
         "standing-versus-handed reach of the writes, neither of which a "
         "single TU can settle."},
        {"FL091", "Hazard Interaction", Severity::Critical,
         "Two hazards on one object whose costs compound rather than add: a "
         "contended line inside a hot allocation path pays the allocator's "
         "serialisation and the coherence transfer on the same operation. "
         "Synthesised in the reduce phase because the constituents are "
         "routinely found in different TUs."},
        {"FL092", "Unapplied In-Tree Mitigation", Severity::Critical,
         "The codebase already isolates some type onto its own cache line, "
         "so the idiom and its cost are understood here, and a second type "
         "with the same hazard does not use it. This grades the gap against "
         "the project's own precedent rather than against a general rule, "
         "which is why it needs the merged layout index."},
        {"B001", "Missing Header", Severity::Informational,
         "Not a hardware mechanism. A translation unit failed to parse on an "
         "include the scan could not resolve, so every rule saw a truncated "
         "AST for it. Reported because a rule that never ran and a rule that "
         "ran and found nothing produce identical output otherwise."},
        {"C002", "Loop-Invariant Load Not Hoisted", Severity::Medium,
         "The compiler's own optimisation remark: a load the loop cannot "
         "hoist because a store through an unrelated pointer may alias it, "
         "so the value is re-fetched every iteration. Taken from the remark "
         "stream rather than the AST, since only the optimiser knows what it "
         "failed to do."},
    };
    return kDocs;
}

const EmitterDoc *findEmitterByID(std::string_view id) {
    for (const auto &d : nonRuleEmitters())
        if (d.id == id)
            return &d;
    return nullptr;
}

} // namespace lshaz
