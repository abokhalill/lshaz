// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>
#include <type_traits>

namespace lshaz {

// A rule's evidence ladder. Rungs are declared weakest first, each
// enumerator's value is its position, and a trailing Count ends the list.
//
// Rank is (position + 1) / (rungs + 1): no tunable constant, never 0, never 1.
// It orders findings within one rule. Cross-rule standing is evidenceTier and
// severitySupportedByClaims().
//
//   enum class Rung : unsigned { NoWriterNamed, RouteOnly, AtomicPair, Count };
//   diag.confidence = rungRank(Rung::RouteOnly);   // 2/4
template <typename Rung>
constexpr double rungRank(Rung r) {
    static_assert(std::is_enum_v<Rung>, "a ladder rung must be an enum class");
    using U = std::underlying_type_t<Rung>;
    return (static_cast<double>(static_cast<U>(r)) + 1.0) /
           (static_cast<double>(static_cast<U>(Rung::Count)) + 1.0);
}

template <typename Rung>
constexpr std::size_t ladderSize() {
    return static_cast<std::size_t>(
        static_cast<std::underlying_type_t<Rung>>(Rung::Count));
}

} // namespace lshaz
