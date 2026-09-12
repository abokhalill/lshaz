// SPDX-License-Identifier: Apache-2.0
#pragma once

namespace lshaz {

// Named evidence factors for IR refinement.
namespace evidence {
    // Site-precise IR confirmation at exact source line.
    constexpr double kSiteConfirmed       = +0.10;
    // IR confirms presence of the pattern in the function (no line match).
    constexpr double kFunctionConfirmed   = +0.05;
    // IR shows pattern was optimized away.
    constexpr double kOptimizedAway       = -0.20;
    // IR confirms heap allocation survives inlining.
    constexpr double kHeapSurvived        = +0.05;
    // IR shows allocation was eliminated.
    constexpr double kHeapEliminated      = -0.15;
    // IR confirms indirect calls remain (devirtualization failed).
    constexpr double kIndirectConfirmed   = +0.10;
    // IR shows all calls devirtualized.
    constexpr double kFullyDevirtualized  = -0.25;
    // IR confirms lock/mutex call in lowered code.
    constexpr double kLockConfirmed       = +0.05;
    // IR-precise stack frame confirms AST estimate.
    constexpr double kStackConfirmed      = +0.10;

    constexpr double kFloor               = 0.10;
    constexpr double kCeilingSiteProven   = 0.98;
    constexpr double kCeilingFuncLevel    = 0.95;
    constexpr double kCeilingModerate     = 0.92;
    constexpr double kFloorOptimizedAway  = 0.30;
    constexpr double kFloorDevirtualized  = 0.30;
    constexpr double kFloorHeapEliminated = 0.40;
    constexpr double kFloorIndirectGone   = 0.35;
}

} // namespace lshaz
