// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace lshaz {

enum class HazardClass : uint8_t {
    CacheGeometry,       // FL001
    FalseSharing,        // FL002
    AtomicOrdering,      // FL010
    AtomicContention,    // FL011
    LockContention,      // FL012
    HeapAllocation,      // FL020
    StackPressure,       // FL021
    VirtualDispatch,     // FL030
    StdFunction,         // FL031
    GlobalState,         // FL040
    ContendedQueue,      // FL041
    DeepConditional,     // FL050
    NUMALocality,        // FL060
    CentralizedDispatch, // FL061
    HazardAmplification,      // FL090
    SynthesizedInteraction,  // FL091
};

constexpr std::string_view hazardClassName(HazardClass hc) {
    switch (hc) {
        case HazardClass::CacheGeometry:       return "CacheGeometry";
        case HazardClass::FalseSharing:        return "FalseSharing";
        case HazardClass::AtomicOrdering:      return "AtomicOrdering";
        case HazardClass::AtomicContention:    return "AtomicContention";
        case HazardClass::LockContention:      return "LockContention";
        case HazardClass::HeapAllocation:      return "HeapAllocation";
        case HazardClass::StackPressure:       return "StackPressure";
        case HazardClass::VirtualDispatch:     return "VirtualDispatch";
        case HazardClass::StdFunction:         return "StdFunction";
        case HazardClass::GlobalState:         return "GlobalState";
        case HazardClass::ContendedQueue:      return "ContendedQueue";
        case HazardClass::DeepConditional:     return "DeepConditional";
        case HazardClass::NUMALocality:        return "NUMALocality";
        case HazardClass::CentralizedDispatch: return "CentralizedDispatch";
        case HazardClass::HazardAmplification:    return "HazardAmplification";
        case HazardClass::SynthesizedInteraction: return "SynthesizedInteraction";
    }
    return "Unknown";
}

inline std::optional<HazardClass> hazardClassFromName(std::string_view name) {
    for (uint8_t i = 0;
         i <= static_cast<uint8_t>(HazardClass::SynthesizedInteraction); ++i) {
        auto hc = static_cast<HazardClass>(i);
        if (hazardClassName(hc) == name)
            return hc;
    }
    return std::nullopt;
}

} // namespace lshaz
