#pragma once

namespace faultline {

constexpr const char *kToolVersion  = "0.2.0";
constexpr const char *kToolName     = "faultline";

// Output schema version. Bump on any structural change to JSON/SARIF output.
// Major: breaking change. Minor: additive field. Patch: cosmetic.
constexpr const char *kOutputSchemaVersion = "1.0.0";

} // namespace faultline
