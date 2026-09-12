// SPDX-License-Identifier: Apache-2.0
#pragma once

namespace lshaz {

constexpr const char *kToolVersion  = "0.4.0";
constexpr const char *kToolName     = "lshaz";

// Output schema version. Bump on any structural change to JSON/SARIF output.
// Major: breaking change. Minor: additive field. Patch: cosmetic.
constexpr const char *kOutputSchemaVersion = "2.0.0";

} // namespace lshaz
