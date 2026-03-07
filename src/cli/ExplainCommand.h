#pragma once

namespace lshaz {

// Entry point for `lshaz explain <rule-id> [options]`.
// Returns process exit code.
int runExplainCommand(int argc, const char **argv);

} // namespace lshaz
