// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "lshaz/analysis/memory.h"

#include <clang/AST/ASTContext.h>

#include <string>
#include <vector>

namespace lshaz {

// Walk a TU and emit points-to constraints plus unresolved field accesses.
// Per-TU partials by construction: nothing here decides where a pointer
// points, only what would have to be true for it to.
MemorySummary buildMemorySummary(clang::ASTContext &Ctx,
                                 const std::vector<std::string> &allocPatterns);

} // namespace lshaz
