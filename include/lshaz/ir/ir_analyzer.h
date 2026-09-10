// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "lshaz/ir/ir_profile.h"

#include <llvm/IR/Module.h>

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace lshaz {

class IRAnalyzer {
public:
    using ProfileMap = std::unordered_map<std::string, IRFunctionProfile>;

    // Analyze a pre-built LLVM module.
    // Non-const: DominatorTree/LoopInfo require mutable Function.
    void analyzeModule(llvm::Module &M);

    const ProfileMap &profiles() const { return profiles_; }

    const IRFunctionProfile *lookup(const std::string &mangledName) const;

    // Merge profiles from another analyzer (shard-level reduction).
    // For duplicate function names, keeps the profile with more basic blocks
    // (heuristic: richer IR → more optimization info).
    void mergeFrom(IRAnalyzer &&other);

private:
    void analyzeFunction(llvm::Function &F);
    bool isHeapAllocFunction(llvm::StringRef name) const;
    bool isHeapFreeFunction(llvm::StringRef name) const;

    ProfileMap profiles_;
};

} // namespace lshaz
