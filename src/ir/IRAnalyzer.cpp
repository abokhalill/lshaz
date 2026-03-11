// SPDX-License-Identifier: Apache-2.0
#include "lshaz/ir/IRAnalyzer.h"

#include <llvm/Analysis/LoopInfo.h>
#include <llvm/Analysis/PostDominators.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/DebugInfoMetadata.h>
#include <llvm/IR/Module.h>
#include <llvm/Demangle/Demangle.h>

namespace lshaz {

void IRAnalyzer::analyzeModule(llvm::Module &M) {
    for (auto &F : M) {
        if (F.isDeclaration())
            continue;
        analyzeFunction(F);
    }
}

const IRFunctionProfile *IRAnalyzer::lookup(const std::string &mangledName) const {
    auto it = profiles_.find(mangledName);
    return it != profiles_.end() ? &it->second : nullptr;
}

void IRAnalyzer::mergeFrom(IRAnalyzer &&other) {
    for (auto &[name, profile] : other.profiles_) {
        auto it = profiles_.find(name);
        if (it == profiles_.end()) {
            profiles_.emplace(std::move(name), std::move(profile));
        } else {
            // Keep the richer profile (more basic blocks → more IR info).
            if (profile.basicBlockCount > it->second.basicBlockCount)
                it->second = std::move(profile);
        }
    }
}

bool IRAnalyzer::isHeapAllocFunction(llvm::StringRef name) const {
    return name == "malloc" || name == "calloc" || name == "realloc" ||
           name == "aligned_alloc" || name == "posix_memalign" ||
           name == "_Znwm" ||    // operator new(size_t)
           name == "_Znam" ||    // operator new[](size_t)
           name == "_ZnwmSt11align_val_t" || // operator new(size_t, align)
           name == "_ZnamSt11align_val_t" || // operator new[](size_t, align)
           name.starts_with("_Znwm") || name.starts_with("_Znam");
}

bool IRAnalyzer::isHeapFreeFunction(llvm::StringRef name) const {
    return name == "free" ||
           name == "_ZdlPv" ||   // operator delete(void*)
           name == "_ZdaPv" ||   // operator delete[](void*)
           name.starts_with("_ZdlPv") || name.starts_with("_ZdaPv");
}

static void extractDebugLoc(const llvm::Instruction &I,
                            std::string &file, unsigned &line) {
    const auto &DL = I.getDebugLoc();
    if (!DL)
        return;
    if (auto *scope = DL->getScope()) {
        file = scope->getFilename().str();
        line = DL.getLine();
    }
}

void IRAnalyzer::analyzeFunction(llvm::Function &F) {
    IRFunctionProfile profile;
    profile.mangledName = F.getName().str();
    profile.demangledName = llvm::demangle(profile.mangledName);
    profile.basicBlockCount = F.size();

    if (auto *SP = F.getSubprogram()) {
        profile.sourceFile = SP->getFilename().str();
        profile.sourceLine = SP->getLine();
    }

    // Build DominatorTree + LoopInfo for precise loop detection.
    llvm::DominatorTree DT(F);
    llvm::LoopInfo LI(DT);

    llvm::SmallPtrSet<const llvm::BasicBlock *, 16> loopBlocks;
    for (const auto &BB : F) {
        if (LI.getLoopFor(&BB))
            loopBlocks.insert(&BB);
    }
    profile.loopCount = LI.getTopLevelLoopsVector().size();

    for (const auto &BB : F) {
        bool bbInLoop = loopBlocks.count(&BB) > 0;

        for (const auto &I : BB) {
            // --- Alloca ---
            if (const auto *AI = llvm::dyn_cast<llvm::AllocaInst>(&I)) {
                IRAllocaInfo info;
                info.name = AI->hasName() ? AI->getName().str() : "<anon>";
                info.isArray = AI->isArrayAllocation();

                auto *allocTy = AI->getAllocatedType();
                uint64_t tySize = F.getParent()->getDataLayout()
                                      .getTypeAllocSize(allocTy);

                if (AI->isArrayAllocation()) {
                    if (const auto *CI = llvm::dyn_cast<llvm::ConstantInt>(
                            AI->getArraySize())) {
                        info.sizeBytes = tySize * CI->getZExtValue();
                    } else {
                        info.sizeBytes = tySize; // VLA — unknown, use element size
                    }
                } else {
                    info.sizeBytes = tySize;
                }

                profile.totalAllocaBytes += info.sizeBytes;
                profile.allocas.push_back(std::move(info));
                continue;
            }

            // --- Atomic Load ---
            if (const auto *LI = llvm::dyn_cast<llvm::LoadInst>(&I)) {
                if (LI->isAtomic()) {
                    IRAtomicInfo ai;
                    ai.op = IRAtomicInfo::Load;
                    ai.ordering = static_cast<unsigned>(LI->getOrdering());
                    ai.isInLoop = bbInLoop;
                    extractDebugLoc(I, ai.sourceFile, ai.sourceLine);
                    profile.atomics.push_back(ai);
                    if (LI->getOrdering() ==
                        llvm::AtomicOrdering::SequentiallyConsistent)
                        ++profile.seqCstCount;
                }
                continue;
            }

            // --- Atomic Store ---
            if (const auto *SI = llvm::dyn_cast<llvm::StoreInst>(&I)) {
                if (SI->isAtomic()) {
                    IRAtomicInfo ai;
                    ai.op = IRAtomicInfo::Store;
                    ai.ordering = static_cast<unsigned>(SI->getOrdering());
                    ai.isInLoop = bbInLoop;
                    extractDebugLoc(I, ai.sourceFile, ai.sourceLine);
                    profile.atomics.push_back(ai);
                    if (SI->getOrdering() ==
                        llvm::AtomicOrdering::SequentiallyConsistent)
                        ++profile.seqCstCount;
                }
                continue;
            }

            // --- AtomicRMW ---
            if (const auto *RMW = llvm::dyn_cast<llvm::AtomicRMWInst>(&I)) {
                IRAtomicInfo ai;
                ai.op = IRAtomicInfo::RMW;
                ai.ordering = static_cast<unsigned>(RMW->getOrdering());
                ai.isInLoop = bbInLoop;
                extractDebugLoc(I, ai.sourceFile, ai.sourceLine);
                profile.atomics.push_back(ai);
                if (RMW->getOrdering() ==
                    llvm::AtomicOrdering::SequentiallyConsistent)
                    ++profile.seqCstCount;
                continue;
            }

            // --- AtomicCmpXchg ---
            if (const auto *CX = llvm::dyn_cast<llvm::AtomicCmpXchgInst>(&I)) {
                IRAtomicInfo ai;
                ai.op = IRAtomicInfo::CmpXchg;
                ai.ordering = static_cast<unsigned>(CX->getSuccessOrdering());
                ai.isInLoop = bbInLoop;
                extractDebugLoc(I, ai.sourceFile, ai.sourceLine);
                profile.atomics.push_back(ai);
                if (CX->getSuccessOrdering() ==
                    llvm::AtomicOrdering::SequentiallyConsistent)
                    ++profile.seqCstCount;
                continue;
            }

            // --- Fence ---
            if (const auto *FI = llvm::dyn_cast<llvm::FenceInst>(&I)) {
                IRAtomicInfo ai;
                ai.op = IRAtomicInfo::Fence;
                ai.ordering = static_cast<unsigned>(FI->getOrdering());
                ai.isInLoop = bbInLoop;
                extractDebugLoc(I, ai.sourceFile, ai.sourceLine);
                profile.atomics.push_back(ai);
                ++profile.fenceCount;
                if (FI->getOrdering() ==
                    llvm::AtomicOrdering::SequentiallyConsistent)
                    ++profile.seqCstCount;
                continue;
            }

            // --- Call instructions ---
            if (const auto *CI = llvm::dyn_cast<llvm::CallInst>(&I)) {
                if (llvm::isa<llvm::IntrinsicInst>(CI))
                    continue;

                const auto *callee = CI->getCalledFunction();
                if (!callee) {
                    ++profile.indirectCallCount;
                    IRCallSiteInfo csi;
                    csi.isIndirect = true;
                    csi.isInLoop = bbInLoop;
                    profile.allCalls.push_back(std::move(csi));
                    continue;
                }

                ++profile.directCallCount;
                llvm::StringRef name = callee->getName();

                IRCallSiteInfo csi;
                csi.calleeName = name.str();
                csi.isIndirect = false;
                csi.isInLoop = bbInLoop;
                profile.allCalls.push_back(csi);

                if (isHeapAllocFunction(name) || isHeapFreeFunction(name))
                    profile.heapAllocCalls.push_back(std::move(csi));
                continue;
            }

            // --- Invoke (exception-aware call) ---
            if (const auto *II = llvm::dyn_cast<llvm::InvokeInst>(&I)) {
                const auto *callee = II->getCalledFunction();
                if (!callee) {
                    ++profile.indirectCallCount;
                    IRCallSiteInfo csi;
                    csi.isIndirect = true;
                    csi.isInLoop = bbInLoop;
                    profile.allCalls.push_back(std::move(csi));
                    continue;
                }

                ++profile.directCallCount;
                llvm::StringRef name = callee->getName();

                IRCallSiteInfo csi;
                csi.calleeName = name.str();
                csi.isIndirect = false;
                csi.isInLoop = bbInLoop;
                profile.allCalls.push_back(csi);

                if (isHeapAllocFunction(name) || isHeapFreeFunction(name))
                    profile.heapAllocCalls.push_back(std::move(csi));
                continue;
            }
        }
    }

    profiles_[profile.mangledName] = std::move(profile);
}

} // namespace lshaz
