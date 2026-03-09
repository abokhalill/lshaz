cmake_minimum_required(VERSION 3.20)
project(lshaz VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# --- LLVM/Clang dependency ---
find_package(LLVM REQUIRED CONFIG)
find_package(Clang REQUIRED CONFIG)

message(STATUS "LLVM version: ${LLVM_VERSION}")
message(STATUS "LLVM include dirs: ${LLVM_INCLUDE_DIRS}")
message(STATUS "Clang include dirs: ${CLANG_INCLUDE_DIRS}")

include_directories(${LLVM_INCLUDE_DIRS})
include_directories(${CLANG_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

# --- Project includes ---
include_directories(${CMAKE_SOURCE_DIR}/include)

# --- Source files ---
set(LSHAZ_SOURCES
    src/main.cpp
    src/core/Diagnostic.cpp
    src/core/Rule.cpp
    src/core/RuleRegistry.cpp
    src/core/Severity.cpp
    src/core/HotPathOracle.cpp
    src/core/Config.cpp
    src/core/DiagnosticDedup.cpp
    src/core/DiagnosticInteraction.cpp
    src/core/PerfProfileParser.cpp
    src/core/PrecisionBudget.cpp
    src/output/CLIOutput.cpp
    src/output/JSONOutput.cpp
    src/output/SARIFOutput.cpp
    src/output/ClangTidyOutput.cpp
    src/analysis/LshazAction.cpp
    src/analysis/LshazASTConsumer.cpp
    src/analysis/StructLayoutVisitor.cpp
    src/analysis/EscapeAnalysis.cpp
    src/analysis/CacheLineMap.cpp
    src/analysis/CallGraph.cpp
    src/analysis/DataFlowAnalyzer.cpp
    src/analysis/AllocatorTopology.cpp
    src/analysis/NUMATopology.cpp
    src/rules/FL001_CacheLineSpanning.cpp
    src/rules/FL002_FalseSharing.cpp
    src/rules/FL020_HeapAllocHotPath.cpp
    src/rules/FL021_LargeStackFrame.cpp
    src/rules/FL030_VirtualDispatch.cpp
    src/rules/FL031_StdFunctionHotPath.cpp
    src/rules/FL010_OverlyStrongOrdering.cpp
    src/rules/FL011_AtomicContention.cpp
    src/rules/FL012_LockHotPath.cpp
    src/rules/FL040_CentralizedGlobalState.cpp
    src/rules/FL041_ContendedQueue.cpp
    src/rules/FL050_DeepConditionalTree.cpp
    src/rules/FL090_HazardAmplification.cpp
    src/rules/FL060_NUMAUnfriendly.cpp
    src/rules/FL061_CentralizedDispatcher.cpp
    src/ir/IRAnalyzer.cpp
    src/ir/DiagnosticRefiner.cpp
    src/hypothesis/HypothesisTemplate.cpp
    src/hypothesis/HypothesisConstructor.cpp
    src/hypothesis/MeasurementPlan.cpp
    src/hypothesis/ExperimentSynthesizer.cpp
    src/hypothesis/CalibrationFeedback.cpp
    src/hypothesis/PMUTraceFeedback.cpp
    src/hypothesis/InteractionModel.cpp
    src/pipeline/ScanPipeline.cpp
    src/pipeline/CompileDBResolver.cpp
    src/pipeline/RepoProvider.cpp
    src/pipeline/SourceFilter.cpp
    src/cli/ScanCommand.cpp
    src/cli/ExplainCommand.cpp
    src/cli/InitCommand.cpp
    src/cli/DiffCommand.cpp
    src/cli/FixCommand.cpp
    src/cli/HypCommand.cpp
    src/cli/ExpCommand.cpp
    src/cli/ScanResultParser.cpp
)

add_executable(lshaz ${LSHAZ_SOURCES})

# --- Link Clang/LLVM libraries ---
target_link_libraries(lshaz
    PRIVATE
    clangTooling
    clangFrontend
    clangSerialization
    clangDriver
    clangParse
    clangSema
    clangAnalysis
    clangAST
    clangASTMatchers
    clangBasic
    clangEdit
    clangLex
    clangRewrite
    LLVM
)

# --- Output contract tests ---
add_executable(output_contract_test
    test/output_contract_test.cpp
    src/output/JSONOutput.cpp
    src/output/SARIFOutput.cpp
    src/output/CLIOutput.cpp
    src/core/Diagnostic.cpp
    src/core/Severity.cpp
)
target_link_libraries(output_contract_test PRIVATE LLVM)

# --- Pipeline unit test ---
add_executable(pipeline_unit_test
    test/pipeline_unit_test.cpp
    src/pipeline/SourceFilter.cpp
    src/pipeline/CompileDBResolver.cpp
    src/pipeline/RepoProvider.cpp
)
target_link_libraries(pipeline_unit_test PRIVATE LLVM)

# --- Analysis ground truth test ---
add_executable(analysis_ground_truth_test
    test/analysis_ground_truth_test.cpp
    src/analysis/CacheLineMap.cpp
)
target_link_libraries(analysis_ground_truth_test PRIVATE
    clangTooling
    clangFrontend
    clangSerialization
    clangDriver
    clangParse
    clangSema
    clangAnalysis
    clangAST
    clangASTMatchers
    clangBasic
    clangEdit
    clangLex
    clangRewrite
    LLVM
)

# --- Scan E2E test ---
add_executable(scan_e2e_test
    test/scan_e2e_test.cpp
)
target_link_libraries(scan_e2e_test PRIVATE LLVM)
