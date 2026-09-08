cmake_minimum_required(VERSION 3.20)
project(lshaz VERSION 0.1.0 LANGUAGES C CXX)

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

# The compiler must be able to consume the LLVM headers we just located.
include(CheckCXXSourceCompiles)
unset(LSHAZ_TOOLCHAIN_SEES_LLVM CACHE)
set(CMAKE_REQUIRED_INCLUDES ${LLVM_INCLUDE_DIRS} ${CLANG_INCLUDE_DIRS})
set(CMAKE_REQUIRED_QUIET ON)
check_cxx_source_compiles(
    "#include <llvm/Support/raw_ostream.h>\nint main(){return 0;}"
    LSHAZ_TOOLCHAIN_SEES_LLVM)
unset(CMAKE_REQUIRED_INCLUDES)
unset(CMAKE_REQUIRED_QUIET)

if(NOT LSHAZ_TOOLCHAIN_SEES_LLVM)
    execute_process(COMMAND ${CMAKE_CXX_COMPILER} -dumpmachine
                    OUTPUT_VARIABLE LSHAZ_CXX_TRIPLE
                    OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
    set(LSHAZ_TOOLCHAIN_ERROR
        "${CMAKE_CXX_COMPILER} (target ${LSHAZ_CXX_TRIPLE}) cannot compile against "
        "the LLVM headers in ${LLVM_INCLUDE_DIRS} on this "
        "${CMAKE_SYSTEM_NAME} ${CMAKE_SYSTEM_PROCESSOR} host. "
        "If the targets disagree, configure with "
        "-DCMAKE_C_COMPILER=/usr/bin/gcc -DCMAKE_CXX_COMPILER=/usr/bin/g++")
    string(REPLACE ";" "" LSHAZ_TOOLCHAIN_ERROR "${LSHAZ_TOOLCHAIN_ERROR}")
    message(FATAL_ERROR "${LSHAZ_TOOLCHAIN_ERROR}")
endif()

# Prefer the monolithic LLVM target (shared builds with LLVM_BUILD_LLVM_DYLIB=ON).
# Fall back to individual component libs for static LLVM builds where the
# monolithic target doesn't exist.
if(TARGET LLVM)
    set(LSHAZ_LLVM_LIBS LLVM)
else()
    llvm_map_components_to_libnames(LSHAZ_LLVM_LIBS
        Core Support IRReader Analysis Demangle)
endif()
message(STATUS "LLVM libs: ${LSHAZ_LLVM_LIBS}")

# --- Project includes ---
include_directories(${CMAKE_SOURCE_DIR}/include)

# --- Embedded harness templates ---
# Single-sourced: the template is a real compilable header, unit-tested by
# pipeline_test and embedded verbatim here, so the code under test and the
# code emitted into a bundle are the same text.
find_package(Threads REQUIRED)
set(LSHAZ_PMU_CALIB_TEMPLATE ${CMAKE_SOURCE_DIR}/src/hypothesis/templates/pmu_calib.h)
file(READ ${LSHAZ_PMU_CALIB_TEMPLATE} LSHAZ_PMU_CALIB_SRC)
# The template is wrapped in a raw string literal; a closing delimiter inside
# it would silently truncate the emitted harness into something that still
# compiles. Refuse to configure instead.
string(FIND "${LSHAZ_PMU_CALIB_SRC}" ")LSHAZ_TPL\"" LSHAZ_TPL_ESCAPE)
if(NOT LSHAZ_TPL_ESCAPE EQUAL -1)
    message(FATAL_ERROR
        "${LSHAZ_PMU_CALIB_TEMPLATE} contains the raw-string terminator "
        "at offset ${LSHAZ_TPL_ESCAPE}; embedding it would truncate the harness.")
endif()
configure_file(${CMAKE_SOURCE_DIR}/src/hypothesis/pmu_calibration.cpp.in
               ${CMAKE_BINARY_DIR}/generated/PMUCalibration.cpp @ONLY)
set_property(DIRECTORY APPEND PROPERTY
             CMAKE_CONFIGURE_DEPENDS ${LSHAZ_PMU_CALIB_TEMPLATE})

# --- Source files ---
set(LSHAZ_SOURCES
    src/main.cpp
    src/core/diagnostic.cpp
    src/core/source_location.cpp
    src/core/rule.cpp
    src/core/registry.cpp
    src/core/severity.cpp
    src/core/hot_path.cpp
    src/core/config.cpp
    src/core/dedup.cpp
    src/core/emitters.cpp
    src/core/interaction.cpp
    src/core/perf_profile.cpp
    src/core/precision.cpp
    src/output/cli.cpp
    src/output/json.cpp
    src/output/sarif.cpp
    src/output/clang_tidy.cpp
    src/analysis/action.cpp
    src/analysis/ast_consumer.cpp
    src/analysis/vocabulary.cpp
    src/analysis/struct_layout.cpp
    src/analysis/escape.cpp
    src/analysis/cache_line.cpp
    src/analysis/call_graph.cpp
    src/analysis/thread_role.cpp
    src/analysis/striped_array_summary.cpp
    src/analysis/striped_array.cpp
    src/analysis/data_flow.cpp
    src/analysis/allocator.cpp
    src/analysis/numa.cpp
    src/rules/fl001.cpp
    src/rules/fl002.cpp
    src/rules/fl005.cpp
    src/rules/fl020.cpp
    src/rules/fl021.cpp
    src/rules/fl030.cpp
    src/rules/fl031.cpp
    src/rules/fl010.cpp
    src/rules/fl011.cpp
    src/rules/fl012.cpp
    src/rules/fl013.cpp
    src/rules/fl014.cpp
    src/rules/fl040.cpp
    src/rules/fl041.cpp
    src/rules/fl050.cpp
    src/rules/fl090.cpp
    src/rules/fl060.cpp
    src/rules/fl070.cpp
    src/rules/fl061.cpp
    src/ir/ir_analyzer.cpp
    src/ir/refiner.cpp
    src/ir/opt_remark.cpp
    src/hypothesis/template.cpp
    src/hypothesis/hypothesis.cpp
    src/hypothesis/measurement.cpp
    src/hypothesis/experiment.cpp
    src/hypothesis/calibration.cpp
    src/hypothesis/pmu_trace.cpp
    src/hypothesis/interaction.cpp
    ${CMAKE_BINARY_DIR}/generated/PMUCalibration.cpp
    src/pipeline/scan_pipeline.cpp
    src/pipeline/abs_path_db.cpp
    src/pipeline/compile_db.cpp
    src/pipeline/repo.cpp
    src/pipeline/filter.cpp
    src/pipeline/tu_cache.cpp
    src/cli/scan.cpp
    src/cli/explain.cpp
    src/cli/init.cpp
    src/cli/diff.cpp
    src/cli/fix.cpp
    src/cli/hyp.cpp
    src/cli/exp.cpp
    src/cli/feedback.cpp
    src/cli/result_parser.cpp
)

add_executable(lshaz ${LSHAZ_SOURCES})
if(LLVM_LIBRARY_DIR)
    target_compile_definitions(lshaz PRIVATE
        LLVM_LIBRARY_DIR="${LLVM_LIBRARY_DIR}")
endif()

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
    ${LSHAZ_LLVM_LIBS}
)

# --- Output contract tests ---
add_executable(output_test
    test/output_test.cpp
    src/output/json.cpp
    src/output/sarif.cpp
    src/output/cli.cpp
    src/core/diagnostic.cpp
    src/core/severity.cpp
)
target_link_libraries(output_test PRIVATE ${LSHAZ_LLVM_LIBS})

# --- Pipeline unit test ---
add_executable(pipeline_test
    test/pipeline_test.cpp
    src/pipeline/filter.cpp
    src/pipeline/tu_cache.cpp
    src/pipeline/compile_db.cpp
    src/pipeline/repo.cpp
    src/analysis/thread_role.cpp
    src/analysis/striped_array_summary.cpp
    ${CMAKE_BINARY_DIR}/generated/PMUCalibration.cpp
)
target_link_libraries(pipeline_test PRIVATE ${LSHAZ_LLVM_LIBS} Threads::Threads)
target_include_directories(pipeline_test PRIVATE ${CMAKE_SOURCE_DIR}/src/hypothesis/templates)

# --- Analysis ground truth test ---
add_executable(analysis_test
    test/analysis_test.cpp
    src/analysis/cache_line.cpp
    src/analysis/call_graph.cpp
    src/analysis/escape.cpp
    src/analysis/thread_role.cpp
    src/analysis/striped_array_summary.cpp
    src/analysis/striped_array.cpp
    src/core/hot_path.cpp
    src/core/config.cpp
)
target_link_libraries(analysis_test PRIVATE
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
    ${LSHAZ_LLVM_LIBS}
)

# --- Scan E2E test ---
add_executable(scan_test
    test/scan_test.cpp
)
target_link_libraries(scan_test PRIVATE ${LSHAZ_LLVM_LIBS})
