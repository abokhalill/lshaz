# SPDX-License-Identifier: Apache-2.0
# fish completion for lshaz

set -l subcmds scan init diff explain version help

complete -c lshaz -f -n "not __fish_seen_subcommand_from $subcmds" -a scan -d "Analyze a project"
complete -c lshaz -f -n "not __fish_seen_subcommand_from $subcmds" -a init -d "Generate compile_commands.json and config"
complete -c lshaz -f -n "not __fish_seen_subcommand_from $subcmds" -a diff -d "Compare two scan results"
complete -c lshaz -f -n "not __fish_seen_subcommand_from $subcmds" -a explain -d "Show rule documentation"
complete -c lshaz -f -n "not __fish_seen_subcommand_from $subcmds" -a version -d "Print version"
complete -c lshaz -f -n "not __fish_seen_subcommand_from $subcmds" -a help -d "Show help"

# scan
complete -c lshaz -n "__fish_seen_subcommand_from scan" -l compile-db -rF -d "Path to compile_commands.json"
complete -c lshaz -n "__fish_seen_subcommand_from scan" -l config -rF -d "Path to lshaz.config.yaml"
complete -c lshaz -n "__fish_seen_subcommand_from scan" -l format -r -a "cli json sarif" -d "Output format"
complete -c lshaz -n "__fish_seen_subcommand_from scan" -l output -rF -d "Write output to file"
complete -c lshaz -n "__fish_seen_subcommand_from scan" -l min-severity -r -a "Informational Medium High Critical" -d "Minimum severity"
complete -c lshaz -n "__fish_seen_subcommand_from scan" -l min-evidence -r -a "speculative likely proven" -d "Minimum evidence tier"
complete -c lshaz -n "__fish_seen_subcommand_from scan" -l no-ir -d "Disable LLVM IR analysis"
complete -c lshaz -n "__fish_seen_subcommand_from scan" -l ir-opt -r -a "O0 O1 O2" -d "IR optimization level"
complete -c lshaz -n "__fish_seen_subcommand_from scan" -l ir-jobs -r -d "Max parallel IR jobs"
complete -c lshaz -n "__fish_seen_subcommand_from scan" -l ir-batch-size -r -d "TUs per IR shard"
complete -c lshaz -n "__fish_seen_subcommand_from scan" -l no-ir-cache -d "Disable IR cache"
complete -c lshaz -n "__fish_seen_subcommand_from scan" -l jobs -r -d "Parallel AST threads"
complete -c lshaz -n "__fish_seen_subcommand_from scan" -l max-files -r -d "Max TUs to analyze"
complete -c lshaz -n "__fish_seen_subcommand_from scan" -l include -rF -d "Include pattern"
complete -c lshaz -n "__fish_seen_subcommand_from scan" -l exclude -rF -d "Exclude pattern"
complete -c lshaz -n "__fish_seen_subcommand_from scan" -l perf-profile -rF -d "Perf profile path"
complete -c lshaz -n "__fish_seen_subcommand_from scan" -l hotness-threshold -r -d "Hotness threshold percent"
complete -c lshaz -n "__fish_seen_subcommand_from scan" -l allocator -r -a "tcmalloc jemalloc mimalloc" -d "Linked allocator"
complete -c lshaz -n "__fish_seen_subcommand_from scan" -l calibration-store -rF -d "Calibration store path"
complete -c lshaz -n "__fish_seen_subcommand_from scan" -l pmu-trace -rF -d "PMU trace data"
complete -c lshaz -n "__fish_seen_subcommand_from scan" -l pmu-priors -rF -d "PMU priors path"
complete -c lshaz -n "__fish_seen_subcommand_from scan" -l watch -d "Watch mode"
complete -c lshaz -n "__fish_seen_subcommand_from scan" -l watch-interval -r -d "Watch poll seconds"
complete -c lshaz -n "__fish_seen_subcommand_from scan" -l trust-build-system -d "Allow build system on cloned repos"
complete -c lshaz -n "__fish_seen_subcommand_from scan" -l help -d "Show help"

# init
complete -c lshaz -n "__fish_seen_subcommand_from init" -l no-config -d "Skip config generation"
complete -c lshaz -n "__fish_seen_subcommand_from init" -l force -d "Regenerate compile_commands.json"
complete -c lshaz -n "__fish_seen_subcommand_from init" -l help -d "Show help"

# diff
complete -c lshaz -n "__fish_seen_subcommand_from diff" -F -d "JSON scan result"

# explain
complete -c lshaz -n "__fish_seen_subcommand_from explain" -l list -d "List all rules"
complete -c lshaz -n "__fish_seen_subcommand_from explain" -l help -d "Show help"
complete -c lshaz -f -n "__fish_seen_subcommand_from explain" -a "FL001 FL002 FL010 FL011 FL012 FL020 FL021 FL030 FL031 FL040 FL041 FL050 FL060 FL061 FL090" -d "Rule ID"
