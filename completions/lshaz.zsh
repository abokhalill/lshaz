# SPDX-License-Identifier: Apache-2.0
#compdef lshaz

_lshaz() {
    local -a subcmds
    subcmds=(
        'scan:Analyze a project for hardware-level performance hazards'
        'fix:Auto-remediate fixable findings'
        'hyp:Construct latency hypotheses from scan diagnostics'
        'exp:Synthesize experiment bundles from scan diagnostics'
        'feedback:Ingest experiment results into calibration store'
        'init:Generate compile_commands.json and starter config'
        'diff:Compare two JSON scan results'
        'explain:Show rule documentation'
        'version:Print version'
        'help:Show help'
    )

    _arguments -C \
        '1:subcommand:->subcmd' \
        '*::arg:->args'

    case "$state" in
        subcmd)
            _describe 'subcommand' subcmds
            ;;
        args)
            case "$words[1]" in
                scan)
                    _arguments \
                        '--compile-db[Path to compile_commands.json]:file:_files' \
                        '--config[Path to lshaz.config.yaml]:file:_files' \
                        '--format[Output format]:format:(cli json sarif tidy)' \
                        '--output[Write output to file]:file:_files' \
                        '--min-severity[Minimum severity]:level:(Informational Medium High Critical)' \
                        '--min-evidence[Minimum evidence tier]:tier:(speculative likely proven)' \
                        '--no-ir[Disable LLVM IR analysis]' \
                        '--ir-opt[IR optimization level]:level:(O0 O1 O2)' \
                        '--ir-jobs[Max parallel IR jobs]:count:' \
                        '--ir-batch-size[TUs per IR shard]:count:' \
                        '--no-ir-cache[Disable IR cache]' \
                        '--jobs[Parallel AST analysis threads]:count:' \
                        '--max-files[Maximum TUs to analyze]:count:' \
                        '--include[Include file pattern]:pattern:_files' \
                        '--exclude[Exclude file pattern]:pattern:_files' \
                        '--perf-profile[Perf profile path]:file:_files' \
                        '--hotness-threshold[Hotness threshold percent]:percent:' \
                        '--allocator[Linked allocator]:allocator:(tcmalloc jemalloc mimalloc)' \
                        '--calibration-store[Calibration store path]:file:_files' \
                        '--pmu-trace[PMU trace data]:file:_files' \
                        '--pmu-priors[PMU priors path]:file:_files' \
                        '--watch[Watch mode]' \
                        '--watch-interval[Watch poll interval]:seconds:' \
                        '--trust-build-system[Allow build system execution on cloned repos]' \
                        '--changed-files[Only scan TUs affected by listed files]:file:_files' \
                        '--target-arch[Target architecture]:arch:(x86-64 arm64 arm64-apple)' \
                        '--help[Show help]' \
                        '1:target:_files -/'
                    ;;
                init)
                    _arguments \
                        '--no-config[Skip config generation]' \
                        '--force[Regenerate compile_commands.json]' \
                        '--help[Show help]' \
                        '1:directory:_files -/'
                    ;;
                diff)
                    _arguments \
                        '1:before:_files -g "*.json"' \
                        '2:after:_files -g "*.json"'
                    ;;
                fix)
                    _arguments \
                        '--compile-db[Path to compile_commands.json]:file:_files' \
                        '--config[Path to lshaz.config.yaml]:file:_files' \
                        '--dry-run[Show patches without modifying files]' \
                        '--rules[Comma-separated rules to fix]:rules:' \
                        '--help[Show help]' \
                        '1:target:_files'
                    ;;
                explain)
                    _arguments \
                        '--list[List all rules]' \
                        '--help[Show help]' \
                        '1:rule:(FL001 FL002 FL010 FL011 FL012 FL020 FL021 FL030 FL031 FL040 FL041 FL050 FL060 FL061 FL090 FL091)'
                    ;;
                hyp)
                    _arguments \
                        '-o[Output file]:file:_files' \
                        '--output[Output file]:file:_files' \
                        '--rule[Filter by rule ID]:rule:(FL001 FL002 FL010 FL011 FL012 FL020 FL021 FL030 FL031 FL040 FL041 FL050 FL060 FL061 FL090 FL091)' \
                        '--min-conf[Minimum confidence]:threshold:' \
                        '--help[Show help]' \
                        '1:scan result:_files -g "*.json"'
                    ;;
                exp)
                    _arguments \
                        '-o[Output directory]:dir:_files -/' \
                        '--output[Output directory]:dir:_files -/' \
                        '--rule[Filter by rule ID]:rule:(FL001 FL002 FL010 FL011 FL012 FL020 FL021 FL030 FL031 FL040 FL041 FL050 FL060 FL061 FL090 FL091)' \
                        '--min-conf[Minimum confidence]:threshold:' \
                        '--sku[CPU SKU family]:sku:' \
                        '--dry-run[Show what would be generated]' \
                        '--help[Show help]' \
                        '1:scan result:_files -g "*.json"'
                    ;;
                feedback)
                    _arguments \
                        '--store[Calibration store path]:file:_files' \
                        '--alpha[Significance level]:alpha:' \
                        '--json[Output verdict as JSON]' \
                        '--help[Show help]' \
                        '1:experiment directory:_files -/'
                    ;;
            esac
            ;;
    esac
}

_lshaz "$@"
