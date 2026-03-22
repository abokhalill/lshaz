# SPDX-License-Identifier: Apache-2.0
# bash completion for lshaz

_lshaz() {
    local cur prev subcmd
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # Determine subcommand.
    subcmd=""
    for ((i=1; i < COMP_CWORD; i++)); do
        case "${COMP_WORDS[i]}" in
            scan|fix|hyp|exp|feedback|init|diff|explain|version|help)
                subcmd="${COMP_WORDS[i]}"
                break
                ;;
        esac
    done

    # Top-level completion.
    if [[ -z "$subcmd" ]]; then
        COMPREPLY=($(compgen -W "scan fix hyp exp feedback init diff explain version help" -- "$cur"))
        return
    fi

    case "$subcmd" in
        scan)
            case "$prev" in
                --compile-db|--config|--output|--perf-profile|--calibration-store|--pmu-trace|--pmu-priors|--changed-files)
                    COMPREPLY=($(compgen -f -- "$cur"))
                    return
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "cli json sarif tidy" -- "$cur"))
                    return
                    ;;
                --min-severity)
                    COMPREPLY=($(compgen -W "Informational Medium High Critical" -- "$cur"))
                    return
                    ;;
                --min-evidence)
                    COMPREPLY=($(compgen -W "speculative likely proven" -- "$cur"))
                    return
                    ;;
                --ir-opt)
                    COMPREPLY=($(compgen -W "O0 O1 O2" -- "$cur"))
                    return
                    ;;
                --allocator)
                    COMPREPLY=($(compgen -W "tcmalloc jemalloc mimalloc" -- "$cur"))
                    return
                    ;;
                --target-arch)
                    COMPREPLY=($(compgen -W "x86-64 arm64 arm64-apple" -- "$cur"))
                    return
                    ;;
                --ir-jobs|--ir-batch-size|--jobs|--max-files|--watch-interval|--hotness-threshold)
                    return
                    ;;
                --include|--exclude)
                    COMPREPLY=($(compgen -f -- "$cur"))
                    return
                    ;;
            esac
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "--compile-db --config --format --output --min-severity --min-evidence --no-ir --ir-opt --ir-jobs --ir-batch-size --no-ir-cache --jobs --max-files --include --exclude --perf-profile --hotness-threshold --allocator --calibration-store --pmu-trace --pmu-priors --watch --watch-interval --trust-build-system --changed-files --target-arch --help" -- "$cur"))
            else
                COMPREPLY=($(compgen -d -- "$cur"))
            fi
            ;;
        init)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "--no-config --force --help" -- "$cur"))
            else
                COMPREPLY=($(compgen -d -- "$cur"))
            fi
            ;;
        diff)
            COMPREPLY=($(compgen -f -X '!*.json' -- "$cur"))
            ;;
        fix)
            case "$prev" in
                --compile-db|--config)
                    COMPREPLY=($(compgen -f -- "$cur"))
                    return
                    ;;
                --rules)
                    COMPREPLY=($(compgen -W "FL001" -- "$cur"))
                    return
                    ;;
            esac
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "--compile-db --config --dry-run --rules --help" -- "$cur"))
            else
                COMPREPLY=($(compgen -d -f -- "$cur"))
            fi
            ;;
        explain)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "--list --help" -- "$cur"))
            else
                COMPREPLY=($(compgen -W "FL001 FL002 FL010 FL011 FL012 FL020 FL021 FL030 FL031 FL040 FL041 FL050 FL060 FL061 FL090 FL091" -- "$cur"))
            fi
            ;;
        hyp)
            case "$prev" in
                -o|--output)
                    COMPREPLY=($(compgen -f -- "$cur"))
                    return
                    ;;
                --rule)
                    COMPREPLY=($(compgen -W "FL001 FL002 FL010 FL011 FL012 FL020 FL021 FL030 FL031 FL040 FL041 FL050 FL060 FL061 FL090 FL091" -- "$cur"))
                    return
                    ;;
            esac
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "-o --output --rule --min-conf --help" -- "$cur"))
            else
                COMPREPLY=($(compgen -f -X '!*.json' -- "$cur"))
            fi
            ;;
        exp)
            case "$prev" in
                -o|--output)
                    COMPREPLY=($(compgen -d -- "$cur"))
                    return
                    ;;
                --rule)
                    COMPREPLY=($(compgen -W "FL001 FL002 FL010 FL011 FL012 FL020 FL021 FL030 FL031 FL040 FL041 FL050 FL060 FL061 FL090 FL091" -- "$cur"))
                    return
                    ;;
                --sku)
                    return
                    ;;
            esac
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "-o --output --rule --min-conf --sku --dry-run --help" -- "$cur"))
            else
                COMPREPLY=($(compgen -f -X '!*.json' -- "$cur"))
            fi
            ;;
        feedback)
            case "$prev" in
                --store)
                    COMPREPLY=($(compgen -f -- "$cur"))
                    return
                    ;;
            esac
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "--store --alpha --json --help" -- "$cur"))
            else
                COMPREPLY=($(compgen -d -- "$cur"))
            fi
            ;;
    esac
}

complete -F _lshaz lshaz
