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
            scan|init|diff|explain|version|help)
                subcmd="${COMP_WORDS[i]}"
                break
                ;;
        esac
    done

    # Top-level completion.
    if [[ -z "$subcmd" ]]; then
        COMPREPLY=($(compgen -W "scan init diff explain version help" -- "$cur"))
        return
    fi

    case "$subcmd" in
        scan)
            case "$prev" in
                --compile-db|--config|--output|--perf-profile|--calibration-store|--pmu-trace|--pmu-priors)
                    COMPREPLY=($(compgen -f -- "$cur"))
                    return
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "cli json sarif" -- "$cur"))
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
                --ir-jobs|--ir-batch-size|--jobs|--max-files|--watch-interval|--hotness-threshold)
                    return
                    ;;
                --include|--exclude)
                    COMPREPLY=($(compgen -f -- "$cur"))
                    return
                    ;;
            esac
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "--compile-db --config --format --output --min-severity --min-evidence --no-ir --ir-opt --ir-jobs --ir-batch-size --no-ir-cache --jobs --max-files --include --exclude --perf-profile --hotness-threshold --allocator --calibration-store --pmu-trace --pmu-priors --watch --watch-interval --trust-build-system --help" -- "$cur"))
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
        explain)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "--list --help" -- "$cur"))
            else
                COMPREPLY=($(compgen -W "FL001 FL002 FL010 FL011 FL012 FL020 FL021 FL030 FL031 FL040 FL041 FL050 FL060 FL061 FL090" -- "$cur"))
            fi
            ;;
    esac
}

complete -F _lshaz lshaz
