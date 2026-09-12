#!/usr/bin/env python3
"""Turn a write-attribution trace into a per-symbol sharing verdict.

The distinction the trace exists to make, and that no static analysis can:

  FALSE_SHARING   one line, DIFFERENT granules, different threads.
                  Nobody races; the line still ping-pongs. This is the claim
                  FL002 makes, and a race detector reports none of it.
  TRUE_SHARING    one granule, several threads. Contention on the field
                  itself -- real, but a different rule's business.
  PRIVATE         one thread. Whatever the layout says, it costs nothing.

  wattr_report.py <trace.tsv> <binary> [--json]
"""
import collections
import json
import subprocess
import sys


LINE = 64
# Writes the quieter side must contribute before a shared line is worth
# reporting. Below this the coherence cost is a rounding error.
MIN_PRESSURE = 100


_site_cache = {}


def site_name(ra_hex, bias, binary):
    """Return address -> file:line. The bias must come off first: addr2line
    speaks link-time addresses and the trace records runtime ones."""
    key = (ra_hex, bias)
    if key in _site_cache:
        return _site_cache[key]
    out = ra_hex
    try:
        link_addr = int(ra_hex, 16) - bias
        r = subprocess.run(["addr2line", "-e", binary, "-f", "-s",
                            hex(link_addr)], capture_output=True, text=True)
        lines = [l.strip() for l in r.stdout.splitlines() if l.strip()]
        if len(lines) >= 2 and lines[1] != "??:0":
            out = f"{lines[0]} {lines[1]}"
    except Exception:
        pass
    _site_cache[key] = out
    return out


def load_symbols(binary):
    """Link-time (addr, size, name) for data symbols, sorted by address."""
    out = subprocess.run(["nm", "-S", "--defined-only", binary],
                         capture_output=True, text=True).stdout
    syms = []
    for ln in out.splitlines():
        parts = ln.split()
        # "addr size type name" -- size only present with -S
        if len(parts) == 4 and parts[2].upper() in ("B", "D", "G", "R", "V"):
            try:
                syms.append((int(parts[0], 16), int(parts[1], 16), parts[3]))
            except ValueError:
                continue
    syms.sort()
    return syms


def resolve(syms, addr):
    lo, hi = 0, len(syms) - 1
    best = None
    while lo <= hi:
        mid = (lo + hi) // 2
        if syms[mid][0] <= addr:
            best = syms[mid]
            lo = mid + 1
        else:
            hi = mid - 1
    if best and best[0] <= addr < best[0] + max(best[1], 1):
        return best[2], addr - best[0]
    return None, 0


def main():
    if len(sys.argv) < 3:
        print(__doc__.strip())
        return 2
    trace, binary = sys.argv[1], sys.argv[2]

    base = 0
    img_lo, img_hi = 0, 0
    rows = []
    allocs = []
    with open(trace) as fh:
        for ln in fh:
            if ln.startswith("# base"):
                base = int(ln.split()[-1], 16)
                continue
            if ln.startswith("# image"):
                _, lo, hi = ln.split("\t")
                img_lo, img_hi = int(lo, 16), int(hi, 16)
                continue
            if ln.startswith("@\t"):
                _, b, sz, ra = ln.split("\t")
                allocs.append((int(b, 16), int(sz), ra.strip()))
                continue
            if ln.startswith("#"):
                continue
            line, off, mask, ntids, writes = ln.split("\t")
            rows.append((int(line, 16), int(off), int(mask), int(ntids),
                         int(writes)))
    allocs.sort()

    syms = load_symbols(binary)
    # Group by cache line, carrying each granule's writer set.
    lines = collections.defaultdict(dict)
    for line, off, mask, _n, writes in rows:
        lines[line][off] = (mask, writes)

    verdicts = []
    for line, granules in sorted(lines.items()):
        # Resolve each granule, not the line: a line begins before the first
        # object on it, and which symbols share the line IS the finding.
        # Static addresses need the bias removed; heap and stack do not
        # resolve, which is itself informative -- a per-request object has
        # no symbol, and that is the handoff case.
        names = []
        for off in sorted(granules):
            a = line + off
            # Only image addresses may be resolved against the symbol table.
            # Subtracting the bias from a heap or stack address yields a
            # number that can land inside some symbol's range and be
            # confidently misattributed -- which it was.
            if not (img_lo <= a < img_hi):
                continue
            n, _o = resolve(syms, a - base)
            if n and n not in names:
                names.append(n)
        if not names:
            # Not a global: attribute to the allocation(s) covering the line.
            # Several matches mean the address was recycled, so the object it
            # belonged to at write time is unknowable without timestamps --
            # reported as reuse rather than guessed at.
            # Plain interval overlap. The earlier two-clause test missed any
            # allocation that starts partway into the line, which is most of
            # them: objects are not line-aligned.
            sites = set()
            for b, sz, ra in allocs:
                if b >= line + LINE:
                    break
                if b + sz > line:
                    sites.add(ra)
            if len(sites) == 1:
                names = [f"heap@{site_name(sites.pop(), base, binary)}"]
            elif len(sites) > 1:
                names = [f"heap@POOL_REUSE({len(sites)} sites)"]
            elif img_hi and not (img_lo <= line < img_hi):
                # Outside the image and matching no allocation: a thread
                # stack. Named rather than left <anon>, because "the object
                # is per-thread" is a verdict, not a gap.
                names = ["<stack-or-unattributed>"]
        name = "+".join(names) if names else None
        off = 0
        union = 0
        for m, _ in granules.values():
            union |= m
        multi_granule = any(bin(m).count("1") > 1 for m, _ in granules.values())
        distinct = bin(union).count("1")

        # Two threads touching a line is not contention. Coherence traffic
        # is bounded by the QUIETER side: a granule written 27,000 times by
        # one thread and three times by another costs three invalidations,
        # not 27,000. A per-class statistics array looks exactly like that,
        # and grading it on thread count alone reports a non-problem.
        #
        # Per-thread write counts are not in the trace (that would need 64
        # counters per granule). Grouping granules by their writer mask and
        # taking the second-largest group's writes is the same quantity for
        # the single-writer-per-granule shape that matters here.
        by_mask = collections.defaultdict(int)
        for m, w in granules.values():
            by_mask[m] += w
        totals = sorted(by_mask.values(), reverse=True)
        pressure = totals[1] if len(totals) > 1 else 0

        if distinct <= 1:
            verdict = "PRIVATE"
        elif multi_granule:
            verdict = "TRUE_SHARING"
        elif len(granules) > 1 and pressure >= MIN_PRESSURE:
            verdict = "FALSE_SHARING"
        elif len(granules) > 1:
            verdict = "COLD_SHARE"     # real, but too rare to cost anything
        else:
            verdict = "PRIVATE"
        verdicts.append({
            "line": hex(line),
            "symbol": name or "<anon>",
            "symbol_offset": off,
            "granules": len(granules),
            "threads": distinct,
            "writes": sum(w for _, w in granules.values()),
            "pressure": pressure,
            "verdict": verdict,
        })

    if "--json" in sys.argv:
        json.dump(verdicts, sys.stdout, indent=2)
        return 0

    counts = collections.Counter(v["verdict"] for v in verdicts)
    print(f"{len(verdicts)} line(s): " +
          ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) + "\n")
    print(f"{'verdict':16} {'symbol':30} {'gran':>5} {'thr':>4} "
          f"{'writes':>10} {'pressure':>9}")
    for v in sorted(verdicts, key=lambda x: -x["writes"]):
        if v["verdict"] == "PRIVATE":
            continue
        print(f"{v['verdict']:16} {v['symbol'][:30]:30} "
              f"{v['granules']:5} {v['threads']:4} {v['writes']:10} "
              f"{v['pressure']:9}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
