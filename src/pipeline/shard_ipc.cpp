// SPDX-License-Identifier: Apache-2.0
#include "shard_ipc.h"

#include <cstdlib>
#include <string>
#include <vector>

namespace lshaz {

std::string serializeShardResult(int exitCode,
                                 const std::vector<FailedTU> &failedTUs,
                                 const std::vector<Diagnostic> &diagnostics,
                                 const EscapeSummary &escapeSummary,
                                 const ThreadRoleSummary &threadRoles,
                                 const StripedArraySummary &striped,
                                 const ScanCoverage &coverage,
                                 const std::string &src) {
    auto esc = [](const std::string &s) -> std::string {
        std::string out;
        out.reserve(s.size() + 4);
        for (char c : s) {
            switch (c) {
                case '"':  out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default: out += c;
            }
        }
        return out;
    };

    std::string buf;
    buf.reserve(4096);
    buf += "{";
    if (!src.empty()) { buf += "\"src\":\""; buf += esc(src); buf += "\","; }
    buf += "\"exitCode\":";
    buf += std::to_string(exitCode);
    buf += ",\"failedTUs\":[";
    for (size_t i = 0; i < failedTUs.size(); ++i) {
        if (i) buf += ',';
        buf += "{\"file\":\""; buf += esc(failedTUs[i].file); buf += "\",";
        buf += "\"error\":\""; buf += esc(failedTUs[i].error); buf += "\",";
        buf += "\"missingHeader\":\"";
        buf += esc(failedTUs[i].missingHeader); buf += "\"}";
    }
    buf += "],\"diagnostics\":[";
    for (size_t i = 0; i < diagnostics.size(); ++i) {
        const auto &d = diagnostics[i];
        if (i) buf += ',';
        buf += "{\"ruleID\":\"" + esc(d.ruleID) + "\"";
        buf += ",\"title\":\"" + esc(d.title) + "\"";
        buf += ",\"severity\":\"" + std::string(severityToString(d.severity)) + "\"";
        // to_chars, not to_string and not snprintf: both format through the
        // C locale and would emit "0,72" under LC_NUMERIC=de_DE, silently
        // corrupting every confidence across the fork. to_chars is
        // locale-independent by specification and round-trips exactly, where
        // %f also truncated to six decimals.
        {
            char cbuf[40];
            auto [end, ec] = std::to_chars(cbuf, cbuf + sizeof(cbuf),
                                           d.confidence);
            buf += ",\"confidence\":";
            buf.append(cbuf, ec == std::errc() ? end : cbuf + 1);
        }
        buf += ",\"evidenceTier\":\"" + std::string(evidenceTierName(d.evidenceTier)) + "\"";
        buf += ",\"suppressed\":" + std::string(d.suppressed ? "true" : "false");
        buf += ",\"location\":{\"file\":\"" + esc(d.location.file) + "\"";
        buf += ",\"line\":" + std::to_string(d.location.line);
        buf += ",\"column\":" + std::to_string(d.location.column) + "}";
        buf += ",\"functionName\":\"" + esc(d.functionName) + "\"";
        buf += ",\"hardwareReasoning\":\"" + esc(d.hardwareReasoning) + "\"";
        buf += ",\"structuralEvidence\":{";
        bool first = true;
        for (const auto &[k, v] : d.structuralEvidence) {
            if (!first) buf += ',';
            buf += '"'; buf += esc(k); buf += "\":\"";
            buf += esc(v); buf += '"';
            first = false;
        }
        buf += "}";
        buf += ",\"mitigation\":\"" + esc(d.mitigation) + "\"";
        buf += ",\"escalations\":[";
        for (size_t j = 0; j < d.escalations.size(); ++j) {
            if (j) buf += ',';
            buf += '"'; buf += esc(d.escalations[j]); buf += '"';
        }
        buf += "]";
        // Unserialized, this would make the cross-TU hotness verdict depend
        // on whether the shard ran forked or sequentially.
        buf += ",\"hot\":" + std::to_string(static_cast<unsigned>(d.hotness));
        // Unserialized fields are a jobs-dependent verdict: present on the
        // sequential path, gone on the forked one. This is the third such
        // field after the FL003 writer tier and the thread-writer escape
        // signal, so it crosses the boundary with the rest.
        buf += ",\"mc\":[";
        for (size_t j = 0; j < d.mechanismClaims.size(); ++j) {
            const auto &c = d.mechanismClaims[j];
            if (j) buf += ',';
            buf += "{\"e\":\"" + esc(c.effect) + "\",\"p\":\"" +
                   esc(c.precondition) + "\",\"k\":" +
                   std::to_string(c.established ? 1 : 0) + ",\"g\":" +
                   std::to_string(c.gating ? 1 : 0) + ",\"s\":\"" +
                   std::string(severityToString(c.supports)) + "\"}";
        }
        buf += "]}";
    }
    buf += "]";

    // Cost estimates are computed in the reduce phase and are not part of
    // this protocol. A rule that sets one in the map phase would have it
    // silently dropped here and kept on the sequential path, which is the
    // jobs-dependent verdict this boundary exists to prevent. Fail rather
    // than serialise half of it.
    for (const auto &d : diagnostics) {
        if (!d.cost.empty()) {
            llvm::errs() << "lshaz: internal error: rule " << d.ruleID
                         << " set a cost estimate in the map phase, which "
                            "does not cross the shard boundary. Emit the "
                            "terms from the reduce phase instead.\n";
            std::abort();
        }
    }

    // Escape summary: {"typeName":{a:0/1,s:0/1,o:0/1,v:0/1,p:0/1,n:N},...}
    buf += ",\"escapeSummary\":{";
    {
        bool first = true;
        for (const auto &[name, sig] : escapeSummary) {
            if (!first) buf += ',';
            buf += '"'; buf += esc(name); buf += "\":{";
            buf += "\"a\":" + std::to_string(sig.hasAtomics ? 1 : 0);
            buf += ",\"s\":" + std::to_string(sig.hasSyncPrims ? 1 : 0);
            buf += ",\"o\":" + std::to_string(sig.hasSharedOwner ? 1 : 0);
            buf += ",\"v\":" + std::to_string(sig.hasVolatile ? 1 : 0);
            buf += ",\"p\":" + std::to_string(sig.hasPublication ? 1 : 0);
            buf += ",\"tw\":" + std::to_string(sig.hasThreadWriters ? 1 : 0);
            buf += ",\"gi\":" + std::to_string(sig.hasGlobalInstance ? 1 : 0);
            buf += ",\"tb\":" + std::to_string(sig.hasThreadBorneWriter ? 1 : 0);
            buf += ",\"sw\":" + std::to_string(sig.hasStandingWrites ? 1 : 0);
            buf += ",\"l\":" + std::to_string(sig.hasDeliberateLayout ? 1 : 0);
            buf += ",\"n\":" + std::to_string(sig.accessorCount);
            if (sig.recordAlignBytes)
                buf += ",\"ra\":" + std::to_string(sig.recordAlignBytes);
            if (!sig.fieldExtents.empty()) {
                buf += ",\"fx\":{";
                bool firstField = true;
                for (const auto &[fname, e] : sig.fieldExtents) {
                    if (!firstField) buf += ',';
                    buf += '"'; buf += esc(fname); buf += "\":[";
                    buf += std::to_string(e.offsetBytes) + ',' +
                           std::to_string(e.sizeBytes) + ',' +
                           std::to_string(e.isAtomic ? 1 : 0) + ',' +
                           std::to_string(e.plainScalar ? 1 : 0) + ',' +
                           std::to_string(e.declLine);
                    buf += ']';
                    firstField = false;
                }
                buf += '}';
            }
            if (sig.declLine) {
                buf += ",\"df\":\""; buf += esc(sig.declFile); buf += '"';
                buf += ",\"dl\":" + std::to_string(sig.declLine);
            }
            buf += '}';
            first = false;
        }
    }
    buf += "}";

    // Thread-role facts: {"entries":[...],"edges":{caller:[callees]},
    // "fieldWriters":{"Type::field":[writers]}}. Ordered containers give
    // a canonical byte sequence for identical facts.
    auto emitNameSets =
        [&](const std::map<std::string, std::set<std::string>> &m) {
            bool firstKey = true;
            for (const auto &[k, vals] : m) {
                if (!firstKey) buf += ',';
                buf += '"'; buf += esc(k); buf += "\":[";
                bool firstVal = true;
                for (const auto &v : vals) {
                    if (!firstVal) buf += ',';
                    buf += '"'; buf += esc(v); buf += '"';
                    firstVal = false;
                }
                buf += ']';
                firstKey = false;
            }
        };
    auto emitNames = [&](const std::set<std::string> &s) {
        bool first = true;
        for (const auto &e : s) {
            if (!first) buf += ',';
            buf += '"'; buf += esc(e); buf += '"';
            first = false;
        }
    };
    buf += ",\"threadRoles\":{\"entries\":[";
    emitNames(threadRoles.threadEntries);
    buf += "],\"edges\":{";
    emitNameSets(threadRoles.callEdges);
    buf += "},\"fieldWriters\":{";
    emitNameSets(threadRoles.fieldWriters);
    buf += "},\"fieldReaders\":{";
    emitNameSets(threadRoles.fieldReaders);
    buf += "},\"fieldWriteSites\":{";
    emitNameSets(threadRoles.fieldWriteSites);
    buf += "},\"fieldAccess\":{";
    {
        bool firstKey = true;
        for (const auto &[k, fa] : threadRoles.fieldAccess) {
            if (fa.empty()) continue;
            if (!firstKey) buf += ',';
            buf += '"'; buf += esc(k); buf += "\":[";
            // Positional and open-ended: the reader consumes as many counts
            // as the array holds and leaves the rest at zero, so adding a
            // measure is one line here and none there. Order is the wire
            // contract and entries are only ever appended.
            for (unsigned v : {fa.writeSites, fa.loopWriteSites,
                               fa.standingWriteSites, fa.handedWriteSites,
                               fa.readSites, fa.standingReadSites,
                               fa.handedReadSites}) {
                if (buf.back() != '[') buf += ',';
                buf += std::to_string(v);
            }
            buf += ']';
            firstKey = false;
        }
    }
    buf += "},\"allocOf\":{";
    emitNameSets(threadRoles.allocatorsOfType);
    buf += "},\"freeOf\":{";
    emitNameSets(threadRoles.freersOfType);
    buf += "},\"retFwd\":{";
    emitNameSets(threadRoles.returnForwards);
    buf += "},\"parFwd\":{";
    emitNameSets(threadRoles.paramForwards);
    buf += "},\"allocSites\":{";
    emitNameSets(threadRoles.allocSitesByCallee);
    buf += "},\"freeSites\":{";
    emitNameSets(threadRoles.freeSitesByCallee);
    buf += "},\"atomicTypes\":[";
    emitNames(threadRoles.atomicTypes);
    buf += "],\"strictParFwd\":{";
    emitNameSets(threadRoles.strictParamForwards);
    buf += "},\"spinAcq\":{";
    emitNameSets(threadRoles.spinAcquireOfType);
    buf += "},\"spinRel\":{";
    emitNameSets(threadRoles.spinReleaseOfType);
    buf += "},\"declLock\":[";
    emitNames(threadRoles.declaredLocks);
    buf += "],\"declUnlock\":[";
    emitNames(threadRoles.declaredUnlocks);
    buf += "],\"declAlloc\":[";
    emitNames(threadRoles.declaredAllocators);
    buf += "],\"declFree\":[";
    emitNames(threadRoles.declaredFreers);
    buf += "],\"defined\":[";
    emitNames(threadRoles.definedFunctions);
    buf += "],\"builtins\":[";
    emitNames(threadRoles.builtinCallees);
    buf += "],\"edgeDepth\":{";
    {
        bool firstCaller = true;
        for (const auto &[caller, edges] : threadRoles.edgeLoopDepth) {
            if (edges.empty()) continue;
            if (!firstCaller) buf += ',';
            buf += '"'; buf += esc(caller); buf += "\":{";
            bool firstEdge = true;
            for (const auto &[callee, d] : edges) {
                if (!firstEdge) buf += ',';
                buf += '"'; buf += esc(callee); buf += "\":" + std::to_string(d);
                firstEdge = false;
            }
            buf += '}';
            firstCaller = false;
        }
    }
    buf += "},\"edgeFreq\":{";
    {
        bool firstCaller = true;
        for (const auto &[caller, edges] : threadRoles.edgeFrequency) {
            if (edges.empty()) continue;
            if (!firstCaller) buf += ',';
            buf += '"'; buf += esc(caller); buf += "\":{";
            bool firstEdge = true;
            for (const auto &[callee, f] : edges) {
                if (!firstEdge) buf += ',';
                buf += '"'; buf += esc(callee); buf += "\":" + std::to_string(f);
                firstEdge = false;
            }
            buf += '}';
            firstCaller = false;
        }
    }
    buf += "},\"ownDepth\":{";
    {
        bool first = true;
        for (const auto &[fn, d] : threadRoles.ownLoopDepth) {
            if (!first) buf += ',';
            buf += '"'; buf += esc(fn); buf += "\":" + std::to_string(d);
            first = false;
        }
    }
    buf += "},\"ownFreq\":{";
    {
        bool first = true;
        for (const auto &[fn, f] : threadRoles.ownFrequency) {
            if (!first) buf += ',';
            buf += '"'; buf += esc(fn); buf += "\":" + std::to_string(f);
            first = false;
        }
    }
    buf += "},\"overridden\":[";
    {
        bool first = true;
        for (const auto &m : threadRoles.overriddenVirtuals) {
            if (!first) buf += ',';
            buf += '"'; buf += esc(m); buf += '"';
            first = false;
        }
    }
    buf += "]}";

    buf += ",\"striped\":{";
    {
        bool first = true;
        for (const auto &[k, a] : striped) {
            if (!first) buf += ',';
            buf += '"'; buf += esc(k); buf += "\":{";
            buf += "\"n\":\"" + esc(a.displayName) + "\"";
            buf += ",\"t\":\"" + esc(a.typeName) + "\"";
            buf += ",\"f\":\"" + esc(a.file) + "\"";
            buf += ",\"l\":" + std::to_string(a.line);
            buf += ",\"es\":" + std::to_string(a.elemSizeBytes);
            buf += ",\"ec\":" + std::to_string(a.elemCount);
            buf += ",\"al\":" + std::to_string(a.declAlignBytes);
            buf += ",\"at\":" + std::to_string(a.elementIsAtomic ? 1 : 0);
            buf += ",\"vo\":" + std::to_string(a.elementIsVolatile ? 1 : 0);
            buf += ",\"st\":" + std::to_string(a.isFileStatic ? 1 : 0);
            buf += ",\"tls\":" + std::to_string(a.tlsIndexed ? 1 : 0);
            buf += ",\"ho\":" + std::to_string(a.indexIsHandedOver ? 1 : 0);
            buf += ",\"oi\":" + std::to_string(a.indexIsOwnIdentity ? 1 : 0);
            buf += ",\"hp\":" + std::to_string(a.hasHeadPaddingOffset ? 1 : 0);
            buf += ",\"wt\":" + std::to_string(a.writerTier);
            buf += ",\"agt\":" + std::to_string(a.aggregatorTier);
            buf += ",\"w\":[";
            bool fw = true;
            for (const auto &w : a.stripedWriters) {
                if (!fw) buf += ',';
                buf += '"'; buf += esc(w); buf += '"'; fw = false;
            }
            buf += "],\"ag\":[";
            bool fa = true;
            for (const auto &g : a.aggregators) {
                if (!fa) buf += ',';
                buf += '"'; buf += esc(g); buf += '"'; fa = false;
            }
            buf += "]}";
            first = false;
        }
    }
    buf += "}";

    buf += ",\"cov\":{\"fs\":" + std::to_string(coverage.functionsSeen) +
           ",\"fh\":" + std::to_string(coverage.functionsHot) +
           ",\"rs\":" + std::to_string(coverage.recordsSeen) + "}";

    buf += "}";
    return buf;
}

namespace ipc {

static void skipWS(const std::string &s, size_t &i) {
    while (i < s.size() && (s[i]==' '||s[i]=='\n'||s[i]=='\r'||s[i]=='\t'))
        ++i;
}

static void skipValue(const std::string &s, size_t &i) {
    skipWS(s, i);
    if (i >= s.size()) return;
    if (s[i] == '"') {
        ++i;
        while (i < s.size() && s[i] != '"') {
            if (s[i] == '\\') ++i;
            ++i;
        }
        if (i < s.size()) ++i;
    } else if (s[i] == '[' || s[i] == '{') {
        char open = s[i];
        char close = (open == '[') ? ']' : '}';
        ++i;
        int depth = 1;
        while (i < s.size() && depth > 0) {
            // String contents are not structure. A ']' inside a string ended
            // the skip early and left the cursor mid-value, which desynchronizes
            // every key after it in an unknown array.
            if (s[i] == '"') {
                ++i;
                while (i < s.size() && s[i] != '"') {
                    if (s[i] == '\\') ++i;
                    ++i;
                }
                if (i < s.size()) ++i;
                continue;
            }
            if (s[i] == open) ++depth;
            else if (s[i] == close) --depth;
            ++i;
        }
    } else {
        while (i < s.size() && s[i] != ',' && s[i] != '}' && s[i] != ']')
            ++i;
    }
}

static bool expect(const std::string &s, size_t &i, char c) {
    skipWS(s, i);
    if (i < s.size() && s[i] == c) { ++i; return true; }
    return false;
}

// Always advances when input remains. Returning without consuming let a
// non-string where a string was expected spin a caller's loop forever, and the
// parent has no timeout to escape it with. Truncation was already safe; this
// covers malformed-but-complete records, which is what a version skew across
// the TU cache produces.
static void skipValue(const std::string &s, size_t &i);
static std::string parseStr(const std::string &s, size_t &i) {
    skipWS(s, i);
    if (i >= s.size()) return {};
    if (s[i] != '"') { skipValue(s, i); return {}; }
    ++i;
    std::string out;
    while (i < s.size() && s[i] != '"') {
        if (s[i] == '\\' && i + 1 < s.size()) {
            ++i;
            switch (s[i]) {
                case '"':  out += '"'; break;
                case '\\': out += '\\'; break;
                case 'n':  out += '\n'; break;
                case 'r':  out += '\r'; break;
                case 't':  out += '\t'; break;
                default:   out += s[i]; break;
            }
        } else {
            out += s[i];
        }
        ++i;
    }
    if (i < s.size()) ++i;
    return out;
}

static double parseNum(const std::string &s, size_t &i) {
    skipWS(s, i);
    size_t start = i;
    if (i < s.size() && s[i] == '-') ++i;
    while (i < s.size() && s[i] >= '0' && s[i] <= '9') ++i;
    if (i < s.size() && s[i] == '.') {
        ++i;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9') ++i;
    }
    if (i < s.size() && (s[i] == 'e' || s[i] == 'E')) {
        ++i;
        if (i < s.size() && (s[i] == '+' || s[i] == '-')) ++i;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9') ++i;
    }
    // No digits consumed leaves the cursor where it was, which spins any loop
    // that called us. Advance past whatever it is instead.
    if (start == i) {
        skipValue(s, i);
        return 0.0;
    }
    // from_chars for the same reason as to_chars on the way out: stod parses
    // through LC_NUMERIC and stops at the '.' under a comma locale, returning
    // 0 for every confidence in the record.
    double v = 0.0;
    auto [ptr, ec] = std::from_chars(s.data() + start, s.data() + i, v);
    (void)ptr;
    return ec == std::errc() ? v : 0.0;
}

static bool parseBool(const std::string &s, size_t &i) {
    skipWS(s, i);
    if (s.compare(i, 4, "true") == 0) { i += 4; return true; }
    if (s.compare(i, 5, "false") == 0) { i += 5; return false; }
    return false;
}


static Severity toSeverity(const std::string &s) {
    if (s == "Critical") return Severity::Critical;
    if (s == "High") return Severity::High;
    if (s == "Medium") return Severity::Medium;
    return Severity::Informational;
}

static EvidenceTier toTier(const std::string &s) {
    if (s == "proven") return EvidenceTier::Proven;
    if (s == "likely") return EvidenceTier::Likely;
    return EvidenceTier::Speculative;
}

static Diagnostic parseDiag(const std::string &s, size_t &i) {
    Diagnostic d;
    while (true) {
        skipWS(s, i);
        if (i >= s.size() || s[i] == '}') { if (i < s.size()) ++i; break; }
        std::string key = parseStr(s, i);
        expect(s, i, ':');
        if (key == "ruleID")            d.ruleID = parseStr(s, i);
        else if (key == "title")        d.title = parseStr(s, i);
        else if (key == "severity")     d.severity = toSeverity(parseStr(s, i));
        else if (key == "confidence")   d.confidence = parseNum(s, i);
        else if (key == "evidenceTier") d.evidenceTier = toTier(parseStr(s, i));
        else if (key == "suppressed")   d.suppressed = parseBool(s, i);
        else if (key == "functionName") d.functionName = parseStr(s, i);
        else if (key == "hardwareReasoning") d.hardwareReasoning = parseStr(s, i);
        else if (key == "mitigation")   d.mitigation = parseStr(s, i);
        else if (key == "location") {
            expect(s, i, '{');
            while (true) {
                skipWS(s, i);
                if (i >= s.size() || s[i] == '}') { if (i < s.size()) ++i; break; }
                std::string lk = parseStr(s, i);
                expect(s, i, ':');
                if (lk == "file")        d.location.file = parseStr(s, i);
                else if (lk == "line")   d.location.line = static_cast<unsigned>(parseNum(s, i));
                else if (lk == "column") d.location.column = static_cast<unsigned>(parseNum(s, i));
                else skipValue(s, i);
                expect(s, i, ',');
            }
        } else if (key == "structuralEvidence") {
            expect(s, i, '{');
            while (true) {
                skipWS(s, i);
                if (i >= s.size() || s[i] == '}') { if (i < s.size()) ++i; break; }
                std::string ek = parseStr(s, i);
                expect(s, i, ':');
                d.structuralEvidence[ek] = parseStr(s, i);
                expect(s, i, ',');
            }
        } else if (key == "escalations") {
            expect(s, i, '[');
            while (true) {
                skipWS(s, i);
                if (i >= s.size() || s[i] == ']') { if (i < s.size()) ++i; break; }
                d.escalations.push_back(parseStr(s, i));
                expect(s, i, ',');
            }
        } else if (key == "hot") {
            d.hotness = static_cast<uint8_t>(parseNum(s, i));
        } else if (key == "mc") {
            expect(s, i, '[');
            while (true) {
                skipWS(s, i);
                if (i >= s.size() || s[i] == ']') { if (i < s.size()) ++i; break; }
                expect(s, i, '{');
                MechanismClaim c;
                while (true) {
                    skipWS(s, i);
                    if (i >= s.size() || s[i] == '}') { if (i < s.size()) ++i; break; }
                    std::string ck = parseStr(s, i);
                    expect(s, i, ':');
                    if (ck == "e")      c.effect = parseStr(s, i);
                    else if (ck == "p") c.precondition = parseStr(s, i);
                    else if (ck == "k") c.established = parseNum(s, i) != 0;
                    else if (ck == "g") c.gating = parseNum(s, i) != 0;
                    else if (ck == "s") c.supports = toSeverity(parseStr(s, i));
                    else skipValue(s, i);
                    expect(s, i, ',');
                }
                d.mechanismClaims.push_back(std::move(c));
                expect(s, i, ',');
            }
        } else {
            skipValue(s, i);
        }
        expect(s, i, ',');
    }
    return d;
}

} // namespace ipc

bool deserializeShardResult(const std::string &json, ShardIPC &out) {
    size_t i = 0;
    if (!ipc::expect(json, i, '{')) return false;
    while (true) {
        ipc::skipWS(json, i);
        if (i >= json.size() || json[i] == '}') break;
        std::string key = ipc::parseStr(json, i);
        ipc::expect(json, i, ':');
        if (key == "src") {
            out.src = ipc::parseStr(json, i);
        } else if (key == "exitCode") {
            out.exitCode = static_cast<int>(ipc::parseNum(json, i));
        } else if (key == "failedTUs") {
            ipc::expect(json, i, '[');
            while (true) {
                ipc::skipWS(json, i);
                if (i >= json.size() || json[i] == ']') { if (i < json.size()) ++i; break; }
                ipc::expect(json, i, '{');
                FailedTU ftu;
                while (true) {
                    ipc::skipWS(json, i);
                    if (json[i] == '}') { ++i; break; }
                    std::string subkey = ipc::parseStr(json, i);
                    ipc::expect(json, i, ':');
                    if (subkey == "file") {
                        ftu.file = ipc::parseStr(json, i);
                    } else if (subkey == "error") {
                        ftu.error = ipc::parseStr(json, i);
                    } else if (subkey == "missingHeader") {
                        ftu.missingHeader = ipc::parseStr(json, i);
                    } else {
                        ipc::skipValue(json, i);
                    }
                    ipc::skipWS(json, i);
                    if (json[i] == ',') { ++i; continue; }
                    if (json[i] == '}') { ++i; break; }
                }
                out.failedTUs.push_back(std::move(ftu));
                ipc::skipWS(json, i);
                if (json[i] == ',') { ++i; }
            }
        } else if (key == "diagnostics") {
            ipc::expect(json, i, '[');
            while (true) {
                ipc::skipWS(json, i);
                if (i >= json.size() || json[i] == ']') { if (i < json.size()) ++i; break; }
                if (!ipc::expect(json, i, '{')) break;
                out.diagnostics.push_back(ipc::parseDiag(json, i));
                ipc::expect(json, i, ',');
            }
        } else if (key == "escapeSummary") {
            ipc::expect(json, i, '{');
            while (true) {
                ipc::skipWS(json, i);
                if (i >= json.size() || json[i] == '}') { if (i < json.size()) ++i; break; }
                std::string typeName = ipc::parseStr(json, i);
                ipc::expect(json, i, ':');
                ipc::expect(json, i, '{');
                TypeEscapeSignals sig;
                while (true) {
                    ipc::skipWS(json, i);
                    if (i >= json.size() || json[i] == '}') { if (i < json.size()) ++i; break; }
                    std::string sk = ipc::parseStr(json, i);
                    ipc::expect(json, i, ':');
                    if (sk == "fx") {
                        ipc::expect(json, i, '{');
                        while (true) {
                            ipc::skipWS(json, i);
                            if (i >= json.size() || json[i] == '}') {
                                if (i < json.size()) ++i;
                                break;
                            }
                            std::string fname = ipc::parseStr(json, i);
                            ipc::expect(json, i, ':');
                            ipc::expect(json, i, '[');
                            FieldExtent e;
                            e.offsetBytes =
                                static_cast<uint64_t>(ipc::parseNum(json, i));
                            ipc::expect(json, i, ',');
                            e.sizeBytes =
                                static_cast<uint64_t>(ipc::parseNum(json, i));
                            ipc::expect(json, i, ',');
                            e.isAtomic = ipc::parseNum(json, i) != 0;
                            if (ipc::expect(json, i, ','))
                                e.plainScalar = ipc::parseNum(json, i) != 0;
                            if (ipc::expect(json, i, ','))
                                e.declLine = static_cast<unsigned>(
                                    ipc::parseNum(json, i));
                            ipc::expect(json, i, ']');
                            sig.fieldExtents[fname] = e;
                            ipc::expect(json, i, ',');
                        }
                        ipc::expect(json, i, ',');
                        continue;
                    }
                    if (sk == "df") {
                        sig.declFile = ipc::parseStr(json, i);
                        ipc::expect(json, i, ',');
                        continue;
                    }
                    auto val = static_cast<int>(ipc::parseNum(json, i));
                    if (sk == "a") sig.hasAtomics = val != 0;
                    else if (sk == "s") sig.hasSyncPrims = val != 0;
                    else if (sk == "o") sig.hasSharedOwner = val != 0;
                    else if (sk == "v") sig.hasVolatile = val != 0;
                    else if (sk == "p") sig.hasPublication = val != 0;
                    else if (sk == "tw") sig.hasThreadWriters = val != 0;
                    else if (sk == "gi") sig.hasGlobalInstance = val != 0;
                    else if (sk == "tb") sig.hasThreadBorneWriter = val != 0;
                    else if (sk == "sw") sig.hasStandingWrites = val != 0;
                    else if (sk == "l") sig.hasDeliberateLayout = val != 0;
                    else if (sk == "n") sig.accessorCount = static_cast<unsigned>(val);
                    else if (sk == "ra") sig.recordAlignBytes = static_cast<uint64_t>(val);
                    else if (sk == "dl") sig.declLine = static_cast<unsigned>(val);
                    ipc::expect(json, i, ',');
                }
                out.escapeSummary[typeName].merge(sig);
                ipc::expect(json, i, ',');
            }
        } else if (key == "threadRoles") {
            auto parseStrArray = [&](std::set<std::string> &dst) {
                ipc::expect(json, i, '[');
                while (true) {
                    ipc::skipWS(json, i);
                    if (i >= json.size() || json[i] == ']') {
                        if (i < json.size()) ++i;
                        break;
                    }
                    dst.insert(ipc::parseStr(json, i));
                    ipc::expect(json, i, ',');
                }
            };
            auto parseNameSets =
                [&](std::map<std::string, std::set<std::string>> &dst) {
                    ipc::expect(json, i, '{');
                    while (true) {
                        ipc::skipWS(json, i);
                        if (i >= json.size() || json[i] == '}') {
                            if (i < json.size()) ++i;
                            break;
                        }
                        std::string k = ipc::parseStr(json, i);
                        ipc::expect(json, i, ':');
                        parseStrArray(dst[k]);
                        ipc::expect(json, i, ',');
                    }
                };
            ipc::expect(json, i, '{');
            while (true) {
                ipc::skipWS(json, i);
                if (i >= json.size() || json[i] == '}') {
                    if (i < json.size()) ++i;
                    break;
                }
                std::string tk = ipc::parseStr(json, i);
                ipc::expect(json, i, ':');
                if (tk == "entries")
                    parseStrArray(out.threadRoles.threadEntries);
                else if (tk == "edges")
                    parseNameSets(out.threadRoles.callEdges);
                else if (tk == "fieldWriters")
                    parseNameSets(out.threadRoles.fieldWriters);
                else if (tk == "fieldReaders")
                    parseNameSets(out.threadRoles.fieldReaders);
                else if (tk == "fieldWriteSites")
                    parseNameSets(out.threadRoles.fieldWriteSites);
                else if (tk == "fieldAccess") {
                    // Positional count vectors rather than named members: the
                    // key set is every touched field in the program and the
                    // tag overhead would dominate the payload. Consumed to
                    // whatever length arrived, so a shard built from an
                    // older or newer source contributes what it has instead
                    // of failing to parse.
                    ipc::expect(json, i, '{');
                    while (true) {
                        ipc::skipWS(json, i);
                        if (i >= json.size() || json[i] == '}') {
                            if (i < json.size()) ++i;
                            break;
                        }
                        const std::string k = ipc::parseStr(json, i);
                        ipc::expect(json, i, ':');
                        ipc::expect(json, i, '[');
                        std::vector<unsigned> v;
                        while (true) {
                            ipc::skipWS(json, i);
                            if (i >= json.size() || json[i] == ']') break;
                            v.push_back(
                                static_cast<unsigned>(ipc::parseNum(json, i)));
                            ipc::skipWS(json, i);
                            if (i < json.size() && json[i] == ',') ++i;
                        }
                        if (i < json.size() && json[i] == ']') ++i;
                        const auto at = [&](size_t n) {
                            return n < v.size() ? v[n] : 0u;
                        };
                        auto &fa = out.threadRoles.fieldAccess[k];
                        fa.writeSites += at(0);
                        fa.loopWriteSites += at(1);
                        fa.standingWriteSites += at(2);
                        fa.handedWriteSites += at(3);
                        fa.readSites += at(4);
                        fa.standingReadSites += at(5);
                        fa.handedReadSites += at(6);
                        ipc::skipWS(json, i);
                        if (i < json.size() && json[i] == ',') ++i;
                    }
                } else if (tk == "allocOf")
                    parseNameSets(out.threadRoles.allocatorsOfType);
                else if (tk == "freeOf")
                    parseNameSets(out.threadRoles.freersOfType);
                else if (tk == "retFwd")
                    parseNameSets(out.threadRoles.returnForwards);
                else if (tk == "parFwd")
                    parseNameSets(out.threadRoles.paramForwards);
                else if (tk == "allocSites")
                    parseNameSets(out.threadRoles.allocSitesByCallee);
                else if (tk == "freeSites")
                    parseNameSets(out.threadRoles.freeSitesByCallee);
                else if (tk == "overridden")
                    parseStrArray(out.threadRoles.overriddenVirtuals);
                else if (tk == "atomicTypes")
                    parseStrArray(out.threadRoles.atomicTypes);
                else if (tk == "strictParFwd")
                    parseNameSets(out.threadRoles.strictParamForwards);
                else if (tk == "spinAcq")
                    parseNameSets(out.threadRoles.spinAcquireOfType);
                else if (tk == "spinRel")
                    parseNameSets(out.threadRoles.spinReleaseOfType);
                else if (tk == "declLock")
                    parseStrArray(out.threadRoles.declaredLocks);
                else if (tk == "declUnlock")
                    parseStrArray(out.threadRoles.declaredUnlocks);
                else if (tk == "declAlloc")
                    parseStrArray(out.threadRoles.declaredAllocators);
                else if (tk == "declFree")
                    parseStrArray(out.threadRoles.declaredFreers);
                else if (tk == "defined")
                    parseStrArray(out.threadRoles.definedFunctions);
                else if (tk == "builtins")
                    parseStrArray(out.threadRoles.builtinCallees);
                else if (tk == "edgeDepth") {
                    ipc::expect(json, i, '{');
                    while (true) {
                        ipc::skipWS(json, i);
                        if (i >= json.size() || json[i] == '}') {
                            if (i < json.size()) ++i;
                            break;
                        }
                        std::string caller = ipc::parseStr(json, i);
                        ipc::expect(json, i, ':');
                        auto &dst = out.threadRoles.edgeLoopDepth[caller];
                        ipc::expect(json, i, '{');
                        while (true) {
                            ipc::skipWS(json, i);
                            if (i >= json.size() || json[i] == '}') {
                                if (i < json.size()) ++i;
                                break;
                            }
                            std::string callee = ipc::parseStr(json, i);
                            ipc::expect(json, i, ':');
                            dst[callee] =
                                static_cast<unsigned>(ipc::parseNum(json, i));
                            ipc::expect(json, i, ',');
                        }
                        ipc::expect(json, i, ',');
                    }
                } else if (tk == "edgeFreq") {
                    ipc::expect(json, i, '{');
                    while (true) {
                        ipc::skipWS(json, i);
                        if (i >= json.size() || json[i] == '}') {
                            if (i < json.size()) ++i;
                            break;
                        }
                        std::string caller = ipc::parseStr(json, i);
                        ipc::expect(json, i, ':');
                        auto &dst = out.threadRoles.edgeFrequency[caller];
                        ipc::expect(json, i, '{');
                        while (true) {
                            ipc::skipWS(json, i);
                            if (i >= json.size() || json[i] == '}') {
                                if (i < json.size()) ++i;
                                break;
                            }
                            std::string callee = ipc::parseStr(json, i);
                            ipc::expect(json, i, ':');
                            const Milli f =
                                static_cast<Milli>(ipc::parseNum(json, i));
                            auto &cur = dst[callee];
                            if (f > cur) cur = f;
                            ipc::expect(json, i, ',');
                        }
                        ipc::expect(json, i, ',');
                    }
                } else if (tk == "ownFreq") {
                    ipc::expect(json, i, '{');
                    while (true) {
                        ipc::skipWS(json, i);
                        if (i >= json.size() || json[i] == '}') {
                            if (i < json.size()) ++i;
                            break;
                        }
                        std::string fn = ipc::parseStr(json, i);
                        ipc::expect(json, i, ':');
                        const Milli f =
                            static_cast<Milli>(ipc::parseNum(json, i));
                        auto &cur = out.threadRoles.ownFrequency[fn];
                        if (f > cur) cur = f;
                        ipc::expect(json, i, ',');
                    }
                } else if (tk == "ownDepth") {
                    ipc::expect(json, i, '{');
                    while (true) {
                        ipc::skipWS(json, i);
                        if (i >= json.size() || json[i] == '}') {
                            if (i < json.size()) ++i;
                            break;
                        }
                        std::string fn = ipc::parseStr(json, i);
                        ipc::expect(json, i, ':');
                        out.threadRoles.ownLoopDepth[fn] =
                            static_cast<unsigned>(ipc::parseNum(json, i));
                        ipc::expect(json, i, ',');
                    }
                } else
                    ipc::skipValue(json, i);
                ipc::expect(json, i, ',');
            }
        } else if (key == "striped") {
            ipc::expect(json, i, '{');
            while (true) {
                ipc::skipWS(json, i);
                if (i >= json.size() || json[i] == '}') {
                    if (i < json.size()) ++i;
                    break;
                }
                std::string k = ipc::parseStr(json, i);
                ipc::expect(json, i, ':');
                ipc::expect(json, i, '{');
                StripedArraySite a;
                a.key = k;
                while (true) {
                    ipc::skipWS(json, i);
                    if (i >= json.size() || json[i] == '}') {
                        if (i < json.size()) ++i;
                        break;
                    }
                    std::string f = ipc::parseStr(json, i);
                    ipc::expect(json, i, ':');
                    auto strArray = [&](std::set<std::string> &dst) {
                        ipc::expect(json, i, '[');
                        while (true) {
                            ipc::skipWS(json, i);
                            if (i >= json.size() || json[i] == ']') {
                                if (i < json.size()) ++i;
                                break;
                            }
                            dst.insert(ipc::parseStr(json, i));
                            ipc::expect(json, i, ',');
                        }
                    };
                    if (f == "n") a.displayName = ipc::parseStr(json, i);
                    else if (f == "t") a.typeName = ipc::parseStr(json, i);
                    else if (f == "f") a.file = ipc::parseStr(json, i);
                    else if (f == "w") strArray(a.stripedWriters);
                    else if (f == "ag") strArray(a.aggregators);
                    else {
                        auto v = static_cast<uint64_t>(ipc::parseNum(json, i));
                        if (f == "l") a.line = static_cast<unsigned>(v);
                        else if (f == "es") a.elemSizeBytes = v;
                        else if (f == "ec") a.elemCount = v;
                        else if (f == "al") a.declAlignBytes = v;
                        else if (f == "at") a.elementIsAtomic = v != 0;
                        else if (f == "vo") a.elementIsVolatile = v != 0;
                        else if (f == "st") a.isFileStatic = v != 0;
                        else if (f == "tls") a.tlsIndexed = v != 0;
                        else if (f == "ho") a.indexIsHandedOver = v != 0;
                        else if (f == "oi") a.indexIsOwnIdentity = v != 0;
                        else if (f == "hp") a.hasHeadPaddingOffset = v != 0;
                        else if (f == "wt") a.writerTier =
                            static_cast<uint8_t>(v);
                        else if (f == "agt") a.aggregatorTier =
                            static_cast<uint8_t>(v);
                    }
                    ipc::expect(json, i, ',');
                }
                auto it = out.striped.find(k);
                if (it == out.striped.end()) out.striped.emplace(k, std::move(a));
                else it->second.merge(a);
                ipc::expect(json, i, ',');
            }
        } else if (key == "cov") {
            ipc::expect(json, i, '{');
            while (true) {
                ipc::skipWS(json, i);
                if (i >= json.size() || json[i] == '}') {
                    if (i < json.size()) ++i;
                    break;
                }
                std::string k = ipc::parseStr(json, i);
                ipc::expect(json, i, ':');
                auto v = static_cast<uint64_t>(ipc::parseNum(json, i));
                if (k == "fs")      out.coverage.functionsSeen = v;
                else if (k == "fh") out.coverage.functionsHot = v;
                else if (k == "rs") out.coverage.recordsSeen = v;
                ipc::expect(json, i, ',');
            }
        } else {
            ipc::skipValue(json, i);
        }
        ipc::expect(json, i, ',');
    }
    return true;
}

} // namespace lshaz
