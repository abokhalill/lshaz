// SPDX-License-Identifier: Apache-2.0
#include "lshaz/analysis/contention.h"

namespace lshaz {

std::set<std::string> ContentionNode::writers() const {
    std::set<std::string> out;
    for (const auto &r : residents)
        out.insert(r.writers.begin(), r.writers.end());
    return out;
}

std::set<std::string> ContentionNode::readers() const {
    std::set<std::string> out;
    for (const auto &r : residents)
        out.insert(r.readers.begin(), r.readers.end());
    return out;
}

std::vector<const ContentionNode::Resident *> ContentionNode::active() const {
    std::vector<const Resident *> out;
    for (const auto &r : residents)
        if (r.written() || r.read())
            out.push_back(&r);
    return out;
}

unsigned ContentionNode::writtenFields() const {
    unsigned n = 0;
    for (const auto &r : residents)
        if (r.written()) ++n;
    return n;
}

bool ContentionNode::anyAtomic() const {
    for (const auto &r : residents)
        if (r.isAtomic) return true;
    return false;
}

const ContentionNode *ContentionGraph::find(const std::string &owner,
                                            uint64_t lineIndex) const {
    auto it = nodes.find({owner, lineIndex});
    return it == nodes.end() ? nullptr : &it->second;
}

ContentionGraph buildContentionGraph(const EscapeSummary &escape,
                                     const ThreadRoleSummary &facts,
                                     uint64_t lineBytes) {
    ContentionGraph g;
    if (lineBytes == 0)
        return g;

    for (const auto &[typeName, sig] : escape) {
        if (sig.fieldExtents.empty())
            continue;

        for (const auto &[fieldName, ext] : sig.fieldExtents) {
            // A field of unknown size cannot be placed on a line. Two TUs
            // disagreeing about its size is the case, and guessing which one
            // was right would put traffic on a line the program does not
            // have.
            if (ext.sizeBytes == 0)
                continue;

            const std::string key = typeName + "::" + fieldName;
            ContentionNode::Resident r;
            r.field = fieldName;
            r.offsetBytes = ext.offsetBytes;
            r.sizeBytes = ext.sizeBytes;
            r.isAtomic = ext.isAtomic;
            r.plainScalar = ext.plainScalar;
            r.declLine = ext.declLine;
            if (auto w = facts.fieldWriters.find(key);
                w != facts.fieldWriters.end())
                r.writers = w->second;
            if (auto rd = facts.fieldReaders.find(key);
                rd != facts.fieldReaders.end())
                r.readers = rd->second;
            if (auto ws = facts.fieldWriteSites.find(key);
                ws != facts.fieldWriteSites.end())
                r.writeSites = ws->second;
            if (auto a = facts.fieldAccess.find(key);
                a != facts.fieldAccess.end())
                r.access = a->second;

            // A field wider than a line lands on several, and every one of
            // them carries its traffic: a store anywhere in it invalidates
            // whichever line it fell on, and a reader of a neighbour on any
            // of those lines pays.
            const uint64_t first = ext.offsetBytes / lineBytes;
            const uint64_t last =
                (ext.offsetBytes + ext.sizeBytes - 1) / lineBytes;
            for (uint64_t line = first; line <= last; ++line) {
                auto &node = g.nodes[{typeName, line}];
                if (node.owner.empty()) {
                    node.owner = typeName;
                    node.lineIndex = line;
                    node.declFile = sig.declFile;
                    node.declLine = sig.declLine;
                    ++g.linesConsidered;
                }
                node.residents.push_back(r);
            }
        }
    }

    for (const auto &[k, node] : g.nodes) {
        (void)k;
        if (!node.writers().empty() || !node.readers().empty())
            ++g.linesWithTraffic;
    }
    return g;
}

} // namespace lshaz
