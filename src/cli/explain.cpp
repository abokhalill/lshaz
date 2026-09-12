// SPDX-License-Identifier: Apache-2.0
#include "lshaz/core/emitters.h"
#include "lshaz/core/registry.h"
#include "lshaz/core/severity.h"

#include <llvm/Support/raw_ostream.h>

#include <cstring>

namespace lshaz {

int runExplainCommand(int argc, const char **argv) {
    const auto &rules = RuleRegistry::instance().rules();

    // Asking for help is a success on stdout. Being given nothing to explain
    // is a bad invocation on stderr.
    const bool askedForHelp =
        argc >= 1 && (std::strcmp(argv[0], "--help") == 0 ||
                      std::strcmp(argv[0], "-h") == 0);
    if (argc < 1 || askedForHelp) {
        llvm::raw_ostream &o = askedForHelp ? llvm::outs() : llvm::errs();
        o << "Usage: lshaz explain <rule-id>\n"
          << "       lshaz explain --list\n"
          << "\n"
          << "Show detailed documentation for a diagnostic rule.\n";
        return askedForHelp ? 0 : 3;
    }

    if (std::strcmp(argv[0], "--list") == 0) {
        llvm::outs() << "Available rules:\n\n";
        for (const auto &r : rules) {
            llvm::outs() << "  " << r->getID() << "  "
                         << r->getTitle() << "  ["
                         << severityToString(r->getBaseSeverity()) << "]\n";
        }
        // Listed alongside the rules, not in a footnote: a consumer that
        // sees FL004 in its JSON looks here for what it means.
        llvm::outs() << "\nEmitted by the reduce phase or a compiler stream:\n\n";
        for (const auto &d : nonRuleEmitters()) {
            llvm::outs() << "  " << d.id << "  " << d.title << "  ["
                         << severityToString(d.baseSeverity) << "]\n";
        }
        return 0;
    }

    const char *id = argv[0];
    if (const EmitterDoc *e = findEmitterByID(id)) {
        llvm::outs() << e->id << ": " << e->title << "\n"
                     << "Severity: " << severityToString(e->baseSeverity)
                     << "\n\n"
                     << "Hardware Mechanism:\n  " << e->mechanism << "\n";
        return 0;
    }

    const Rule *rule = RuleRegistry::instance().findByID(id);
    if (!rule) {
        llvm::errs() << "lshaz explain: unknown rule '" << id << "'\n"
                     << "Run 'lshaz explain --list' for available rules.\n";
        return 1;
    }

    llvm::outs() << rule->getID() << ": " << rule->getTitle() << "\n"
                 << "Severity: " << severityToString(rule->getBaseSeverity())
                 << "\n\n"
                 << "Hardware Mechanism:\n  " << rule->getHardwareMechanism()
                 << "\n";

    return 0;
}

} // namespace lshaz
