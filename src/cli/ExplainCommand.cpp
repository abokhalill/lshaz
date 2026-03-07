#include "lshaz/core/RuleRegistry.h"
#include "lshaz/core/Severity.h"

#include <llvm/Support/raw_ostream.h>

#include <cstring>

namespace lshaz {

int runExplainCommand(int argc, const char **argv) {
    const auto &rules = RuleRegistry::instance().rules();

    if (argc < 1 || (argc == 1 && std::strcmp(argv[0], "--help") == 0)) {
        llvm::errs() << "Usage: lshaz explain <rule-id>\n"
                     << "       lshaz explain --list\n"
                     << "\n"
                     << "Show detailed documentation for a diagnostic rule.\n";
        return 0;
    }

    if (std::strcmp(argv[0], "--list") == 0) {
        llvm::outs() << "Available rules:\n\n";
        for (const auto &r : rules) {
            llvm::outs() << "  " << r->getID() << "  "
                         << r->getTitle() << "  ["
                         << severityToString(r->getBaseSeverity()) << "]\n";
        }
        return 0;
    }

    const char *id = argv[0];
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
