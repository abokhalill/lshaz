// Cross-TU read/write line sharing. The store and the read compile apart, so
// no single TU holds both halves and a per-TU field-evidence gate cannot
// express the pair. The shape is a dispatch table whose call counter is
// incremented in one file while the lookup path reads neighbouring fields on
// the same line from another.
#ifndef CANARY_XTU_H
#define CANARY_XTU_H

typedef struct {
    unsigned long key_spec_a;
    unsigned long key_spec_b;
    unsigned long key_spec_c;
    unsigned long calls;
} canary_xtu_cmd;

extern canary_xtu_cmd canary_xtu_table[4];

#ifdef __cplusplus
extern "C" {
#endif
unsigned long canary_xtu_lookup(int slot);
#ifdef __cplusplus
}
#endif

#endif
