// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <clang/AST/Type.h>

namespace lshaz {

// Strip array extents down to the element type.
//
// `_Atomic uint64_t c[N]` has field type ArrayType(element), so a predicate
// inspecting the field type sees an array and not an atomic. Arrays of
// atomics are the dominant striped-counter shape, so atomic, sync and
// volatile detection all have to peel first.
inline clang::QualType peelArrays(clang::QualType QT) {
    while (const clang::ArrayType *AT = QT->getAsArrayTypeUnsafe())
        QT = AT->getElementType();
    return QT;
}

} // namespace lshaz
