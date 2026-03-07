#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

# lshaz installer
# Usage: curl -sL <url>/install.sh | bash
#
# Installs lshaz by building from source. Requires:
#   - Linux x86-64
#   - LLVM/Clang 16+ development libraries
#   - CMake 3.20+
#   - C++20 compiler

REPO="https://github.com/abokhalill/lshaz.git"
INSTALL_DIR="${LSHAZ_INSTALL_DIR:-$HOME/.local/bin}"
BUILD_TYPE="${LSHAZ_BUILD_TYPE:-Release}"

die() { echo "lshaz-install: error: $*" >&2; exit 1; }
info() { echo "lshaz-install: $*" >&2; }

# Check platform.
ARCH="$(uname -m)"
OS="$(uname -s)"
[[ "$OS" == "Linux" ]] || die "unsupported OS: $OS (Linux required)"
[[ "$ARCH" == "x86_64" ]] || die "unsupported architecture: $ARCH (x86-64 required)"

# Check dependencies.
command -v cmake >/dev/null 2>&1 || die "cmake not found"
command -v git   >/dev/null 2>&1 || die "git not found"

# Detect LLVM.
LLVM_PREFIX=""
for v in 18 17 16; do
    if [ -d "/usr/lib/llvm-${v}" ]; then
        LLVM_PREFIX="/usr/lib/llvm-${v}"
        break
    fi
done
if [ -z "$LLVM_PREFIX" ]; then
    # Try generic llvm-config.
    if command -v llvm-config >/dev/null 2>&1; then
        LLVM_PREFIX="$(llvm-config --prefix)"
    else
        die "LLVM development libraries not found. Install llvm-18-dev libclang-18-dev clang-18"
    fi
fi
info "using LLVM at $LLVM_PREFIX"

# Clone into temp directory.
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

info "cloning lshaz..."
git clone --depth 1 "$REPO" "$TMPDIR/lshaz" > "$TMPDIR/clone.log" 2>&1 \
    || { cat "$TMPDIR/clone.log"; die "clone failed"; }

# Build.
info "building (${BUILD_TYPE})..."
cmake -S "$TMPDIR/lshaz" -B "$TMPDIR/lshaz/build" \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DCMAKE_PREFIX_PATH="$LLVM_PREFIX" \
    > "$TMPDIR/cmake.log" 2>&1 \
    || { cat "$TMPDIR/cmake.log"; die "cmake configure failed"; }

cmake --build "$TMPDIR/lshaz/build" -j"$(nproc)" \
    > "$TMPDIR/build.log" 2>&1 \
    || { tail -20 "$TMPDIR/build.log"; die "build failed"; }

# Verify.
"$TMPDIR/lshaz/build/lshaz" --version >/dev/null 2>&1 \
    || die "built binary does not execute"

# Run contract tests.
info "running contract tests..."
"$TMPDIR/lshaz/build/output_contract_test" \
    > "$TMPDIR/test.log" 2>&1 \
    || { cat "$TMPDIR/test.log"; die "contract tests failed"; }

# Install.
mkdir -p "$INSTALL_DIR"
cp "$TMPDIR/lshaz/build/lshaz" "$INSTALL_DIR/lshaz"
chmod +x "$INSTALL_DIR/lshaz"

info "installed to $INSTALL_DIR/lshaz"

# Check PATH.
if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
    info ""
    info "  $INSTALL_DIR is not in your PATH."
    info "  Add to your shell profile:"
    info "    export PATH=\"$INSTALL_DIR:\$PATH\""
fi

info ""
info "done. Run: lshaz scan <project-path>"
