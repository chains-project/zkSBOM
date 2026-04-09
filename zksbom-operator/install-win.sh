#!/bin/bash
#
# install-windows.sh - Build zksbom-operator on Windows (Git Bash)
#
# Prerequisites:
#   - Git (with Git Bash)
#   - Visual Studio 2022 with C++ workload
#   - CMake (3.13+)
#   - Rust toolchain (rustup + cargo)
#   - LLVM (for bindgen/libclang) - install via:
#       winget install LLVM.LLVM
#     or download from https://github.com/llvm/llvm-project/releases
#   - vcpkg (git clone https://github.com/microsoft/vcpkg && ./vcpkg/bootstrap-vcpkg.bat)
#
# Environment variables you can set before running:
#
#   VCPKG_ROOT           Path to your vcpkg installation.
#                        Will be prompted if not set.
#
#   LIBCLANG_PATH        Path to directory containing libclang.dll.
#                        Auto-detected from "C:/Program Files/LLVM/bin" if not set.
#                        Install LLVM if missing (see prerequisites above).
#
#   VCPKG_TARGET_TRIPLET vcpkg triplet to use.
#                        Default: x64-windows-static-md
#                        IMPORTANT: Must use "x64-windows-static-md" (not "x64-windows-static").
#                        The "-md" variant uses the dynamic CRT (/MD) which matches Rust's
#                        default MSVC CRT linkage. Using "x64-windows-static" causes linker
#                        errors due to CRT mismatch (/MT vs /MD).
#
#   CMAKE_GENERATOR      CMake generator to use.
#                        Default: "Visual Studio 17 2022"
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "=========================================="
echo " zksbom-operator Windows Build"
echo "=========================================="
echo ""

# -- 1. Check LIBCLANG_PATH (required by bindgen) ----------------------------
if [ -z "$LIBCLANG_PATH" ]; then
    # Auto-detect: try Git Bash path (/c/...) and WSL path (/mnt/c/...)
    if [ -f "/c/Program Files/LLVM/bin/libclang.dll" ]; then
        export LIBCLANG_PATH="C:/Program Files/LLVM/bin"
        echo "[OK] Auto-detected LIBCLANG_PATH: $LIBCLANG_PATH"
    elif [ -f "/mnt/c/Program Files/LLVM/bin/libclang.dll" ]; then
        export LIBCLANG_PATH="C:/Program Files/LLVM/bin"
        echo "[OK] Auto-detected LIBCLANG_PATH: $LIBCLANG_PATH"
    else
        echo "[ERROR] LLVM not found. bindgen requires libclang.dll."
        echo ""
        echo "  Install LLVM:  winget install LLVM.LLVM"
        echo "  Or download:   https://github.com/llvm/llvm-project/releases"
        echo ""
        echo "  Then either:"
        echo "    - Re-run this script (it will auto-detect), or"
        echo "    - Set LIBCLANG_PATH manually:"
        echo '        export LIBCLANG_PATH="C:/Program Files/LLVM/bin"'
        exit 1
    fi
else
    # Validate the provided path actually contains libclang.dll
    # Convert backslashes to forward slashes for the test
    LIBCLANG_TEST="${LIBCLANG_PATH//\\//}"
    if [ ! -f "$LIBCLANG_TEST/libclang.dll" ]; then
        echo "[WARNING] LIBCLANG_PATH is set to: $LIBCLANG_PATH"
        echo "  but libclang.dll was not found there. Trying auto-detect..."
        if [ -f "/c/Program Files/LLVM/bin/libclang.dll" ]; then
            export LIBCLANG_PATH="C:/Program Files/LLVM/bin"
            echo "[OK] Auto-detected LIBCLANG_PATH: $LIBCLANG_PATH"
        elif [ -f "/mnt/c/Program Files/LLVM/bin/libclang.dll" ]; then
            export LIBCLANG_PATH="C:/Program Files/LLVM/bin"
            echo "[OK] Auto-detected LIBCLANG_PATH: $LIBCLANG_PATH"
        else
            echo "[ERROR] Could not find libclang.dll. Install LLVM."
            exit 1
        fi
    else
        echo "[OK] LIBCLANG_PATH: $LIBCLANG_PATH"
    fi
fi

# -- 2. Locate vcpkg ---------------------------------------------------------
if [ -z "$VCPKG_ROOT" ]; then
    echo ""
    echo "Please provide the path to your vcpkg installation"
    echo '  (e.g., C:\Users\yourname\vcpkg or /c/Users/yourname/vcpkg):'
    read -r VCPKG_ROOT
fi

# Normalize path for cmake (use forward slashes)
VCPKG_ROOT="${VCPKG_ROOT//\\//}"

CMAKE_TOOLCHAIN="${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
if [ ! -f "$CMAKE_TOOLCHAIN" ]; then
    echo "[ERROR] vcpkg toolchain not found at: $CMAKE_TOOLCHAIN"
    echo "  Make sure vcpkg is bootstrapped: cd $VCPKG_ROOT && bootstrap-vcpkg.bat"
    exit 1
fi
echo "[OK] vcpkg toolchain: $CMAKE_TOOLCHAIN"

# -- 3. Set triplet -----------------------------------------------------------
# x64-windows-static-md = static libraries + dynamic CRT (/MD)
# This MUST match Rust's CRT linkage. Rust on MSVC defaults to /MD.
# Using x64-windows-static (/MT) causes LNK2038 RuntimeLibrary mismatches.
TRIPLET="${VCPKG_TARGET_TRIPLET:-x64-windows-static-md}"
echo "[OK] vcpkg triplet: $TRIPLET"

if [ "$TRIPLET" = "x64-windows-static" ]; then
    echo ""
    echo "[WARNING] Triplet 'x64-windows-static' uses /MT (static CRT)."
    echo "  Rust uses /MD (dynamic CRT) by default. This will cause linker errors."
    echo "  Recommended: use 'x64-windows-static-md' instead."
    echo ""
fi

# -- 4. Set CMake generator ---------------------------------------------------
GENERATOR="${CMAKE_GENERATOR:-Visual Studio 17 2022}"
echo "[OK] CMake generator: $GENERATOR"

# -- 5. Initialize git submodules ---------------------------------------------
echo ""
if [ ! -d "third_party/oZKS/.git" ] && [ ! -f "third_party/oZKS/.git" ]; then
    echo "Initializing git submodules..."
    git submodule update --init --recursive
    echo "Git submodules initialized."
else
    echo "Git submodules already initialized."
fi

# -- 6. Build oZKS ------------------------------------------------------------
echo ""
echo "=========================================="
echo " Building oZKS (third_party/oZKS)"
echo "=========================================="
echo ""

OZKS_DIR="$SCRIPT_DIR/third_party/oZKS"
cd "$OZKS_DIR"

# Clean previous build if triplet or config changed
if [ -d "build" ]; then
    EXISTING_TRIPLET=""
    if [ -d "build/vcpkg_installed/$TRIPLET" ]; then
        EXISTING_TRIPLET="$TRIPLET"
    fi

    if [ -z "$EXISTING_TRIPLET" ]; then
        echo "Previous build used a different triplet. Cleaning build directory..."
        rm -rf build
    elif [ -d "build/lib/Debug" ] && [ ! -d "build/lib/Release" ]; then
        echo "Previous build was Debug only. Cleaning to rebuild as Release..."
        rm -rf build
    fi
fi

echo "Configuring oZKS..."
cmake -B build \
    -G "$GENERATOR" \
    -DCMAKE_TOOLCHAIN_FILE="$CMAKE_TOOLCHAIN" \
    -DVCPKG_TARGET_TRIPLET="$TRIPLET" \
    -DOZKS_BUILD_EXAMPLES=ON

# IMPORTANT: Must use --config Release with Visual Studio generator.
# VS is a multi-config generator, so CMAKE_BUILD_TYPE is ignored.
# Without --config Release, it defaults to Debug, which uses /MDd
# and _ITERATOR_DEBUG_LEVEL=2, causing mismatches with Rust's /MD.
echo ""
echo "Building oZKS (Release configuration)..."
cmake --build build --config Release

echo ""
echo "[OK] oZKS built successfully."

# -- 7. Build zksbom-operator ----------------------------------------------------------
cd "$SCRIPT_DIR"

echo ""
echo "=========================================="
echo " Building zksbom-operator"
echo "=========================================="
echo ""

cargo build --release

echo ""
echo "=========================================="
echo " Build complete!"
echo "=========================================="
echo ""
echo "Binary: target/release/zksbom-operator.exe"
