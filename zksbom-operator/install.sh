#!/bin/bash

set -e

echo

echo "Please provide the path to your vcpkg installation (e.g., /Users/yourname/vcpkg):"
read VCPKG_PATH

CMAKE_TOOLCHAIN="${VCPKG_PATH}/scripts/buildsystems/vcpkg.cmake"

echo "Checking for git submodules..."
if [ ! -d "third_party/oZKS" ] || [ -z "$(ls -A third_party/oZKS 2>/dev/null)" ]; then
    echo "Submodules not initialized. Initializing now..."
    git submodule update --init --recursive
    echo "Git submodules initialized."
else
    echo "Git submodules are already initialized."
fi
echo

if [ ! -f "$CMAKE_TOOLCHAIN" ]; then
    echo "Error: $CMAKE_TOOLCHAIN does not exist."
    exit 1
fi

echo "Using vcpkg toolchain at: $CMAKE_TOOLCHAIN"
echo

# Build oZKS
cd "$(dirname "$0")/third_party/oZKS"

cmake -B build \
  -DCMAKE_TOOLCHAIN_FILE="$CMAKE_TOOLCHAIN" \
  -DOZKS_BUILD_EXAMPLES=ON

cmake --build build

echo "oZKS built successfully."

# Back to zksbom-operator root
cd ../../

# Build zksbom-operator
cargo build --release

echo "zksbom-operator built successfully!"
