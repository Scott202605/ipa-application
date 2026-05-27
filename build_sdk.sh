#!/bin/bash
# Build IPA SDK Script

set -e

SDK_DIR="${1:-/workspace/ipa_sdk_pc}"
BUILD_TYPE="${2:-Release}"
BUILD_DIR="${SDK_DIR}/build"

echo "========================================="
echo "Building IPA SDK"
echo "========================================="
echo "SDK Directory: ${SDK_DIR}"
echo "Build Type: ${BUILD_TYPE}"
echo "Build Directory: ${BUILD_DIR}"
echo ""

# Clean previous build
if [ -d "${BUILD_DIR}" ]; then
    echo "Cleaning previous build..."
    rm -rf "${BUILD_DIR}"
fi

# Create build directory
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

# Run CMake
echo "Running CMake..."
cmake -DCMAKE_BUILD_TYPE=${BUILD_TYPE} ..

# Build
echo "Building SDK..."
make -j$(nproc)

# Install to local directory
echo ""
echo "Installing SDK to ${SDK_DIR}/dist..."
make install DESTDIR="${SDK_DIR}/dist" || {
    echo "No install target, copying files manually..."
    mkdir -p "${SDK_DIR}/dist/include"
    mkdir -p "${SDK_DIR}/dist/lib"
    
    # Copy headers
    cp -r "${SDK_DIR}/include/"* "${SDK_DIR}/dist/include/" 2>/dev/null || true
    
    # Copy libraries
    find "${BUILD_DIR}" -name "*.a" -o -name "*.so" | xargs cp -t "${SDK_DIR}/dist/lib/" 2>/dev/null || true
    cp "${BUILD_DIR}"/*.a "${SDK_DIR}/dist/lib/" 2>/dev/null || true
    cp "${BUILD_DIR}"/*.so "${SDK_DIR}/dist/lib/" 2>/dev/null || true
}

echo ""
echo "========================================="
echo "Build completed successfully!"
echo "========================================="
echo "SDK Library: ${SDK_DIR}/dist/lib/"
echo "SDK Headers: ${SDK_DIR}/dist/include/"
