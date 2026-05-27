#!/bin/bash
# Build IPA Host Application with SDK

set -e

PROJECT_ROOT="/workspace"
SDK_DIR="${PROJECT_ROOT}/ipa_sdk_pc"
HOST_APP_DIR="${PROJECT_ROOT}/ipad_host_app"
BUILD_DIR="${HOST_APP_DIR}/build"

echo "=================================================="
echo "IPA Host Application - Build Script"
echo "=================================================="
echo ""

# Step 1: Build SDK
echo "[Step 1/3] Building IPA SDK..."
"${PROJECT_ROOT}/build_sdk.sh" "${SDK_DIR}" "Release"
echo ""

# Step 2: Install SDK dependencies
echo "[Step 2/3] Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y -qq libgtk-3-dev libcurl4-openssl-dev libssl-dev pkg-config > /dev/null 2>&1 || {
    echo "Warning: Could not install dependencies automatically"
    echo "Please install manually:"
    echo "  sudo apt-get install libgtk-3-dev libcurl4-openssl-dev libssl-dev pkg-config"
}
echo ""

# Step 3: Build host application
echo "[Step 3/3] Building IPA Host Application..."
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

cmake -DCMAKE_BUILD_TYPE=Release \
      -DIPAD_SDK_ROOT="${SDK_DIR}/dist" \
      ..

make -j$(nproc)

echo ""
echo "=================================================="
echo "Build completed successfully!"
echo "=================================================="
echo "Executable: ${BUILD_DIR}/ipad_host_app"
echo ""
echo "To run:"
echo "  cd ${BUILD_DIR}"
echo "  ./ipad_host_app"
echo ""
