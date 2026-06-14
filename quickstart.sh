#!/bin/bash
# IPA 上位机程序 - 快速启动脚本

echo "=================================================="
echo "IPA 上位机程序 - 快速启动"
echo "=================================================="
echo ""

WORKSPACE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_DIR="${WORKSPACE}/ipa_sdk_pc"
HOST_APP_DIR="${WORKSPACE}/ipad_host_app"

# 检查依赖
check_dependencies() {
    echo "[检查] 系统依赖..."
    
    MISSING_DEPS=()

    if ! command -v gcc >/dev/null 2>&1 || ! command -v make >/dev/null 2>&1; then
        MISSING_DEPS+=("build-essential")
    fi

    if ! command -v cmake >/dev/null 2>&1; then
        MISSING_DEPS+=("cmake")
    fi

    if ! command -v pkg-config >/dev/null 2>&1; then
        MISSING_DEPS+=("pkg-config")
    fi
    
    # 检查 GTK3
    if ! pkg-config --exists gtk+-3.0 2>/dev/null; then
        MISSING_DEPS+=("libgtk-3-dev")
    fi
    
    # 检查 libcurl
    if ! pkg-config --exists libcurl 2>/dev/null; then
        MISSING_DEPS+=("libcurl4-openssl-dev")
    fi
    
    # 检查 OpenSSL
    if ! pkg-config --exists openssl 2>/dev/null; then
        MISSING_DEPS+=("libssl-dev")
    fi

    if ! pkg-config --exists libserialport 2>/dev/null; then
        MISSING_DEPS+=("libserialport-dev")
    fi

    if ! ldconfig -p 2>/dev/null | grep -q "libpaho-mqtt3cs"; then
        MISSING_DEPS+=("libpaho-mqtt-dev")
    fi
    
    if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
        echo "缺少以下依赖:"
        printf '  • %s\n' "${MISSING_DEPS[@]}"
        echo ""
        if command -v apt-get >/dev/null 2>&1; then
            echo "正在安装依赖..."
            SUDO=""
            if [ "$(id -u)" -ne 0 ]; then
                SUDO="sudo"
            fi
            ${SUDO} apt-get update -qq
            if ${SUDO} apt-get install -y -qq "${MISSING_DEPS[@]}"; then
                echo "✓ 依赖安装成功"
            else
                echo "✗ 依赖安装失败，请手动安装"
                exit 1
            fi
        else
            echo "✗ 当前系统未检测到 apt-get，请手动安装上述依赖"
            exit 1
        fi
    else
        echo "✓ 所有依赖已满足"
    fi
    echo ""
}

# 编译 SDK
build_sdk() {
    echo "[1/3] 编译 IPAd SDK..."
    
    if [ ! -d "${SDK_DIR}/build" ] ||
       { [ ! -f "${SDK_DIR}/build/ipa-src/hw/linux/libipa.so" ] &&
         [ ! -f "${SDK_DIR}/build/ipa-src/hw/linux/libipa.a" ]; }; then
        cd "${WORKSPACE}"
        ./build_sdk.sh
        if [ $? -ne 0 ]; then
            echo "✗ SDK 编译失败"
            exit 1
        fi
    else
        echo "✓ SDK 已编译，跳过"
    fi
    echo ""
}

# 编译上位机程序
build_host_app() {
    echo "[2/3] 编译 IPA 上位机程序..."
    
    if [ ! -f "${HOST_APP_DIR}/build/ipad_host_app" ]; then
        cd "${HOST_APP_DIR}"
        mkdir -p build && cd build
        
        cmake -DCMAKE_BUILD_TYPE=Release -DIPAD_SDK_ROOT="${SDK_DIR}" ..
        if [ $? -ne 0 ]; then
            echo "✗ CMake 配置失败"
            exit 1
        fi
        
        make -j$(nproc)
        if [ $? -ne 0 ]; then
            echo "✗ 编译失败"
            exit 1
        fi
        echo "✓ 编译成功"
    else
        echo "✓ 上位机程序已编译，跳过"
    fi
    echo ""
}

# 启动程序
run_app() {
    echo "[3/3] 启动 IPA 上位机程序..."
    echo ""
    
    cd "${HOST_APP_DIR}/build"
    
    # 设置库路径
    export LD_LIBRARY_PATH="${SDK_DIR}/dist/lib:${SDK_DIR}/build/ipa-src/hw/linux:${LD_LIBRARY_PATH}"
    
    echo "=================================================="
    echo "IPA 上位机程序启动成功!"
    echo ""
    echo "程序路径：${HOST_APP_DIR}/build/ipad_host_app"
    echo "库路径：${LD_LIBRARY_PATH}"
    echo "=================================================="
    echo ""
    
    # 运行
    ./ipad_host_app
}

# 主流程
check_dependencies
build_sdk
build_host_app
run_app

