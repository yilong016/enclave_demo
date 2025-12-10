#!/bin/bash

# Enclave 停止脚本
# 停止运行中的 Nitro Enclave

set -e

echo "正在查找运行中的 Enclave..."

# 获取所有运行中的 Enclave
ENCLAVES=$(nitro-cli describe-enclaves 2>/dev/null)

if [ -z "$ENCLAVES" ] || [ "$ENCLAVES" == "[]" ]; then
    echo "没有运行中的 Enclave"
    exit 0
fi

echo "运行中的 Enclave:"
echo "$ENCLAVES"
echo ""

# 提取所有 Enclave ID
ENCLAVE_IDS=$(echo "$ENCLAVES" | grep -oP '"EnclaveID":\s*"\K[^"]+' || echo "")

if [ -z "$ENCLAVE_IDS" ]; then
    echo "没有找到 Enclave ID"
    exit 0
fi

# 停止所有 Enclave
for ENCLAVE_ID in $ENCLAVE_IDS; do
    echo "正在停止 Enclave: $ENCLAVE_ID"
    nitro-cli terminate-enclave --enclave-id "$ENCLAVE_ID"
    echo "Enclave $ENCLAVE_ID 已停止"
done

# 清理 CID 文件
if [ -f "enclave_cid.txt" ]; then
    rm enclave_cid.txt
    echo "已清理 enclave_cid.txt"
fi

echo ""
echo "所有 Enclave 已停止"
