#!/bin/bash

# Enclave 镜像构建脚本
# 构建 Docker 镜像并转换为 EIF 格式

set -e

DOCKER_IMAGE_NAME="enclave-app"
DOCKER_TAG="latest"
EIF_FILE="enclave.eif"

echo "正在构建 Enclave Docker 镜像..."

# 构建 Docker 镜像
docker build -t "${DOCKER_IMAGE_NAME}:${DOCKER_TAG}" ./enclave

if [ $? -ne 0 ]; then
    echo "错误: Docker 镜像构建失败"
    exit 1
fi

echo "Docker 镜像构建成功: ${DOCKER_IMAGE_NAME}:${DOCKER_TAG}"

# 转换为 EIF 格式
echo "正在转换为 EIF 格式..."
nitro-cli build-enclave \
    --docker-uri "${DOCKER_IMAGE_NAME}:${DOCKER_TAG}" \
    --output-file "$EIF_FILE"

if [ $? -ne 0 ]; then
    echo "错误: EIF 文件生成失败"
    exit 1
fi

echo "EIF 文件生成成功: $EIF_FILE"

# 显示 EIF 信息
echo ""
echo "==================================="
echo "Enclave 镜像信息:"
nitro-cli describe-eif --eif-path "$EIF_FILE"
echo "==================================="

# 提取 PCR0 哈希值
PCR0=$(nitro-cli describe-eif --eif-path "$EIF_FILE" 2>/dev/null | grep -oP '"PCR0":\s*"\K[^"]+' || echo "")
if [ -n "$PCR0" ]; then
    echo ""
    echo "PCR0 哈希值: $PCR0"
    echo "$PCR0" > enclave_pcr0.txt
    echo "PCR0 已保存到 enclave_pcr0.txt"
fi

echo ""
echo "构建完成！可以使用 ./scripts/start_enclave.sh 启动 Enclave"
