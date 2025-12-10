#!/bin/bash

# Enclave 启动脚本
# 启动 Nitro Enclave 并获取 CID

set -e

EIF_FILE="enclave.eif"
ENCLAVE_NAME="enclave-demo"
CPU_COUNT=2
MEMORY_MB=2048

# 检查设备文件
echo "检查 Nitro Enclaves 设备..."
if [ ! -e /dev/nitro_enclaves ]; then
    echo "❌ 错误: /dev/nitro_enclaves 不存在"
    echo ""
    echo "可能的原因:"
    echo "1. 实例未启用 Nitro Enclaves (最常见)"
    echo "2. 实例类型不支持 Nitro Enclaves"
    echo "3. 内核模块未加载"
    echo ""
    echo "解决方法:"
    INSTANCE_ID=$(ec2-metadata --instance-id 2>/dev/null | cut -d ' ' -f 2 || echo "unknown")
    if [ "$INSTANCE_ID" != "unknown" ]; then
        echo "1. 检查实例 Enclave 选项:"
        echo "   aws ec2 describe-instances --instance-ids $INSTANCE_ID --query 'Reservations[0].Instances[0].EnclaveOptions' --region us-east-1"
        echo ""
        echo "2. 如果 Enabled=false，需要停止实例并启用 Enclaves"
        echo "   请参考 setup_environment.sh 中的说明"
    else
        echo "1. 确认实例已启用 Nitro Enclaves"
        echo "2. 确认实例类型支持 Enclaves (如 m6i, c6i, r6i 系列)"
    fi
    exit 1
fi

if [ ! -r /dev/nitro_enclaves ] || [ ! -w /dev/nitro_enclaves ]; then
    echo "❌ 错误: 没有权限访问 /dev/nitro_enclaves"
    echo ""
    echo "请确认:"
    echo "1. 当前用户在 'ne' 组中:"
    echo "   groups | grep ne"
    echo ""
    echo "2. 已重新登录使组权限生效"
    echo "   exit 后重新 SSH 登录"
    exit 1
fi

echo "✓ Nitro Enclaves 设备就绪"
echo ""

# 检查并重启资源分配器
echo "正在检查资源分配器配置..."
ALLOCATOR_CONFIG="/etc/nitro_enclaves/allocator.yaml"

# 确保配置正确
echo "更新资源分配器配置..."
sudo tee "$ALLOCATOR_CONFIG" > /dev/null <<EOF
---
cpu_count: 2
memory_mib: 2048
EOF

echo "当前配置:"
cat "$ALLOCATOR_CONFIG"
echo ""

echo "停止资源分配器服务..."
sudo systemctl stop nitro-enclaves-allocator.service
sleep 1

echo "启动资源分配器服务..."
sudo systemctl start nitro-enclaves-allocator.service
sleep 3

if sudo systemctl is-active --quiet nitro-enclaves-allocator.service; then
    echo "资源分配器服务运行正常"
else
    echo "错误: 资源分配器服务未运行"
    sudo systemctl status nitro-enclaves-allocator.service
    exit 1
fi
echo ""

# 检查 EIF 文件是否存在
if [ ! -f "$EIF_FILE" ]; then
    echo "错误: 未找到 EIF 文件: $EIF_FILE"
    echo "请先运行 ./scripts/build_enclave.sh 构建 Enclave 镜像"
    exit 1
fi

# 检查是否已有运行中的 Enclave
RUNNING_ENCLAVE=$(nitro-cli describe-enclaves 2>/dev/null | grep -oP '"EnclaveID":\s*"\K[^"]+' || echo "")
if [ -n "$RUNNING_ENCLAVE" ]; then
    echo "检测到运行中的 Enclave: $RUNNING_ENCLAVE"
    read -p "是否停止现有 Enclave 并启动新的？(y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "正在停止现有 Enclave..."
        nitro-cli terminate-enclave --enclave-id "$RUNNING_ENCLAVE"
        sleep 2
    else
        echo "取消启动"
        exit 0
    fi
fi

echo "正在启动 Enclave..."
echo "配置: CPU=$CPU_COUNT, 内存=${MEMORY_MB}MB"

# 启动 Enclave
ENCLAVE_OUTPUT=$(nitro-cli run-enclave \
    --eif-path "$EIF_FILE" \
    --cpu-count "$CPU_COUNT" \
    --memory "$MEMORY_MB" \
    --enclave-name "$ENCLAVE_NAME" \
    --debug-mode)

if [ $? -ne 0 ]; then
    echo "错误: Enclave 启动失败"
    echo "$ENCLAVE_OUTPUT"
    exit 1
fi

echo "Enclave 启动成功！"
echo ""
echo "$ENCLAVE_OUTPUT"

# 提取 Enclave ID 和 CID
ENCLAVE_ID=$(echo "$ENCLAVE_OUTPUT" | grep -oP '"EnclaveID":\s*"\K[^"]+' || echo "")
ENCLAVE_CID=$(echo "$ENCLAVE_OUTPUT" | grep -oP '"EnclaveCID":\s*\K[0-9]+' || echo "")

if [ -z "$ENCLAVE_CID" ]; then
    echo "警告: 无法获取 Enclave CID"
    exit 1
fi

# 保存 CID 到文件
echo "$ENCLAVE_CID" > enclave_cid.txt
echo ""
echo "==================================="
echo "Enclave 信息:"
echo "Enclave ID: $ENCLAVE_ID"
echo "Enclave CID: $ENCLAVE_CID"
echo "==================================="
echo ""
echo "CID 已保存到 enclave_cid.txt"
echo ""
echo "查看 Enclave 日志:"
echo "  nitro-cli console --enclave-id $ENCLAVE_ID"
echo ""
echo "停止 Enclave:"
echo "  nitro-cli terminate-enclave --enclave-id $ENCLAVE_ID"
