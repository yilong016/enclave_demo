#!/bin/bash

# 环境配置脚本
# 安装和配置 Nitro Enclaves CLI 及相关依赖

set -e

# 切换到项目根目录
cd "$(dirname "$0")/.."

echo "==================================="
echo "开始配置 Enclave 环境"
echo "==================================="
echo ""

# 检查实例是否启用 Nitro Enclaves
echo "步骤 0: 检查 Nitro Enclaves 支持"
echo "-----------------------------------"

INSTANCE_ID=$(ec2-metadata --instance-id 2>/dev/null | cut -d ' ' -f 2 || echo "unknown")
if [ "$INSTANCE_ID" != "unknown" ]; then
    ENCLAVE_ENABLED=$(aws ec2 describe-instances \
        --instance-ids "$INSTANCE_ID" \
        --query 'Reservations[0].Instances[0].EnclaveOptions.Enabled' \
        --output text 2>/dev/null || echo "false")
    
    if [ "$ENCLAVE_ENABLED" != "True" ]; then
        echo "❌ 错误: 实例未启用 Nitro Enclaves"
        echo ""
        echo "请执行以下步骤:"
        echo "1. 停止当前实例:"
        echo "   aws ec2 stop-instances --instance-ids $INSTANCE_ID --region us-east-1"
        echo ""
        echo "2. 等待实例停止:"
        echo "   aws ec2 wait instance-stopped --instance-ids $INSTANCE_ID --region us-east-1"
        echo ""
        echo "3. 启用 Nitro Enclaves:"
        echo "   aws ec2 modify-instance-attribute --instance-id $INSTANCE_ID --enclave-options Enabled=true --region us-east-1"
        echo ""
        echo "4. 启动实例:"
        echo "   aws ec2 start-instances --instance-ids $INSTANCE_ID --region us-east-1"
        echo ""
        echo "5. 重新 SSH 登录后，再次运行此脚本"
        exit 1
    fi
    echo "✓ 实例已启用 Nitro Enclaves (Instance ID: $INSTANCE_ID)"
else
    echo "⚠️  警告: 无法检测实例 ID，跳过 Enclave 启用检查"
fi
echo ""

# 检查操作系统
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
else
    echo "错误: 无法检测操作系统"
    exit 1
fi

echo "检测到操作系统: $OS $VERSION"

# 安装 Nitro Enclaves CLI
echo ""
echo "步骤 1: 安装 Nitro Enclaves CLI"
echo "-----------------------------------"

if [ "$OS" == "amzn" ]; then
    # Amazon Linux 2023
    echo "正在安装 Nitro Enclaves CLI (Amazon Linux)..."
    sudo yum install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel
elif [ "$OS" == "ubuntu" ]; then
    # Ubuntu
    echo "正在安装 Nitro Enclaves CLI (Ubuntu)..."
    sudo apt-get update
    sudo apt-get install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel
else
    echo "警告: 不支持的操作系统，请手动安装 Nitro Enclaves CLI"
fi

# 验证安装
if command -v nitro-cli &> /dev/null; then
    echo "Nitro Enclaves CLI 安装成功"
    nitro-cli --version
else
    echo "错误: Nitro Enclaves CLI 安装失败"
    exit 1
fi

# 配置 Enclave 资源分配器
echo ""
echo "步骤 2: 配置 Enclave 资源分配器"
echo "-----------------------------------"

# 创建配置文件
ALLOCATOR_CONFIG="/etc/nitro_enclaves/allocator.yaml"
sudo mkdir -p /etc/nitro_enclaves

echo "正在配置资源分配..."
sudo tee "$ALLOCATOR_CONFIG" > /dev/null <<EOF
---
cpu_count: 2
memory_mib: 2048
EOF

echo "资源分配配置已创建: $ALLOCATOR_CONFIG"

# 启用并启动 allocator 服务
echo "正在启动资源分配器服务..."
sudo systemctl enable nitro-enclaves-allocator.service
sudo systemctl start nitro-enclaves-allocator.service

# 检查服务状态
if sudo systemctl is-active --quiet nitro-enclaves-allocator.service; then
    echo "资源分配器服务已启动"
else
    echo "警告: 资源分配器服务启动失败"
fi

# 将当前用户添加到 ne 组
echo ""
echo "步骤 3: 配置用户权限"
echo "-----------------------------------"
CURRENT_USER=$(whoami)
echo "正在将用户 $CURRENT_USER 添加到 ne 组..."
sudo usermod -aG ne "$CURRENT_USER"
echo "用户权限配置完成"
echo "注意: 需要重新登录才能使权限生效"

# 安装 Docker（如果未安装）
echo ""
echo "步骤 4: 检查 Docker 安装"
echo "-----------------------------------"

if command -v docker &> /dev/null; then
    echo "Docker 已安装"
    docker --version
else
    echo "正在安装 Docker..."
    if [ "$OS" == "amzn" ]; then
        sudo yum install -y docker
    elif [ "$OS" == "ubuntu" ]; then
        sudo apt-get install -y docker.io
    fi
    echo "Docker 安装完成"
fi

# 确保 Docker 服务启动
echo "正在启动 Docker 服务..."
sudo systemctl enable docker
sudo systemctl start docker

# 将用户添加到 docker 组
sudo usermod -aG docker "$CURRENT_USER"

# 验证 Docker 运行状态
if sudo systemctl is-active --quiet docker; then
    echo "Docker 服务运行正常"
else
    echo "错误: Docker 服务启动失败"
    exit 1
fi

# 创建 Python 虚拟环境
echo ""
echo "步骤 5: 创建 Python 虚拟环境"
echo "-----------------------------------"

# 检查 Python 版本
if command -v python3.12 &> /dev/null; then
    PYTHON_CMD=python3.12
elif command -v python3 &> /dev/null; then
    PYTHON_CMD=python3
else
    echo "错误: 未找到 Python 3"
    exit 1
fi

echo "使用 Python: $PYTHON_CMD"
$PYTHON_CMD --version

# 安装 venv 模块（如果需要）
if [ "$OS" == "amzn" ] || [ "$OS" == "ubuntu" ]; then
    echo "正在安装 Python venv 模块..."
    if [ "$OS" == "amzn" ]; then
        sudo yum install -y python3-pip
    else
        sudo apt-get install -y python3-venv python3-pip
    fi
fi

# 创建虚拟环境
VENV_DIR="venv"
if [ ! -d "$VENV_DIR" ]; then
    echo "正在创建虚拟环境: $VENV_DIR"
    $PYTHON_CMD -m venv "$VENV_DIR"
    echo "虚拟环境创建成功"
else
    echo "虚拟环境已存在: $VENV_DIR"
fi

# 激活虚拟环境并安装依赖
echo "正在安装 Python 依赖..."
source "$VENV_DIR/bin/activate"
pip install --upgrade pip
pip install -r parent/requirements.txt
deactivate

echo "Python 依赖安装完成"

# 检查是否需要重启
if [ "${NEED_REBOOT:-0}" -eq 1 ]; then
    echo ""
    echo "==================================="
    echo "重要: 需要重启系统"
    echo "==================================="
    echo ""
    echo "内核参数已更新，请运行以下命令重启系统:"
    echo "  sudo reboot"
    echo ""
    echo "重启后，继续执行:"
    echo "  ./scripts/build_enclave.sh"
    echo "  ./scripts/start_enclave.sh"
fi

# 完成
echo ""
echo "==================================="
echo "环境配置完成！"
echo "==================================="
echo ""
echo "⚠️  重要提示："
echo ""
echo "1. 重新登录以使用户组权限生效："
echo "   exit"
echo "   # 然后重新 SSH 登录"
echo ""
echo "2. 重启系统以加载内核模块："
echo "   sudo reboot"
echo ""
echo "3. 重启后继续部署："
echo "   cd enclave-demo"
echo "   ./scripts/build_enclave.sh"
echo "   ./scripts/start_enclave.sh"
echo ""
echo "注意: 如果实例未启用 Nitro Enclaves，重启也无法解决问题。"
echo "      请确保在步骤 0 中已通过 Enclave 启用检查。"
