#!/bin/bash

# 一键演示脚本
# 整合所有步骤：构建、启动、运行、验证

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 配置变量
DEMO_MESSAGE="Hello from EC2 Nitro Enclave Demo!"
VENV_DIR="venv"
EIF_FILE="enclave.eif"
REGION="us-east-1"

# 打印带颜色的消息
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_banner() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║     EC2 Nitro Enclave KMS Signing Demo                   ║"
    echo "║     一键演示脚本                                          ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo ""
}

print_step() {
    echo ""
    echo "============================================================"
    echo "  步骤 $1: $2"
    echo "============================================================"
}

# 错误处理函数
cleanup_on_error() {
    print_error "演示过程中发生错误，正在清理..."
    
    # 尝试停止 Enclave
    ENCLAVE_ID=$(nitro-cli describe-enclaves 2>/dev/null | grep -oP '"EnclaveID":\s*"\K[^"]+' || echo "")
    if [ -n "$ENCLAVE_ID" ]; then
        print_info "停止 Enclave: $ENCLAVE_ID"
        nitro-cli terminate-enclave --enclave-id "$ENCLAVE_ID" 2>/dev/null || true
    fi
    
    print_error "演示失败，请检查错误信息"
    exit 1
}

# 设置错误陷阱
trap cleanup_on_error ERR

# 检查前置条件
check_prerequisites() {
    print_step 1 "检查前置条件"
    
    # 检查 nitro-cli
    if ! command -v nitro-cli &> /dev/null; then
        print_error "未找到 nitro-cli，请先运行 ./scripts/setup_environment.sh"
        exit 1
    fi
    print_success "nitro-cli 已安装"
    
    # 检查 Docker
    if ! command -v docker &> /dev/null; then
        print_error "未找到 Docker，请先运行 ./scripts/setup_environment.sh"
        exit 1
    fi
    print_success "Docker 已安装"
    
    # 检查 Python 虚拟环境
    if [ ! -d "$VENV_DIR" ]; then
        print_error "未找到 Python 虚拟环境，请先运行 ./scripts/setup_environment.sh"
        exit 1
    fi
    print_success "Python 虚拟环境已创建"
    
    # 检查 KMS 密钥配置
    if [ ! -f "kms_key_id.txt" ]; then
        print_warning "未找到 KMS 密钥 ID 文件"
        print_info "请确保已运行 ./scripts/setup_kms_key.sh 创建 KMS 密钥"
        read -p "是否继续？(y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 0
        fi
    else
        KMS_KEY_ID=$(cat kms_key_id.txt)
        print_success "KMS 密钥 ID: $KMS_KEY_ID"
    fi
    
    # 检查 IAM 角色
    print_info "检查 IAM 角色配置..."
    INSTANCE_PROFILE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ || echo "")
    if [ -z "$INSTANCE_PROFILE" ]; then
        print_warning "未检测到 IAM 实例配置文件"
        print_info "请确保 EC2 实例已附加正确的 IAM 角色"
    else
        print_success "IAM 实例配置文件: $INSTANCE_PROFILE"
    fi
}

# 构建 Enclave 镜像
build_enclave() {
    print_step 2 "构建 Enclave 镜像"
    
    if [ -f "$EIF_FILE" ]; then
        print_warning "检测到已存在的 EIF 文件"
        read -p "是否重新构建？(y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "跳过构建，使用现有 EIF 文件"
            return 0
        fi
    fi
    
    print_info "开始构建 Enclave 镜像..."
    ./scripts/build_enclave.sh
    
    if [ ! -f "$EIF_FILE" ]; then
        print_error "EIF 文件构建失败"
        exit 1
    fi
    
    print_success "Enclave 镜像构建完成"
}

# 启动 Enclave
start_enclave() {
    print_step 3 "启动 Enclave"
    
    # 检查是否已有运行中的 Enclave
    RUNNING_ENCLAVE=$(nitro-cli describe-enclaves 2>/dev/null | grep -oP '"EnclaveID":\s*"\K[^"]+' || echo "")
    if [ -n "$RUNNING_ENCLAVE" ]; then
        print_warning "检测到运行中的 Enclave: $RUNNING_ENCLAVE"
        print_info "正在停止现有 Enclave..."
        nitro-cli terminate-enclave --enclave-id "$RUNNING_ENCLAVE" 2>/dev/null || true
        sleep 2
    fi
    
    print_info "正在启动 Enclave..."
    ./scripts/start_enclave.sh
    
    # 验证 Enclave 已启动
    sleep 3
    ENCLAVE_CID=$(cat enclave_cid.txt 2>/dev/null || echo "")
    if [ -z "$ENCLAVE_CID" ]; then
        print_error "无法获取 Enclave CID"
        exit 1
    fi
    
    print_success "Enclave 已启动，CID: $ENCLAVE_CID"
    
    # 等待 Enclave 初始化
    print_info "等待 Enclave 初始化（5秒）..."
    sleep 5
}

# 运行签名演示
run_demo() {
    print_step 4 "运行签名演示"
    
    ENCLAVE_CID=$(cat enclave_cid.txt 2>/dev/null || echo "")
    if [ -z "$ENCLAVE_CID" ]; then
        print_error "无法读取 Enclave CID"
        exit 1
    fi
    
    print_info "激活 Python 虚拟环境..."
    source "$VENV_DIR/bin/activate"
    
    print_info "发送签名请求到 Enclave..."
    print_info "敏感数据: My credit card: 1234-5678-9012-3456"
    print_info "交易数据: Transfer \$1000 from Alice to Bob"
    echo ""
    
    # 运行 parent 应用
    cd parent
    python3 parent_app.py \
        --cid "$ENCLAVE_CID" \
        --sensitive-data "My credit card: 1234-5678-9012-3456" \
        --transaction "Transfer \$1000 from Alice to Bob" \
        --region "$REGION"
    
    DEMO_RESULT=$?
    cd ..
    
    deactivate
    
    if [ $DEMO_RESULT -eq 0 ]; then
        print_success "签名演示完成"
        return 0
    else
        print_error "签名演示失败"
        return 1
    fi
}

# 显示 Enclave 日志
show_enclave_logs() {
    print_step 5 "Enclave 日志"
    
    ENCLAVE_ID=$(nitro-cli describe-enclaves 2>/dev/null | grep -oP '"EnclaveID":\s*"\K[^"]+' || echo "")
    if [ -z "$ENCLAVE_ID" ]; then
        print_warning "无法获取 Enclave ID，跳过日志显示"
        return 0
    fi
    
    print_info "显示 Enclave 控制台日志（最后 20 行）..."
    echo ""
    echo "----------------------------------------"
    timeout 5 nitro-cli console --enclave-id "$ENCLAVE_ID" 2>/dev/null | tail -20 || print_warning "无法获取日志"
    echo "----------------------------------------"
    echo ""
}

# 询问是否清理
ask_cleanup() {
    echo ""
    print_info "演示完成！"
    echo ""
    read -p "是否停止 Enclave 并清理资源？(y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_info "正在清理资源..."
        ./scripts/cleanup.sh --keep-images
        print_success "清理完成"
    else
        print_info "Enclave 保持运行状态"
        ENCLAVE_ID=$(nitro-cli describe-enclaves 2>/dev/null | grep -oP '"EnclaveID":\s*"\K[^"]+' || echo "")
        if [ -n "$ENCLAVE_ID" ]; then
            echo ""
            print_info "查看 Enclave 日志:"
            echo "  nitro-cli console --enclave-id $ENCLAVE_ID"
            echo ""
            print_info "停止 Enclave:"
            echo "  ./scripts/cleanup.sh"
        fi
    fi
}

# 主函数
main() {
    print_banner
    
    print_info "开始 EC2 Nitro Enclave KMS 签名演示"
    print_info "区域: $REGION"
    print_info "演示消息: $DEMO_MESSAGE"
    
    # 执行各个步骤
    check_prerequisites
    build_enclave
    start_enclave
    
    # 运行演示
    if run_demo; then
        show_enclave_logs
        
        echo ""
        echo "╔═══════════════════════════════════════════════════════════╗"
        echo "║                                                           ║"
        echo "║  ✓ 演示成功完成！                                         ║"
        echo "║                                                           ║"
        echo "║  已成功演示：                                             ║"
        echo "║  1. 在 Enclave 中生成 Attestation Document               ║"
        echo "║  2. 使用 KMS 在 Enclave 中签名                            ║"
        echo "║  3. 在 Parent Instance 中验证签名                         ║"
        echo "║                                                           ║"
        echo "╚═══════════════════════════════════════════════════════════╝"
        echo ""
        
        ask_cleanup
        exit 0
    else
        print_error "演示失败"
        show_enclave_logs
        ask_cleanup
        exit 1
    fi
}

# 运行主函数
main
