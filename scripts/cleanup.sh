#!/bin/bash

# 资源清理脚本
# 停止 Enclave、清理临时文件和镜像

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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
    echo "║     EC2 Nitro Enclave 资源清理脚本                        ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo ""
}

# 解析命令行参数
KEEP_IMAGES=false
KEEP_KMS=true
KEEP_IAM=true
FORCE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --keep-images)
            KEEP_IMAGES=true
            shift
            ;;
        --delete-kms)
            KEEP_KMS=false
            shift
            ;;
        --delete-iam)
            KEEP_IAM=false
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        -h|--help)
            echo "用法: $0 [选项]"
            echo ""
            echo "选项:"
            echo "  --keep-images    保留 Docker 镜像和 EIF 文件"
            echo "  --delete-kms     删除 KMS 密钥（默认保留）"
            echo "  --delete-iam     删除 IAM 角色（默认保留）"
            echo "  --force          不询问确认，直接执行"
            echo "  -h, --help       显示此帮助信息"
            echo ""
            echo "示例:"
            echo "  $0                      # 基本清理（停止 Enclave，清理临时文件）"
            echo "  $0 --keep-images        # 清理但保留镜像"
            echo "  $0 --delete-kms         # 清理并删除 KMS 密钥"
            echo "  $0 --delete-kms --delete-iam --force  # 完全清理"
            exit 0
            ;;
        *)
            print_error "未知选项: $1"
            echo "使用 --help 查看帮助"
            exit 1
            ;;
    esac
done

# 确认清理操作
confirm_cleanup() {
    if [ "$FORCE" = true ]; then
        return 0
    fi
    
    echo ""
    print_warning "即将执行以下清理操作:"
    echo "  - 停止并终止运行中的 Enclave"
    echo "  - 清理临时文件（CID、PCR0 等）"
    
    if [ "$KEEP_IMAGES" = false ]; then
        echo "  - 删除 Docker 镜像和 EIF 文件"
    fi
    
    if [ "$KEEP_KMS" = false ]; then
        echo "  - 删除 KMS 密钥"
    fi
    
    if [ "$KEEP_IAM" = false ]; then
        echo "  - 删除 IAM 角色"
    fi
    
    echo ""
    read -p "确认继续？(y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "取消清理"
        exit 0
    fi
}

# 停止 Enclave
stop_enclave() {
    print_info "检查运行中的 Enclave..."
    
    ENCLAVE_ID=$(nitro-cli describe-enclaves 2>/dev/null | grep -oP '"EnclaveID":\s*"\K[^"]+' || echo "")
    
    if [ -z "$ENCLAVE_ID" ]; then
        print_info "没有运行中的 Enclave"
        return 0
    fi
    
    print_info "停止 Enclave: $ENCLAVE_ID"
    
    if nitro-cli terminate-enclave --enclave-id "$ENCLAVE_ID" 2>/dev/null; then
        print_success "Enclave 已停止"
    else
        print_warning "停止 Enclave 失败或 Enclave 已停止"
    fi
    
    # 等待 Enclave 完全停止
    sleep 2
}

# 清理临时文件
cleanup_temp_files() {
    print_info "清理临时文件..."
    
    local files_to_remove=(
        "enclave_cid.txt"
        "enclave_pcr0.txt"
    )
    
    local removed_count=0
    for file in "${files_to_remove[@]}"; do
        if [ -f "$file" ]; then
            rm -f "$file"
            print_success "已删除: $file"
            ((removed_count++))
        fi
    done
    
    if [ $removed_count -eq 0 ]; then
        print_info "没有临时文件需要清理"
    else
        print_success "已清理 $removed_count 个临时文件"
    fi
}

# 清理 Docker 镜像和 EIF 文件
cleanup_images() {
    if [ "$KEEP_IMAGES" = true ]; then
        print_info "跳过镜像清理（--keep-images）"
        return 0
    fi
    
    print_info "清理 Docker 镜像和 EIF 文件..."
    
    # 删除 EIF 文件
    if [ -f "enclave.eif" ]; then
        rm -f enclave.eif
        print_success "已删除: enclave.eif"
    fi
    
    # 删除 Docker 镜像
    DOCKER_IMAGE="enclave-app:latest"
    if docker images -q "$DOCKER_IMAGE" 2>/dev/null | grep -q .; then
        print_info "删除 Docker 镜像: $DOCKER_IMAGE"
        docker rmi "$DOCKER_IMAGE" 2>/dev/null || print_warning "删除 Docker 镜像失败"
        print_success "Docker 镜像已删除"
    else
        print_info "没有找到 Docker 镜像: $DOCKER_IMAGE"
    fi
    
    # 清理悬空镜像
    DANGLING_IMAGES=$(docker images -f "dangling=true" -q 2>/dev/null || echo "")
    if [ -n "$DANGLING_IMAGES" ]; then
        print_info "清理悬空 Docker 镜像..."
        docker rmi $DANGLING_IMAGES 2>/dev/null || print_warning "清理悬空镜像失败"
    fi
}

# 删除 KMS 密钥
delete_kms_key() {
    if [ "$KEEP_KMS" = true ]; then
        print_info "跳过 KMS 密钥删除（默认保留）"
        return 0
    fi
    
    print_info "删除 KMS 密钥..."
    
    if [ ! -f "kms_key_id.txt" ]; then
        print_warning "未找到 KMS 密钥 ID 文件"
        return 0
    fi
    
    KMS_KEY_ID=$(cat kms_key_id.txt)
    
    if [ -z "$KMS_KEY_ID" ]; then
        print_warning "KMS 密钥 ID 为空"
        return 0
    fi
    
    print_warning "准备删除 KMS 密钥: $KMS_KEY_ID"
    print_warning "注意: KMS 密钥将被计划删除（默认 30 天等待期）"
    
    if [ "$FORCE" = false ]; then
        read -p "确认删除 KMS 密钥？(y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "跳过 KMS 密钥删除"
            return 0
        fi
    fi
    
    # 计划删除密钥（30 天等待期）
    if aws kms schedule-key-deletion \
        --key-id "$KMS_KEY_ID" \
        --pending-window-in-days 30 \
        --region us-east-1 2>/dev/null; then
        print_success "KMS 密钥已计划删除（30 天后）"
        rm -f kms_key_id.txt
    else
        print_error "删除 KMS 密钥失败"
    fi
}

# 删除 IAM 角色
delete_iam_role() {
    if [ "$KEEP_IAM" = true ]; then
        print_info "跳过 IAM 角色删除（默认保留）"
        return 0
    fi
    
    print_info "删除 IAM 角色..."
    
    if [ ! -f "iam_role_name.txt" ]; then
        print_warning "未找到 IAM 角色名称文件"
        return 0
    fi
    
    IAM_ROLE_NAME=$(cat iam_role_name.txt)
    
    if [ -z "$IAM_ROLE_NAME" ]; then
        print_warning "IAM 角色名称为空"
        return 0
    fi
    
    print_warning "准备删除 IAM 角色: $IAM_ROLE_NAME"
    
    if [ "$FORCE" = false ]; then
        read -p "确认删除 IAM 角色？(y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "跳过 IAM 角色删除"
            return 0
        fi
    fi
    
    # 分离策略
    print_info "分离 IAM 策略..."
    ATTACHED_POLICIES=$(aws iam list-attached-role-policies \
        --role-name "$IAM_ROLE_NAME" \
        --query 'AttachedPolicies[*].PolicyArn' \
        --output text 2>/dev/null || echo "")
    
    if [ -n "$ATTACHED_POLICIES" ]; then
        for policy_arn in $ATTACHED_POLICIES; do
            aws iam detach-role-policy \
                --role-name "$IAM_ROLE_NAME" \
                --policy-arn "$policy_arn" 2>/dev/null || true
        done
    fi
    
    # 删除实例配置文件关联
    print_info "删除实例配置文件关联..."
    aws iam remove-role-from-instance-profile \
        --instance-profile-name "$IAM_ROLE_NAME" \
        --role-name "$IAM_ROLE_NAME" 2>/dev/null || true
    
    # 删除实例配置文件
    aws iam delete-instance-profile \
        --instance-profile-name "$IAM_ROLE_NAME" 2>/dev/null || true
    
    # 删除角色
    if aws iam delete-role --role-name "$IAM_ROLE_NAME" 2>/dev/null; then
        print_success "IAM 角色已删除"
        rm -f iam_role_name.txt
    else
        print_error "删除 IAM 角色失败"
    fi
}

# 显示清理摘要
show_summary() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║                                                           ║"
    echo "║  ✓ 清理完成                                               ║"
    echo "║                                                           ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo ""
    
    print_info "清理摘要:"
    echo "  - Enclave: 已停止"
    echo "  - 临时文件: 已清理"
    
    if [ "$KEEP_IMAGES" = false ]; then
        echo "  - Docker 镜像和 EIF: 已删除"
    else
        echo "  - Docker 镜像和 EIF: 已保留"
    fi
    
    if [ "$KEEP_KMS" = false ]; then
        echo "  - KMS 密钥: 已计划删除"
    else
        echo "  - KMS 密钥: 已保留"
    fi
    
    if [ "$KEEP_IAM" = false ]; then
        echo "  - IAM 角色: 已删除"
    else
        echo "  - IAM 角色: 已保留"
    fi
    
    echo ""
    
    if [ "$KEEP_IMAGES" = true ] || [ "$KEEP_KMS" = true ] || [ "$KEEP_IAM" = true ]; then
        print_info "提示:"
        
        if [ "$KEEP_IMAGES" = true ]; then
            echo "  - 要删除镜像，运行: $0"
        fi
        
        if [ "$KEEP_KMS" = true ]; then
            echo "  - 要删除 KMS 密钥，运行: $0 --delete-kms"
        fi
        
        if [ "$KEEP_IAM" = true ]; then
            echo "  - 要删除 IAM 角色，运行: $0 --delete-iam"
        fi
        
        echo ""
    fi
}

# 主函数
main() {
    print_banner
    
    # 确认清理操作
    confirm_cleanup
    
    echo ""
    print_info "开始清理资源..."
    echo ""
    
    # 执行清理步骤
    stop_enclave
    cleanup_temp_files
    cleanup_images
    delete_kms_key
    delete_iam_role
    
    # 显示摘要
    show_summary
}

# 运行主函数
main
