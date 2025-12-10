#!/bin/bash

# IAM 角色配置脚本
# 创建 EC2 实例角色用于 Enclave 访问 KMS

set -e

REGION="us-east-1"
ROLE_NAME="EnclaveRole"
POLICY_NAME="EnclaveKMSPolicy"
INSTANCE_PROFILE_NAME="EnclaveInstanceProfile"

echo "正在创建 IAM 角色..."

# 创建信任策略文档
TRUST_POLICY=$(cat <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
EOF
)

# 创建 IAM 角色
aws iam create-role \
    --role-name "$ROLE_NAME" \
    --assume-role-policy-document "$TRUST_POLICY" \
    --description "Role for EC2 instance running Nitro Enclave" \
    2>/dev/null || echo "角色可能已存在，继续..."

echo "IAM 角色创建成功: $ROLE_NAME"

# 读取 KMS 密钥 ID
KMS_KEY_ID=""
if [ -f "kms_key_id.txt" ]; then
    KMS_KEY_ID=$(cat kms_key_id.txt)
    echo "使用 KMS 密钥 ID: $KMS_KEY_ID"
fi

# 获取账户 ID
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# 创建 KMS 权限策略
if [ -n "$KMS_KEY_ID" ]; then
    KMS_POLICY=$(cat <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "kms:Sign",
                "kms:GetPublicKey",
                "kms:DescribeKey"
            ],
            "Resource": "arn:aws:kms:${REGION}:${ACCOUNT_ID}:key/${KMS_KEY_ID}"
        }
    ]
}
EOF
)
else
    echo "警告: 未找到 KMS 密钥 ID，创建通用策略"
    KMS_POLICY=$(cat <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "kms:Sign",
                "kms:GetPublicKey",
                "kms:DescribeKey"
            ],
            "Resource": "arn:aws:kms:${REGION}:${ACCOUNT_ID}:key/*"
        }
    ]
}
EOF
)
fi

# 创建或更新策略
echo "正在配置 KMS 权限策略..."
POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/${POLICY_NAME}"

# 尝试创建策略
aws iam create-policy \
    --policy-name "$POLICY_NAME" \
    --policy-document "$KMS_POLICY" \
    --description "Policy for Enclave to access KMS" \
    2>/dev/null || {
        echo "策略已存在，正在更新..."
        # 获取现有策略的默认版本
        DEFAULT_VERSION=$(aws iam get-policy --policy-arn "$POLICY_ARN" --query 'Policy.DefaultVersionId' --output text)
        # 删除旧版本（如果有多个版本）
        aws iam delete-policy-version --policy-arn "$POLICY_ARN" --version-id "$DEFAULT_VERSION" 2>/dev/null || true
        # 创建新版本
        aws iam create-policy-version \
            --policy-arn "$POLICY_ARN" \
            --policy-document "$KMS_POLICY" \
            --set-as-default 2>/dev/null || echo "策略更新可能失败"
    }

echo "KMS 权限策略配置完成: $POLICY_NAME"

# 附加策略到角色
echo "正在附加策略到角色..."
aws iam attach-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-arn "$POLICY_ARN" \
    2>/dev/null || echo "策略可能已附加"

echo "策略已附加到角色"

# 创建实例配置文件
echo "正在创建实例配置文件..."
aws iam create-instance-profile \
    --instance-profile-name "$INSTANCE_PROFILE_NAME" \
    2>/dev/null || echo "实例配置文件可能已存在"

# 将角色添加到实例配置文件
aws iam add-role-to-instance-profile \
    --instance-profile-name "$INSTANCE_PROFILE_NAME" \
    --role-name "$ROLE_NAME" \
    2>/dev/null || echo "角色可能已添加到实例配置文件"

echo "实例配置文件创建完成: $INSTANCE_PROFILE_NAME"

echo ""
echo "==================================="
echo "IAM 角色配置完成"
echo "角色名称: $ROLE_NAME"
echo "策略名称: $POLICY_NAME"
echo "实例配置文件: $INSTANCE_PROFILE_NAME"
echo "==================================="
echo ""
echo "提示: 启动 EC2 实例时，请附加实例配置文件: $INSTANCE_PROFILE_NAME"
