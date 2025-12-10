#!/bin/bash

# KMS 密钥配置脚本
# 创建用于 Enclave GenerateDataKey 的 KMS 密钥

set -e

REGION="us-east-1"

echo "正在创建 KMS 密钥..."

# 创建对称加密密钥（用于 GenerateDataKey）
KEY_ID=$(aws kms create-key \
    --region "$REGION" \
    --description "Enclave data key generation for demo" \
    --query 'KeyMetadata.KeyId' \
    --output text)

if [ -z "$KEY_ID" ]; then
    echo "错误: 创建 KMS 密钥失败"
    exit 1
fi

echo "KMS 密钥创建成功: $KEY_ID"

# 创建密钥别名
ALIAS_NAME="alias/enclave-datakey-demo"
aws kms create-alias \
    --region "$REGION" \
    --alias-name "$ALIAS_NAME" \
    --target-key-id "$KEY_ID" || echo "警告: 别名可能已存在"

echo "密钥别名: $ALIAS_NAME"

# 获取当前账户 ID
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# 获取 Enclave 镜像哈希
ENCLAVE_HASH=""
if [ -f "enclave_pcr0.txt" ]; then
    ENCLAVE_HASH=$(cat enclave_pcr0.txt)
    echo "从 enclave_pcr0.txt 读取 PCR0: $ENCLAVE_HASH"
elif [ -f "enclave.eif" ]; then
    ENCLAVE_HASH=$(nitro-cli describe-eif --eif-path enclave.eif 2>/dev/null | grep -oP '"PCR0":\s*"\K[^"]+' || echo "")
    echo "从 enclave.eif 提取 PCR0: $ENCLAVE_HASH"
fi

# 创建密钥策略
if [ -n "$ENCLAVE_HASH" ]; then
    echo "使用 Attestation 条件创建密钥策略..."
    POLICY=$(cat <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Enable IAM User Permissions",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::${ACCOUNT_ID}:root"
            },
            "Action": "kms:*",
            "Resource": "*"
        },
        {
            "Sid": "Enable enclave data key generation",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::${ACCOUNT_ID}:role/EnclaveRole"
            },
            "Action": [
                "kms:GenerateDataKey",
                "kms:Decrypt"
            ],
            "Resource": "*",
            "Condition": {
                "StringEqualsIgnoreCase": {
                    "kms:RecipientAttestation:PCR0": "${ENCLAVE_HASH}"
                }
            }
        }
    ]
}
EOF
)
else
    echo "警告: 未找到 Enclave PCR0，创建不带 Attestation 条件的策略"
    POLICY=$(cat <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Enable IAM User Permissions",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::${ACCOUNT_ID}:root"
            },
            "Action": "kms:*",
            "Resource": "*"
        },
        {
            "Sid": "Enable enclave data key generation",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::${ACCOUNT_ID}:role/EnclaveRole"
            },
            "Action": [
                "kms:GenerateDataKey",
                "kms:Decrypt"
            ],
            "Resource": "*"
        }
    ]
}
EOF
)
fi

# 应用密钥策略
echo "正在配置密钥策略..."
aws kms put-key-policy \
    --region "$REGION" \
    --key-id "$KEY_ID" \
    --policy-name default \
    --policy "$POLICY"

echo "密钥策略配置完成"

# 保存密钥 ID 到文件
echo "$KEY_ID" > kms_key_id.txt
echo "密钥 ID 已保存到 kms_key_id.txt"

echo ""
echo "==================================="
echo "KMS 密钥配置完成"
echo "密钥 ID: $KEY_ID"
echo "密钥别名: $ALIAS_NAME"
echo "密钥类型: SYMMETRIC_DEFAULT"
echo "用途: GenerateDataKey with Recipient"
echo "区域: $REGION"
echo "==================================="
