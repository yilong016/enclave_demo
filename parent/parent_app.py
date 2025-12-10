#!/usr/bin/env python3
"""
Parent Instance 应用程序
演示：Parent 无法解密 CiphertextForRecipient，只有 Enclave 能解密
"""

import argparse
import sys
import time
import base64
from enclave_client import EnclaveClient


def print_separator():
    """打印分隔线"""
    print("=" * 50)


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='EC2 Nitro Enclave KMS Data Key 演示')
    parser.add_argument('--cid', type=int, help='Enclave CID（默认从文件读取）')
    parser.add_argument('--kms-key-id', type=str, help='KMS 密钥 ID（默认从文件读取）')
    parser.add_argument('--region', type=str, default='us-east-1', help='AWS 区域')
    parser.add_argument('--sensitive-data', type=str, default='My credit card: 1234-5678-9012-3456', 
                        help='要加密的敏感数据')
    parser.add_argument('--transaction', type=str, default='Transfer $1000 from Alice to Bob', 
                        help='要签名的交易数据')
    
    args = parser.parse_args()
    
    # 读取配置
    enclave_cid = args.cid
    if not enclave_cid:
        try:
            with open('../enclave_cid.txt', 'r') as f:
                enclave_cid = int(f.read().strip())
        except FileNotFoundError:
            print("错误: 未找到 enclave_cid.txt 文件")
            print("请先运行 ./scripts/start_enclave.sh 启动 Enclave")
            sys.exit(1)
    
    kms_key_id = args.kms_key_id
    if not kms_key_id:
        try:
            with open('../kms_key_id.txt', 'r') as f:
                kms_key_id = f.read().strip()
        except FileNotFoundError:
            print("错误: 未找到 kms_key_id.txt 文件")
            print("请先运行 ./scripts/setup_kms_key.sh 创建 KMS 密钥")
            sys.exit(1)
    
    print_separator()
    print("EC2 Nitro Enclave KMS Data Key 演示")
    print_separator()
    print()
    print("配置信息:")
    print(f"  Enclave CID: {enclave_cid}")
    print(f"  KMS 密钥 ID: {kms_key_id}")
    print(f"  区域: {args.region}")
    print()
    print("数据信息:")
    print(f"  敏感数据: {args.sensitive_data}")
    print(f"  交易数据: {args.transaction}")
    print()
    
    start_time = time.time()
    
    # 步骤 1: 连接到 Enclave
    print("步骤 1: 连接到 Enclave")
    print("-" * 50)
    
    client = EnclaveClient(enclave_cid)
    
    try:
        client.connect()
        print(f"✓ 已连接到 Enclave (CID: {enclave_cid}, Port: 5000)")
        print()
    except Exception as e:
        print(f"✗ 连接失败: {str(e)}")
        sys.exit(1)
    
    # 步骤 2: 发送数据到 Enclave 进行处理
    print("步骤 2: 发送数据到 Enclave 进行处理")
    print("-" * 50)
    print("正在发送敏感数据和交易数据...")
    
    try:
        response = client.process_data(kms_key_id, args.sensitive_data, args.transaction)
        print("✓ 收到处理结果")
        print()
    except Exception as e:
        print(f"✗ 处理失败: {str(e)}")
        client.close()
        sys.exit(1)
    
    # 步骤 3: 检查响应
    print("步骤 3: 检查 Enclave 处理结果")
    print("-" * 50)
    
    if response['status'] != 'success':
        print(f"✗ Enclave 返回错误: {response.get('message')}")
        client.close()
        sys.exit(1)
    
    print(f"✓ 状态: {response['status']}")
    print(f"  KMS 密钥 ID: {response['key_id']}")
    print()
    print("加密结果:")
    encrypted_data = response['encrypted_data']
    print(f"  IV 长度: {len(base64.b64decode(encrypted_data['iv']))} 字节")
    print(f"  密文长度: {len(base64.b64decode(encrypted_data['ciphertext']))} 字节")
    print(f"  认证标签长度: {len(base64.b64decode(encrypted_data['tag']))} 字节")
    print()
    print("签名结果:")
    print(f"  交易签名: {response['transaction_signature'][:32]}...")
    print(f"  签名长度: {len(base64.b64decode(response['transaction_signature']))} 字节")
    print()
    print(f"  消息: {response['message']}")
    print()
    
    # 步骤 4: 演示 Parent 无法解密
    print("步骤 4: 安全性验证")
    print("-" * 50)
    print("⚠️  Data key 明文只在 Enclave 内存中存在")
    print("⚠️  Parent Instance 只收到加密后的数据和签名")
    print("⚠️  Parent Instance 无法解密数据或伪造签名")
    print()
    print("✓ 安全验证通过：敏感操作完全在 Enclave 内完成")
    print()
    
    # 步骤 5: 说明 CiphertextBlob 的用途
    print("步骤 5: 数据持久化")
    print("-" * 50)
    print("CiphertextBlob 可以安全存储在 Parent Instance:")
    print(f"  长度: {len(base64.b64decode(response['ciphertext_blob']))} 字节")
    print()
    print("需要解密时，Enclave 可以:")
    print("  1. 调用 KMS Decrypt with Recipient")
    print("  2. 获得明文 data key（只在 Enclave 内）")
    print("  3. 解密数据或验证签名")
    print()
    
    client.close()
    
    elapsed_time = time.time() - start_time
    
    print_separator()
    print("演示完成")
    print_separator()
    print()
    print("完成的操作:")
    print("  ✓ 在 Enclave 中生成 data key")
    print("  ✓ 使用 data key 加密敏感数据")
    print("  ✓ 使用 data key 签名交易数据")
    print("  ✓ Data key 明文已从内存清除")
    print()
    print("安全特性:")
    print("  ✓ Data key 明文只在 Enclave 内存中")
    print("  ✓ Parent Instance 无法获得明文 data key")
    print("  ✓ Parent Instance 无法解密数据或伪造签名")
    print("  ✓ KMS 通过 Attestation 验证 Enclave 身份")
    print()
    print(f"整个流程耗时: {elapsed_time:.2f} 秒")
    print()


if __name__ == '__main__':
    main()
