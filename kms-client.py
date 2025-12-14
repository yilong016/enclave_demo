#!/usr/bin/env python3
"""
Nitro Enclave KMS 客户端应用

这个应用运行在 parent instance 上，通过 vsock 与 enclave 通信，
提供加密和解密功能的命令行接口。

主要功能：
1. 加密操作：发送文本到 enclave 进行加密和签名
2. 解密操作：发送加密数据到 enclave 进行解密和验证签名

通信协议：
- 使用 vsock 协议与 enclave 安全通信
- JSON 格式的请求和响应
- 自动获取和传递 AWS credentials

使用方法：
  加密: python3 kms-client-full.py <enclave_cid> <port> encrypt "<message>"
  解密: python3 kms-client-full.py <enclave_cid> <port> decrypt <encrypted> <signature> <ciphertext_blob>
"""

import socket
import sys
import json
import boto3

def get_aws_credentials():
    """
    获取当前环境的 AWS credentials
    
    支持多种 credentials 来源：
    1. IAM Role (推荐用于 EC2 实例)
    2. AWS CLI 配置文件 (~/.aws/credentials)
    3. 环境变量 (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    4. IAM 用户的长期凭证
    
    Returns:
        dict: 包含 access_key_id, secret_access_key, session_token 的字典
              如果获取失败返回 None
    """
    try:
        # 创建 boto3 session，自动检测 credentials
        session = boto3.Session()
        credentials = session.get_credentials()
        
        if not credentials:
            print("✗ 无法获取 AWS credentials")
            print("请确保：")
            print("1. EC2 实例附加了 IAM role，或")
            print("2. 配置了 AWS CLI (aws configure)，或")
            print("3. 设置了环境变量 AWS_ACCESS_KEY_ID 和 AWS_SECRET_ACCESS_KEY")
            return None
            
        # 构造 credentials 字典
        # session_token 可能为 None (长期凭证) 或包含临时凭证的 token
        return {
            "access_key_id": credentials.access_key,
            "secret_access_key": credentials.secret_key,
            "session_token": credentials.token or ""  # 如果是 None 则使用空字符串
        }
        
    except Exception as e:
        print(f"✗ 获取 credentials 失败: {e}")
        return None

def send_encrypt_request(enclave_cid, port, message):
    """
    发送加密请求到 enclave
    
    工作流程：
    1. 获取 AWS credentials
    2. 建立 vsock 连接到 enclave
    3. 发送加密请求 (JSON 格式)
    4. 接收加密结果
    
    Args:
        enclave_cid: Enclave 的 CID (Context ID)
        port: Enclave 监听的端口
        message: 要加密的文本消息
        
    Returns:
        dict: 加密结果 (包含 encrypted, signature, ciphertext_blob) 或 None
    """
    print(f"连接到 Enclave CID {enclave_cid}, 端口 {port}")
    
    # 获取 AWS credentials
    credentials = get_aws_credentials()
    if not credentials:
        return None
    
    try:
        # 创建 vsock 连接
        # AF_VSOCK: vsock 地址族，用于与 enclave 通信
        # SOCK_STREAM: TCP 类型的可靠连接
        sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        sock.connect((enclave_cid, port))
        
        # 构造加密请求
        request = {
            "operation": "encrypt",      # 操作类型
            "message": message,          # 要加密的文本
            "credentials": credentials   # AWS credentials
        }
        
        # 发送请求
        # 1. 发送 JSON 数据
        sock.sendall(json.dumps(request).encode())
        # 2. 关闭写端，告诉 enclave 数据发送完毕
        sock.shutdown(socket.SHUT_WR)
        
        # 接收响应
        # 循环接收所有响应数据
        response_data = b""
        while True:
            chunk = sock.recv(1024)
            if not chunk:  # 连接关闭
                break
            response_data += chunk
        
        # 关闭连接
        sock.close()
        
        # 解析 JSON 响应
        response = json.loads(response_data.decode())
        return response
        
    except Exception as e:
        print(f"✗ 加密请求失败: {e}")
        return None

def send_decrypt_request(enclave_cid, port, encrypted_data, signature, ciphertext_blob):
    """
    发送解密请求到 enclave
    
    工作流程：
    1. 获取 AWS credentials
    2. 建立 vsock 连接到 enclave
    3. 发送解密请求 (包含加密数据、签名、加密的 data key)
    4. 接收解密结果和签名验证状态
    
    Args:
        enclave_cid: Enclave 的 CID
        port: Enclave 监听的端口
        encrypted_data: base64 编码的加密数据
        signature: base64 编码的 HMAC 签名
        ciphertext_blob: base64 编码的加密 data key
        
    Returns:
        dict: 解密结果 (包含 decrypted, signature_valid) 或 None
    """
    print(f"连接到 Enclave CID {enclave_cid}, 端口 {port}")
    
    # 获取 AWS credentials
    credentials = get_aws_credentials()
    if not credentials:
        return None
    
    try:
        # 创建 vsock 连接
        sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        sock.connect((enclave_cid, port))
        
        # 构造解密请求
        request = {
            "operation": "decrypt",           # 操作类型
            "encrypted": encrypted_data,      # 加密的数据
            "signature": signature,           # HMAC 签名
            "ciphertext_blob": ciphertext_blob,  # 加密的 data key
            "credentials": credentials        # AWS credentials
        }
        
        # 发送请求
        sock.sendall(json.dumps(request).encode())
        sock.shutdown(socket.SHUT_WR)
        
        # 接收响应
        response_data = b""
        while True:
            chunk = sock.recv(1024)
            if not chunk:
                break
            response_data += chunk
        
        # 关闭连接
        sock.close()
        
        # 解析 JSON 响应
        response = json.loads(response_data.decode())
        return response
        
    except Exception as e:
        print(f"✗ 解密请求失败: {e}")
        return None

def main():
    """
    主函数：解析命令行参数并执行相应操作
    
    支持两种操作模式：
    1. 加密模式：encrypt <message>
    2. 解密模式：decrypt <encrypted> <signature> <ciphertext_blob>
    """
    # 检查命令行参数
    if len(sys.argv) < 4:
        print("用法:")
        print("  加密: python3 kms-client-full.py <enclave_cid> <port> encrypt \"<message>\"")
        print("  解密: python3 kms-client-full.py <enclave_cid> <port> decrypt <encrypted> <signature> <ciphertext_blob>")
        print("")
        print("参数说明:")
        print("  enclave_cid: Enclave 的 CID (可通过 nitro-cli describe-enclaves 获取)")
        print("  port: Enclave 监听的端口 (默认 5000)")
        print("  message: 要加密的文本消息")
        print("  encrypted: base64 编码的加密数据")
        print("  signature: base64 编码的 HMAC 签名")
        print("  ciphertext_blob: base64 编码的加密 data key")
        sys.exit(1)
    
    # 解析基本参数
    enclave_cid = int(sys.argv[1])  # Enclave CID
    port = int(sys.argv[2])         # 端口号
    operation = sys.argv[3]         # 操作类型 (encrypt/decrypt)
    
    if operation == "encrypt":
        # ========== 加密模式 ==========
        if len(sys.argv) != 5:
            print("加密用法: python3 kms-client-full.py <enclave_cid> <port> encrypt \"<message>\"")
            sys.exit(1)
            
        message = sys.argv[4]
        print(f"发送加密请求: {message}")
        
        # 发送加密请求
        response = send_encrypt_request(enclave_cid, port, message)
        
        # 处理响应
        if response and "error" not in response:
            # 加密成功，显示结果
            print("\n" + "="*60)
            print("加密和签名结果:")
            print("="*60)
            print(f"原文: {response['plaintext']}")
            print(f"加密结果 (Base64): {response['encrypted']}")
            print(f"签名 (Base64): {response['signature']}")
            print(f"加密的 Data Key (Base64): {response['ciphertext_blob']}")
            print("="*60)
            
            # 提供解密命令示例
            print("\n保存以下信息用于解密:")
            print(f"ENCRYPTED={response['encrypted']}")
            print(f"SIGNATURE={response['signature']}")
            print(f"CIPHERTEXT_BLOB={response['ciphertext_blob']}")
        else:
            # 加密失败
            error_msg = response.get('error', 'Unknown error') if response else 'No response'
            print(f"✗ 加密失败: {error_msg}")
    
    elif operation == "decrypt":
        # ========== 解密模式 ==========
        if len(sys.argv) != 7:
            print("解密用法: python3 kms-client-full.py <enclave_cid> <port> decrypt <encrypted> <signature> <ciphertext_blob>")
            sys.exit(1)
            
        # 解析解密参数
        encrypted_data = sys.argv[4]    # 加密数据
        signature = sys.argv[5]         # HMAC 签名
        ciphertext_blob = sys.argv[6]   # 加密的 data key
        
        print(f"发送解密请求...")
        
        # 发送解密请求
        response = send_decrypt_request(enclave_cid, port, encrypted_data, signature, ciphertext_blob)
        
        # 处理响应
        if response and "error" not in response:
            # 解密成功，显示结果
            print("\n" + "="*60)
            print("解密和验证结果:")
            print("="*60)
            print(f"解密结果: {response['decrypted']}")
            
            # 显示签名验证状态
            if response['signature_valid']:
                print(f"签名验证: ✓ 通过")
            else:
                print(f"签名验证: ✗ 失败")
                
            print("="*60)
        else:
            # 解密失败
            error_msg = response.get('error', 'Unknown error') if response else 'No response'
            print(f"✗ 解密失败: {error_msg}")
    
    else:
        # 不支持的操作
        print(f"✗ 不支持的操作: {operation}")
        print("支持的操作: encrypt, decrypt")
        sys.exit(1)

if __name__ == "__main__":
    main()
