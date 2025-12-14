#!/usr/bin/env python3
"""
Nitro Enclave KMS 加密解密应用

这个应用运行在 AWS Nitro Enclave 内部，提供安全的文本加密/解密和签名/验证功能。
通过 vsock 与 parent instance 通信，使用 KMS attestation 获取和解密 data key。

主要功能：
1. 加密操作：生成 data key，加密文本，生成签名
2. 解密操作：解密 data key，解密文本，验证签名

安全特性：
- 运行在隔离的 enclave 环境中
- 通过 KMS attestation 验证 enclave 身份
- data key 仅在 enclave 内存中存在
- 支持 AES-256-GCM 加密和 HMAC-SHA256 签名
"""

import socket
import sys
import json
import base64
import subprocess
import os

print("=== Enclave 应用启动 ===", flush=True)
print(f"Python 版本: {sys.version}", flush=True)

# 导入加密库
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import hashes, hmac
    from cryptography.hazmat.backends import default_backend
    print("✓ cryptography 库加载成功", flush=True)
except Exception as e:
    print(f"✗ cryptography 库加载失败: {e}", flush=True)
    sys.exit(1)

# KMS Proxy 端口配置
# vsock-proxy 在 parent instance 上监听此端口，转发 KMS 请求
KMS_PROXY_PORT = 8000

def get_data_key_from_kms(key_id, credentials, region="us-east-1"):
    """
    通过 kmstool_enclave_cli 从 KMS 获取新的 data key
    
    工作流程：
    1. 调用 kmstool_enclave_cli genkey 命令
    2. kmstool 自动生成 attestation document
    3. 通过 vsock-proxy 调用 KMS GenerateDataKey API
    4. KMS 验证 attestation document 和 PCR 值
    5. 返回明文 data key 和加密的 data key
    
    Args:
        key_id: KMS key ID
        credentials: AWS credentials (access_key_id, secret_access_key, session_token)
        region: AWS 区域
        
    Returns:
        tuple: (明文 data key bytes, 加密的 data key base64 string) 或 (None, None)
    """
    print(f"开始调用 KMS GenerateDataKey，Key ID: {key_id}", flush=True)
    try:
        # 构造 kmstool_enclave_cli genkey 命令
        cmd = [
            "/usr/bin/kmstool_enclave_cli",
            "genkey",                                    # 生成新的 data key
            "--region", region,                          # AWS 区域
            "--proxy-port", str(KMS_PROXY_PORT),        # vsock-proxy 端口
            "--aws-access-key-id", credentials["access_key_id"],
            "--aws-secret-access-key", credentials["secret_access_key"],
            "--aws-session-token", credentials["session_token"],
            "--key-id", key_id,                         # KMS key ID
            "--key-spec", "AES-256"                     # 生成 256 位 AES key
        ]
        
        print(f"执行 KMS GenerateDataKey 调用...", flush=True)
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"✗ KMS 调用失败，返回码: {result.returncode}", flush=True)
            print(f"stderr: {result.stderr}", flush=True)
            return None, None
        
        print(f"✓ KMS GenerateDataKey 调用成功", flush=True)
        
        # 解析 kmstool 输出格式
        # PLAINTEXT: <base64_encoded_data_key>     # 明文 data key
        # CIPHERTEXT: <base64_encoded_ciphertext>  # 加密的 data key (CiphertextBlob)
        plaintext_b64 = None
        ciphertext_b64 = None
        
        for line in result.stdout.split('\n'):
            if line.startswith('PLAINTEXT:'):
                plaintext_b64 = line.split(':', 1)[1].strip()
            elif line.startswith('CIPHERTEXT:'):
                ciphertext_b64 = line.split(':', 1)[1].strip()
        
        if not plaintext_b64:
            print("✗ 未找到 PLAINTEXT 字段", flush=True)
            return None, None
            
        if not ciphertext_b64:
            print("✗ 未找到 CIPHERTEXT 字段", flush=True)
            return None, None
        
        # 解码明文 data key
        data_key = base64.b64decode(plaintext_b64)
        print(f"✓ Data key 解码成功，长度: {len(data_key)} 字节", flush=True)
        return data_key, ciphertext_b64
        
    except Exception as e:
        print(f"✗ 获取 data key 异常: {e}", flush=True)
        import traceback
        traceback.print_exc()
        return None, None

def decrypt_data_key_from_kms(ciphertext_blob, credentials, region="us-east-1"):
    """
    通过 kmstool_enclave_cli 从 KMS 解密 data key
    
    工作流程：
    1. 调用 kmstool_enclave_cli decrypt 命令
    2. kmstool 自动生成 attestation document
    3. 通过 vsock-proxy 调用 KMS Decrypt API
    4. KMS 验证 attestation document 和 PCR 值
    5. 返回解密后的明文 data key
    
    Args:
        ciphertext_blob: 加密的 data key (base64 编码)
        credentials: AWS credentials
        region: AWS 区域
        
    Returns:
        bytes: 解密后的明文 data key 或 None
    """
    print(f"开始调用 KMS Decrypt", flush=True)
    try:
        # 构造 kmstool_enclave_cli decrypt 命令
        cmd = [
            "/usr/bin/kmstool_enclave_cli",
            "decrypt",                                   # 解密操作
            "--region", region,
            "--proxy-port", str(KMS_PROXY_PORT),
            "--aws-access-key-id", credentials["access_key_id"],
            "--aws-secret-access-key", credentials["secret_access_key"],
            "--aws-session-token", credentials["session_token"],
            "--ciphertext", ciphertext_blob             # 注意：参数名是 --ciphertext，不是 --ciphertext-blob
        ]
        
        print(f"执行 KMS Decrypt 调用...", flush=True)
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"✗ KMS Decrypt 调用失败，返回码: {result.returncode}", flush=True)
            print(f"stderr: {result.stderr}", flush=True)
            return None
        
        print(f"✓ KMS Decrypt 调用成功", flush=True)
        
        # 解析 kmstool 输出格式: PLAINTEXT: <base64_encoded_data_key>
        for line in result.stdout.split('\n'):
            if line.startswith('PLAINTEXT:'):
                plaintext_b64 = line.split(':', 1)[1].strip()
                break
        else:
            print("✗ 未找到 PLAINTEXT 字段", flush=True)
            return None
        
        # 解码明文 data key
        data_key = base64.b64decode(plaintext_b64)
        print(f"✓ Data key 解密成功，长度: {len(data_key)} 字节", flush=True)
        return data_key
        
    except Exception as e:
        print(f"✗ 解密 data key 异常: {e}", flush=True)
        import traceback
        traceback.print_exc()
        return None

def encrypt_text(plaintext, data_key):
    """
    使用 AES-256-GCM 加密文本
    
    AES-GCM 提供：
    - 机密性：数据加密
    - 完整性：认证标签防止篡改
    - 随机性：每次加密使用不同的 IV
    
    Args:
        plaintext: 要加密的文本
        data_key: 256 位 AES 密钥
        
    Returns:
        str: base64 编码的加密数据 (IV + Tag + Ciphertext)
    """
    print("开始加密文本", flush=True)
    
    # 生成 12 字节随机 IV (推荐的 GCM IV 长度)
    iv = os.urandom(12)
    
    # 创建 AES-GCM 加密器
    cipher = Cipher(algorithms.AES(data_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # 加密文本 (UTF-8 编码)
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    
    # 组合结果: IV (12 bytes) + Tag (16 bytes) + Ciphertext
    # 这样接收方可以提取各个部分进行解密
    result = base64.b64encode(iv + encryptor.tag + ciphertext).decode()
    print("✓ 加密完成", flush=True)
    return result

def sign_text(plaintext, data_key):
    """
    使用 HMAC-SHA256 签名文本
    
    HMAC 提供：
    - 消息认证：验证消息未被篡改
    - 身份认证：验证消息来源
    - 不可否认性：发送方无法否认发送过消息
    
    Args:
        plaintext: 要签名的文本
        data_key: HMAC 密钥 (与加密使用同一个 data key)
        
    Returns:
        str: base64 编码的 HMAC 签名
    """
    print("开始签名文本", flush=True)
    
    # 创建 HMAC-SHA256 签名器
    h = hmac.HMAC(data_key, hashes.SHA256(), backend=default_backend())
    
    # 对文本进行签名 (UTF-8 编码)
    h.update(plaintext.encode())
    signature = h.finalize()
    
    result = base64.b64encode(signature).decode()
    print("✓ 签名完成", flush=True)
    return result

def decrypt_text(encrypted_data_b64, data_key):
    """
    使用 AES-256-GCM 解密文本
    
    Args:
        encrypted_data_b64: base64 编码的加密数据 (IV + Tag + Ciphertext)
        data_key: 256 位 AES 密钥
        
    Returns:
        str: 解密后的文本 或 None (如果解密失败)
    """
    print("开始解密文本", flush=True)
    try:
        # 解码 base64 数据
        encrypted_data = base64.b64decode(encrypted_data_b64)
        
        # 提取各个部分
        iv = encrypted_data[:12]        # 前 12 字节是 IV
        tag = encrypted_data[12:28]     # 接下来 16 字节是认证标签
        ciphertext = encrypted_data[28:] # 剩余部分是密文
        
        # 创建 AES-GCM 解密器
        cipher = Cipher(algorithms.AES(data_key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # 解密并验证认证标签
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # 解码为 UTF-8 文本
        result = plaintext.decode()
        print("✓ 解密完成", flush=True)
        return result
        
    except Exception as e:
        print(f"✗ 解密失败: {e}", flush=True)
        return None

def verify_signature(plaintext, signature_b64, data_key):
    """
    使用 HMAC-SHA256 验证签名
    
    Args:
        plaintext: 原始文本
        signature_b64: base64 编码的签名
        data_key: HMAC 密钥
        
    Returns:
        bool: 签名验证结果 (True=通过, False=失败)
    """
    print("开始验证签名", flush=True)
    try:
        # 解码签名
        signature = base64.b64decode(signature_b64)
        
        # 创建 HMAC-SHA256 验证器
        h = hmac.HMAC(data_key, hashes.SHA256(), backend=default_backend())
        h.update(plaintext.encode())
        
        # 验证签名 (如果不匹配会抛出异常)
        h.verify(signature)
        
        print("✓ 签名验证成功", flush=True)
        return True
        
    except Exception as e:
        print(f"✗ 签名验证失败: {e}", flush=True)
        return False

def server_handler(port, key_id):
    """
    Vsock server 处理函数
    
    监听来自 parent instance 的连接，处理加密和解密请求。
    使用 vsock 协议进行安全的本地通信。
    
    Args:
        port: vsock 监听端口
        key_id: KMS key ID
    """
    print(f"准备创建 vsock socket，端口: {port}", flush=True)
    
    # 创建 vsock socket
    # AF_VSOCK: vsock 地址族，用于 parent instance 和 enclave 之间的通信
    # SOCK_STREAM: TCP 类型的可靠连接
    try:
        sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        print("✓ Vsock socket 创建成功", flush=True)
    except Exception as e:
        print(f"✗ Vsock socket 创建失败: {e}", flush=True)
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    # 绑定到指定端口
    # VMADDR_CID_ANY: 接受来自任何 CID 的连接
    try:
        sock.bind((socket.VMADDR_CID_ANY, port))
        print(f"✓ Socket 绑定成功", flush=True)
    except Exception as e:
        print(f"✗ Socket 绑定失败: {e}", flush=True)
        sys.exit(1)
    
    # 开始监听连接
    try:
        sock.listen(128)
        print(f"✓ Socket 监听成功", flush=True)
    except Exception as e:
        print(f"✗ Socket 监听失败: {e}", flush=True)
        sys.exit(1)
    
    print(f"=== Enclave server 已启动，监听端口 {port} ===", flush=True)
    print(f"KMS Key ID: {key_id}", flush=True)
    
    # 主循环：处理客户端连接
    while True:
        try:
            print("等待连接...", flush=True)
            
            # 接受新连接
            conn, (remote_cid, remote_port) = sock.accept()
            print(f"\n✓ 接收到来自 CID {remote_cid} 的连接", flush=True)
            
            # 接收请求数据
            # 使用循环接收所有数据，直到连接关闭
            data = b""
            while True:
                chunk = conn.recv(1024)
                if not chunk:  # 连接关闭
                    break
                data += chunk
            
            # 解析 JSON 请求
            payload = json.loads(data.decode())
            operation = payload.get("operation", "encrypt")  # 默认为加密操作
            credentials = payload["credentials"]
            
            if operation == "encrypt":
                # ========== 加密操作 ==========
                plaintext = payload["message"]
                print(f"加密操作 - 原文: {plaintext}", flush=True)
                print(f"✓ 收到 credentials (Access Key: {credentials['access_key_id'][:10]}...)", flush=True)
                
                # 步骤1: 从 KMS 获取新的 data key
                print("正在从 KMS 获取 data key...", flush=True)
                data_key, ciphertext_blob = get_data_key_from_kms(key_id, credentials)
                
                if not data_key or not ciphertext_blob:
                    print("✗ 无法获取 data key，返回错误", flush=True)
                    error_response = {
                        "error": "Failed to get data key from KMS"
                    }
                    conn.sendall(json.dumps(error_response).encode())
                    conn.close()
                    continue
                
                # 步骤2: 使用 data key 加密文本
                encrypted = encrypt_text(plaintext, data_key)
                print(f"加密结果 (Base64): {encrypted}", flush=True)
                
                # 步骤3: 使用 data key 签名文本
                signature = sign_text(plaintext, data_key)
                print(f"签名 (Base64): {signature}", flush=True)
                
                # 构造加密响应
                response = {
                    "operation": "encrypt",
                    "plaintext": plaintext,
                    "encrypted": encrypted,
                    "signature": signature,
                    "ciphertext_blob": ciphertext_blob  # 返回加密的 data key，用于后续解密
                }
                
            elif operation == "decrypt":
                # ========== 解密操作 ==========
                encrypted_data = payload["encrypted"]
                signature_data = payload["signature"]
                ciphertext_blob = payload["ciphertext_blob"]
                print(f"解密操作 - 加密数据: {encrypted_data[:50]}...", flush=True)
                print(f"✓ 收到 credentials (Access Key: {credentials['access_key_id'][:10]}...)", flush=True)
                
                # 步骤1: 从 KMS 解密 data key
                print("正在从 KMS 解密 data key...", flush=True)
                data_key = decrypt_data_key_from_kms(ciphertext_blob, credentials)
                
                if not data_key:
                    print("✗ 无法解密 data key，返回错误", flush=True)
                    error_response = {
                        "error": "Failed to decrypt data key from KMS"
                    }
                    conn.sendall(json.dumps(error_response).encode())
                    conn.close()
                    continue
                
                # 步骤2: 使用 data key 解密文本
                decrypted_text = decrypt_text(encrypted_data, data_key)
                if not decrypted_text:
                    print("✗ 解密失败，返回错误", flush=True)
                    error_response = {
                        "error": "Failed to decrypt text"
                    }
                    conn.sendall(json.dumps(error_response).encode())
                    conn.close()
                    continue
                
                print(f"解密结果: {decrypted_text}", flush=True)
                
                # 步骤3: 验证签名
                signature_valid = verify_signature(decrypted_text, signature_data, data_key)
                
                # 构造解密响应
                response = {
                    "operation": "decrypt",
                    "decrypted": decrypted_text,
                    "signature_valid": signature_valid
                }
                
            else:
                # 不支持的操作
                print(f"✗ 不支持的操作: {operation}", flush=True)
                error_response = {
                    "error": f"Unsupported operation: {operation}"
                }
                conn.sendall(json.dumps(error_response).encode())
                conn.close()
                continue
            
            # 发送响应回 parent instance
            print("发送结果回 parent instance...", flush=True)
            conn.sendall(json.dumps(response).encode())
            print("✓ 结果已发送", flush=True)
            
            # 关闭连接
            conn.close()
            print("连接已关闭\n", flush=True)
            
        except Exception as e:
            print(f"✗ 处理消息时出错: {e}", flush=True)
            import traceback
            traceback.print_exc()

def main():
    """
    主函数：初始化环境变量并启动 vsock server
    """
    print("进入 main 函数", flush=True)
    
    # 从环境变量获取配置
    port = int(os.environ.get("VSOCK_PORT", "5000"))
    key_id = os.environ.get("KMS_KEY_ID", "")
    
    print(f"环境变量 VSOCK_PORT: {port}", flush=True)
    print(f"环境变量 KMS_KEY_ID: {key_id}", flush=True)
    
    # 验证必需的环境变量
    if not key_id:
        print("✗ 错误: 未设置 KMS_KEY_ID 环境变量", flush=True)
        sys.exit(1)
    
    print("准备启动 server", flush=True)
    server_handler(port, key_id)

if __name__ == "__main__":
    print("脚本开始执行", flush=True)
    try:
        main()
    except Exception as e:
        print(f"✗ 主程序异常: {e}", flush=True)
        import traceback
        traceback.print_exc()
        sys.exit(1)
