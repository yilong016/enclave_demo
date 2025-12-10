#!/usr/bin/env python3
"""
Enclave 应用程序 - 使用 KMS GenerateDataKey with Recipient
演示如何在 Enclave 中安全获取 data key，确保 Parent Instance 无法获得明文
"""

import socket
import json
import base64
import sys
import traceback
import hashlib
import hmac
import boto3
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os

# Nitro Enclaves SDK
try:
    import aws_nitro_enclaves_sdk_python as ne_sdk
except ImportError:
    print("[ERROR] aws-nitro-enclaves-sdk-python not installed")
    sys.exit(1)

PORT = 5000
REGION = "us-east-1"


def encrypt_data_with_key(plaintext_data_key, data):
    """
    使用 data key 加密数据（AES-256-GCM）
    
    Args:
        plaintext_data_key: 32字节的 AES-256 密钥
        data: 要加密的数据（字符串或字节）
    
    Returns:
        dict: 包含 iv, ciphertext, tag
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # 生成随机 IV
    iv = os.urandom(12)  # GCM 推荐 12 字节
    
    # 创建加密器
    cipher = Cipher(
        algorithms.AES(plaintext_data_key),
        modes.GCM(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # 加密
    ciphertext = encryptor.update(data) + encryptor.finalize()
    
    return {
        'iv': iv,
        'ciphertext': ciphertext,
        'tag': encryptor.tag
    }


def sign_transaction_with_key(plaintext_data_key, transaction_data):
    """
    使用 data key 对交易数据进行 HMAC-SHA256 签名
    
    Args:
        plaintext_data_key: 32字节的密钥
        transaction_data: 交易数据（字符串或字节）
    
    Returns:
        bytes: HMAC 签名
    """
    if isinstance(transaction_data, str):
        transaction_data = transaction_data.encode('utf-8')
    
    # 使用 HMAC-SHA256
    signature = hmac.new(
        plaintext_data_key,
        transaction_data,
        hashlib.sha256
    ).digest()
    
    return signature


def generate_data_key_with_recipient(kms_key_id):
    """
    使用 Recipient 参数调用 KMS GenerateDataKey
    返回加密的 data key，只有 Enclave 能解密
    """
    print(f"[INFO] Generating attestation document...")
    
    # 生成 Attestation Document
    # SDK 会自动生成临时密钥对并包含在 attestation 中
    attestation_doc = ne_sdk.generate_attestation_document()
    
    print(f"[INFO] Attestation document generated (length: {len(attestation_doc)} bytes)")
    
    # 创建 KMS 客户端
    kms_client = boto3.client('kms', region_name=REGION)
    
    print(f"[INFO] Calling KMS GenerateDataKey with Recipient...")
    
    try:
        response = kms_client.generate_data_key(
            KeyId=kms_key_id,
            KeySpec='AES_256',
            Recipient={
                'KeyEncryptionAlgorithm': 'RSAES_OAEP_SHA_256',
                'AttestationDocument': attestation_doc
            }
        )
        
        print(f"[INFO] KMS GenerateDataKey successful")
        
        # 返回值：
        # - CiphertextForRecipient: 用 Enclave 公钥加密的 data key
        # - CiphertextBlob: 用 KMS 密钥加密的 data key（供存储）
        # - Plaintext: 空（因为使用了 Recipient）
        
        ciphertext_for_recipient = response.get('CiphertextForRecipient')
        ciphertext_blob = response.get('CiphertextBlob')
        plaintext = response.get('Plaintext')
        
        print(f"[INFO] CiphertextForRecipient length: {len(ciphertext_for_recipient)} bytes")
        print(f"[INFO] CiphertextBlob length: {len(ciphertext_blob)} bytes")
        print(f"[INFO] Plaintext: {'EMPTY (as expected)' if not plaintext else 'UNEXPECTED!'}")
        
        # 解密 CiphertextForRecipient 得到明文 data key
        print(f"[INFO] Decrypting data key with Enclave private key...")
        plaintext_data_key = ne_sdk.decrypt_ciphertext_for_recipient(ciphertext_for_recipient)
        
        print(f"[INFO] Data key decrypted successfully (length: {len(plaintext_data_key)} bytes)")
        
        return {
            'plaintext_data_key': plaintext_data_key,
            'ciphertext_for_recipient': ciphertext_for_recipient,
            'ciphertext_blob': ciphertext_blob,
            'key_id': response['KeyId']
        }
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_msg = e.response['Error']['Message']
        print(f"[ERROR] KMS API error: {error_code} - {error_msg}")
        raise
    except Exception as e:
        print(f"[ERROR] Unexpected error: {str(e)}")
        traceback.print_exc()
        raise


def handle_request(data, kms_key_id):
    """处理来自 Parent 的请求"""
    action = data.get('action')
    
    if action == 'process_data':
        print(f"[INFO] Received process_data request")
        
        # 获取要处理的数据
        sensitive_data = data.get('sensitive_data', 'Default sensitive data')
        transaction_data = data.get('transaction_data', 'Default transaction')
        
        print(f"[INFO] Sensitive data: {sensitive_data[:50]}...")
        print(f"[INFO] Transaction data: {transaction_data[:50]}...")
        
        # 1. 生成 data key
        print(f"[INFO] Step 1: Generating data key...")
        result = generate_data_key_with_recipient(kms_key_id)
        plaintext_data_key = result['plaintext_data_key']
        
        # 2. 使用 data key 加密敏感数据
        print(f"[INFO] Step 2: Encrypting sensitive data...")
        encrypted = encrypt_data_with_key(plaintext_data_key, sensitive_data)
        
        # 3. 使用 data key 签名交易数据
        print(f"[INFO] Step 3: Signing transaction data...")
        signature = sign_transaction_with_key(plaintext_data_key, transaction_data)
        
        # 4. 清除内存中的明文 data key
        plaintext_data_key = None
        print(f"[INFO] Step 4: Plaintext data key cleared from memory")
        
        # 返回响应
        return {
            'status': 'success',
            'encrypted_data': {
                'iv': base64.b64encode(encrypted['iv']).decode('utf-8'),
                'ciphertext': base64.b64encode(encrypted['ciphertext']).decode('utf-8'),
                'tag': base64.b64encode(encrypted['tag']).decode('utf-8')
            },
            'transaction_signature': base64.b64encode(signature).decode('utf-8'),
            'ciphertext_blob': base64.b64encode(result['ciphertext_blob']).decode('utf-8'),
            'key_id': result['key_id'],
            'message': 'Data encrypted and transaction signed successfully in Enclave'
        }
    else:
        return {
            'status': 'error',
            'message': f'Unknown action: {action}'
        }


def main():
    """主函数"""
    print("[INFO] Enclave server starting...")
    print(f"[INFO] Listening on port {PORT}")
    
    # 从环境变量或文件读取 KMS 密钥 ID
    # 在实际部署中，可以通过 vsock 从 Parent 传入
    kms_key_id = None
    
    # 创建 vsock 服务器
    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    sock.bind((socket.VMADDR_CID_ANY, PORT))
    sock.listen(1)
    
    print("[INFO] Waiting for connections...")
    
    while True:
        try:
            conn, addr = sock.accept()
            print(f"[INFO] Client connected from CID: {addr[0]}")
            
            # 接收数据
            data_bytes = conn.recv(4096)
            if not data_bytes:
                print("[WARN] No data received")
                conn.close()
                continue
            
            data = json.loads(data_bytes.decode('utf-8'))
            print(f"[INFO] Received request: {data.get('action')}")
            
            # 如果是第一次请求，获取 KMS 密钥 ID
            if not kms_key_id and 'kms_key_id' in data:
                kms_key_id = data['kms_key_id']
                print(f"[INFO] KMS Key ID set to: {kms_key_id}")
            
            if not kms_key_id:
                response = {
                    'status': 'error',
                    'message': 'KMS key ID not provided'
                }
            else:
                # 处理请求
                response = handle_request(data, kms_key_id)
            
            # 发送响应
            response_bytes = json.dumps(response).encode('utf-8')
            conn.sendall(response_bytes)
            
            print(f"[INFO] Response sent to client")
            conn.close()
            
        except KeyboardInterrupt:
            print("\n[INFO] Shutting down...")
            break
        except Exception as e:
            print(f"[ERROR] Error handling request: {str(e)}")
            traceback.print_exc()
            try:
                error_response = {
                    'status': 'error',
                    'message': str(e)
                }
                conn.sendall(json.dumps(error_response).encode('utf-8'))
                conn.close()
            except:
                pass
    
    sock.close()
    print("[INFO] Server stopped")


if __name__ == '__main__':
    main()
