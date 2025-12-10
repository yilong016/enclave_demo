#!/usr/bin/env python3
"""
Enclave 客户端 - 通过 vsock 与 Enclave 通信
"""

import socket
import json


DEFAULT_PORT = 5000
TIMEOUT = 30


class EnclaveClient:
    """Enclave 客户端类"""
    
    def __init__(self, cid, port=DEFAULT_PORT):
        """
        初始化客户端
        
        Args:
            cid: Enclave 的 CID
            port: Enclave 监听的端口
        """
        self.cid = cid
        self.port = port
        self.sock = None
    
    def connect(self):
        """连接到 Enclave"""
        self.sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        self.sock.settimeout(TIMEOUT)
        self.sock.connect((self.cid, self.port))
    
    def close(self):
        """关闭连接"""
        if self.sock:
            self.sock.close()
            self.sock = None
    
    def send_request(self, request):
        """
        发送请求到 Enclave
        
        Args:
            request: 请求字典
            
        Returns:
            响应字典
        """
        if not self.sock:
            raise RuntimeError("Not connected to Enclave")
        
        # 发送请求
        request_bytes = json.dumps(request).encode('utf-8')
        self.sock.sendall(request_bytes)
        
        # 接收响应
        response_bytes = self.sock.recv(8192)
        response = json.loads(response_bytes.decode('utf-8'))
        
        return response
    
    def process_data(self, kms_key_id, sensitive_data, transaction_data):
        """
        请求 Enclave 处理数据（加密和签名）
        
        Args:
            kms_key_id: KMS 密钥 ID
            sensitive_data: 要加密的敏感数据
            transaction_data: 要签名的交易数据
            
        Returns:
            响应字典，包含加密数据和签名
        """
        request = {
            'action': 'process_data',
            'kms_key_id': kms_key_id,
            'sensitive_data': sensitive_data,
            'transaction_data': transaction_data
        }
        
        return self.send_request(request)
