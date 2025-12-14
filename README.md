# Nitro Enclaves KMS 加密签名应用实施方案

## 必需文件清单

在开始之前，确保以下文件已准备好（这些文件应随本文档一起提供）：

### 1. 应用代码文件（必需）
- **kms-enclave-app.py** - Enclave 内运行的主应用
- **kms-client.py** - Parent instance 上的客户端
- **Dockerfile.kms** - Docker 构建文件（包含完整的 Nitro Enclaves SDK 编译流程）
- **requirements.txt** - Python 依赖列表（内容：`boto3`）

### 2. 文档文件（必需）
- **README.md** - 本实施文档

### 3. 文件放置位置
所有文件应放在同一目录下，例如：
```
/home/ec2-user/nitro-kms-demo/
├── kms-enclave-app.py
├── kms-client.py
├── Dockerfile.kms
├── requirements.txt
└── README.md
```

---

## 前置步骤：配置 Enclave 资源分配

在开始之前，需要为 Nitro Enclaves 分配 CPU 和内存资源。

### 1. 编辑 allocator 配置文件
```bash
sudo vim /etc/nitro_enclaves/allocator.yaml
```

配置示例（根据实例规格调整）：
```yaml
# 分配给 enclave 的内存（MB）
memory_mib: 2048

# 分配给 enclave 的 CPU 数量
cpu_count: 4
```

### 2. 终止所有运行中的 enclave
```bash
# 查看运行中的 enclave
nitro-cli describe-enclaves

# 终止 enclave（如果有）
nitro-cli terminate-enclave --enclave-id <enclave-id>
```

### 3. 重启 allocator 服务
```bash
sudo systemctl restart nitro-enclaves-allocator.service
sudo systemctl status nitro-enclaves-allocator.service
```

验证输出应显示：
```
Successfully allocated Nitro Enclaves resources: 2048 MiB, 4 CPUs
```

---

## 项目目标

创建一个 Nitro Enclave 应用，实现安全的文本加密/解密和签名/验证：

### 加密流程
- Parent instance 通过 vsock 向 enclave 发送文本和 AWS credentials
- Enclave 通过 KMS attestation 获取 data key
- 使用 data key 对文本进行 AES-256-GCM 加密和 HMAC-SHA256 签名
- 通过 vsock 返回加密结果、签名和加密的 data key 给 parent instance

### 解密流程
- Parent instance 通过 vsock 向 enclave 发送加密数据、签名、加密的 data key 和 AWS credentials
- Enclave 通过 KMS attestation 解密 data key
- 使用解密的 data key 对数据进行 AES-256-GCM 解密
- 验证 HMAC-SHA256 签名
- 通过 vsock 返回解密结果和签名验证状态给 parent instance

## 技术架构

```
Parent Instance                    Enclave                         KMS
      |                               |                              |
      |---(1) 发送消息+credentials--->|                              |
      |       (vsock)                 |                              |
      |                               |---(2) KMS GenerateDataKey -->|
      |                               |    (通过 vsock-proxy)        |
      |                               |    (附带 attestation doc)    |
      |<--(3) 转发 KMS 请求 ---------|                              |
      |    (vsock-proxy)              |                              |
      |----------------------------------(4) 转发到 KMS ------------->|
      |                               |                              |
      |<---------------------------------(5) 返回加密的 data key ----|
      |                               |                              |
      |---(6) 返回到 enclave -------->|                              |
      |                               |                              |
      |                               |---(7) 解密 data key          |
      |                               |    (kmstool 自动完成)        |
      |                               |                              |
      |                               |---(8) 加密文本 (AES-256-GCM) |
      |                               |                              |
      |                               |---(9) 签名文本 (HMAC-SHA256) |
      |                               |                              |
      |<--(10) 返回结果 (vsock)-------|                              |
```

## 关键技术点

### 1. **vsock 通信**
- **单连接双向通信**：使用一条 vsock 连接完成请求-响应
- **工作流程**：
  1. kms-client.py 连接到 enclave:5000
  2. 发送 JSON payload：`{"message": "...", "credentials": {...}}`
  3. 调用 `sock.shutdown(socket.SHUT_WR)` 表示发送完成
  4. 等待接收 enclave 的 JSON 响应
  5. enclave 在同一连接上返回结果

### 2. **vsock-proxy (KMS Proxy)**
- **作用**：Enclave 无网络访问，必须通过 parent instance 的 vsock-proxy 与 KMS 通信
- **位置**：运行在 parent instance 上
- **配置**：`vsock-proxy 8000 kms.us-east-1.amazonaws.com 443`

### 3. **kmstool_enclave_cli 工作原理**

`kmstool_enclave_cli` 是 AWS Nitro Enclaves SDK 提供的工具，支持以下 KMS 操作：

#### 支持的命令：
1. **genkey** - 生成新的 data key
2. **decrypt** - 解密已加密的 data key
3. **generate-random** - 生成随机数

#### genkey 命令流程：
1. **生成临时密钥对**
   - 调用 NSM (Nitro Security Module) API (`/dev/nsm`)
   - 生成 RSA 密钥对（公钥 + 私钥）
   - 私钥保存在 enclave 内存中，永不离开 enclave

2. **构造 Attestation Document**
   - 包含 PCR 值（PCR0-PCR8）
   - 包含上述生成的公钥
   - 由 Nitro Hypervisor 签名

3. **调用 KMS GenerateDataKey**
   - 使用 `Recipient` 参数传递 attestation document
   - KMS 验证 Nitro 签名和 PCR 值
   - KMS 返回两份加密的 data key：
     - `CiphertextBlob`：用 KMS key 加密
     - `CiphertextForRecipient`：用 enclave 公钥加密

4. **解密 Data Key**
   - 用内存中的私钥解密 `CiphertextForRecipient`
   - 输出明文 data key（PLAINTEXT 字段）和加密的 data key（CIPHERTEXT 字段）

#### decrypt 命令流程：
1. **生成临时密钥对**（同 genkey）
2. **构造 Attestation Document**（同 genkey）
3. **调用 KMS Decrypt**
   - 传递 `CiphertextBlob`（加密的 data key）
   - 使用 `Recipient` 参数传递 attestation document
   - KMS 验证 attestation document 和 PCR 值
4. **返回解密的 Data Key**
   - 输出明文 data key（PLAINTEXT 字段）

#### 输出格式：
```
CIPHERTEXT: <base64 encoded CiphertextBlob>  # 仅 genkey 命令
PLAINTEXT: <base64 encoded data key>         # 两个命令都有
```

#### 关键优势：
- **自动化**：无需手动处理密钥对生成、attestation 构造、解密等复杂逻辑
- **安全性**：私钥永不离开 enclave 内存
- **简单性**：应用代码只需解析输出的 PLAINTEXT 字段

### 4. **PCR 值和 Attestation**
- **PCR (Platform Configuration Register)**：enclave 的测量值，用于验证 enclave 的完整性
- **重要**：每次修改代码重新构建，PCR 值会变化，需要更新 KMS key policy
- **Debug 模式**：PCR 值全为 0，无法通过 attestation，仅用于开发调试

---

## 实施步骤

### 阶段 1: 环境准备

#### 1.1 安装依赖
```bash
pip3 install -r requirements.txt --user
```

#### 1.2 创建 KMS Key
```bash
aws kms create-key --description "Nitro Enclaves Demo Key" --region us-east-1
```

记录返回的 KeyId（示例：`c6fb2925-469d-447e-923f-a9332c3bd32f`）

#### 1.3 确认 IAM Role
确保 EC2 实例有 IAM role，包含以下权限：
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "arn:aws:kms:us-east-1:<account-id>:key/<key-id>"
    }
  ]
}
```

---

### 阶段 2: 构建 Enclave 镜像

#### 2.1 构建 Docker 镜像
```bash
export KMS_KEY_ID="<your-kms-key-id>"
docker build -t kms-enclave-app -f Dockerfile.kms --build-arg KMS_KEY_ID=$KMS_KEY_ID .
```

**注意**：首次构建需要几分钟，编译整个 Nitro Enclaves SDK。

#### 2.2 构建 EIF 并记录 PCR 值
```bash
nitro-cli build-enclave --docker-uri kms-enclave-app --output-file kms-enclave.eif
```

记录输出的 PCR0, PCR1, PCR2 值，用于配置 KMS key policy。

---

### 阶段 3: 配置 KMS Key Policy

#### 3.1 创建 KMS key policy
```bash
cat > /tmp/kms-key-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Enable IAM User Permissions",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<account-id>:root"
      },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "Enable Enclave to use KMS",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<account-id>:role/<role-name>"
      },
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "*",
      "Condition": {
        "StringEqualsIgnoreCase": {
          "kms:RecipientAttestation:PCR0": "<PCR0-value>",
          "kms:RecipientAttestation:PCR1": "<PCR1-value>",
          "kms:RecipientAttestation:PCR2": "<PCR2-value>"
        }
      }
    }
  ]
}
EOF
```

替换 `<account-id>`, `<role-name>`, `<PCR0-value>`, `<PCR1-value>`, `<PCR2-value>`。

#### 3.2 应用 policy
```bash
aws kms put-key-policy --key-id <your-kms-key-id> --policy-name default --policy file:///tmp/kms-key-policy.json
```

---

### 阶段 4: 运行应用

#### 4.1 启动 vsock-proxy
```bash
vsock-proxy 8000 kms.us-east-1.amazonaws.com 443 &
```

#### 4.2 启动 Enclave
```bash
# Debug 模式（可查看日志）
nitro-cli run-enclave --eif-path kms-enclave.eif --cpu-count 4 --memory 2048 --debug-mode

# 生产模式（真实 attestation）
nitro-cli run-enclave --eif-path kms-enclave.eif --cpu-count 4 --memory 2048
```

#### 4.3 获取 Enclave CID
```bash
ENCLAVE_CID=$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveCID')
echo "Enclave CID: $ENCLAVE_CID"
```

#### 4.4 运行客户端测试

**加密测试：**
```bash
python3 kms-client-full.py $ENCLAVE_CID 5000 encrypt "Hello, this is a secret message!"
```

**解密测试：**
```bash
# 使用加密测试返回的结果
python3 kms-client-full.py $ENCLAVE_CID 5000 decrypt <ENCRYPTED> <SIGNATURE> <CIPHERTEXT_BLOB>
```

#### 4.5 查看结果

**加密结果：**
```
============================================================
加密和签名结果:
============================================================
原文: Hello, this is a secret message!
加密结果 (Base64): <encrypted-data>
签名 (Base64): <hmac-signature>
加密的 Data Key (Base64): <ciphertext-blob>
============================================================

保存以下信息用于解密:
ENCRYPTED=<encrypted-data>
SIGNATURE=<hmac-signature>
CIPHERTEXT_BLOB=<ciphertext-blob>
```

**解密结果：**
```
============================================================
解密和验证结果:
============================================================
解密结果: Hello, this is a secret message!
签名验证: ✓ 通过
============================================================
```

#### 4.6 查看 Enclave 日志（Debug 模式）
```bash
nitro-cli console --enclave-id $(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')
```

---

## 故障排查

### 问题 1: KMS 返回 AccessDenied
**原因**：
- IAM role 权限不足
- KMS key policy 中的 PCR 值不匹配
- 使用了 debug 模式但 policy 中配置了非零 PCR 值

**解决**：
1. 检查 IAM role 是否附加到 EC2 实例
2. 验证 KMS key policy 中的 PCR 值与 EIF 构建输出的 PCR 值一致
3. Debug 模式测试时，暂时移除 PCR 条件或使用全零 PCR 值

### 问题 2: vsock-proxy 连接失败
**症状**：Enclave 日志显示连接超时

**解决**：
```bash
# 检查 vsock-proxy 是否运行
ps aux | grep vsock-proxy

# 重启 vsock-proxy
pkill vsock-proxy
vsock-proxy 8000 kms.us-east-1.amazonaws.com 443 &
```

### 问题 3: Enclave 启动后立即退出
**排查**：
```bash
# 查看 Nitro Enclaves 日志
sudo tail -100 /var/log/nitro_enclaves/nitro_enclaves.log

# 使用 debug 模式查看详细输出
nitro-cli run-enclave --eif-path kms-enclave.eif --cpu-count 4 --memory 2048 --debug-mode --attach-console
```

### 问题 4: 内存或 CPU 不足
**症状**：`E26 Insufficient memory requested` 或 `No CPUs available`

**解决**：
1. 终止其他运行的 enclave
2. 调整 `/etc/nitro_enclaves/allocator.yaml` 配置
3. 重启 allocator 服务

---

## 文件清单

### 提供的文件（部署前）
- `README.md`: 本实施文档
- `kms-enclave-app.py`: Enclave 应用（支持加密和解密）
- `kms-client.py`: Parent instance 客户端（支持加密和解密）
- `Dockerfile.kms`: Docker 构建文件
- `requirements.txt`: Python 依赖

### 生成的文件（部署后）
- `kms-enclave.eif`: 编译好的 Enclave Image File（由 nitro-cli 构建生成）
- `/tmp/kms-key-policy.json`: KMS key policy 配置（部署时创建）

---

## 项目状态

✅ **已完成并测试通过**
- Docker 镜像构建
- EIF 构建
- KMS key 创建和 policy 配置
- vsock 双向通信
- 完整的加密和签名流程
- **完整的解密和验证签名流程**
- **端到端加密解密测试验证成功**
- **支持中文等 UTF-8 字符**

### 最新测试结果（2025-12-14）
- ✅ 加密功能：正常
- ✅ 解密功能：正常  
- ✅ 签名验证：正常
- ✅ 中文字符支持：正常
- ✅ kmstool_enclave_cli decrypt 命令：正常（参数为 `--ciphertext`）

---

## 📚 参考文档链接

### 项目实施中实际使用的文档

#### KMS 和 Nitro Enclaves 集成（核心）
- [使用 KMS 进行加密认证](https://docs.aws.amazon.com/enclaves/latest/user/kms.html) - **实际使用**：了解 kmstool API 和工作流程
- [GenerateDataKey API](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html) - **实际使用**：确认 Nitro Enclaves 支持和 CiphertextForRecipient 机制
- [Decrypt API](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html) - **实际使用**：确认 kmstool_enclave_cli decrypt 命令支持

#### kmstool_enclave_cli 功能确认
- [KMS 加密认证支持](https://docs.aws.amazon.com/kms/latest/developerguide/cryptographic-attestation.html) - **实际使用**：确认支持的操作（Decrypt, GenerateDataKey, GenerateRandom）
- [KMS 认证调用](https://docs.aws.amazon.com/kms/latest/developerguide/attested-calls.html) - **实际使用**：理解 Recipient 参数和 attestation document 机制

#### 故障排查和监控
- [监控 Nitro Enclaves 请求](https://docs.aws.amazon.com/kms/latest/developerguide/ct-nitro-enclave.html) - **实际使用**：理解 CloudTrail 日志格式，确认 Decrypt 操作记录

#### 条件键和安全策略
- [Nitro Enclaves 条件键](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-nitro-enclave.html) - **实际使用**：配置 KMS key policy 的 PCR 条件

### 其他有用的参考文档

#### 概念和架构理解
- [AWS Nitro Enclaves 用户指南](https://docs.aws.amazon.com/enclaves/latest/user/)
- [Nitro Enclaves 概念和架构](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-concepts.html)
- [AWS Nitro Enclaves SDK GitHub](https://github.com/aws/aws-nitro-enclaves-sdk-c)

#### 示例和最佳实践
- [KMS Tool 示例应用](https://docs.aws.amazon.com/enclaves/latest/user/hello-kms.html)
- [Enclave 工作流程概述](https://docs.aws.amazon.com/enclaves/latest/user/flow.html)
