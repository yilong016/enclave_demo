# EC2 Enclave KMS Data Key 演示

这是一个极简的 AWS Nitro Enclaves 演示项目，展示如何在隔离的 Enclave 环境中安全地获取 KMS data key，确保 Parent Instance 无法获得明文。

> **⚠️ 部署架构说明**  
> 本项目采用**跳板机 EC2 + Enclave EC2**的部署方式：
> - **跳板机 EC2**：具有管理员权限，用于创建 AWS 资源（KMS、IAM）
> - **Enclave EC2**：通过 SSM Session Manager 登录，用于构建和运行 Enclave
> - **文件传输**：通过 S3 传输 PCR0 和 KMS 密钥 ID
> 
> 这种方式实现了权限分离，更安全且符合最佳实践。

## 项目概述

本项目演示 Nitro Enclaves 的核心安全特性：**使用 KMS Recipient 功能确保 data key 只能在 Enclave 内解密**

### 安全保证

**Data key 明文只在两个地方存在：**
1. **KMS 内部**：生成 data key 时
2. **Enclave 内存**：解密后用于加密/签名操作

**Data key 明文绝不会出现在：**
- ❌ Parent Instance（EC2 主机）
- ❌ 网络传输中
- ❌ 磁盘存储中
- ❌ 日志文件中

### 工作流程

1. **Enclave** 生成 Attestation Document（包含临时公钥）
2. **Enclave** 调用 KMS GenerateDataKey，传入 Attestation
3. **KMS** 验证 Attestation，用其中的公钥加密 data key
4. **KMS** 返回两个加密的 data key：
   - `CiphertextForRecipient`：用 Enclave 临时公钥加密（只能在当前会话解密）
   - `CiphertextBlob`：用 KMS 密钥加密（可持久化，任何时候都能解密）
5. **Enclave** 用私钥解密 `CiphertextForRecipient` 得到明文 data key
6. **Enclave** 使用 data key 加密数据和签名交易
7. **Parent Instance** 存储 `CiphertextBlob` 和加密的数据
8. **Enclave 重启后**：可以用 `CiphertextBlob` 通过 KMS Decrypt 重新获取 data key

### 密钥生命周期

**临时密钥对（Enclave 会话级别）：**
- 每次 Enclave 启动时生成新的密钥对
- 私钥只在 Enclave 内存中，停机后丢失
- `CiphertextForRecipient` 只能在当前会话解密

**Data Key（持久化）：**
- 通过 `CiphertextBlob` 持久化存储
- Enclave 重启后可以通过 KMS Decrypt with Recipient 重新获取
- KMS 会用新的 Enclave 公钥重新加密返回

### 核心特性

- ✅ 极简设计：最少的 AWS 服务和代码
- ✅ 安全保证：Parent Instance 无法获得明文 data key
- ✅ Attestation 验证：KMS 验证 Enclave 身份
- ✅ 权限分离：管理操作和运行操作分离
- ✅ 完整演示：从环境配置到 data key 获取的完整流程

## 架构

```
┌─────────────────────────────────────┐
│   跳板机 EC2（管理员权限）            │
│   - 创建 KMS 密钥                    │
│   - 创建 IAM 角色                    │
│   - 配置密钥策略                     │
└──────────────┬──────────────────────┘
               │ SSM Session Manager
               ▼
┌─────────────────────────────────────┐
│      Enclave EC2 (Parent)           │
│  ┌──────────────────────────────┐   │
│  │   Python Client              │   │
│  │   - 请求 data key             │   │
│  │   - 无法解密明文              │   │
│  └──────────┬───────────────────┘   │
│             │ vsock                  │
│  ┌──────────▼───────────────────┐   │
│  │   Nitro Enclave              │   │
│  │  ┌────────────────────────┐  │   │
│  │  │  Python Server         │  │   │
│  │  │  - 生成 Attestation    │  │   │
│  │  │  - 调用 KMS            │  │   │
│  │  │  - 解密 data key       │  │   │
│  │  └────────────────────────┘  │   │
│  └──────────────────────────────┘   │
└─────────────────────────────────────┘
                 │
                 │ HTTPS
                 ▼
         ┌──────────────┐
         │   AWS KMS    │
         │ GenerateDataKey
         │ with Recipient │
         └──────────────┘
```

## 前置要求

### 跳板机（管理员 EC2）

- AWS CLI 已配置，具有管理员权限
- 可以创建 EC2、KMS、IAM 资源
- 区域：us-east-1

### EC2 实例要求

- **实例类型**: c6i.xlarge 或更高（必须支持 Nitro Enclaves）
- **操作系统**: Amazon Linux 2023
- **区域**: us-east-1
- **存储**: 至少 20 GB
- **访问方式**: SSM Session Manager（无需 SSH 密钥）
- **IAM 角色**: EnclaveInstanceProfile（脚本会创建）

### 必需的 AWS 服务
- EC2 (Nitro Enclaves)
- KMS (对称加密密钥)
- IAM (角色和权限)
- SSM (Session Manager)
- S3 (可选，用于文件传输)

## 项目结构

```
.
├── parent/                      # Parent Instance 应用程序
│   ├── parent_app.py            # 主程序入口
│   ├── enclave_client.py        # Enclave 客户端（vsock 通信）
│   ├── signature_verifier.py   # 签名验证模块
│   └── requirements.txt         # Python 依赖
├── enclave/                     # Enclave 应用程序
│   ├── enclave_app.py           # Enclave 服务器（签名服务）
│   ├── Dockerfile               # Enclave 镜像构建文件
│   └── requirements.txt         # Python 依赖
├── scripts/                     # 部署和管理脚本
│   ├── setup_environment.sh     # 环境配置（Nitro CLI、Docker 等）
│   ├── setup_kms_key.sh         # KMS 密钥创建和配置
│   ├── setup_iam_role.sh        # IAM 角色和权限配置
│   ├── build_enclave.sh         # Enclave 镜像构建
│   ├── start_enclave.sh         # Enclave 启动
│   ├── stop_enclave.sh          # Enclave 停止
│   ├── demo.sh                  # 一键演示脚本
│   └── cleanup.sh               # 资源清理
└── README.md                    # 本文件
```


## 快速开始

### 部署流程概览

```
跳板机操作 → EC2操作 → 跳板机操作 → EC2操作
   (IAM)    (构建)    (KMS)     (运行)
```

### 阶段 1: 在跳板机上创建 IAM 角色

**📍 在本地笔记本执行**

```bash
cd enclave-demo/scripts
./setup_iam_role.sh
```

这会创建：
- IAM 角色：`EnclaveRole`
- IAM 策略：`EnclaveKMSPolicy`（允许使用 KMS 签名）
- 实例配置文件：`EnclaveInstanceProfile`

### 阶段 2: 启动 EC2 实例

**📍 在本地笔记本执行**

方式 1 - 使用 AWS CLI：

```bash
# 获取最新的 Amazon Linux 2023 AMI
AMI_ID=$(aws ec2 describe-images \
    --owners amazon \
    --filters "Name=name,Values=al2023-ami-2023*-x86_64" \
    --query 'Images | sort_by(@, &CreationDate) | [-1].ImageId' \
    --output text \
    --region us-east-1)

# 启动实例
aws ec2 run-instances \
    --image-id $AMI_ID \
    --instance-type c6i.xlarge \
    --iam-instance-profile Name=EnclaveInstanceProfile \
    --enclave-options Enabled=true \
    --region us-east-1 \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=enclave-demo}]'
```

方式 2 - 使用 AWS 控制台：
1. 启动 EC2 实例
2. 实例类型选择：c6i.xlarge
3. AMI 选择：Amazon Linux 2023
4. IAM 角色选择：EnclaveInstanceProfile
5. 高级详细信息 → Nitro Enclave：启用

### 阶段 3: 上传代码到 EC2

**📍 在本地笔记本执行**

方式 1 - 使用 S3（推荐）：

```bash
# 打包代码
tar -czf enclave-demo.tar.gz enclave-demo/

# 上传到 S3
aws s3 cp enclave-demo.tar.gz s3://your-bucket-name/

# 记录 S3 路径，稍后在 EC2 上下载
```

方式 2 - 使用 Git（如果代码在 Git 仓库）：

```bash
# 在 EC2 上直接 git clone（见下一阶段）
```

### 阶段 4: 在 EC2 上配置环境

**📍 通过 SSM 登录 EC2**

```bash
# 在本地笔记本执行，获取实例 ID
INSTANCE_ID=$(aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=enclave-demo" "Name=instance-state-name,Values=running" \
    --query 'Reservations[0].Instances[0].InstanceId' \
    --output text \
    --region us-east-1)

# 通过 SSM 登录
aws ssm start-session --target $INSTANCE_ID --region us-east-1
```

**📍 以下命令在 EC2 上执行**

```bash
# 下载代码（如果使用 S3）
aws s3 cp s3://your-bucket-name/enclave-demo.tar.gz .
tar -xzf enclave-demo.tar.gz

# 或者使用 git clone
# git clone <your-repo-url> enclave-demo

# 进入项目目录
cd enclave-demo/scripts

# 配置环境
./setup_environment.sh

# ⚠️ 重要：退出并重新登录以使用户组权限生效
exit
```

### 阶段 5: 在 EC2 上构建 Enclave 镜像

**📍 重新通过 SSM 登录 EC2**

```bash
# 在本地笔记本执行
aws ssm start-session --target $INSTANCE_ID --region us-east-1
```

**📍 在 EC2 上执行**

```bash
cd enclave-demo/scripts
./build_enclave.sh

# 构建完成后，会显示 PCR0 哈希值，例如：
# PCR0: 1ad18e6babd110fde34f6d57caa22de651cd3110d1f60d005c3f78e6110ffcb69130356f20138ae4d6373f737b842381

# 将 PCR0 上传到 S3（供跳板机使用）
aws s3 cp enclave_pcr0.txt s3://your-bucket-name/
```

### 阶段 6: 在跳板机上创建 KMS 密钥

**📍 在本地笔记本执行**

```bash
# 下载 PCR0 值
aws s3 cp s3://your-bucket-name/enclave_pcr0.txt enclave-demo/

# 创建 KMS 密钥（脚本会自动读取 enclave_pcr0.txt）
cd enclave-demo/scripts
./setup_kms_key.sh

# 将 KMS 密钥 ID 上传到 S3
aws s3 cp kms_key_id.txt s3://your-bucket-name/
```

### 阶段 7: 在 EC2 上运行演示

**📍 通过 SSM 登录 EC2**

```bash
# 在本地笔记本执行
aws ssm start-session --target $INSTANCE_ID --region us-east-1
```

**📍 在 EC2 上执行**

```bash
cd enclave-demo

# 下载 KMS 密钥 ID
aws s3 cp s3://your-bucket-name/kms_key_id.txt .

# 启动 Enclave
./scripts/start_enclave.sh

# 运行演示
cd parent
source ../venv/bin/activate
python parent_app.py --sensitive-data "My credit card: 1234-5678" --transaction "Transfer $100"
```

### 一键演示（环境已配置）

如果所有资源已创建，可以直接运行：

```bash
# 📍 在 EC2 上执行
cd enclave-demo
./scripts/demo.sh
```


激活 Python 虚拟环境并运行客户端：

```bash
cd ../parent
source ../venv/bin/activate
python parent_app.py --message "Hello from Enclave!"
```

#### 步骤 6: 清理资源

停止 Enclave 并清理临时文件：

```bash
cd ../scripts
./cleanup.sh
```

清理选项：
- `./cleanup.sh` - 基本清理（停止 Enclave，清理临时文件）
- `./cleanup.sh --keep-images` - 保留 Docker 镜像和 EIF 文件
- `./cleanup.sh --delete-kms` - 同时删除 KMS 密钥
- `./cleanup.sh --delete-iam` - 同时删除 IAM 角色
- `./cleanup.sh --force` - 不询问确认，直接执行

## 工作流程

1. **Parent Instance** 启动 Enclave 并通过 vsock 建立连接
2. **Parent Instance** 发送待签名的消息到 Enclave
3. **Enclave** 生成 Attestation Document 证明其身份
4. **Enclave** 使用 Attestation 调用 KMS API 进行签名
5. **KMS** 验证 Attestation 并返回签名结果
6. **Enclave** 将签名返回给 Parent Instance
7. **Parent Instance** 使用 KMS 公钥验证签名

## 使用示例

### 基本用法

```bash
# 使用默认消息运行演示
./scripts/demo.sh
```

### 自定义消息

```bash
# 激活虚拟环境
source venv/bin/activate

# 运行 Parent 应用并指定自定义消息
cd parent
python parent_app.py --message "My custom message to sign"

# 指定 Enclave CID（如果不使用默认值）
python parent_app.py --cid 16 --message "Hello Enclave"

# 指定 AWS 区域
python parent_app.py --region us-west-2 --message "Test message"
```

### 预期输出

成功运行时，您应该看到类似以下的输出：

```
=================================
EC2 Nitro Enclave KMS 签名演示
=================================

配置信息:
  Enclave CID: 16
  消息: Hello from EC2 Nitro Enclave Demo!
  区域: us-east-1

步骤 1: 连接到 Enclave
-----------------------------------
✓ 已连接到 Enclave (CID: 16, Port: 5000)

步骤 2: 发送签名请求
-----------------------------------
正在发送消息到 Enclave...
✓ 签名请求已发送

步骤 3: 接收签名结果
-----------------------------------
✓ 收到签名响应
  KMS 密钥 ID: 12345678-1234-1234-1234-123456789012
  签名长度: 256 字节

步骤 4: 验证签名
-----------------------------------
正在获取 KMS 公钥...
✓ 公钥获取成功
正在验证签名...
✓ 签名验证成功！

=================================
演示完成
=================================

签名详情:
  消息: Hello from EC2 Nitro Enclave Demo!
  签名算法: RSASSA_PKCS1_V1_5_SHA_256
  密钥规格: RSA_2048
  验证结果: ✓ 有效

整个流程耗时: 0.85 秒
```

### 查看 Enclave 日志

```bash
# 获取 Enclave ID
ENCLAVE_ID=$(nitro-cli describe-enclaves | grep -oP '"EnclaveID":\s*"\K[^"]+')

# 查看实时日志
nitro-cli console --enclave-id $ENCLAVE_ID

# 预期看到的日志内容：
# [INFO] Enclave server starting on port 5000...
# [INFO] Waiting for connections...
# [INFO] Client connected from CID: 3
# [INFO] Received sign request for message: Hello from EC2 Nitro Enclave Demo!
# [INFO] Generating attestation document...
# [INFO] Calling KMS to sign message...
# [INFO] Signature generated successfully
# [INFO] Sending response to client...
```

## 通信协议

### 签名请求 (Parent → Enclave)
```json
{
    "action": "sign",
    "message": "待签名的消息内容"
}
```

### 签名响应 (Enclave → Parent)
```json
{
    "status": "success",
    "signature": "base64编码的签名",
    "key_id": "KMS密钥ID"
}
```

## 配置说明

### Enclave 资源分配

默认配置（在 `/etc/nitro_enclaves/allocator.yaml`）：
```yaml
cpu_count: 2
memory_mib: 512
```

调整资源分配：
```bash
# 编辑配置文件
sudo nano /etc/nitro_enclaves/allocator.yaml

# 重启分配器服务
sudo systemctl restart nitro-enclaves-allocator.service

# 验证新配置
cat /sys/module/nitro_enclaves/parameters/ne_cpus
cat /sys/module/nitro_enclaves/parameters/ne_mem_size
```

也可以在启动 Enclave 时指定资源：
```bash
# 编辑 scripts/start_enclave.sh
CPU_COUNT=4
MEMORY_MB=1024
```

### KMS 密钥配置

**密钥类型**: SIGN_VERIFY  
**密钥规格**: RSA_2048（默认）或 ECC_NIST_P256  
**签名算法**: RSASSA_PKCS1_V1_5_SHA_256

**密钥策略示例**（包含 Attestation 验证）：
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Enable enclave signing",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::ACCOUNT_ID:role/EnclaveRole"
            },
            "Action": [
                "kms:Sign",
                "kms:GetPublicKey",
                "kms:DescribeKey"
            ],
            "Resource": "*",
            "Condition": {
                "StringEqualsIgnoreCase": {
                    "kms:RecipientAttestation:PCR0": "ENCLAVE_PCR0_HASH"
                }
            }
        }
    ]
}
```

**重要**: PCR0 哈希值必须与 Enclave 镜像的实际哈希值匹配。每次重新构建 Enclave 镜像时，PCR0 值都会改变，需要更新密钥策略。

### vsock 通信配置

**默认端口**: 5000  
**超时时间**: 30 秒  
**重试次数**: 3 次

修改端口号：
```python
# 在 enclave/enclave_app.py 中
PORT = 5000  # 修改为其他端口

# 在 parent/enclave_client.py 中
DEFAULT_PORT = 5000  # 修改为相同端口
```

### 环境变量

可以通过环境变量配置某些参数：

```bash
# AWS 区域
export AWS_DEFAULT_REGION=us-east-1

# KMS 密钥 ID（如果不使用文件）
export KMS_KEY_ID=12345678-1234-1234-1234-123456789012

# Enclave CID（如果不使用文件）
export ENCLAVE_CID=16

# 日志级别
export LOG_LEVEL=DEBUG
```

## 故障排查

### 问题 1: Enclave 启动失败

**症状**: `nitro-cli run-enclave` 命令失败

**可能原因和解决方案**:

1. **实例不支持 Nitro Enclaves**
   ```bash
   # 检查实例类型
   curl -s http://169.254.169.254/latest/meta-data/instance-type
   ```
   确保使用 c6i、m6i、r6i 等支持 Enclaves 的实例类型。

2. **资源分配不足**
   ```bash
   # 检查资源分配器状态
   sudo systemctl status nitro-enclaves-allocator.service
   
   # 查看可用资源
   cat /sys/module/nitro_enclaves/parameters/ne_cpus
   cat /sys/module/nitro_enclaves/parameters/ne_mem_size
   ```
   如果资源不足，编辑 `/etc/nitro_enclaves/allocator.yaml` 并重启服务。

3. **权限问题**
   ```bash
   # 确认用户在 ne 组中
   groups
   ```
   如果不在，运行 `sudo usermod -aG ne $USER` 并重新登录。

4. **查看详细错误日志**
   ```bash
   # 查看 Enclave 控制台输出
   nitro-cli console --enclave-id <ENCLAVE_ID>
   
   # 查看系统日志
   sudo journalctl -u nitro-enclaves-allocator.service
   ```

### 问题 2: KMS 签名失败

**症状**: Enclave 返回 KMS 签名错误

**可能原因和解决方案**:

1. **IAM 角色未附加或权限不足**
   ```bash
   # 检查实例配置文件
   curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
   
   # 验证角色权限
   aws iam get-role-policy --role-name EnclaveRole --policy-name EnclaveKMSPolicy
   ```
   确保 EC2 实例附加了 `EnclaveInstanceProfile`。

2. **KMS 密钥策略配置错误**
   ```bash
   # 查看密钥策略
   aws kms get-key-policy --key-id <KEY_ID> --policy-name default
   ```
   确认策略中包含 Enclave 角色和正确的 Attestation 条件。

3. **Attestation Document 验证失败**
   ```bash
   # 检查 Enclave PCR0 哈希
   cat enclave_pcr0.txt
   
   # 对比密钥策略中的哈希值
   aws kms get-key-policy --key-id <KEY_ID> --policy-name default | grep PCR0
   ```
   如果哈希不匹配，需要更新密钥策略或重新构建 Enclave。

4. **网络连接问题**
   ```bash
   # 在 Parent Instance 测试 KMS 连接
   aws kms describe-key --key-id <KEY_ID> --region us-east-1
   ```
   确保 EC2 实例可以访问 KMS 服务。

### 问题 3: vsock 通信失败

**症状**: Parent 应用无法连接到 Enclave

**可能原因和解决方案**:

1. **Enclave 未启动或已停止**
   ```bash
   # 检查 Enclave 状态
   nitro-cli describe-enclaves
   ```
   如果没有输出，说明 Enclave 未运行，需要重新启动。

2. **CID 不正确**
   ```bash
   # 获取正确的 CID
   cat enclave_cid.txt
   
   # 或从 describe-enclaves 输出中获取
   nitro-cli describe-enclaves | grep EnclaveCID
   ```
   确保 Parent 应用使用正确的 CID。

3. **端口号不匹配**
   - Enclave 监听端口：5000（在 `enclave/enclave_app.py` 中定义）
   - Parent 连接端口：5000（在 `parent/enclave_client.py` 中定义）
   
   确保两边使用相同的端口号。

4. **Enclave 应用崩溃**
   ```bash
   # 查看 Enclave 日志
   nitro-cli console --enclave-id <ENCLAVE_ID>
   ```
   检查是否有 Python 错误或其他异常。

### 问题 4: 签名验证失败

**症状**: Parent 应用报告签名验证失败

**可能原因和解决方案**:

1. **消息内容不一致**
   - 确保签名的消息和验证的消息完全相同
   - 检查字符编码（应该都是 UTF-8）

2. **公钥获取失败**
   ```bash
   # 测试获取公钥
   aws kms get-public-key --key-id <KEY_ID> --region us-east-1
   ```

3. **签名格式错误**
   - 确认签名是 Base64 编码的
   - 检查签名算法（应该是 RSASSA_PKCS1_V1_5_SHA_256）

### 问题 5: Python 依赖问题

**症状**: 导入模块失败

**解决方案**:

```bash
# 重新创建虚拟环境
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r parent/requirements.txt

# 对于 Enclave，重新构建镜像
./scripts/build_enclave.sh
```

### 获取帮助

如果问题仍未解决：

1. **查看完整日志**
   ```bash
   # Enclave 日志
   nitro-cli console --enclave-id <ENCLAVE_ID>
   
   # 系统日志
   sudo journalctl -xe
   ```

2. **检查 AWS 服务状态**
   - 访问 [AWS Service Health Dashboard](https://status.aws.amazon.com/)

3. **参考官方文档**
   - [AWS Nitro Enclaves 故障排查](https://docs.aws.amazon.com/enclaves/latest/user/troubleshooting.html)
   - [AWS KMS 故障排查](https://docs.aws.amazon.com/kms/latest/developerguide/troubleshooting.html)

## 安全考虑

### Attestation 验证

- **PCR0 验证**: KMS 密钥策略验证 Enclave 的 PCR0 哈希值，确保只有特定的 Enclave 镜像可以访问密钥
- **动态 Attestation**: 每次签名请求都会生成新的 Attestation Document
- **防篡改**: Enclave 镜像的任何修改都会导致 PCR0 值改变，从而无法通过 KMS 验证

### 网络隔离

- **vsock 通信**: Enclave 只能通过 vsock 与 Parent Instance 通信，无法直接访问网络
- **代理访问**: Enclave 通过 Parent Instance 的网络代理访问 AWS KMS
- **无入站连接**: Enclave 不接受来自外部的网络连接

### 最小权限原则

- **IAM 角色**: 仅授予 `kms:Sign`、`kms:GetPublicKey` 和 `kms:DescribeKey` 权限
- **密钥策略**: 限制只能使用特定的 KMS 密钥
- **条件访问**: 通过 Attestation 条件限制访问

### 数据保护

- **内存隔离**: Enclave 内存与 Parent Instance 完全隔离
- **无持久化**: Enclave 不保存任何敏感数据到磁盘
- **临时密钥**: 不在 Enclave 中存储长期密钥

### 生产环境建议

1. **启用 Attestation 验证**: 确保 KMS 密钥策略包含 PCR0 条件
2. **使用专用密钥**: 为每个应用创建独立的 KMS 密钥
3. **监控和审计**: 启用 CloudTrail 记录所有 KMS API 调用
4. **定期更新**: 及时更新 Nitro Enclaves CLI 和依赖包
5. **禁用调试模式**: 生产环境不要使用 `--debug-mode` 启动 Enclave
6. **限制访问**: 使用 IAM 策略限制谁可以启动和管理 Enclave

## 性能指标

- **vsock 通信延迟**: < 1ms（本地通信）
- **KMS 签名延迟**: 50-200ms（取决于网络和 KMS 服务响应时间）
- **Attestation 生成**: 10-50ms
- **签名验证**: < 10ms（本地验证）
- **总体响应时间**: < 500ms（端到端）

### 性能优化建议

1. **连接复用**: 保持 vsock 连接打开，避免频繁建立连接
2. **批量处理**: 如果需要签名多个消息，可以修改协议支持批量请求
3. **异步处理**: 使用异步 I/O 提高并发处理能力
4. **资源调整**: 根据负载调整 Enclave 的 CPU 和内存分配

## 限制和注意事项

### 技术限制

1. **实例类型**: 只有特定的 EC2 实例类型支持 Nitro Enclaves（c6i、m6i、r6i 等）
2. **资源限制**: Enclave 最多可以使用主机 50% 的 vCPU 和内存
3. **网络限制**: Enclave 无法直接访问网络，必须通过 Parent Instance 代理
4. **存储限制**: Enclave 没有持久化存储，所有数据在内存中
5. **调试限制**: 生产环境不应使用调试模式，调试模式会降低安全性

### 演示项目限制

1. **单线程处理**: 当前实现每次只处理一个签名请求
2. **无持久化**: 不保存签名历史或日志到持久化存储
3. **简单错误处理**: 错误处理较为基础，生产环境需要更完善的错误处理
4. **无负载均衡**: 不支持多个 Enclave 实例的负载均衡
5. **固定算法**: 只支持 RSA_2048 和 RSASSA_PKCS1_V1_5_SHA_256

### 成本考虑

- **EC2 实例**: c6i 系列实例按小时计费
- **KMS 密钥**: 每个密钥 $1/月
- **KMS API 调用**: 前 20,000 次请求免费，之后 $0.03/10,000 次
- **数据传输**: 同区域内的数据传输免费

## 常见问题 (FAQ)

### Q1: 为什么需要 Nitro Enclaves？

**A**: Nitro Enclaves 提供了一个隔离的计算环境，可以保护敏感数据和操作免受主机系统的影响。即使主机被攻破，Enclave 内的数据和操作仍然是安全的。

### Q2: Attestation Document 包含什么信息？

**A**: Attestation Document 包含：
- PCR 值（Platform Configuration Registers）
- Enclave 镜像的哈希值
- 公钥和签名
- 时间戳和随机数

这些信息可以证明 Enclave 的身份和完整性。

### Q3: 可以在 Enclave 中运行其他加密操作吗？

**A**: 可以。这个演示项目专注于签名操作，但您可以扩展它来支持：
- KMS 加密/解密
- 密钥派生
- 其他加密算法
- 自定义加密逻辑

### Q4: 如何在生产环境中使用？

**A**: 生产环境部署建议：
1. 禁用 Enclave 调试模式
2. 启用 CloudTrail 审计
3. 使用专用的 KMS 密钥
4. 实现完善的错误处理和日志记录
5. 添加监控和告警
6. 使用 Auto Scaling 和负载均衡
7. 定期更新和打补丁

### Q5: PCR0 值什么时候会改变？

**A**: PCR0 值在以下情况下会改变：
- 修改 Enclave 应用代码
- 修改 Dockerfile
- 更新依赖包
- 更改 Python 版本
- 任何影响 Enclave 镜像的修改

每次改变后都需要更新 KMS 密钥策略。

### Q6: 可以在本地开发环境测试吗？

**A**: 不可以。Nitro Enclaves 需要特定的硬件支持，只能在支持的 EC2 实例上运行。但您可以：
- 在 EC2 上创建开发环境
- 使用 EC2 Spot 实例降低成本
- 模拟 Enclave 接口进行单元测试

### Q7: 如何监控 Enclave 的运行状态？

**A**: 可以通过以下方式监控：
```bash
# 查看 Enclave 状态
nitro-cli describe-enclaves

# 查看实时日志
nitro-cli console --enclave-id <ENCLAVE_ID>

# 查看资源使用
nitro-cli describe-enclaves | grep -E "CPU|Memory"
```

生产环境建议集成 CloudWatch 进行监控。

### Q8: 签名失败后如何调试？

**A**: 调试步骤：
1. 检查 Enclave 日志：`nitro-cli console --enclave-id <ENCLAVE_ID>`
2. 验证 IAM 权限：`aws iam get-role-policy`
3. 检查 KMS 密钥策略：`aws kms get-key-policy`
4. 验证 PCR0 哈希：对比 `enclave_pcr0.txt` 和密钥策略
5. 测试 KMS 连接：`aws kms describe-key --key-id <KEY_ID>`

## 依赖项

### Parent Instance
- Python 3.12
- boto3 (AWS SDK)
- cryptography (签名验证)

### Enclave
- Python 3.12
- boto3 (AWS SDK)
- aws-nitro-enclaves-sdk-python (Attestation)

## 扩展和定制

### 添加新的签名算法

修改 `enclave/enclave_app.py` 和 `parent/signature_verifier.py` 以支持其他算法：

```python
# 支持 ECC 签名
KEY_SPEC = "ECC_NIST_P256"
SIGNING_ALGORITHM = "ECDSA_SHA_256"
```

### 批量签名

修改通信协议以支持批量请求：

```json
{
    "action": "sign_batch",
    "messages": ["message1", "message2", "message3"]
}
```

### 添加加密功能

扩展 Enclave 应用以支持 KMS 加密：

```python
def encrypt_with_kms(plaintext, key_id, attestation):
    response = kms_client.encrypt(
        KeyId=key_id,
        Plaintext=plaintext,
        RecipientAttestation=attestation
    )
    return response['CiphertextBlob']
```

### 集成 CloudWatch 日志

添加日志记录到 CloudWatch：

```python
import boto3
logs_client = boto3.client('logs')

def send_log(message):
    logs_client.put_log_events(
        logGroupName='/aws/enclave/demo',
        logStreamName='enclave-app',
        logEvents=[{
            'timestamp': int(time.time() * 1000),
            'message': message
        }]
    )
```

## 参考资料

### 官方文档

- [AWS Nitro Enclaves 用户指南](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html)
- [AWS Nitro Enclaves CLI 参考](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli.html)
- [AWS KMS 开发者指南](https://docs.aws.amazon.com/kms/latest/developerguide/)
- [KMS Attestation 文档](https://docs.aws.amazon.com/kms/latest/developerguide/services-nitro-enclaves.html)

### SDK 和工具

- [Nitro Enclaves SDK for Python](https://github.com/aws/aws-nitro-enclaves-sdk-python)
- [AWS SDK for Python (Boto3)](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
- [Cryptography Library](https://cryptography.io/)

### 示例和教程

- [AWS Nitro Enclaves 示例](https://github.com/aws/aws-nitro-enclaves-samples)
- [Nitro Enclaves Workshop](https://catalog.workshops.aws/nitro-enclaves/)
- [KMS 最佳实践](https://docs.aws.amazon.com/kms/latest/developerguide/best-practices.html)

### 相关博客文章

- [Introducing AWS Nitro Enclaves](https://aws.amazon.com/blogs/aws/aws-nitro-enclaves-isolated-ec2-environments-to-process-confidential-data/)
- [Using AWS KMS with Nitro Enclaves](https://aws.amazon.com/blogs/security/confidential-computing-an-aws-perspective/)

## 许可证

本项目仅用于演示和学习目的。代码以 MIT 许可证发布。

## 贡献

欢迎提交 Issue 和 Pull Request！

### 贡献指南

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

### 报告问题

如果您发现 bug 或有功能建议，请创建 Issue 并包含：
- 问题描述
- 复现步骤
- 预期行为
- 实际行为
- 环境信息（实例类型、操作系统、Python 版本等）

## 致谢

感谢 AWS Nitro Enclaves 团队提供的优秀文档和示例代码。

---

**注意**: 本项目是一个极简演示，旨在帮助理解 Nitro Enclaves 和 KMS 的集成。生产环境使用需要额外的安全加固、错误处理、监控和测试。
