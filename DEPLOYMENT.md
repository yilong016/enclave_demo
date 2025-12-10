# 部署指南

本文档详细说明如何从零开始部署 EC2 Enclave KMS 签名演示项目。

## 📍 在哪里执行？

这是最常见的问题！请记住：

| 操作 | 执行位置 | 说明 |
|------|---------|------|
| 克隆/下载代码 | 本地笔记本 | 获取项目代码 |
| 启动 EC2 实例 | 本地笔记本（AWS 控制台/CLI） | 创建 EC2 实例 |
| 上传代码 | 本地笔记本 | 使用 scp 上传到 EC2 |
| SSH 登录 | 本地笔记本 | 连接到 EC2 |
| **所有部署脚本** | **EC2 实例** | ⚠️ 必须在 EC2 上执行 |
| **运行演示** | **EC2 实例** | ⚠️ 必须在 EC2 上执行 |

## 🚀 完整部署流程

### 阶段 1: 准备工作（在本地笔记本）

#### 1.1 获取项目代码

```bash
# 克隆或下载项目
git clone <repository-url> enclave-demo
cd enclave-demo

# 或者如果已经有代码，直接进入目录
cd enclave-demo
```

#### 1.2 启动 EC2 实例

**方式 A: 使用 AWS 控制台**

1. 登录 AWS 控制台
2. 进入 EC2 服务
3. 点击"启动实例"
4. 配置：
   - **名称**: enclave-demo
   - **AMI**: Amazon Linux 2023
   - **实例类型**: c6i.xlarge（或更高）
   - **密钥对**: 选择或创建密钥对
   - **网络设置**: 允许 SSH (端口 22)
   - **存储**: 20 GB gp3
   - **区域**: us-east-1
5. 点击"启动实例"
6. 等待实例状态变为"运行中"
7. 记录实例的公网 IP 地址

**方式 B: 使用 AWS CLI**

```bash
# 创建密钥对（如果还没有）
aws ec2 create-key-pair \
  --key-name enclave-demo-key \
  --query 'KeyMaterial' \
  --output text > enclave-demo-key.pem

chmod 400 enclave-demo-key.pem

# 启动实例
aws ec2 run-instances \
  --image-id ami-0c55b159cbfafe1f0 \
  --instance-type c6i.xlarge \
  --key-name enclave-demo-key \
  --security-group-ids sg-xxxxxxxx \
  --subnet-id subnet-xxxxxxxx \
  --region us-east-1 \
  --enclave-options Enabled=true \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=enclave-demo}]'

# 获取实例 IP
aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=enclave-demo" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' \
  --output text
```

#### 1.3 上传代码到 EC2

```bash
# 替换 <EC2-IP> 为您的实例 IP 地址
# 替换 your-key.pem 为您的密钥文件

scp -i your-key.pem -r enclave-demo ec2-user@<EC2-IP>:~/

# 示例：
# scp -i enclave-demo-key.pem -r enclave-demo ec2-user@3.80.123.45:~/
```

上传可能需要几秒钟，取决于网络速度。

#### 1.4 SSH 登录到 EC2

```bash
ssh -i your-key.pem ec2-user@<EC2-IP>

# 示例：
# ssh -i enclave-demo-key.pem ec2-user@3.80.123.45
```

成功登录后，您应该看到 Amazon Linux 的欢迎信息。

---

### 阶段 2: 环境配置（在 EC2 实例上）

**⚠️ 从现在开始，所有命令都在 EC2 实例上执行！**

#### 2.1 进入项目目录

```bash
cd enclave-demo
ls -la  # 确认文件已上传
```

#### 2.2 运行环境配置脚本

```bash
cd scripts
./setup_environment.sh
```

这个脚本会：
- 安装 Nitro Enclaves CLI
- 配置资源分配器（2 vCPU, 512 MB 内存）
- 安装 Docker
- 创建 Python 虚拟环境
- 安装 Python 依赖

**预计时间**: 2-3 分钟

**重要**: 脚本完成后，您需要重新登录以使用户组权限生效：

```bash
# 退出 EC2
exit

# 在本地笔记本重新登录
ssh -i your-key.pem ec2-user@<EC2-IP>

# 重新进入项目目录
cd enclave-demo/scripts
```

---

### 阶段 3: AWS 资源配置（在 EC2 实例上）

#### 3.1 创建 KMS 密钥

```bash
./setup_kms_key.sh
```

这个脚本会：
- 创建 KMS 签名密钥（RSA_2048）
- 创建密钥别名
- 配置密钥策略
- 保存密钥 ID 到 `kms_key_id.txt`

**预计时间**: 30 秒

#### 3.2 配置 IAM 角色

```bash
./setup_iam_role.sh
```

这个脚本会：
- 创建 IAM 角色 `EnclaveRole`
- 创建 KMS 权限策略
- 创建实例配置文件 `EnclaveInstanceProfile`

**预计时间**: 30 秒

#### 3.3 附加 IAM 角色到 EC2 实例

**重要**: 这一步需要在 AWS 控制台或使用 CLI 完成。

**方式 A: 使用 AWS 控制台**

1. 进入 EC2 控制台
2. 选择您的实例
3. 点击"操作" > "安全" > "修改 IAM 角色"
4. 选择 `EnclaveInstanceProfile`
5. 点击"更新 IAM 角色"

**方式 B: 使用 AWS CLI（在本地笔记本）**

```bash
# 获取实例 ID
INSTANCE_ID=$(aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=enclave-demo" \
  --query 'Reservations[0].Instances[0].InstanceId' \
  --output text)

# 附加 IAM 角色
aws ec2 associate-iam-instance-profile \
  --instance-id $INSTANCE_ID \
  --iam-instance-profile Name=EnclaveInstanceProfile
```

---

### 阶段 4: 构建和启动 Enclave（在 EC2 实例上）

#### 4.1 构建 Enclave 镜像

```bash
./build_enclave.sh
```

这个脚本会：
- 构建 Docker 镜像
- 转换为 EIF 格式
- 生成 PCR0 哈希值
- 保存哈希到 `enclave_pcr0.txt`

**预计时间**: 1-2 分钟

#### 4.2 更新 KMS 密钥策略（可选但推荐）

如果您想启用 Attestation 验证（生产环境推荐）：

```bash
# 重新运行 KMS 配置脚本，它会检测到 EIF 文件并更新策略
./setup_kms_key.sh
```

#### 4.3 启动 Enclave

```bash
./start_enclave.sh
```

这个脚本会：
- 启动 Nitro Enclave
- 分配资源（2 vCPU, 512 MB）
- 获取 Enclave CID
- 保存 CID 到 `enclave_cid.txt`

**预计时间**: 10 秒

---

### 阶段 5: 运行演示（在 EC2 实例上）

#### 5.1 运行一键演示脚本

```bash
./demo.sh
```

这个脚本会：
1. 检查前置条件
2. 确认 Enclave 已启动
3. 运行签名演示
4. 验证签名
5. 显示结果

**预计时间**: < 1 秒

#### 5.2 查看输出

成功运行时，您应该看到：

```
╔═══════════════════════════════════════════════════════════╗
║     EC2 Nitro Enclave KMS Signing Demo                   ║
║     一键演示脚本                                          ║
╚═══════════════════════════════════════════════════════════╝

[INFO] 开始 EC2 Nitro Enclave KMS 签名演示
[INFO] 区域: us-east-1
[INFO] 演示消息: Hello from EC2 Nitro Enclave Demo!

============================================================
  步骤 1: 检查前置条件
============================================================
[SUCCESS] nitro-cli 已安装
[SUCCESS] Docker 已安装
[SUCCESS] Python 虚拟环境已创建
[SUCCESS] KMS 密钥 ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

...

╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║  ✓ 演示成功完成！                                         ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
```

---

### 阶段 6: 清理资源（在 EC2 实例上）

#### 6.1 停止 Enclave

```bash
./cleanup.sh
```

#### 6.2 完全清理（可选）

如果您想删除所有资源：

```bash
# 删除 KMS 密钥和 IAM 角色
./cleanup.sh --delete-kms --delete-iam --force
```

#### 6.3 终止 EC2 实例（在本地笔记本）

**方式 A: 使用 AWS 控制台**

1. 进入 EC2 控制台
2. 选择实例
3. 点击"实例状态" > "终止实例"

**方式 B: 使用 AWS CLI**

```bash
aws ec2 terminate-instances --instance-ids $INSTANCE_ID
```

---

## 🔍 验证部署

### 检查 Enclave 状态

```bash
nitro-cli describe-enclaves
```

应该显示：
```json
[
  {
    "EnclaveID": "i-xxxxxxxxxxxxx-enc-xxxxxxxxx",
    "EnclaveCID": 16,
    "NumberOfCPUs": 2,
    "CPUIDs": [1, 3],
    "MemoryMiB": 512,
    "State": "RUNNING",
    "Flags": "DEBUG_MODE"
  }
]
```

### 检查 KMS 密钥

```bash
aws kms describe-key --key-id $(cat kms_key_id.txt) --region us-east-1
```

### 检查 IAM 角色

```bash
aws iam get-role --role-name EnclaveRole
```

---

## 📊 时间估算

| 阶段 | 操作 | 预计时间 |
|------|------|---------|
| 1 | 准备工作（本地） | 5-10 分钟 |
| 2 | 环境配置（EC2） | 2-3 分钟 |
| 3 | AWS 资源配置（EC2） | 1 分钟 |
| 4 | 构建和启动（EC2） | 1-2 分钟 |
| 5 | 运行演示（EC2） | < 1 秒 |
| **总计** | | **约 10-15 分钟** |

---

## ❓ 常见问题

### Q: 为什么不能在本地笔记本运行？

A: Nitro Enclaves 需要特定的硬件支持（AWS Nitro System），这只在 AWS EC2 实例上可用。本地环境无法模拟这个硬件。

### Q: 可以使用其他实例类型吗？

A: 必须使用支持 Nitro Enclaves 的实例类型，如 c6i、m6i、r6i 系列。不支持的实例类型无法启动 Enclave。

### Q: 可以在其他区域部署吗？

A: 可以，但需要修改脚本中的 `REGION` 变量。本演示默认使用 us-east-1。

### Q: 部署失败怎么办？

A: 查看 [README.md](README.md) 的故障排查部分，或运行：
```bash
# 查看 Enclave 日志
nitro-cli console --enclave-id <ENCLAVE_ID>

# 查看系统日志
sudo journalctl -xe
```

### Q: 如何重新开始？

A: 运行清理脚本，然后重新执行部署：
```bash
./cleanup.sh --force
# 然后重新开始从阶段 4
```

---

## 📚 相关文档

- [README.md](README.md) - 完整项目文档
- [QUICK_START.md](QUICK_START.md) - 快速参考指南
- [config.example.json](config.example.json) - 配置示例
- [.env.example](.env.example) - 环境变量示例

---

## 🆘 获取帮助

如果遇到问题：

1. 查看 [README.md](README.md) 的故障排查部分
2. 检查 AWS 服务状态
3. 查看项目 Issues
4. 参考 [AWS Nitro Enclaves 文档](https://docs.aws.amazon.com/enclaves/)
