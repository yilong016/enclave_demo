# 部署检查清单

## 代码安全性验证 ✅

### Enclave 端
- ✅ 使用 `generate_attestation_document()` 生成 Attestation
- ✅ 调用 `kms.generate_data_key()` with `Recipient` 参数
- ✅ 使用 `decrypt_ciphertext_for_recipient()` 解密 data key
- ✅ 使用 data key 加密数据（AES-256-GCM）
- ✅ 使用 data key 签名交易（HMAC-SHA256）
- ✅ 使用后立即清除明文：`plaintext_data_key = None`
- ✅ 返回响应中不包含明文 data key

### Parent 端
- ✅ 只接收加密数据和签名
- ✅ 不尝试解密任何内容
- ✅ 只存储 `CiphertextBlob`（可持久化）

### KMS 配置
- ✅ 使用对称密钥（SYMMETRIC_DEFAULT）
- ✅ 权限：`kms:GenerateDataKey` 和 `kms:Decrypt`
- ✅ 条件：`kms:RecipientAttestation:PCR0`

## 部署步骤

### 阶段 1: 跳板机 - 创建 IAM 角色
```bash
cd enclave-demo/scripts
./setup_iam_role.sh
```

### 阶段 2: 跳板机 - 启动 EC2 实例
- 实例类型：c6i.xlarge
- IAM 角色：EnclaveInstanceProfile
- Nitro Enclave：启用

### 阶段 3: 跳板机 - 上传代码
```bash
tar -czf enclave-demo.tar.gz enclave-demo/
aws s3 cp enclave-demo.tar.gz s3://your-bucket/
```

### 阶段 4: EC2 - 配置环境
```bash
# SSM 登录
aws ssm start-session --target i-xxx --region us-east-1

# 下载代码
aws s3 cp s3://your-bucket/enclave-demo.tar.gz .
tar -xzf enclave-demo.tar.gz

# 配置环境
cd enclave-demo/scripts
./setup_environment.sh

# 重新登录
exit
```

### 阶段 5: EC2 - 构建 Enclave
```bash
cd enclave-demo/scripts
./build_enclave.sh

# 上传 PCR0
aws s3 cp enclave_pcr0.txt s3://your-bucket/
```

### 阶段 6: 跳板机 - 创建 KMS 密钥
```bash
# 下载 PCR0
aws s3 cp s3://your-bucket/enclave_pcr0.txt enclave-demo/

# 创建 KMS 密钥
cd enclave-demo/scripts
./setup_kms_key.sh

# 上传密钥 ID
aws s3 cp kms_key_id.txt s3://your-bucket/
```

### 阶段 7: EC2 - 运行演示
```bash
# 下载密钥 ID
cd enclave-demo
aws s3 cp s3://your-bucket/kms_key_id.txt .

# 启动 Enclave
./scripts/start_enclave.sh

# 运行演示
cd parent
source ../venv/bin/activate
python parent_app.py \
  --sensitive-data "Credit card: 1234-5678-9012-3456" \
  --transaction "Transfer $1000 from Alice to Bob"
```

## 预期输出

```
步骤 1: 连接到 Enclave
✓ 已连接到 Enclave

步骤 2: 发送数据到 Enclave 进行处理
✓ 收到处理结果

步骤 3: 检查 Enclave 处理结果
✓ 状态: success
加密结果:
  IV 长度: 12 字节
  密文长度: XX 字节
  认证标签长度: 16 字节
签名结果:
  交易签名: ...
  签名长度: 32 字节

步骤 4: 安全性验证
⚠️  Data key 明文只在 Enclave 内存中存在
⚠️  Parent Instance 只收到加密后的数据和签名
⚠️  Parent Instance 无法解密数据或伪造签名
✓ 安全验证通过

步骤 5: 数据持久化
CiphertextBlob 可以安全存储在 Parent Instance
```

## 安全验证

### Data Key 明文位置
- ✅ KMS 内部（生成时）
- ✅ Enclave 内存（使用时）
- ❌ Parent Instance（永远不会）
- ❌ 网络传输（永远不会）
- ❌ 磁盘存储（永远不会）

### 加密数据流
```
敏感数据 → Enclave → AES-256-GCM 加密 → Parent
交易数据 → Enclave → HMAC-SHA256 签名 → Parent
```

### 持久化
```
CiphertextBlob → 存储 → 下次使用时 → KMS Decrypt with Recipient → Enclave
```
