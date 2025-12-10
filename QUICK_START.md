# 快速开始指南

这是一个快速参考指南，帮助您在 5 分钟内启动和运行 EC2 Enclave KMS 签名演示。

> **📖 首次部署？**  
> 如果这是您第一次部署，建议先阅读 [完整部署指南 (DEPLOYMENT.md)](DEPLOYMENT.md)，  
> 其中详细说明了从本地笔记本到 EC2 实例的完整流程。

## ⚠️ 重要：在哪里执行？

**所有脚本必须在 EC2 实例上执行，不能在本地笔记本上运行！**

### 部署步骤概览

```
本地笔记本                          EC2 实例 (Parent Instance)
    │                                      │
    │  1. 启动 EC2 实例                    │
    │     (AWS 控制台/CLI)                 │
    │                                      │
    │  2. 上传代码                         │
    │─────scp────────────────────────────>│
    │                                      │
    │  3. SSH 登录                         │
    │─────ssh────────────────────────────>│
    │                                      │
    │                                      │  4. 执行部署脚本
    │                                      │     ./setup_environment.sh
    │                                      │     ./setup_kms_key.sh
    │                                      │     ./demo.sh
    │                                      │
    │                                      │  5. Enclave 在 EC2 内运行
    │                                      │     ┌─────────────┐
    │                                      │     │   Enclave   │
    │                                      │     └─────────────┘
```

## 准备工作（在本地笔记本）

```bash
# 1. 启动 EC2 实例（通过 AWS 控制台或 CLI）
# - 实例类型：c6i.xlarge
# - AMI：Amazon Linux 2023
# - 区域：us-east-1

# 2. 上传代码到 EC2
scp -i your-key.pem -r enclave-demo ec2-user@<EC2-IP>:~/

# 3. SSH 登录到 EC2
ssh -i your-key.pem ec2-user@<EC2-IP>

# 4. 进入项目目录
cd enclave-demo
```

## 前置条件检查（在 EC2 实例上）

```bash
# 1. 确认实例类型支持 Nitro Enclaves
curl -s http://169.254.169.254/latest/meta-data/instance-type
# 应该是 c6i、m6i、r6i 等系列

# 2. 确认区域
curl -s http://169.254.169.254/latest/meta-data/placement/region
# 应该是 us-east-1

# 3. 确认 IAM 角色已附加
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
# 应该显示角色名称
```

## 一键部署（推荐）

**⚠️ 确保已经 SSH 登录到 EC2 实例！**

如果这是首次部署，按顺序运行以下命令：

```bash
# ⚠️ 以下所有命令都在 EC2 实例上执行

# 1. 环境配置（约 2-3 分钟）
cd enclave-demo/scripts
./setup_environment.sh

# 重要: 重新登录以使用户组权限生效
exit
# 重新 SSH 登录

# 2. 配置 AWS 资源（约 30 秒）
cd scripts
./setup_kms_key.sh
./setup_iam_role.sh

# 注意: 如果 EC2 实例还没有附加 IAM 角色，需要在 AWS 控制台手动附加

# 3. 运行演示（约 1 分钟）
./demo.sh
```

## 分步部署

### 步骤 1: 环境配置

```bash
cd scripts
./setup_environment.sh
```

**完成后需要重新登录！**

### 步骤 2: AWS 资源配置

```bash
# 创建 KMS 密钥
./setup_kms_key.sh

# 创建 IAM 角色
./setup_iam_role.sh
```

### 步骤 3: 构建和启动

```bash
# 构建 Enclave 镜像
./build_enclave.sh

# 启动 Enclave
./start_enclave.sh
```

### 步骤 4: 运行演示

```bash
# 方式 1: 使用演示脚本
./demo.sh

# 方式 2: 手动运行
cd ../parent
source ../venv/bin/activate
python parent_app.py --message "Hello Enclave!"
```

## 常用命令

### Enclave 管理

```bash
# 查看 Enclave 状态
nitro-cli describe-enclaves

# 查看 Enclave 日志
nitro-cli console --enclave-id <ENCLAVE_ID>

# 停止 Enclave
nitro-cli terminate-enclave --enclave-id <ENCLAVE_ID>

# 或使用脚本
./scripts/stop_enclave.sh
```

### 资源清理

```bash
# 基本清理（停止 Enclave，清理临时文件）
./scripts/cleanup.sh

# 保留镜像
./scripts/cleanup.sh --keep-images

# 完全清理（包括 KMS 密钥和 IAM 角色）
./scripts/cleanup.sh --delete-kms --delete-iam --force
```

### 调试

```bash
# 检查资源分配
cat /sys/module/nitro_enclaves/parameters/ne_cpus
cat /sys/module/nitro_enclaves/parameters/ne_mem_size

# 检查服务状态
sudo systemctl status nitro-enclaves-allocator.service

# 查看系统日志
sudo journalctl -u nitro-enclaves-allocator.service

# 测试 KMS 连接
aws kms describe-key --key-id $(cat kms_key_id.txt) --region us-east-1
```

## 故障排查速查表

| 问题 | 快速检查 | 解决方案 |
|------|---------|---------|
| Enclave 启动失败 | `nitro-cli describe-enclaves` | 检查资源分配，查看日志 |
| KMS 签名失败 | `aws kms describe-key --key-id <KEY_ID>` | 检查 IAM 权限和密钥策略 |
| vsock 连接失败 | `cat enclave_cid.txt` | 确认 Enclave 已启动，CID 正确 |
| 权限错误 | `groups` | 确认在 ne 和 docker 组中 |
| Python 模块缺失 | `pip list` | 重新安装依赖 |

## 配置文件位置

| 文件 | 位置 | 说明 |
|------|------|------|
| Enclave 镜像 | `enclave.eif` | 构建后生成 |
| Enclave CID | `enclave_cid.txt` | 启动后生成 |
| KMS 密钥 ID | `kms_key_id.txt` | 创建密钥后生成 |
| PCR0 哈希 | `enclave_pcr0.txt` | 构建后生成 |
| 资源分配 | `/etc/nitro_enclaves/allocator.yaml` | 系统配置 |

## 预期时间

- 环境配置: 2-3 分钟
- AWS 资源配置: 30 秒
- 构建 Enclave: 1-2 分钟
- 启动 Enclave: 10 秒
- 运行签名: < 1 秒

## 下一步

- 阅读完整的 [README.md](README.md) 了解详细信息
- 查看 [config.example.json](config.example.json) 了解配置选项
- 查看 [.env.example](.env.example) 了解环境变量
- 修改代码以适应您的需求

## 获取帮助

如果遇到问题：

1. 查看 [README.md](README.md) 的故障排查部分
2. 检查 Enclave 日志: `nitro-cli console --enclave-id <ENCLAVE_ID>`
3. 查看系统日志: `sudo journalctl -xe`
4. 参考 [AWS Nitro Enclaves 文档](https://docs.aws.amazon.com/enclaves/)

## 重要提示

- ⚠️ 首次运行 `setup_environment.sh` 后必须重新登录
- ⚠️ 确保 EC2 实例附加了正确的 IAM 角色
- ⚠️ 每次重新构建 Enclave 后，PCR0 值会改变，需要更新 KMS 密钥策略
- ⚠️ 生产环境不要使用 `--debug-mode` 启动 Enclave
- ⚠️ 不要将包含敏感信息的配置文件提交到版本控制
