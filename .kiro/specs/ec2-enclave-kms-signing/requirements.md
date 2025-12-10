# 需求文档

## 简介

本项目旨在创建一个极简的 EC2 Enclave 演示，展示如何在隔离的 Enclave 环境中使用 AWS KMS 进行签名操作，并在 EC2 主机环境中验证签名。项目专注于最小化 AWS 服务使用和代码复杂度，便于演示和理解 Enclave 的安全特性。

## 术语表

- **EC2 Instance**: 运行演示的 Amazon EC2 虚拟机实例
- **Enclave**: EC2 Nitro Enclaves，一个隔离的计算环境，用于处理敏感数据
- **KMS**: AWS Key Management Service，用于密钥管理和加密操作的服务
- **Parent Instance**: 托管 Enclave 的 EC2 实例（主机环境）
- **Enclave Application**: 运行在 Enclave 内部的应用程序
- **vsock**: 用于 Parent Instance 和 Enclave 之间通信的虚拟套接字
- **Attestation Document**: Enclave 生成的证明文档，用于验证 Enclave 的身份

## 需求

### 需求 1

**用户故事:** 作为演示者，我想要在 EC2 实例上启用 Enclave 环境，以便展示隔离计算环境的创建过程

#### 验收标准

1. THE EC2 Instance SHALL 支持 Nitro Enclaves 功能
2. THE EC2 Instance SHALL 在 us-east-1 区域部署
3. WHEN 配置 Enclave 时，THE EC2 Instance SHALL 分配指定的 CPU 核心和内存给 Enclave
4. THE Enclave Application SHALL 成功启动并运行在隔离环境中
5. THE Parent Instance SHALL 能够通过 vsock 与 Enclave Application 建立通信

### 需求 2

**用户故事:** 作为演示者，我想要在 Enclave 内部调用 KMS 进行签名操作，以便展示 Enclave 如何安全地处理加密操作

#### 验收标准

1. THE Enclave Application SHALL 生成 Attestation Document 以证明其身份
2. WHEN Enclave Application 请求签名时，THE Enclave Application SHALL 使用 KMS API 进行签名操作
3. THE KMS SHALL 验证 Attestation Document 后授权签名操作
4. THE Enclave Application SHALL 接收来自 Parent Instance 的待签名数据
5. THE Enclave Application SHALL 返回签名结果给 Parent Instance

### 需求 3

**用户故事:** 作为演示者，我想要在 EC2 主机环境中验证签名，以便展示完整的签名和验证流程

#### 验收标准

1. THE Parent Instance SHALL 发送待签名数据到 Enclave Application
2. WHEN 接收到签名结果时，THE Parent Instance SHALL 使用 KMS 公钥验证签名
3. THE Parent Instance SHALL 显示签名验证结果（成功或失败）
4. THE Parent Instance SHALL 记录整个签名和验证过程的关键步骤

### 需求 4

**用户故事:** 作为开发者，我想要使用最少的 AWS 服务和代码，以便简化演示和降低成本

#### 验收标准

1. THE EC2 Instance SHALL 仅使用 EC2、KMS 和必要的 IAM 服务
2. THE Enclave Application SHALL 使用 Python 实现
3. THE Parent Instance SHALL 使用 Python 虚拟环境部署应用
4. THE EC2 Instance SHALL 使用最小化的依赖包
5. THE EC2 Instance SHALL 提供清晰的部署和运行脚本

### 需求 5

**用户故事:** 作为演示者，我想要有清晰的部署和运行步骤，以便快速搭建和展示演示环境

#### 验收标准

1. THE EC2 Instance SHALL 提供自动化的环境配置脚本
2. THE EC2 Instance SHALL 包含 Enclave 镜像构建脚本
3. THE Parent Instance SHALL 提供一键启动演示的命令
4. THE EC2 Instance SHALL 输出清晰的日志信息以便理解执行流程
5. THE EC2 Instance SHALL 提供清理资源的脚本
