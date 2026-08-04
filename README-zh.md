# Certarium

[![Release](https://img.shields.io/github/v/release/F-Ar1es/certarium)](https://github.com/F-Ar1es/certarium/releases/latest)
[![CI](https://github.com/F-Ar1es/certarium/actions/workflows/ci.yml/badge.svg)](https://github.com/F-Ar1es/certarium/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![AI-assisted: OpenAI Codex](https://img.shields.io/badge/AI--assisted-OpenAI%20Codex-000000.svg)](AI_ASSISTED_DEVELOPMENT.md)

[English](README.md) · [项目文档](docs/PRODUCT.md) · [版本发布](https://github.com/F-Ar1es/certarium/releases)

Certarium 是一个面向开发与互操作实验的自托管证书实验室。它的主旨是：
当公司产品需要测试标准 TLS 或国密/TLCP 证书时，减少重复搭建 CA、编写
配置和手工申请证书的时间，让开发与测试人员可以更快获得可用证书。

Certarium 只负责测试证书的签发与生命周期管理，不承担 TLS 卸载、反向代理、
负载均衡，也不是面向公网的受信任 CA。

## 为什么需要 Certarium？

TLS/TLCP 实验通常需要反复准备 CA 数据库、OpenSSL/Tongsuo 配置、证书扩展、
国密双证书、CRL 和 OCSP 服务。Certarium 将这些步骤封装到一个本地 Web 界面
和 API 中，避免每次产品测试都重新手搓一套临时 PKI。

## 主要功能

- 初始化相互独立的 RSA 与 SM2 私有根 CA；
- 签发用于标准 TLS 的 RSA 服务端证书；
- 签发用于 TLCP 的 SM2 签名证书和加密证书；
- 支持 DNS、IPv4 和 IPv6 SAN；
- 查看序列号、用途、SAN、有效期和证书状态；
- 下载单个文件或包含完整证书材料的 ZIP 包；
- 吊销证书并发布 RSA/SM2 CRL；
- 通过标准 OCSP 请求查询 good、revoked 或 unknown 状态；
- 使用 AES-256 加密 CA 私钥；
- 使用 JSONL 审计关键操作；
- 创建和恢复加密离线备份；
- 提供仅监听回环地址的 Web UI 与自动化 API。

## 支持的发行环境

Certarium v0.1.0 提供自包含的 **x86_64** 安装包，包内包含服务程序和固定版本的
**Tongsuo 8.4.0**：

| 系统 | 安装包 |
| --- | --- |
| CentOS 7 兼容 RPM 系统 | `certarium-0.1.0-1.el7.x86_64.rpm` |
| Debian 兼容系统 | `certarium_0.1.0-1_amd64.deb` |

v0.1 暂不提供 ARM64 安装包，也没有实现真实 HSM/PKCS#11 对接。

## 快速开始

从 [v0.1.0 Release](https://github.com/F-Ar1es/certarium/releases/tag/v0.1.0)
下载安装包，然后执行：

```sh
# CentOS 7 兼容系统
sudo yum install ./certarium-0.1.0-1.el7.x86_64.rpm

# Debian 兼容系统
sudo apt install ./certarium_0.1.0-1_amd64.deb
```

启动服务：

```sh
sudo systemctl enable --now certarium
curl http://127.0.0.1:8080/api/v1/health
```

Certarium 默认只监听 `127.0.0.1:8080`。如果从其他电脑访问，请建立 SSH 隧道：

```sh
ssh -L 8080:127.0.0.1:8080 user@certarium-host
```

浏览器打开 <http://127.0.0.1:8080>，然后：

1. 填写组织名称并初始化实验 CA；
2. 下载 RSA 或 SM2 根证书，只导入需要参与测试的客户端；
3. 选择签发 RSA 证书或 TLCP 签名/加密双证书；
4. 填写客户端实际使用的全部域名和 IP 地址；
5. 明确确认由服务端生成私钥；
6. 下载单个文件或完整压缩包，并妥善保管其中的私钥。

## 备份与恢复

请使用单独的 0400 权限口令文件，并在服务停止后进行一致性备份：

```sh
sudo systemctl stop certarium
sudo certarium-backup -mode backup \
  -data-dir /var/lib/certarium \
  -config-dir /etc/certarium \
  -file /secure/certarium.backup \
  -passphrase-file /secure/backup.pass
sudo systemctl start certarium
```

使用 `-replace` 恢复现有环境前，请先阅读[备份与恢复说明](docs/BACKUP-RESTORE.md)。

## 安全与功能边界

Certarium 面向隔离的开发和互操作实验环境。Web/API 没有用户认证，是因为服务
被限制在回环地址；不要将其直接暴露到局域网或互联网，也不要将生成的根 CA
作为公网信任根。

v0.1 不包含：

- TLS/TLCP 流量终止或证书卸载；
- 反向代理、负载均衡、健康检查和 HA；
- 公共 CA、多租户、身份认证和 RBAC；
- 生产级 HSM/PKCS#11 私钥托管；
- ARM64 发行包。

进一步测试前请阅读[安全说明](docs/SECURITY.md)、[安装说明](docs/INSTALL.md)和
[运维说明](docs/OPERATIONS.md)。

## 构建与验证

Apple Silicon + Apple Container：

```sh
./scripts/build-packages-apple-container.sh
./scripts/test-install-packages-apple-container.sh
```

x86_64 Linux + Docker：

```sh
./scripts/build-packages-linux.sh
./scripts/test-install-packages-linux.sh
```

项目使用 old-coder 的证据优先开发流程。可执行发布规格和验证结果分别见
[SPEC-v0.1-release.md](docs/SPEC-v0.1-release.md) 与
[EVIDENCE-v0.1.md](docs/EVIDENCE-v0.1.md)。

## 人类主导与 Codex 协助

项目设想、产品范围、验收和发布决策由 **Carl Flynn** 主导。OpenAI Codex
协助完成实现、测试、文档、资料研究和验证。Codex 是开发工具，不是版权人、
维护者或发布决策者，详情见 [AI 辅助开发声明](AI_ASSISTED_DEVELOPMENT.md)。

Codex 和兼容 coding agent 的仓库级工作规范位于 [AGENTS.md](AGENTS.md)。
这是 Codex 官方支持的仓库指令机制，应用程序本身并没有嵌入 AI 服务。

## 许可证

Certarium 原创代码采用 `AGPL-3.0-only`。无法采用 AGPL 的组织可以联系获取
单独的商业许可，参见 [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md)。
第三方组件继续遵循各自许可证，详见
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
