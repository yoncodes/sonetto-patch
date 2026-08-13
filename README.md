# Sonetto-Patch

## English

### How to use

1. Download the latest build from the [releases page](https://github.com/yoncodes/sonetto-patch/releases) and extract it next to `reverse1999.exe`.
2. Copy `sonetto.example.toml` to `sonetto.toml` and configure your TLS and game endpoints.
3. Run `launcher.exe` as administrator.

### Build from source

- Clone the repository.
- Install [Rust](https://rust-lang.org/tools/install/).
- Run `cargo build --release`.

### What it patches

- Redirects official SDK requests through WinHTTP without calling protected IL2CPP exports.
- Redirects the game TCP connection through `connect()`.
- Reads endpoints from `sonetto.toml`, so no proxy or hard-coded private server address is required.
- Writes startup and redirect diagnostics to `sonetto-runtime.log`.

Reverse: 1999 PC 3.7 protects the IL2CPP export path used by older builds. The WinHTTP route avoids that startup crash while retaining DNS and certificate-policy compatibility fallbacks.

## 中文

### 使用方法

1. 从[发布页面](https://github.com/yoncodes/sonetto-patch/releases)下载最新构建，并解压到 `reverse1999.exe` 所在目录。
2. 将 `sonetto.example.toml` 复制为 `sonetto.toml`，填写 TLS 和游戏服地址。
3. 以管理员身份运行 `launcher.exe`。

### 从源码构建

- 克隆本仓库。
- 安装 [Rust](https://rust-lang.org/tools/install/)。
- 运行 `cargo build --release`。

### 补丁功能

- 在 WinHTTP 层重定向官方 SDK 请求，不调用受保护的 IL2CPP 导出。
- 通过 `connect()` 重定向游戏 TCP 连接。
- 从 `sonetto.toml` 读取服务端地址，不需要系统代理，也不在源码中硬编码私服地址。
- 将启动和重定向诊断写入 `sonetto-runtime.log`。

《重返未来1999》PC 3.7 对旧补丁依赖的 IL2CPP 导出路径增加了保护。WinHTTP 方案避开了该启动崩溃，同时保留 DNS 与证书策略兼容后备。
