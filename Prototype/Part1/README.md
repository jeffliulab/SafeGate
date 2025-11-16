# HTTPS Proxy Server

> A robust HTTPS proxy implementation in C with TLS interception, dynamic certificate generation, and header injection capabilities.

**CS112 Final Project - Part 1** | [中文文档](#chinese-documentation)

---

## Table of Contents

- [Project Overview](#project-overview)
- [Project Structure](#project-structure)
- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation & Compilation](#installation--compilation)
- [Usage](#usage)
- [Browser Configuration](#browser-configuration)
- [Testing](#testing)
- [Implementation Details](#implementation-details)
- [Troubleshooting](#troubleshooting)
- [Submission](#submission)

---

## Project Overview

A robust HTTPS proxy server implementation in C that supports both plaintext HTTP and encrypted HTTPS traffic. The proxy uses TLS interception (MITM - Man-In-The-Middle) to inspect and modify encrypted traffic, featuring multi-threading, dynamic certificate generation, and HTTP header injection.

This is Part 1 of the CS112 Final Project, implementing a foundation proxy server that will be enhanced with LLM capabilities in Part 2.

---

## Project Structure

### Directory Structure

```
Part1/
├── proxy.c                      # Main proxy implementation (755 lines)
│   ├── Main server loop         # Accept connections, spawn threads
│   ├── HTTP handler             # Handle plain HTTP requests
│   ├── HTTPS handler            # Handle CONNECT and TLS interception
│   ├── Certificate generator    # Dynamic X.509 cert generation
│   ├── Header injector          # Add X-Proxy:CS112 header
│   └── Utility functions        # Parsing, connection management
│
├── Makefile                     # Build configuration
│   ├── Compiler flags           # Security checks (banned functions)
│   ├── Dependencies             # OpenSSL, pthread, nsl
│   └── Build targets            # proxy, clean
│
├── README.md                    # This documentation
│
├── proxyCertificates/           # CA certificates directory
│   ├── proxy_ca.crt            # CA public certificate (for browser import)
│   └── proxy_ca.key            # CA private key (for signing certs)
│
├── proxy                        # Compiled executable (after make)
└── proxy.o                      # Object file (after make)
```

### System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           HTTPS Proxy Server                             │
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Main Thread (Listening on Port 8080)                           │   │
│  │  • Socket creation & binding                                     │   │
│  │  • Accept incoming connections                                   │   │
│  │  • Spawn worker threads for each client                         │   │
│  └───────────────────────────┬─────────────────────────────────────┘   │
│                              │                                           │
│              ┌───────────────┴───────────────┐                          │
│              ▼                               ▼                          │
│  ┌─────────────────────┐         ┌─────────────────────┐              │
│  │  HTTP Handler       │         │  HTTPS Handler      │              │
│  │  (Worker Thread)    │         │  (Worker Thread)    │              │
│  └─────────────────────┘         └─────────────────────┘              │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

### HTTP Request Flow

```
 Client                  Proxy                    Target Server
   │                       │                            │
   │  1. HTTP Request      │                            │
   ├──────────────────────>│                            │
   │  GET /page HTTP/1.1   │                            │
   │  Host: example.com    │  2. Forward Request        │
   │                       ├───────────────────────────>│
   │                       │  GET /page HTTP/1.1        │
   │                       │  Host: example.com         │
   │                       │                            │
   │                       │  3. HTTP Response          │
   │                       │<───────────────────────────┤
   │                       │  HTTP/1.1 200 OK           │
   │  4. Inject Header     │  Content-Type: text/html   │
   │  + Forward Response   │  [body]                    │
   │<──────────────────────┤                            │
   │  HTTP/1.1 200 OK      │                            │
   │  X-Proxy:CS112        │  ← Header injected here   │
   │  Content-Type: ...    │                            │
   │  [body]               │                            │
```

### HTTPS Request Flow (TLS Interception)

```
 Client                    Proxy                      Target Server
   │                         │                              │
   │  1. CONNECT Request     │                              │
   ├────────────────────────>│                              │
   │  CONNECT example.com:443│                              │
   │                         │  2. Connect to Server        │
   │                         ├─────────────────────────────>│
   │                         │                              │
   │                         │  3. TLS Handshake            │
   │                         │<─────────────────────────────│
   │                         │  (Proxy as TLS Client)       │
   │                         │                              │
   │  4. 200 Connection Est. │                              │
   │<────────────────────────┤                              │
   │                         │                              │
   │  5. TLS Handshake       │  6. Generate Certificate     │
   │<────────────────────────┤  for example.com             │
   │  (Proxy as TLS Server)  │  • Signed by CA              │
   │  • Fake cert for        │  • Include SAN extension     │
   │    example.com          │                              │
   │                         │                              │
   │  7. Encrypted Request   │  8. Decrypt                  │
   ├────────────────────────>│                              │
   │  [TLS: GET /page]       │                              │
   │                         │  9. Re-encrypt & Forward     │
   │                         ├─────────────────────────────>│
   │                         │  [TLS: GET /page]            │
   │                         │                              │
   │                         │  10. Encrypted Response      │
   │                         │<─────────────────────────────┤
   │                         │  [TLS: 200 OK + body]        │
   │  11. Decrypt            │                              │
   │      Inject Header      │                              │
   │      Re-encrypt         │                              │
   │<────────────────────────┤                              │
   │  [TLS: 200 OK +         │                              │
   │   X-Proxy:CS112 + body] │                              │
```

### Component Interaction

```
┌──────────────────────────────────────────────────────────────────┐
│                         Proxy Components                          │
│                                                                    │
│  ┌────────────────┐      ┌──────────────────┐                   │
│  │  Client Socket │─────>│  Request Parser  │                   │
│  └────────────────┘      └──────────────────┘                   │
│                                    │                              │
│                          ┌─────────┴─────────┐                   │
│                          ▼                   ▼                   │
│                  ┌──────────────┐    ┌──────────────┐           │
│                  │ HTTP Handler │    │ HTTPS Handler│           │
│                  └──────────────┘    └──────────────┘           │
│                          │                   │                   │
│                          │            ┌──────┴────────┐          │
│                          │            ▼               ▼          │
│                          │    ┌──────────────┐ ┌──────────────┐ │
│                          │    │ Cert Generator│ │ SSL Context │ │
│                          │    └──────────────┘ └──────────────┘ │
│                          │            │               │          │
│                          └────────────┴───────────────┘          │
│                                       │                          │
│                                       ▼                          │
│                          ┌────────────────────────┐              │
│                          │   Header Injector      │              │
│                          │  (X-Proxy:CS112)       │              │
│                          └────────────────────────┘              │
│                                       │                          │
│                                       ▼                          │
│                          ┌────────────────────────┐              │
│                          │   Server Connection    │              │
│                          └────────────────────────┘              │
└──────────────────────────────────────────────────────────────────┘
```

---

## Features

- ✅ **HTTP Support**: Full support for HTTP GET, POST, and HEAD methods
- ✅ **HTTPS Support**: TLS interception with CONNECT method handling
- ✅ **Multi-threading**: Concurrent handling of multiple client connections using pthreads
- ✅ **Dynamic Certificate Generation**: On-the-fly SSL certificate generation for intercepted HTTPS domains
- ✅ **Header Injection**: Automatically adds `X-Proxy:CS112` header to all HTTP/HTTPS responses
- ✅ **Error Handling**: Robust error handling for network failures and malformed requests
- ✅ **Performance Optimized**: Non-blocking I/O and efficient buffering for high-performance proxy operation

---

## Architecture

### Core Technologies
- **Language**: C (POSIX compliant)
- **TLS/SSL**: OpenSSL library for certificate generation and encryption
- **Concurrency**: POSIX threads (pthread) for multi-client support
- **Networking**: BSD sockets with select() for I/O multiplexing

### Request Processing Flow
1. **Client Connection**: Proxy listens on specified port and accepts incoming connections
2. **Request Analysis**: Determines if request is HTTP or HTTPS (CONNECT method)
3. **HTTP Flow**: Direct forwarding with header injection
4. **HTTPS Flow**:
   - Establishes SSL connection to upstream server
   - Generates domain-specific certificate signed by CA
   - Performs SSL handshake with client
   - Relays encrypted traffic bidirectionally with header injection

---

## Prerequisites

- GCC compiler
- OpenSSL development libraries (`libssl-dev`)
- POSIX-compliant Linux/Unix environment
- CA certificate and private key files

---

## Installation & Compilation

```bash
# Navigate to the project directory
cd /path/to/Part1

# Compile the proxy
make

# This will generate an executable named 'proxy'
```

The Makefile includes:
- Security checks (banned unsafe C functions)
- OpenSSL linking flags
- pthread support
- Automatic dependency management

---

## Usage

### Command-Line Arguments

```bash
./proxy <port> <ca_cert_path> <ca_key_path>
```

**Parameters:**
- `<port>`: Port number for the proxy to listen on (e.g., 8080)
- `<ca_cert_path>`: Path to the CA certificate file (proxy_ca.crt)
- `<ca_key_path>`: Path to the CA private key file (proxy_ca.key)

### Example

```bash
# Start proxy on port 8080
./proxy 8080 proxyCertificates/proxy_ca.crt proxyCertificates/proxy_ca.key
```

### Expected Output

```
Proxy server listening on port 8080
```

The proxy will now run continuously, handling HTTP and HTTPS requests.

---

## Browser Configuration

### Firefox (Recommended)

#### 1. Install CA Certificate

1. Open Firefox
2. Go to **Settings** → **Privacy & Security**
3. Scroll to **Certificates** → Click **View Certificates**
4. Select **Authorities** tab
5. Click **Import**
6. Select `proxyCertificates/proxy_ca.crt`
7. Check **"Trust this CA to identify websites"**
8. Click **OK**

#### 2. Configure Proxy Settings

1. Go to **Settings** → **Network Settings**
2. Click **Settings** button
3. Select **Manual proxy configuration**
4. Enter:
   - **HTTP Proxy**: `127.0.0.1`, Port: `8080`
   - **HTTPS Proxy**: `127.0.0.1`, Port: `8080`
5. Check **"Also use this proxy for HTTPS"**
6. Click **OK**

---

## Testing

### Command-Line Testing (Recommended for homework server)

```bash
# Get your private IP address
ifconfig

# Test with curl (replace <private_ip> with your actual IP)
curl -x <private_ip>:8080 --cacert proxyCertificates/proxy_ca.crt https://www.example.com

# Verify X-Proxy header is injected
curl -v -x <private_ip>:8080 --cacert proxyCertificates/proxy_ca.crt https://www.example.com 2>&1 | grep "X-Proxy"
```

Expected output should include:
```
< X-Proxy:CS112
```

### Browser Testing

After configuring Firefox with the proxy:

1. Open Firefox
2. Navigate to any HTTPS website
3. Open Developer Tools (F12)
4. Go to **Network** tab
5. Reload the page
6. Click on any request
7. Check **Response Headers** - you should see `X-Proxy:CS112`

### Tested Websites

The following websites have been successfully tested with this proxy:

- ✅ https://www.youtube.com
- ✅ https://www.reddit.com/r/programming
- ✅ https://stackoverflow.com/questions/tagged/python
- ✅ https://en.wikipedia.org/wiki/Artificial_intelligence
- ✅ https://en.wikipedia.org/wiki/Computer_science
- ✅ https://www.google.com

---

## Implementation Details

### Certificate Generation

The proxy dynamically generates SSL certificates for each intercepted HTTPS domain:

- **Format**: X.509 v3 certificates
- **Extensions**: 
  - Subject Alternative Name (SAN) - required for modern browsers
  - Basic Constraints (CA:FALSE)
  - Key Usage (digitalSignature, keyEncipherment)
  - Extended Key Usage (serverAuth)
- **Validity**: 1 year, backdated 1 day to handle clock skew
- **Signing**: Signed by CA certificate using RSA-2048 and SHA-256
- **Subject**: CN matches the target hostname

### Header Injection

The proxy injects a custom header into all HTTP/HTTPS responses:

- **Header**: `X-Proxy:CS112` (no space after colon)
- **Location**: Inserted immediately after the HTTP status line
- **Scope**: Applied to both HTTP and HTTPS traffic
- **Detection**: Checks to avoid duplicate injection

### Performance Optimizations

1. **Multi-threading**: Each client handled in separate detached thread
2. **Non-blocking I/O**: Socket operations with select() for multiplexing
3. **Buffer Management**: 64KB buffers for efficient data transfer
4. **Timeouts**: 
   - Client connections: 30 seconds
   - SSL tunnels: 60 seconds
5. **Connection Management**: Proper resource cleanup and connection reuse

### Security Considerations

- **MITM Warning**: This is a man-in-the-middle proxy for educational purposes
- **Certificate Trust**: Requires CA certificate installation in client browser
- **No Verification**: Upstream SSL certificates are not verified (for testing)
- **Header Visibility**: X-Proxy header makes interception detectable

---

## Troubleshooting

### Issue: "Did Not Connect: Potential Security Issue"

**Symptoms**: Firefox shows HSTS security error for sites like Wikipedia

**Causes**:
- System clock is incorrect
- Certificate validity period doesn't include current time
- CA certificate not properly installed

**Solutions**:
1. Verify system time is correct: `date`
2. Check certificate validity: `openssl x509 -in proxyCertificates/proxy_ca.crt -noout -dates`
3. Ensure CA certificate is imported in Firefox (see Browser Configuration)

---

### Issue: "Software is Preventing Firefox From Safely Connecting"

**Symptoms**: Firefox blocks connection due to certificate issues

**Causes**:
- CA certificate not trusted
- Missing SAN extension in generated certificates
- Common Name doesn't match domain

**Solutions**:
1. Verify CA is imported: Firefox Settings → Certificates → View Certificates → Authorities
2. Check SAN extension in code (line 693-701 in proxy.c)
3. Ensure certificate generation uses correct hostname

---

### Issue: "400 Bad Request" from target server

**Symptoms**: Server returns 400 error when accessed through proxy

**Causes**:
- Malformed HTTP request forwarding
- Missing or incorrect headers
- Protocol version mismatch

**Solutions**:
1. Check that all client headers are forwarded correctly
2. Verify HTTP/1.1 compliance
3. Test with verbose curl: `curl -v -x ...`
4. Examine request in Wireshark or tcpdump

---

### Issue: Slow performance or timeouts

**Symptoms**: Pages load slowly or connections time out

**Solutions**:
1. Increase buffer sizes (BUFFER_SIZE in proxy.c)
2. Adjust timeout values (lines 205-208, 576-580)
3. Check network latency to target server
4. Verify no resource leaks (use valgrind)

---

## Submission

### Package Your Code

```bash
# Package proxy.c and Makefile
tar -czvf fp.tar.gz proxy.c Makefile

# Verify package contents
tar -tzvf fp.tar.gz
```

### Submit to Course System

```bash
# Submit to CS112
provide comp112 fp fp.tar.gz

# Check submission status
progress comp112 fp
```

### Pre-Submission Checklist

- [ ] Code compiles without errors on homework server
- [ ] `make` produces executable named `proxy`
- [ ] Proxy accepts correct command-line arguments
- [ ] All tested websites work (YouTube, Reddit, Wikipedia, etc.)
- [ ] X-Proxy:CS112 header is injected (verify with curl -v)
- [ ] No HSTS or certificate errors in Firefox
- [ ] Makefile is included in submission
- [ ] Code is properly commented

---

## Clean Up

```bash
# Remove compiled files
make clean

# This removes proxy.o and proxy executable
```

---

## License & Academic Integrity

This project is part of CS112 coursework at Tufts University. Please adhere to the course's academic integrity policies. This implementation is for educational purposes only.

---

## Technical Notes

### Key Implementation Highlights

1. **Dual SSL Context**: Proxy maintains two SSL contexts simultaneously
   - Acts as SSL server to client (with generated certificate)
   - Acts as SSL client to upstream server (with no verification)

2. **Thread Safety**: Each client connection runs in isolated detached thread
   - No shared state between threads (except read-only CA cert/key)
   - Proper resource cleanup on thread exit

3. **Certificate Compatibility**: 
   - SAN extension required for modern browsers (Chrome, Firefox)
   - Clock skew handling with 1-day backdating
   - Proper X.509v3 extension setup

4. **I/O Efficiency**:
   - select() multiplexing for bidirectional SSL relay
   - Non-blocking sockets to prevent deadlock
   - Large buffers (64KB) to minimize system calls

### Author
CS112 Final Project - Part 1

### Version
1.0 - November 2025

---
---
---

<a name="chinese-documentation"></a>
# 中文文档

> 基于C语言的强大HTTPS代理实现，具有TLS拦截、动态证书生成和头部注入功能。

**CS112期末项目 - 第一部分** | [English Documentation](#https-proxy-server)

---

## 项目概述

一个用C语言实现的强大的HTTPS代理服务器，支持明文HTTP和加密HTTPS流量。该代理使用TLS拦截技术（中间人攻击）来检查和修改加密流量，具有多线程、动态证书生成和HTTP头部注入等功能。

这是CS112期末项目的第一部分，实现了一个基础代理服务器，将在第二部分中增强LLM功能。

---

## 项目结构

### 目录结构

```
Part1/
├── proxy.c                      # 主代理实现（755行）
│   ├── 主服务器循环              # 接受连接，生成线程
│   ├── HTTP处理器               # 处理明文HTTP请求
│   ├── HTTPS处理器              # 处理CONNECT和TLS拦截
│   ├── 证书生成器                # 动态X.509证书生成
│   ├── 头部注入器                # 添加X-Proxy:CS112头部
│   └── 工具函数                  # 解析、连接管理
│
├── Makefile                     # 构建配置
│   ├── 编译器标志                # 安全检查（禁用函数）
│   ├── 依赖项                    # OpenSSL、pthread、nsl
│   └── 构建目标                  # proxy、clean
│
├── README.md                    # 本文档
│
├── proxyCertificates/           # CA证书目录
│   ├── proxy_ca.crt            # CA公共证书（用于浏览器导入）
│   └── proxy_ca.key            # CA私钥（用于签名证书）
│
├── proxy                        # 编译后的可执行文件
└── proxy.o                      # 对象文件
```

---

## 功能特性

- ✅ **HTTP支持**：完整支持HTTP GET、POST和HEAD方法
- ✅ **HTTPS支持**：支持CONNECT方法的TLS拦截
- ✅ **多线程**：使用pthread并发处理多个客户端连接
- ✅ **动态证书生成**：为拦截的HTTPS域名即时生成SSL证书
- ✅ **头部注入**：自动向所有HTTP/HTTPS响应添加`X-Proxy:CS112`头部
- ✅ **错误处理**：对网络故障和错误请求进行强大的错误处理
- ✅ **性能优化**：非阻塞I/O和高效缓冲，实现高性能代理操作

---

## 系统要求

- GCC编译器
- OpenSSL开发库（`libssl-dev`）
- POSIX兼容的Linux/Unix环境
- CA证书和私钥文件

---

## 安装与编译

```bash
# 进入项目目录
cd /path/to/Part1

# 编译代理
make

# 这将生成名为'proxy'的可执行文件
```

---

## 使用方法

### 命令行参数

```bash
./proxy <端口> <CA证书路径> <CA私钥路径>
```

**参数说明：**
- `<端口>`：代理监听的端口号（例如8080）
- `<CA证书路径>`：CA证书文件路径（proxy_ca.crt）
- `<CA私钥路径>`：CA私钥文件路径（proxy_ca.key）

### 示例

```bash
# 在8080端口启动代理
./proxy 8080 proxyCertificates/proxy_ca.crt proxyCertificates/proxy_ca.key
```

---

## 浏览器配置

### Firefox（推荐）

#### 1. 安装CA证书

1. 打开Firefox
2. 进入 **设置** → **隐私与安全**
3. 滚动到 **证书** → 点击 **查看证书**
4. 选择 **证书颁发机构** 标签
5. 点击 **导入**
6. 选择 `proxyCertificates/proxy_ca.crt`
7. 勾选 **"信任此CA以标识网站"**
8. 点击 **确定**

#### 2. 配置代理设置

1. 进入 **设置** → **网络设置**
2. 点击 **设置** 按钮
3. 选择 **手动代理配置**
4. 输入：
   - **HTTP代理**：`127.0.0.1`，端口：`8080`
   - **HTTPS代理**：`127.0.0.1`，端口：`8080`
5. 勾选 **"同时为HTTPS使用此代理"**
6. 点击 **确定**

---

## 测试

### 命令行测试（推荐用于作业服务器）

```bash
# 获取私有IP地址
ifconfig

# 使用curl测试（将<private_ip>替换为你的实际IP）
curl -x <private_ip>:8080 --cacert proxyCertificates/proxy_ca.crt https://www.example.com

# 验证X-Proxy头部已注入
curl -v -x <private_ip>:8080 --cacert proxyCertificates/proxy_ca.crt https://www.example.com 2>&1 | grep "X-Proxy"
```

### 已测试网站

以下网站已成功通过此代理测试：

- ✅ https://www.youtube.com
- ✅ https://www.reddit.com/r/programming
- ✅ https://stackoverflow.com/questions/tagged/python
- ✅ https://en.wikipedia.org/wiki/Artificial_intelligence
- ✅ https://en.wikipedia.org/wiki/Computer_science
- ✅ https://www.google.com

---

## 实现细节

### 证书生成

代理为每个拦截的HTTPS域名动态生成SSL证书：

- **格式**：X.509 v3证书
- **扩展**：
  - 主题备用名称（SAN）- 现代浏览器要求
  - 基本约束（CA:FALSE）
  - 密钥用法（数字签名、密钥加密）
  - 扩展密钥用法（服务器身份验证）
- **有效期**：1年，提前1天生效以处理时钟偏差
- **签名**：使用CA证书签名，采用RSA-2048和SHA-256
- **主题**：CN匹配目标主机名

### 头部注入

代理向所有HTTP/HTTPS响应注入自定义头部：

- **头部**：`X-Proxy:CS112`（冒号后无空格）
- **位置**：紧接在HTTP状态行之后插入
- **范围**：应用于HTTP和HTTPS流量
- **检测**：检查以避免重复注入

### 性能优化

1. **多线程**：每个客户端在独立的分离线程中处理
2. **非阻塞I/O**：使用select()进行多路复用的套接字操作
3. **缓冲区管理**：64KB缓冲区实现高效数据传输
4. **超时设置**：
   - 客户端连接：30秒
   - SSL隧道：60秒
5. **连接管理**：正确的资源清理和连接复用

---

## 故障排除

### 问题："未连接：潜在安全问题"

**解决方案**：
1. 确保系统时钟设置正确
2. 证书有效期包含当前时间
3. CA证书已正确安装在浏览器中

---

### 问题："软件阻止Firefox安全连接"

**解决方案**：
1. 验证CA证书已导入为受信任的颁发机构
2. 检查证书生成包含SAN扩展
3. 确保证书通用名称与域名匹配

---

### 问题："400错误请求"错误

**解决方案**：
1. 检查代理是否正确转发所有请求头
2. 验证HTTP/1.1协议合规性
3. 确保正确处理分块传输编码

---

## 提交作业

### 打包代码

```bash
# 打包proxy.c和Makefile
tar -czvf fp.tar.gz proxy.c Makefile

# 验证打包内容
tar -tzvf fp.tar.gz
```

### 提交到课程系统

```bash
# 提交到CS112
provide comp112 fp fp.tar.gz

# 检查提交状态
progress comp112 fp
```

### 提交前检查清单

- [ ] 代码在作业服务器上编译无错误
- [ ] `make`生成名为`proxy`的可执行文件
- [ ] 代理接受正确的命令行参数
- [ ] 所有测试网站正常工作（YouTube、Reddit、Wikipedia等）
- [ ] X-Proxy:CS112头部已注入（使用curl -v验证）
- [ ] Firefox中无HSTS或证书错误
- [ ] Makefile已包含在提交中
- [ ] 代码有适当的注释

---

## 清理

```bash
# 删除编译文件
make clean
```

---

## 许可证与学术诚信

本项目是Tufts大学CS112课程作业的一部分。请遵守课程的学术诚信政策。此实现仅用于教育目的。

---

**版本**：1.0 - 2025年11月
