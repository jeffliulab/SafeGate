# HTTPS Proxy - CS112 Final Project Part 1

A man-in-the-middle (MITM) proxy server that supports both HTTP and HTTPS traffic interception with dynamic certificate generation.

## Features

- ✓ HTTP/1.1 proxy support (GET method)
- ✓ HTTPS proxy with CONNECT method
- ✓ TLS/SSL interception (MITM)
- ✓ Dynamic certificate generation
- ✓ Response header injection (X-Proxy: CS112)
- ✓ Multi-client support using select()
- ✓ Based on Assignment 2 architecture

## Architecture

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│   Client    │◄───────►│  HTTPS Proxy │◄───────►│   Server    │
│  (Browser)  │  SSL 1  │   (MITM)     │  SSL 2  │ (Real Site) │
└─────────────┘         └──────────────┘         └─────────────┘
                              │
                        Decrypts both!
                        Can inspect &
                        modify traffic
```

### Core Components

```
┌───────────────────────────────────────────────────┐
│                HTTPS Proxy Server                 │
├───────────────────────────────────────────────────┤
│  Network Layer (select-based I/O multiplexing)   │
│  ├── Socket management                            │
│  ├── Multi-client handling                        │
│  └── Connection pooling                           │
├───────────────────────────────────────────────────┤
│  HTTP Protocol Layer                              │
│  ├── Request parsing (GET, CONNECT)               │
│  ├── HTTP forwarding                              │
│  └── Response modification                        │
├───────────────────────────────────────────────────┤
│  SSL/TLS Layer (OpenSSL)                          │
│  ├── Certificate generation                       │
│  ├── SSL handshake (client & server)              │
│  └── Encrypted communication                      │
├───────────────────────────────────────────────────┤
│  Certificate Management                           │
│  ├── CA credential loading                        │
│  ├── Dynamic cert generation                      │
│  └── Certificate signing                          │
└───────────────────────────────────────────────────┘
```

## HTTPS MITM Flow

```
1. Client sends CONNECT request
   │
   ▼
┌──────────────────────────────┐
│ CONNECT www.google.com:443   │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ Proxy connects to real server│
│ TCP connection to google.com │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ Send "200 Connection         │
│ Established" to client       │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ Generate fake certificate    │
│ - Create X.509 cert          │
│ - Set CN=www.google.com      │
│ - Sign with CA private key   │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────────────────┐
│ Dual SSL handshake                       │
│ ┌─────────────┐     ┌─────────────┐     │
│ │ SSL_accept()│     │SSL_connect()│     │
│ │(with client)│     │(with server)│     │
│ └──────┬──────┘     └──────┬──────┘     │
│        │                   │             │
│        └─────────┬─────────┘             │
└──────────────────┼───────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────┐
│ Transparent data forwarding            │
│                                        │
│ Client → [SSL_read]  → Decrypt         │
│             ↓                          │
│       Plain text data                  │
│       (can inspect!)                   │
│             ↓                          │
│    Inject X-Proxy header               │
│             ↓                          │
│       [SSL_write] → Encrypt            │
│             ↓                          │
│          Client                        │
└────────────────────────────────────────┘
```

## Data Structure

```c
typedef struct {
    int client_fd;              // Client socket
    int server_fd;              // Upstream server socket
    SSL *client_ssl;            // SSL to client (fake cert)
    SSL *server_ssl;            // SSL to server (real cert)
    SSL_CTX *client_ctx;        // SSL context
    SSL_CTX *server_ctx;
    int is_https;               // Connection type
    char hostname[256];         // For cert generation
    char client_buffer[16384];  // Data buffer
    int slot;                   // Connection pool slot
} connection_info;
```

## Key Functions

| Function | Purpose |
|----------|---------|
| `generate_fake_certificate()` | Creates X.509 cert signed by CA |
| `setup_client_ssl()` | SSL handshake with client (as server) |
| `setup_server_ssl()` | SSL handshake with server (as client) |
| `handle_connect_request()` | Process HTTPS CONNECT method |
| `handle_http_request()` | Process regular HTTP requests |
| `inject_proxy_header()` | Add X-Proxy: CS112 to response |
| `handle_data_transfer()` | Bidirectional data forwarding |

## Build

```bash
make
```

Generates `proxy` executable.

## Usage

```bash
./proxy <port> <ca_cert_path> <ca_key_path>
```

Example:
```bash
./proxy 8080 proxyCertificates/proxy_ca.crt proxyCertificates/proxy_ca.key
```

## Testing

### On Homework Server

```bash
# Get private IP
ifconfig

# Test HTTPS (verify X-Proxy header injection)
curl -x <private_ip>:8080 --cacert proxyCertificates/proxy_ca.crt https://www.example.com -I | grep X-Proxy

# Expected output:
# X-Proxy: CS112
```

### Tested Sites

- ✓ example.com (HTTP & HTTPS)
- ✓ google.com (HTTPS)
- ✓ youtube.com (HTTPS)
- ✓ wikipedia.org (HTTPS)

## Technical Details

**Language:** C  
**Concurrency:** select() I/O multiplexing  
**SSL/TLS:** OpenSSL 1.1.1+  
**Protocol:** HTTP/1.1, HTTPS (TLS 1.2/1.3)  
**Lines of Code:** ~670

## Implementation Notes

- Based on Assignment 2's select-based architecture
- Uses OpenSSL for all TLS operations
- Dynamically generates certificates per hostname
- Injects X-Proxy header into all HTTPS responses
- Handles SIGPIPE to prevent crashes

## Limitations

- Supports HTTP/1.1 only (not HTTP/2)
- Some websites may not be compatible
- Performance depends on SSL handshake overhead
