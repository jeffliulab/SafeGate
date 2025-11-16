// CS112 Final Project Part1 - HTTPS Proxy
// Based on a2 code with proxy features added (eg. openssl)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <time.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>

// OpenSSL headers for HTTPS
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

#define MAX_CLIENTS 200
#define BUFFER_SIZE 16384

// Global CA cert and key - loaded from command line args
X509 *g_ca_cert = NULL;
EVP_PKEY *g_ca_key = NULL;

// Connection info - modified from a2
typedef struct {
    int client_fd;
    int server_fd;
    SSL *client_ssl;        // for HTTPS connections
    SSL *server_ssl;
    SSL_CTX *client_ctx;
    SSL_CTX *server_ctx;
    int is_https;
    char hostname[256];     // need this for cert generation
    int port;
    char client_buffer[BUFFER_SIZE];
    int client_buffer_len;
    int slot;
    time_t last_activity_time;
} connection_info;

connection_info connections[MAX_CLIENTS];
int proxy_listen_fd;
fd_set master_fds;

// Function declarations
void init_connection(int index);
void close_connection(int index);
int connect_to_server(const char *hostname, int port);
int parse_http_request(const char *buffer, char *method, char *host, int *port, char *path);
int handle_http_request(int conn_index);
int handle_connect_request(int conn_index, const char *hostname, int port);
X509 *generate_fake_certificate(const char *hostname, EVP_PKEY *pkey);
int setup_client_ssl(int conn_index);
int setup_server_ssl(int conn_index);
void inject_proxy_header(char *response, int *response_len);
void handle_data_transfer(int conn_index, int from_client);

// Init openssl - needed before any SSL operations
void init_openssl() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

// Load CA certificate and private key from files
// We use these to sign fake certs later
int load_ca_credentials(const char *cert_path, const char *key_path) {
    FILE *fp = fopen(cert_path, "r");
    if (!fp) {
        perror("Failed to open CA certificate");
        return -1;
    }
    g_ca_cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!g_ca_cert) {
        fprintf(stderr, "Failed to read CA certificate\n");
        return -1;
    }
    
    fp = fopen(key_path, "r");
    if (!fp) {
        perror("Failed to open CA private key");
        return -1;
    }
    g_ca_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!g_ca_key) {
        fprintf(stderr, "Failed to read CA private key\n");
        return -1;
    }
    
    printf("CA credentials loaded successfully\n");
    return 0;
}

// Generate fake cert for the target hostname
// This gets signed by our CA so the browser trusts it
X509 *generate_fake_certificate(const char *hostname, EVP_PKEY *pkey) {
    X509 *cert = X509_new();
    if (!cert) return NULL;
    
    X509_set_version(cert, 2);  // v3
    ASN1_INTEGER_set(X509_get_serialNumber(cert), (long)time(NULL));
    
    // Valid for 1 year
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);
    
    X509_set_pubkey(cert, pkey);
    
    // Set CN to the hostname (important - must match!)
    X509_NAME *name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, 
                               (unsigned char *)hostname, -1, -1, 0);
    X509_set_subject_name(cert, name);
    
    // Issuer is our CA
    X509_set_issuer_name(cert, X509_get_subject_name(g_ca_cert));
    
    // Sign with CA private key - this is the key part
    X509_sign(cert, g_ca_key, EVP_sha256());
    
    return cert;
}

// Connect to the upstream server
int connect_to_server(const char *hostname, int port) {
    struct sockaddr_in server_addr;
    struct hostent *server;
    int sockfd;
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Failed to create socket for upstream server");
        return -1;
    }
    
    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr, "Failed to resolve hostname: %s\n", hostname);
        close(sockfd);
        return -1;
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    server_addr.sin_port = htons(port);
    
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Failed to connect to upstream server");
        close(sockfd);
        return -1;
    }
    
    return sockfd;
}

// Parse HTTP request - extract method, host, port, path
int parse_http_request(const char *buffer, char *method, char *host, int *port, char *path) {
    char temp_url[512];
    
    // Get method and URL from first line
    if (sscanf(buffer, "%s %s", method, temp_url) != 2) {
        return -1;
    }
    
    *port = 80;
    strcpy(path, "/");
    
    // CONNECT requests have different format
    if (strcmp(method, "CONNECT") == 0) {
        if (sscanf(temp_url, "%[^:]:%d", host, port) < 1) {
            return -1;
        }
        return 0;
    }
    
    // For GET/POST etc, extract host from Host header
    char *host_line = strstr(buffer, "Host: ");
    if (!host_line) {
        return -1;
    }
    
    host_line += 6;
    if (sscanf(host_line, "%[^:\r\n]:%d", host, port) < 1) {
        sscanf(host_line, "%[^\r\n]", host);
    }
    
    // Extract path from URL
    if (strstr(temp_url, "http://") == temp_url) {
        char *path_start = strchr(temp_url + 7, '/');
        if (path_start) {
            strcpy(path, path_start);
        }
    } else {
        strcpy(path, temp_url);
    }
    
    return 0;
}

// Handle regular HTTP requests (GET, POST, etc)
int handle_http_request(int conn_index) {
    char method[16], host[256], path[512];
    int port;
    
    if (parse_http_request(connections[conn_index].client_buffer, method, host, &port, path) < 0) {
        fprintf(stderr, "Failed to parse HTTP request\n");
        return -1;
    }
    
    printf("HTTP %s request to %s:%d%s\n", method, host, port, path);
    
    // Connect to the actual server
    connections[conn_index].server_fd = connect_to_server(host, port);
    if (connections[conn_index].server_fd < 0) {
        return -1;
    }
    
    // Rebuild request and forward it
    char request[BUFFER_SIZE];
    snprintf(request, sizeof(request), "%s %s HTTP/1.1\r\n", method, path);
    
    char *headers = strstr(connections[conn_index].client_buffer, "\r\n");
    if (headers) {
        headers += 2;
        strncat(request, headers, sizeof(request) - strlen(request) - 1);
    }
    
    if (write(connections[conn_index].server_fd, request, strlen(request)) < 0) {
        perror("Failed to send request to upstream server");
        return -1;
    }
    
    FD_SET(connections[conn_index].server_fd, &master_fds);
    
    return 0;
}

// Handle CONNECT requests for HTTPS
int handle_connect_request(int conn_index, const char *hostname, int port) {
    printf("CONNECT request to %s:%d\n", hostname, port);
    
    // Save hostname - we need it for generating the fake cert
    strncpy(connections[conn_index].hostname, hostname, sizeof(connections[conn_index].hostname) - 1);
    connections[conn_index].hostname[sizeof(connections[conn_index].hostname) - 1] = '\0';
    connections[conn_index].port = port;
    connections[conn_index].is_https = 1;
    
    // Connect to real server
    connections[conn_index].server_fd = connect_to_server(hostname, port);
    if (connections[conn_index].server_fd < 0) {
        return -1;
    }
    
    // Send 200 to client
    const char *response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    if (write(connections[conn_index].client_fd, response, strlen(response)) < 0) {
        perror("Failed to send CONNECT response");
        return -1;
    }
    
    // Now setup SSL on both sides - this is the MITM part
    if (setup_client_ssl(conn_index) < 0) {
        fprintf(stderr, "Failed to setup SSL with client\n");
        return -1;
    }
    
    if (setup_server_ssl(conn_index) < 0) {
        fprintf(stderr, "Failed to setup SSL with server\n");
        return -1;
    }
    
    FD_SET(connections[conn_index].server_fd, &master_fds);
    
    return 0;
}

// Setup SSL with client - we pretend to be the server
// This is where we use the fake cert
int setup_client_ssl(int conn_index) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    // Generate RSA key pair for this connection
    EVP_PKEY *pkey = EVP_PKEY_new();
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    BN_set_word(bn, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, bn, NULL);
    EVP_PKEY_assign_RSA(pkey, rsa);
    BN_free(bn);
    
    // Generate fake cert with the hostname
    X509 *cert = generate_fake_certificate(connections[conn_index].hostname, pkey);
    if (!cert) {
        fprintf(stderr, "Failed to generate fake certificate\n");
        EVP_PKEY_free(pkey);
        SSL_CTX_free(ctx);
        return -1;
    }
    
    SSL_CTX_use_certificate(ctx, cert);
    SSL_CTX_use_PrivateKey(ctx, pkey);
    
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, connections[conn_index].client_fd);
    
    // Do SSL handshake as server
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return -1;
    }
    
    connections[conn_index].client_ssl = ssl;
    connections[conn_index].client_ctx = ctx;
    
    printf("SSL established with client for %s\n", connections[conn_index].hostname);
    return 0;
}

// Setup SSL with real server - we act as client
int setup_server_ssl(int conn_index) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, connections[conn_index].server_fd);
    
    // SSL handshake as client
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return -1;
    }
    
    connections[conn_index].server_ssl = ssl;
    connections[conn_index].server_ctx = ctx;
    
    printf("SSL established with server %s\n", connections[conn_index].hostname);
    return 0;
}

// Inject X-Proxy: CS112 header into HTTP response
void inject_proxy_header(char *response, int *response_len) {
    char *header_end = strstr(response, "\r\n\r\n");
    if (!header_end) {
        return;  // not a valid HTTP response
    }
    
    // Don't inject twice
    if (strstr(response, "X-Proxy: CS112") != NULL) {
        return;
    }
    
    int header_len = header_end - response;
    int body_len = *response_len - header_len - 4;
    
    // Make sure we have space
    if (body_len < 0 || header_len + 21 + body_len > BUFFER_SIZE) {
        return;
    }
    
    // Shift body data to make room for new header
    memmove(header_end + 21, header_end + 4, body_len);
    
    // Insert X-Proxy header (21 bytes total)
    memcpy(header_end, "\r\nX-Proxy: CS112\r\n\r\n", 21);
    
    *response_len = header_len + 21 + body_len;
}

// Transfer data between client and server
void handle_data_transfer(int conn_index, int from_client) {
    char buffer[BUFFER_SIZE];
    int bytes_read;
    
    if (from_client) {
        // Read from client
        if (connections[conn_index].client_ssl) {
            bytes_read = SSL_read(connections[conn_index].client_ssl, buffer, sizeof(buffer));
        } else {
            bytes_read = read(connections[conn_index].client_fd, buffer, sizeof(buffer));
        }
        
        if (bytes_read <= 0) {
            close_connection(conn_index);
            return;
        }
        
        // Forward to server
        int bytes_written;
        if (connections[conn_index].server_ssl) {
            bytes_written = SSL_write(connections[conn_index].server_ssl, buffer, bytes_read);
        } else {
            bytes_written = write(connections[conn_index].server_fd, buffer, bytes_read);
        }
        
        if (bytes_written <= 0) {
            close_connection(conn_index);
            return;
        }
    } else {
        // Read from server
        if (connections[conn_index].server_ssl) {
            bytes_read = SSL_read(connections[conn_index].server_ssl, buffer, sizeof(buffer));
        } else {
            bytes_read = read(connections[conn_index].server_fd, buffer, sizeof(buffer));
        }
        
        if (bytes_read <= 0) {
            close_connection(conn_index);
            return;
        }
        
        // Inject header if this is an HTTP response
        if (strstr(buffer, "HTTP/") == buffer) {
            inject_proxy_header(buffer, &bytes_read);
        }
        
        // Forward to client
        int bytes_written;
        if (connections[conn_index].client_ssl) {
            bytes_written = SSL_write(connections[conn_index].client_ssl, buffer, bytes_read);
        } else {
            bytes_written = write(connections[conn_index].client_fd, buffer, bytes_read);
        }
        
        if (bytes_written <= 0) {
            close_connection(conn_index);
            return;
        }
    }
    
    connections[conn_index].last_activity_time = time(NULL);
}

void init_connection(int index) {
    connections[index].client_fd = -1;
    connections[index].server_fd = -1;
    connections[index].client_ssl = NULL;
    connections[index].server_ssl = NULL;
    connections[index].client_ctx = NULL;
    connections[index].server_ctx = NULL;
    connections[index].is_https = 0;
    connections[index].hostname[0] = '\0';
    connections[index].port = 0;
    connections[index].client_buffer_len = 0;
    connections[index].slot = 0;
    connections[index].last_activity_time = 0;
}

void close_connection(int index) {
    if (connections[index].slot == 0) return;
    
    // Clean up SSL stuff
    if (connections[index].client_ssl) {
        SSL_shutdown(connections[index].client_ssl);
        SSL_free(connections[index].client_ssl);
        connections[index].client_ssl = NULL;
    }
    
    if (connections[index].server_ssl) {
        SSL_shutdown(connections[index].server_ssl);
        SSL_free(connections[index].server_ssl);
        connections[index].server_ssl = NULL;
    }
    
    if (connections[index].client_ctx) {
        SSL_CTX_free(connections[index].client_ctx);
        connections[index].client_ctx = NULL;
    }
    
    if (connections[index].server_ctx) {
        SSL_CTX_free(connections[index].server_ctx);
        connections[index].server_ctx = NULL;
    }
    
    // Close sockets
    if (connections[index].client_fd >= 0) {
        FD_CLR(connections[index].client_fd, &master_fds);
        close(connections[index].client_fd);
    }
    
    if (connections[index].server_fd >= 0) {
        FD_CLR(connections[index].server_fd, &master_fds);
        close(connections[index].server_fd);
    }
    
    init_connection(index);
}

void add_new_connection(int client_fd) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (connections[i].slot == 0) {
            connections[i].client_fd = client_fd;
            connections[i].slot = 1;
            connections[i].last_activity_time = time(NULL);
            FD_SET(client_fd, &master_fds);
            printf("New connection accepted, fd=%d\n", client_fd);
            return;
        }
    }
    
    printf("Maximum clients reached, connection rejected\n");
    close(client_fd);
}

int main(int argc, char *argv[]) {
    // Ignore SIGPIPE - prevents crash when client closes connection
    signal(SIGPIPE, SIG_IGN);
    
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <port> <ca_cert_path> <ca_key_path>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    int port = atoi(argv[1]);
    char *ca_cert_path = argv[2];
    char *ca_key_path = argv[3];
    
    printf("Starting proxy on port %d\n", port);
    printf("Using CA cert: %s\n", ca_cert_path);
    printf("Using CA key: %s\n", ca_key_path);
    
    init_openssl();
    if (load_ca_credentials(ca_cert_path, ca_key_path) < 0) {
        fprintf(stderr, "Failed to load CA credentials\n");
        exit(EXIT_FAILURE);
    }
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        init_connection(i);
    }
    
    // Setup listening socket - same as a2
    struct sockaddr_in server_addr;
    proxy_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (proxy_listen_fd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    int opt = 1;
    setsockopt(proxy_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    
    if (bind(proxy_listen_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
    
    if (listen(proxy_listen_fd, 10) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }
    
    printf("Proxy listening on port %d\n", port);
    
    fd_set read_fds;
    FD_ZERO(&master_fds);
    FD_SET(proxy_listen_fd, &master_fds);
    
    // Main select loop
    while (1) {
        read_fds = master_fds;
        
        int max_fd = proxy_listen_fd;
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (connections[i].client_fd > max_fd) {
                max_fd = connections[i].client_fd;
            }
            if (connections[i].server_fd > max_fd) {
                max_fd = connections[i].server_fd;
            }
        }
        
        struct timeval tv = {1, 0};
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &tv);
        
        if (activity < 0 && errno != EINTR) {
            perror("Select error");
            break;
        }
        
        // New connection?
        if (FD_ISSET(proxy_listen_fd, &read_fds)) {
            int new_socket = accept(proxy_listen_fd, NULL, NULL);
            if (new_socket > 0) {
                add_new_connection(new_socket);
            }
        }
        
        // Handle existing connections
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (connections[i].slot == 0) continue;
            
            if (connections[i].client_fd >= 0 && FD_ISSET(connections[i].client_fd, &read_fds)) {
                if (connections[i].server_fd < 0) {
                    // First request - need to parse and setup
                    int bytes = read(connections[i].client_fd, connections[i].client_buffer, 
                                   sizeof(connections[i].client_buffer) - 1);
                    
                    if (bytes <= 0) {
                        close_connection(i);
                        continue;
                    }
                    
                    connections[i].client_buffer[bytes] = '\0';
                    connections[i].client_buffer_len = bytes;
                    
                    char method[16], host[256], path[512];
                    int port;
                    
                    if (parse_http_request(connections[i].client_buffer, method, host, &port, path) < 0) {
                        fprintf(stderr, "Invalid HTTP request\n");
                        close_connection(i);
                        continue;
                    }
                    
                    if (strcmp(method, "CONNECT") == 0) {
                        // HTTPS - need SSL setup
                        if (handle_connect_request(i, host, port) < 0) {
                            close_connection(i);
                        }
                    } else {
                        // Regular HTTP
                        if (handle_http_request(i) < 0) {
                            close_connection(i);
                        }
                    }
                } else {
                    handle_data_transfer(i, 1);
                }
            }
            
            if (connections[i].server_fd >= 0 && FD_ISSET(connections[i].server_fd, &read_fds)) {
                handle_data_transfer(i, 0);
            }
        }
    }
    
    close(proxy_listen_fd);
    
    if (g_ca_cert) X509_free(g_ca_cert);
    if (g_ca_key) EVP_PKEY_free(g_ca_key);
    
    return 0;
}

