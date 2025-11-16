/* CS112 Final Project Part 1 - HTTPS Proxy
 * Supports HTTP and HTTPS with TLS interception (MITM)
 * Features: Multi-threading, certificate generation, header injection
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <sys/select.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

#define BUFFER_SIZE 65536
#define MAX_HEADER_SIZE 8192
#define BACKLOG 128

/* Global CA certificate and key for signing */
static X509 *ca_cert = NULL;
static EVP_PKEY *ca_key = NULL;

/* Client connection context */
typedef struct {
    int client_fd;
    struct sockaddr_in client_addr;
} client_context_t;

/* Function prototypes */
void *handle_client(void *arg);
void handle_http_request(int client_fd, char *request, size_t req_len);
void handle_https_connect(int client_fd, char *request, size_t req_len);
int connect_to_server(const char *hostname, int port);
X509 *generate_cert(const char *hostname);
SSL_CTX *create_ssl_context_server(void);
SSL_CTX *create_ssl_context_client(void);
void inject_header(char *response, size_t *response_len, size_t buffer_size);
int read_line(int fd, char *buf, size_t max_len);
void parse_host_port(char *host_header, char **hostname, int *port);
int load_ca_cert_and_key(const char *cert_path, const char *key_path);

/* Signal handler for clean shutdown */
void signal_handler(int sig) {
    if (sig == SIGPIPE) {
        /* Ignore SIGPIPE */
        return;
    }
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <port> <ca_cert_path> <ca_key_path>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int port = atoi(argv[1]);
    const char *ca_cert_path = argv[2];
    const char *ca_key_path = argv[3];

    /* Load CA certificate and key */
    if (load_ca_cert_and_key(ca_cert_path, ca_key_path) != 0) {
        fprintf(stderr, "Failed to load CA certificate and key\n");
        exit(EXIT_FAILURE);
    }

    /* Initialize OpenSSL */
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    /* Ignore SIGPIPE */
    signal(SIGPIPE, signal_handler);

    /* Create listening socket */
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    /* Set socket options */
    int opt = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(listen_fd);
        exit(EXIT_FAILURE);
    }

    /* Bind socket */
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(listen_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(listen_fd);
        exit(EXIT_FAILURE);
    }

    /* Listen */
    if (listen(listen_fd, BACKLOG) < 0) {
        perror("listen");
        close(listen_fd);
        exit(EXIT_FAILURE);
    }

    printf("Proxy server listening on port %d\n", port);

    /* Accept connections */
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_len);

        if (client_fd < 0) {
            perror("accept");
            continue;
        }

        /* Create client context */
        client_context_t *ctx = malloc(sizeof(client_context_t));
        if (!ctx) {
            close(client_fd);
            continue;
        }
        ctx->client_fd = client_fd;
        ctx->client_addr = client_addr;

        /* Handle client in a new thread */
        pthread_t thread;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        
        if (pthread_create(&thread, &attr, handle_client, ctx) != 0) {
            perror("pthread_create");
            close(client_fd);
            free(ctx);
        }
        pthread_attr_destroy(&attr);
    }

    close(listen_fd);
    X509_free(ca_cert);
    EVP_PKEY_free(ca_key);
    return 0;
}

/* Load CA certificate and key */
int load_ca_cert_and_key(const char *cert_path, const char *key_path) {
    FILE *fp = fopen(cert_path, "r");
    if (!fp) {
        perror("fopen ca_cert");
        return -1;
    }
    ca_cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!ca_cert) {
        fprintf(stderr, "Failed to read CA certificate\n");
        return -1;
    }

    fp = fopen(key_path, "r");
    if (!fp) {
        perror("fopen ca_key");
        X509_free(ca_cert);
        ca_cert = NULL;
        return -1;
    }
    ca_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!ca_key) {
        fprintf(stderr, "Failed to read CA key\n");
        X509_free(ca_cert);
        ca_cert = NULL;
        return -1;
    }

    return 0;
}

/* Handle client connection */
void *handle_client(void *arg) {
    client_context_t *ctx = (client_context_t *)arg;
    int client_fd = ctx->client_fd;
    free(ctx);

    /* Set socket timeout */
    struct timeval tv;
    tv.tv_sec = 30;
    tv.tv_usec = 0;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    char request[MAX_HEADER_SIZE];
    ssize_t bytes_read = recv(client_fd, request, sizeof(request) - 1, 0);

    if (bytes_read <= 0) {
        close(client_fd);
        return NULL;
    }

    request[bytes_read] = '\0';

    /* Check if it's a CONNECT request (HTTPS) */
    if (strncmp(request, "CONNECT ", 8) == 0) {
        handle_https_connect(client_fd, request, bytes_read);
    } else if (strncmp(request, "GET ", 4) == 0 || 
               strncmp(request, "POST ", 5) == 0 ||
               strncmp(request, "HEAD ", 5) == 0) {
        handle_http_request(client_fd, request, bytes_read);
    } else {
        /* Unknown method */
        const char *err = "HTTP/1.1 501 Not Implemented\r\n\r\n";
        send(client_fd, err, strlen(err), 0);
    }

    close(client_fd);
    return NULL;
}

/* Handle HTTP request */
void handle_http_request(int client_fd, char *request, size_t req_len) {
    char method[16], url[2048], version[16];
    char hostname[256] = {0};
    int port = 80;
    char *host_line = NULL;

    /* Parse request line */
    if (sscanf(request, "%15s %2047s %15s", method, url, version) != 3) {
        const char *err = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send(client_fd, err, strlen(err), 0);
        return;
    }

    /* Extract hostname from Host header */
    host_line = strstr(request, "Host: ");
    if (host_line) {
        host_line += 6;
        char *end = strstr(host_line, "\r\n");
        if (end) {
            size_t len = end - host_line;
            if (len < sizeof(hostname)) {
                strncpy(hostname, host_line, len);
                hostname[len] = '\0';
                parse_host_port(hostname, NULL, &port);
            }
        }
    }

    if (hostname[0] == '\0') {
        const char *err = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send(client_fd, err, strlen(err), 0);
        return;
    }

    /* Connect to server */
    int server_fd = connect_to_server(hostname, port);
    if (server_fd < 0) {
        const char *err = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
        send(client_fd, err, strlen(err), 0);
        return;
    }

    /* Forward request to server */
    ssize_t sent = 0;
    while (sent < (ssize_t)req_len) {
        ssize_t n = send(server_fd, request + sent, req_len - sent, 0);
        if (n < 0) {
            close(server_fd);
            return;
        }
        sent += n;
    }

    /* Receive response and inject header */
    char response[BUFFER_SIZE];
    ssize_t total_bytes = 0;
    int first_chunk = 1;
    
    while (1) {
        ssize_t bytes = recv(server_fd, response, sizeof(response), 0);
        if (bytes <= 0) {
            break;
        }
        
        size_t response_len = bytes;
        
        /* Inject header in first chunk if it's HTTP response */
        if (first_chunk && bytes >= 5 && strncmp(response, "HTTP/", 5) == 0) {
            inject_header(response, &response_len, sizeof(response));
            first_chunk = 0;
        }
        
        /* Send to client */
        ssize_t sent_to_client = 0;
        while (sent_to_client < (ssize_t)response_len) {
            ssize_t n = send(client_fd, response + sent_to_client, 
                           response_len - sent_to_client, 0);
            if (n < 0) {
                close(server_fd);
                return;
            }
            sent_to_client += n;
        }
        
        total_bytes += bytes;
    }

    close(server_fd);
}

/* Handle HTTPS CONNECT request */
void handle_https_connect(int client_fd, char *request, size_t req_len) {
    char hostname[256], port_str[16];
    int port = 443;

    /* Parse CONNECT request: CONNECT hostname:port HTTP/1.1 */
    char *space = strchr(request + 8, ' ');
    if (!space) {
        const char *err = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send(client_fd, err, strlen(err), 0);
        return;
    }

    size_t host_len = space - (request + 8);
    if (host_len >= sizeof(hostname)) {
        const char *err = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send(client_fd, err, strlen(err), 0);
        return;
    }

    strncpy(hostname, request + 8, host_len);
    hostname[host_len] = '\0';

    /* Parse hostname and port */
    char *colon = strchr(hostname, ':');
    if (colon) {
        *colon = '\0';
        port = atoi(colon + 1);
    }

    /* Connect to upstream server */
    int server_fd = connect_to_server(hostname, port);
    if (server_fd < 0) {
        const char *err = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
        send(client_fd, err, strlen(err), 0);
        return;
    }

    /* Create SSL connection to upstream server */
    SSL_CTX *server_ctx = create_ssl_context_client();
    if (!server_ctx) {
        fprintf(stderr, "Failed to create server SSL context\n");
        close(server_fd);
        const char *err = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
        send(client_fd, err, strlen(err), 0);
        return;
    }

    SSL *server_ssl = SSL_new(server_ctx);
    if (!server_ssl) {
        fprintf(stderr, "Failed to create server SSL object\n");
        SSL_CTX_free(server_ctx);
        close(server_fd);
        const char *err = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
        send(client_fd, err, strlen(err), 0);
        return;
    }

    SSL_set_fd(server_ssl, server_fd);
    SSL_set_tlsext_host_name(server_ssl, hostname);

    /* Try SSL connection with timeout */
    int ssl_ret = SSL_connect(server_ssl);
    if (ssl_ret <= 0) {
        /* Connection to upstream server failed - silently handle it */
        SSL_free(server_ssl);
        SSL_CTX_free(server_ctx);
        close(server_fd);
        const char *err = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
        send(client_fd, err, strlen(err), 0);
        return;
    }

    /* Send 200 Connection Established to client */
    const char *response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    send(client_fd, response, strlen(response), 0);

    /* Create SSL context for client connection with generated cert */
    SSL_CTX *client_ctx = create_ssl_context_server();
    if (!client_ctx) {
        SSL_shutdown(server_ssl);
        SSL_free(server_ssl);
        SSL_CTX_free(server_ctx);
        close(server_fd);
        return;
    }

    /* Generate certificate for this hostname */
    X509 *cert = generate_cert(hostname);
    if (!cert) {
        SSL_CTX_free(client_ctx);
        SSL_shutdown(server_ssl);
        SSL_free(server_ssl);
        SSL_CTX_free(server_ctx);
        close(server_fd);
        return;
    }

    /* Set certificate and key in client SSL context */
    SSL_CTX_use_certificate(client_ctx, cert);
    SSL_CTX_use_PrivateKey(client_ctx, ca_key);

    /* Create SSL connection to client */
    SSL *client_ssl = SSL_new(client_ctx);
    if (!client_ssl) {
        fprintf(stderr, "Failed to create client SSL object\n");
        SSL_CTX_free(client_ctx);
        X509_free(cert);
        SSL_shutdown(server_ssl);
        SSL_free(server_ssl);
        SSL_CTX_free(server_ctx);
        close(server_fd);
        return;
    }

    SSL_set_fd(client_ssl, client_fd);

    /* Accept SSL connection from client */
    int accept_ret = SSL_accept(client_ssl);
    if (accept_ret <= 0) {
        /* Connection failed - usually normal browser behavior (EOF during handshake)
         * Don't log these errors as they clutter the output and are expected */
        SSL_free(client_ssl);
        SSL_CTX_free(client_ctx);
        X509_free(cert);
        SSL_shutdown(server_ssl);
        SSL_free(server_ssl);
        SSL_CTX_free(server_ctx);
        close(server_fd);
        return;
    }

    /* Now we have encrypted connections to both client and server */
    /* Relay data between them with header injection */
    
    fd_set readfds;
    int max_fd = (client_fd > server_fd) ? client_fd : server_fd;
    char client_buffer[BUFFER_SIZE];
    char server_buffer[BUFFER_SIZE];
    int active = 1;
    int first_response = 1;

    /* Set non-blocking mode for better performance */
    int flags = fcntl(client_fd, F_GETFL, 0);
    fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(server_fd, F_GETFL, 0);
    fcntl(server_fd, F_SETFL, flags | O_NONBLOCK);

    while (active) {
        FD_ZERO(&readfds);
        FD_SET(client_fd, &readfds);
        FD_SET(server_fd, &readfds);

        struct timeval timeout;
        timeout.tv_sec = 60;
        timeout.tv_usec = 0;

        int ret = select(max_fd + 1, &readfds, NULL, NULL, &timeout);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (ret == 0) {
            break; /* Timeout */
        }

        /* Data from client to server */
        if (FD_ISSET(client_fd, &readfds)) {
            int bytes = SSL_read(client_ssl, client_buffer, sizeof(client_buffer));
            if (bytes <= 0) {
                int err = SSL_get_error(client_ssl, bytes);
                if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                    break;
                }
            } else {
                int sent = 0;
                while (sent < bytes) {
                    int n = SSL_write(server_ssl, client_buffer + sent, bytes - sent);
                    if (n <= 0) {
                        int err = SSL_get_error(server_ssl, n);
                        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                            active = 0;
                            break;
                        }
                    } else {
                        sent += n;
                    }
                }
            }
        }

        /* Data from server to client (inject header here) */
        if (FD_ISSET(server_fd, &readfds) && active) {
            int bytes = SSL_read(server_ssl, server_buffer, sizeof(server_buffer));
            if (bytes <= 0) {
                int err = SSL_get_error(server_ssl, bytes);
                if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                    break;
                }
            } else {
                /* Try to inject header if this looks like HTTP response */
                size_t len = bytes;
                if (first_response && bytes >= 5 && strncmp(server_buffer, "HTTP/", 5) == 0) {
                    inject_header(server_buffer, &len, sizeof(server_buffer));
                    first_response = 0;
                }
                
                int sent = 0;
                while (sent < (int)len) {
                    int n = SSL_write(client_ssl, server_buffer + sent, len - sent);
                    if (n <= 0) {
                        int err = SSL_get_error(client_ssl, n);
                        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                            active = 0;
                            break;
                        }
                    } else {
                        sent += n;
                    }
                }
            }
        }
    }

    /* Cleanup */
    SSL_shutdown(client_ssl);
    SSL_free(client_ssl);
    SSL_CTX_free(client_ctx);
    X509_free(cert);
    SSL_shutdown(server_ssl);
    SSL_free(server_ssl);
    SSL_CTX_free(server_ctx);
    close(server_fd);
}

/* Connect to upstream server */
int connect_to_server(const char *hostname, int port) {
    struct hostent *host = gethostbyname(hostname);
    if (!host) {
        return -1;
    }

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return -1;
    }

    /* Set socket timeout */
    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    memcpy(&server_addr.sin_addr, host->h_addr_list[0], host->h_length);

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        close(sockfd);
        return -1;
    }

    return sockfd;
}

/* Create SSL context for server (proxy as server to client) */
SSL_CTX *create_ssl_context_server(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        return NULL;
    }
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    return ctx;
}

/* Create SSL context for client (proxy as client to server) */
SSL_CTX *create_ssl_context_client(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        return NULL;
    }
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    return ctx;
}

/* Generate certificate for hostname signed by CA */
X509 *generate_cert(const char *hostname) {
    X509 *cert = X509_new();
    if (!cert) {
        fprintf(stderr, "Failed to create X509 certificate\n");
        return NULL;
    }

    /* Set version (X509 v3) */
    if (!X509_set_version(cert, 2)) {
        fprintf(stderr, "Failed to set certificate version\n");
        X509_free(cert);
        return NULL;
    }

    /* Set serial number - use random value based on time and hostname */
    unsigned long serial = (unsigned long)time(NULL);
    for (size_t i = 0; hostname[i] != '\0'; i++) {
        serial = serial * 31 + hostname[i];
    }
    ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);

    /* Set validity period - start 1 day in past to handle clock skew */
    X509_gmtime_adj(X509_get_notBefore(cert), -86400L);  /* -1 day */
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L); /* +1 year */

    /* Set subject */
    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, 
                               (unsigned char *)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, 
                               (unsigned char *)"CS112 Proxy", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, 
                               (unsigned char *)hostname, -1, -1, 0);

    /* Set issuer (CA) */
    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));

    /* Set public key */
    if (!X509_set_pubkey(cert, ca_key)) {
        fprintf(stderr, "Failed to set public key\n");
        X509_free(cert);
        return NULL;
    }

    /* Setup extension context */
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, ca_cert, cert, NULL, NULL, 0);
    
    /* Add Basic Constraints extension */
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, 
                                              NID_basic_constraints, 
                                              "CA:FALSE");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    /* Add Key Usage extension */
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage, 
                              "digitalSignature,keyEncipherment");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    /* Add Extended Key Usage extension for TLS Web Server Authentication */
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_ext_key_usage, 
                              "serverAuth");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    /* Add Subject Alternative Name (SAN) extension - CRITICAL for modern browsers */
    char san[512];
    snprintf(san, sizeof(san), "DNS:%s", hostname);
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_alt_name, san);
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    } else {
        fprintf(stderr, "Warning: Failed to add SAN extension for %s\n", hostname);
    }

    /* Sign certificate with CA key */
    if (!X509_sign(cert, ca_key, EVP_sha256())) {
        fprintf(stderr, "Failed to sign certificate\n");
        ERR_print_errors_fp(stderr);
        X509_free(cert);
        return NULL;
    }

    return cert;
}

/* Inject X-Proxy:CS112 header into HTTP response */
void inject_header(char *response, size_t *response_len, size_t buffer_size) {
    /* Find end of status line */
    char *header_end = strstr(response, "\r\n");
    if (!header_end) {
        return;
    }

    /* Check if header already exists */
    if (strstr(response, "X-Proxy:")) {
        return;
    }

    /* Calculate new size */
    const char *new_header = "X-Proxy:CS112\r\n";
    size_t new_header_len = strlen(new_header);
    size_t insert_pos = header_end + 2 - response;

    if (*response_len + new_header_len >= buffer_size) {
        return; /* Not enough space */
    }

    /* Move data to make room */
    memmove(response + insert_pos + new_header_len,
            response + insert_pos,
            *response_len - insert_pos);

    /* Insert header */
    memcpy(response + insert_pos, new_header, new_header_len);
    *response_len += new_header_len;
}

/* Parse hostname and port from Host header */
void parse_host_port(char *host_header, char **hostname, int *port) {
    char *colon = strchr(host_header, ':');
    if (colon) {
        *colon = '\0';
        *port = atoi(colon + 1);
    }
}

