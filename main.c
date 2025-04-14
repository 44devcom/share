/*
 * Simple HTTP/HTTPS File Server with Basic Authentication
 *
 * Supports serving a file via HTTP or HTTPS based on the provided options.
 * If --cert and --key are given, the server will enable HTTPS using OpenSSL.
 *
 * Compile with:
 * gcc main.c -o file_server -lssl -lcrypto
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <getopt.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER_SIZE 1024

typedef struct {
    int port;
    char user[64];
    char pass[64];
    char file_path[256];
    bool use_ssl;
    char cert_path[256];
    char key_path[256];
} ServerConfig;

ServerConfig config = {
    .port = 3385,
    .user = "admin",
    .pass = "password",
    .file_path = "shared_file.txt",
    .use_ssl = false
};

// Helper: show usage help
void show_help(const char *progname) {
    printf(
        "Usage: %s [options]\n"
        "Options:\n"
        "  --port <port>       Port number to listen on (default: 3385)\n"
        "  --user <user>       Username for basic authentication\n"
        "  --pass <pass>       Password for basic authentication\n"
        "  --file <path>       Path to the file to serve\n"
        "  --cert <cert.pem>   Path to SSL certificate (enable HTTPS)\n"
        "  --key <key.pem>     Path to SSL private key (enable HTTPS)\n"
        "  --help              Show this help and exit\n",
        progname
    );
}

char *base64_encode(const char *input) {
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input, strlen(input));
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &buffer_ptr);

    char *b64text = malloc(buffer_ptr->length + 1);
    memcpy(b64text, buffer_ptr->data, buffer_ptr->length);
    b64text[buffer_ptr->length] = '\0';

    BIO_free_all(bio);
    return b64text;
}

bool check_authentication(const char *header, const char *expected_b64) {
    if (!header) return false;
    const char *auth_prefix = "Authorization: Basic ";
    if (strncmp(header, auth_prefix, strlen(auth_prefix)) == 0) {
        header += strlen(auth_prefix);
        char clean_auth[BUFFER_SIZE];
        strncpy(clean_auth, header, BUFFER_SIZE - 1);
        clean_auth[BUFFER_SIZE - 1] = '\0';
        char *newline = strpbrk(clean_auth, "\r\n");
        if (newline) *newline = '\0';
        return strcmp(clean_auth, expected_b64) == 0;
    }
    return false;
}

void handle_client_http(int client_socket, const char *expected_auth) {
    char buffer[BUFFER_SIZE];
    const char *unauth = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"Secure\"\r\n\r\n";
    const char *ok = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n";

    ssize_t bytes_read = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_read <= 0) return;
    buffer[bytes_read] = '\0';

    char *auth_header = strstr(buffer, "Authorization: ");
    if (!check_authentication(auth_header, expected_auth)) {
        send(client_socket, unauth, strlen(unauth), 0);
        return;
    }

    send(client_socket, ok, strlen(ok), 0);
    int file_fd = open(config.file_path, O_RDONLY);
    if (file_fd < 0) return;
    while ((bytes_read = read(file_fd, buffer, BUFFER_SIZE)) > 0) {
        send(client_socket, buffer, bytes_read, 0);
    }
    close(file_fd);
}

void handle_client_ssl(SSL *ssl, const char *expected_auth) {
    char buffer[BUFFER_SIZE];
    const char *unauth = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"Secure\"\r\n\r\n";
    const char *ok = "HTTP/1.1 200 OK\r\n"Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="config.file_path"
\r\n";

    int bytes_read = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
    if (bytes_read <= 0) return;
    buffer[bytes_read] = '\0';

    char *auth_header = strstr(buffer, "Authorization: ");
    if (!check_authentication(auth_header, expected_auth)) {
        SSL_write(ssl, unauth, strlen(unauth));
        return;
    }

    SSL_write(ssl, ok, strlen(ok));
    int file_fd = open(config.file_path, O_RDONLY);
    if (file_fd < 0) return;
    while ((bytes_read = read(file_fd, buffer, BUFFER_SIZE)) > 0) {
        SSL_write(ssl, buffer, bytes_read);
    }
    close(file_fd);
}

void parse_args(int argc, char *argv[]) {
    static struct option options[] = {
        {"port", required_argument, 0, 0},
        {"user", required_argument, 0, 0},
        {"pass", required_argument, 0, 0},
        {"file", required_argument, 0, 0},
        {"cert", required_argument, 0, 0},
        {"key", required_argument, 0, 0},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int idx = 0;
    while (1) {
        int c = getopt_long(argc, argv, "h", options, &idx);
        if (c == -1) break;
        switch (c) {
            case 0:
                if (!strcmp(options[idx].name, "port")) config.port = atoi(optarg);
                else if (!strcmp(options[idx].name, "user")) strncpy(config.user, optarg, 63);
                else if (!strcmp(options[idx].name, "pass")) strncpy(config.pass, optarg, 63);
                else if (!strcmp(options[idx].name, "file")) strncpy(config.file_path, optarg, 255);
                else if (!strcmp(options[idx].name, "cert")) { config.use_ssl = true; strncpy(config.cert_path, optarg, 255); }
                else if (!strcmp(options[idx].name, "key")) strncpy(config.key_path, optarg, 255);
                break;
            case 'h':
            default:
                show_help(argv[0]);
                exit(0);
        }
    }
}

int main(int argc, char *argv[]) {
    // If no parameters are passed, show help
    if (argc == 1) {
        show_help(argv[0]);
        exit(0);
    }
    
    parse_args(argc, argv);

    char credentials[128];
    snprintf(credentials, sizeof(credentials), "%s:%s", config.user, config.pass);
    char *expected_auth = base64_encode(credentials);

    SSL_CTX *ctx = NULL;
    if (config.use_ssl) {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        ctx = SSL_CTX_new(TLS_server_method());
        SSL_CTX_use_certificate_file(ctx, config.cert_path, SSL_FILETYPE_PEM);
        SSL_CTX_use_PrivateKey_file(ctx, config.key_path, SSL_FILETYPE_PEM);
    }

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(config.port), .sin_addr.s_addr = INADDR_ANY };
    bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    listen(sockfd, 5);

    printf("Server running on port %d %s\n", config.port, config.use_ssl ? "(HTTPS)" : "(HTTP)");

    while (1) {
        int client = accept(sockfd, NULL, NULL);
        if (config.use_ssl) {
            SSL *ssl = SSL_new(ctx);
            SSL_set_fd(ssl, client);
            if (SSL_accept(ssl) <= 0) ERR_print_errors_fp(stderr);
            else handle_client_ssl(ssl, expected_auth);
            SSL_shutdown(ssl); SSL_free(ssl);
        } else {
            handle_client_http(client, expected_auth);
        }
        close(client);
    }

    if (ctx) SSL_CTX_free(ctx);
    free(expected_auth);
    return 0;
}