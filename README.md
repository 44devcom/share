# Simple HTTP/HTTPS File Server in C

This is a lightweight file server written in C that supports:
- HTTP or HTTPS (TLS) using OpenSSL
- Basic Authentication (Base64 encoded)
- Serving a single file securely

## 🔧 Build

```sh
gcc main.c -o file_server -lssl -lcrypto
```

## 🚀 Usage

### HTTP (default)
```sh
./file_server --port 8080 --user admin --pass secret --file myfile.zip
```

### HTTPS (requires OpenSSL certs)
```sh
./file_server --port 8443 --user admin --pass secret --file myfile.zip --cert cert.pem --key key.pem
```

## 🔐 Generate Self-Signed Certificate

```sh
sh generate_certs.sh
```

## 📦 Options

| Flag      | Description                             |
|-----------|-----------------------------------------|
| `--port`  | Port to listen on                       |
| `--user`  | Username for Basic Auth                 |
| `--pass`  | Password for Basic Auth                 |
| `--file`  | Path to file to serve                   |
| `--cert`  | Path to SSL certificate (enables HTTPS) |
| `--key`   | Path to SSL private key                 |

