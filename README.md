# Share  - Simple HTTP/HTTPS File Server in C

This is a lightweight file server written in C that supports:
- HTTP or HTTPS (TLS) using OpenSSL
- Basic Authentication (Base64 encoded)
- Serving a single file securely

## 🔧 Build

```sh
gcc src/main.c -o bin/share -lssl -lcrypto
```

## 🚀 Usage

### HTTP (default)
```sh
./bin/share --port 8080 --user admin --pass secret --file myfile.zip
```

### HTTPS (requires OpenSSL certs)
```sh
./bin/share --port 8443 --user admin --pass secret --file myfile.zip --cert ssl/cert.pem --key ssl/key.pem
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

