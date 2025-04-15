#!/bin/bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365 \
  -subj "/C=US/ST=None/L=None/O=FileServer/CN=localhost"
echo "Certificate and key generated: cert.pem, key.pem"
