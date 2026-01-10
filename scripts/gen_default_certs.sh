#!/bin/bash

mkdir -p certs

generate_cert() {

    local prefix=$1
    openssl genpkey -algorithm RSA -out certs/${prefix}_server.key -pkeyopt rsa_keygen_bits:4096
    cat > ${prefix}_cert_config.cnf << EOL
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no
[req_distinguished_name]
C = US
ST = AL
L = Birmingham
O = Organization
OU = Organizational Unit
CN = *
[v3_req]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = *
DNS.2 = *.*
DNS.3 = *.*.*
DNS.4 = *.*.*.*
DNS.5 = *.*.*.*.*
DNS.6 = localhost
IP.1 = 127.0.0.1
IP.2 = 0.0.0.0
EOL

    openssl req -new -key certs/${prefix}_server.key -out certs/${prefix}_server.csr -config ${prefix}_cert_config.cnf
    openssl x509 -req -days 3652 -in certs/${prefix}_server.csr -signkey certs/${prefix}_server.key -out certs/${prefix}_server.crt \
        -extfile ${prefix}_cert_config.cnf -extensions v3_req
    
    echo "${prefix} certificates generated"
    rm ${prefix}_cert_config.cnf
}

generate_cert "web"
generate_cert "ws"
generate_cert "rpc"
generate_cert "api"

echo "Certificate generation complete for RPC, Web, REST API, and Websocket servers"

echo "Copying ws_server.crt to client/certs folder..."
cp certs/ws_server.crt ../client/certs/
echo "ws_server.crt copied successfully"