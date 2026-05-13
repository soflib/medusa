apt install -y protobuf-compiler

cargo install sqlx-cli --no-default-features --features postgres
sqlx database create
sqlx migrate run

##############################################################
# 1. Crear directorio
mkdir -p certs && \

# 2. Generar CA
openssl genrsa -out certs/ca.key 4096 && \
openssl req -new -x509 -days 3650 -key certs/ca.key -out certs/ca.crt \
  -subj "/CN=doc-seal-ca/O=DocSeal/C=MX" 

# 3. Certificado del AUTH SERVER
openssl genrsa -out certs/server.key 4096 && \
openssl req -new -key certs/server.key -out certs/server.csr \
  -subj "/CN=auth-server/O=DocSeal/C=MX" && \
openssl x509 -req -days 3650 -in certs/server.csr \
  -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
  -out certs/server.crt

# 4. Certificado del DOCS SERVICE
openssl genrsa -out certs/client.key 4096 && \
openssl req -new -key certs/client.key -out certs/client.csr \
  -subj "/CN=docs-service/O=DocSeal/C=MX" && \
openssl x509 -req -days 3650 -in certs/client.csr \
  -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
  -out certs/client.crt 

# 5. Limpiar temporales
rm certs/*.csr certs/*.srl

echo "Certificados generados en certs/"


certs/
  ca.crt       ← va en ambos servicios (verifica al otro lado)
  server.crt   ← auth server
  server.key   ← auth server
  client.crt   ← docs service
  client.key   ← docs service