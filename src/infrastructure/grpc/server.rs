use std::net::SocketAddr;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

use crate::generated::auth::auth_service_server::AuthServiceServer;
use crate::infrastructure::grpc::handler::AuthGrpcHandler;

pub async fn start_mtls(
    addr:        SocketAddr,
    handler:     AuthGrpcHandler,
    ca_cert:     &[u8],   // para verificar el certificado del cliente
    server_cert: &[u8],
    server_key:  &[u8],
) -> Result<(), tonic::transport::Error> {
    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(server_cert, server_key))
        .client_ca_root(Certificate::from_pem(ca_cert)); // exige cert del cliente

    tracing::info!("gRPC server listening on {} (mTLS)", addr);

    Server::builder()
        .tls_config(tls)?
        .add_service(AuthServiceServer::new(handler))
        .serve(addr)
        .await
}

pub async fn start_insecure(
    addr:    SocketAddr,
    handler: AuthGrpcHandler,
) -> Result<(), tonic::transport::Error> {
    tracing::info!("gRPC server listening on {} (insecure)", addr);

    Server::builder()
        .add_service(AuthServiceServer::new(handler))
        .serve(addr)
        .await
}