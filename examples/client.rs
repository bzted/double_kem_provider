use std::convert::TryInto;
use std::io::{stdout, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use double_kem_provider::provider;
use log::debug;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::Error;
use rustls::{ClientConfig, ClientConnection};

#[derive(Debug)]
struct Verifier;

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName,
        ocsp_response: &[u8],
        now_time: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        debug!(
            "verify_tls12_signature called with {} bytes message",
            message.len()
        );
        Err(Error::General(
            "AuthKEM doesn't use traditional signatures".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        debug!(
            "verify_tls13_signature called with {} bytes message",
            message.len()
        );
        Err(Error::General(
            "AuthKEM doesn't use traditional signatures".into(),
        ))
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        debug!("supported_verify_schemes called");
        Vec::new()
    }

    fn requires_raw_public_keys(&self) -> bool {
        debug!("requires_raw_public_keys called - returning true");
        true
    }

    fn authkem(&self) -> bool {
        debug!("Trying authkem flow");
        true
    }

    fn encapsulate(&self, server_pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        debug!("About to encapsulate to peers public key");

        let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem768)
            .map_err(|_| Error::General("Failed to create KEM instance".into()))?;

        let pk = kem
            .public_key_from_bytes(server_pk)
            .ok_or_else(|| Error::General("Invalid public key".into()))?;
        let (ct, ss) = kem
            .encapsulate(pk)
            .map_err(|_| Error::General("Encapsulation failed".into()))?;

        Ok((ct.as_ref().to_vec(), ss.as_ref().to_vec()))
    }
}

fn main() {
    env_logger::init();

    let server_verifier = Arc::new(Verifier);

    let crypto_provider = provider();

    let client_config = ClientConfig::builder_with_provider(crypto_provider.into())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(server_verifier)
        .with_no_client_auth();

    let server_name = "servername".try_into().unwrap();
    let mut client = ClientConnection::new(Arc::new(client_config), server_name).unwrap();
    debug!("Connecting to server at 127.0.0.1:8443...");
    let mut stream = TcpStream::connect("127.0.0.1:8443").unwrap();

    stream.set_nodelay(true).unwrap();

    let mut tls_stream = rustls::Stream::new(&mut client, &mut stream);

    tls_stream
        .write_all(
            concat!(
                "GET / HTTP/1.1\n",
                "Host: www.rust-lang-org\r\n",
                "Connection: close\r\n",
                "Accept-Encoding: identity\r\n",
                "\r\n"
            )
            .as_bytes(),
        )
        .unwrap();

    let cs = tls_stream.conn.negotiated_cipher_suite().unwrap();
    writeln!(
        &mut std::io::stderr(),
        "Curernt ciphersuite: {:?}",
        cs.suite()
    )
    .unwrap();

    let mut plaintext = Vec::new();
    tls_stream.read_to_end(&mut plaintext).unwrap();
    stdout().write_all(&plaintext).unwrap();
}
