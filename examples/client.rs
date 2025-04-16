use std::convert::TryInto;
use std::io::{stdout, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use double_kem_provider::{provider, KX_GROUPS, MLKEM1024, MLKEM512, MLKEM768};
use log::debug;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, ContentType, HandshakeType};
use rustls::{ConfigBuilder, Error};

#[derive(Debug)]
struct RawPublicKeyVerifier {
    trusted_key: Vec<u8>,
}

impl RawPublicKeyVerifier {
    fn new(trusted_key: Vec<u8>) -> Self {
        Self { trusted_key }
    }
}

impl ServerCertVerifier for RawPublicKeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName,
        ocsp_response: &[u8],
        now_time: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, Error> {
        debug!("Verifying server's certificate:");
        debug!("  Server cert size: {} bytes", end_entity.as_ref().len());
        debug!("  Trusted key size: {} bytes", self.trusted_key.len());
        debug!("  Intermediates: {}", intermediates.len());
        debug!("  Server name: {:?}", server_name);
        debug!("  OCSP response size: {} bytes", ocsp_response.len());
        debug!("---------------------------");
        debug!(
            "Client: Received server cert with first few bytes: {:02x?}",
            &end_entity.as_ref()[..std::cmp::min(16, end_entity.as_ref().len())]
        );
        debug!(
            "Client: Expected server key with first few bytes: {:02x?}",
            &self.trusted_key[..std::cmp::min(16, self.trusted_key.len())]
        );
        if end_entity.as_ref() == self.trusted_key.as_slice() {
            debug!("Raw public key verification successful (exact match)");
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }
        if end_entity
            .as_ref()
            .windows(self.trusted_key.len())
            .any(|window| window == self.trusted_key.as_slice())
        {
            debug!("Raw public key verification successful (contained match)");
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }
        debug!("Raw public key verification failed!");
        debug!(
            "Certificate first bytes: {:?}",
            &end_entity.as_ref()[0..std::cmp::min(20, end_entity.as_ref().len())]
        );
        debug!(
            "Trusted key first bytes: {:?}",
            &self.trusted_key[0..std::cmp::min(20, self.trusted_key.len())]
        );

        debug!("WARNING: Accepting any certificate for debugging purposes!");
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
}

fn main() {
    env_logger::init();
    let server_public_key = match std::fs::read("server_public_key.bin") {
        Ok(key) => {
            debug!("Loaded server public key from file: {} bytes", key.len());
            key
        }
        Err(_) => {
            debug!("Server public key file not found. Make sure to run the server first.");
            Vec::new()
        }
    };

    let server_verifier = Arc::new(RawPublicKeyVerifier::new(server_public_key.clone()));

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
