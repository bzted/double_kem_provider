use double_kem_provider::{provider, MlKemKey};
use log::debug;
use oqs::kem::Kem;
use rustls::pki_types::CertificateDer;
use rustls::server::{self, ClientHello};
use rustls::server::{Acceptor, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{NamedGroup, ServerConfig};
use std::io::Write;
use std::sync::Arc;

#[derive(Debug)]
struct Resolver {
    key_pair: KeyPair,
}

impl Resolver {
    fn new(key_pair: KeyPair) -> Self {
        Self { key_pair }
    }
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        debug!("Resolver::resolve called");
        debug!(
            "Key size: {} bytes",
            self.key_pair.public_key.as_ref().len()
        );

        let raw_key = self.key_pair.public_key.as_ref().to_vec();

        let cert = CertificateDer::from(raw_key.clone());

        let certified_key = CertifiedKey {
            cert: vec![cert],
            key: self.key_pair.private_key.clone(),
            ocsp: None,
            kem_key: self.key_pair.kem_key.clone(),
        };

        Some(Arc::new(certified_key))
    }

    fn only_raw_public_keys(&self) -> bool {
        true
    }
}

#[derive(Debug)]
struct KeyPair {
    public_key: oqs::kem::PublicKey,
    private_key: Arc<dyn rustls::sign::SigningKey>,
    kem_key: Option<Arc<dyn rustls::sign::KemKey>>,
}

#[derive(Debug)]
struct DummySigningKey;

impl rustls::sign::SigningKey for DummySigningKey {
    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::KEM
    }

    fn choose_scheme(
        &self,
        offered: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        debug!(
            "DummySigningKey::choose_scheme called with schemes: {:?}",
            offered
        );

        let scheme = offered
            .first()
            .copied()
            .unwrap_or(rustls::SignatureScheme::MLKEM768);
        Some(Box::new(DummySigner { scheme }))
    }
}

#[derive(Debug)]
struct DummySigner {
    scheme: rustls::SignatureScheme,
}

impl rustls::sign::Signer for DummySigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        debug!(
            "WARNING: DummySigner.sign() called with {} bytes - returning dummy signature",
            message.len()
        );
        Ok(vec![0u8; 64])
    }

    fn scheme(&self) -> rustls::SignatureScheme {
        self.scheme
    }
}

fn main() {
    env_logger::init();

    debug!("Starting AuthKEM server...");
    // Generate a server KEM key pair
    let kem =
        Kem::new(oqs::kem::Algorithm::MlKem768).expect("Failed to create ML-KEM-768 instance");

    let (public_key, secret_key) = kem.keypair().expect("Failed to generate KEM key pair");

    // Save public key to a file for the client to use
    std::fs::write("server_public_key.bin", public_key.as_ref())
        .expect("Failed to write server public key to file");
    debug!("Server public key saved to server_public_key.bin");

    let signing_key = Arc::new(DummySigningKey);
    let kem_key = Arc::new(MlKemKey::new(
        NamedGroup::MLKEM768,
        secret_key.as_ref().to_vec(),
    ));
    // Create our key pair structure
    let key_pair = KeyPair {
        public_key,
        private_key: signing_key,
        kem_key: Some(kem_key),
    };

    // Create our custom resolver
    let resolver = Arc::new(Resolver::new(key_pair));

    // Set up TLS server with AuthKEM provider
    let crypto_provider = provider();

    debug!("Provider has {} kx_groups", crypto_provider.kx_groups.len());
    for kx in &crypto_provider.kx_groups {
        debug!("  KX group: {:?}", kx.name());
    }

    let mut server_config = ServerConfig::builder_with_provider(crypto_provider.into())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(resolver);

    server_config.key_log = Arc::new(rustls::KeyLogFile::new());
    debug!("Server config created successfully");

    let listener = std::net::TcpListener::bind(format!("[::]:{}", 8443)).unwrap();

    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let mut acceptor = Acceptor::default();

        let accepted = loop {
            acceptor.read_tls(&mut stream).unwrap();
            if let Some(accepted) = acceptor.accept().unwrap() {
                break accepted;
            }
        };

        match accepted.into_connection(server_config.clone().into()) {
            Ok(mut conn) => {
                let msg = concat!(
                    "HTTP/1.1 200 OK\r\n",
                    "Connection: closed\r\n",
                    "Content-Type: text/html\r\n",
                    "\r\n",
                    "<h1>Hello World!</h1>\r\n"
                )
                .as_bytes();

                conn.writer().write_all(msg).unwrap();
                conn.write_tls(&mut stream).unwrap();
                conn.complete_io(&mut stream).unwrap();

                conn.send_close_notify();
                conn.write_tls(&mut stream).unwrap();
                conn.complete_io(&mut stream).unwrap();
            }
            Err(e) => {
                eprintln!("{:?}", e);
            }
        }
    }
}
