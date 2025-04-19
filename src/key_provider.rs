extern crate alloc;
use alloc::boxed::Box;
use log::debug;
use oqs::kem::Kem;
use rustls::sign::KemKey;
use rustls::Error;
use rustls::NamedGroup;
use rustls::{crypto::KeyProvider, pki_types::PrivateKeyDer};
use std::sync::Arc;
#[derive(Debug)]
pub struct MlKemKey {
    algorithm: NamedGroup,
    sk: Vec<u8>,
}
impl MlKemKey {
    pub fn new(algorithm: NamedGroup, sk: Vec<u8>) -> Self {
        Self { algorithm, sk }
    }
}
impl KemKey for MlKemKey {
    fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let kem = match self.algorithm {
            NamedGroup::MLKEM512 => oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem512),
            NamedGroup::MLKEM768 => oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem768),
            NamedGroup::MLKEM1024 => oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem1024),
            _ => return Err(Error::General("Unsupported KEM algorithm".into())),
        }
        .map_err(|_| Error::General("Failed to create KEM instance".into()))?;

        let sk = oqs::kem::Kem::secret_key_from_bytes(&kem, &self.sk)
            .ok_or_else(|| Error::General("Invalid private key".into()))?;

        let ct = oqs::kem::Kem::ciphertext_from_bytes(&kem, ciphertext)
            .ok_or_else(|| Error::General("Invalid ciphertext".into()))?;

        let ss = kem.decapsulate(sk, ct).map_err(|e| {
            debug!("Decapsulation failed: {}", e);
            Error::General("Decapsulation failed".into())
        })?;
        debug!("Decapsulation successful!");
        debug!("Shared secret size: {} bytes", ss.as_ref().len());

        Ok(ss.as_ref().to_vec())
    }

    fn algorithm(&self) -> NamedGroup {
        self.algorithm
    }
}

#[derive(Debug)]
pub struct KemKeyProvider;

impl KeyProvider for KemKeyProvider {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn rustls::sign::SigningKey>, Error> {
        Err(Error::General("No private key".into()))
    }

    fn load_kem_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
        algorithm: NamedGroup,
    ) -> Result<Arc<dyn KemKey>, Error> {
        let private_key = match key_der {
            PrivateKeyDer::Pkcs8(ref pkcs8) => pkcs8.secret_pkcs8_der().to_vec(),
            PrivateKeyDer::Sec1(ref sec1) => sec1.secret_sec1_der().to_vec(),
            PrivateKeyDer::Pkcs1(ref pkcs1) => pkcs1.secret_pkcs1_der().to_vec(),
            _ => return Err(Error::General("Unsupported key format for KEM".into())),
        };
        println!("KEM private key loaded, size: {} bytes", private_key.len());
        Ok(Arc::new(MlKemKey::new(algorithm, private_key)))
    }

    fn fips(&self) -> bool {
        false
    }
}
