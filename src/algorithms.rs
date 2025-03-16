extern crate alloc;
use crate::key_exchange::KeyExchange;
use alloc::boxed::Box;
use crypto::SupportedKxGroup;
use oqs::kem::Kem;
use rustls::crypto;

pub const KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    &MLKEM512 as &dyn SupportedKxGroup,
    &MLKEM768 as &dyn SupportedKxGroup,
    &MLKEM1024 as &dyn SupportedKxGroup,
];

#[derive(Debug)]
pub struct MLKEM512;
#[derive(Debug)]
pub struct MLKEM768;
#[derive(Debug)]
pub struct MLKEM1024;

impl crypto::SupportedKxGroup for MLKEM512 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        let kem = Kem::new(oqs::kem::Algorithm::MlKem512)
            .map_err(|_| rustls::Error::General("ML-KEM512 Algorithm not found".into()))?;
        let (pk, sk) = kem
            .keypair()
            .map_err(|_| rustls::Error::General("Failed to generate ML-KEM512 keypair".into()))?;
        let (auth_pk, auth_sk) = kem.keypair().map_err(|_| {
            rustls::Error::General("Failed to generate authentication keypair".into())
        })?;

        Ok(Box::new(KeyExchange::new(pk, sk, kem, auth_pk, auth_sk)))
    }
    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::MLKEM512
    }
}
impl crypto::SupportedKxGroup for MLKEM768 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        let kem = Kem::new(oqs::kem::Algorithm::MlKem768)
            .map_err(|_| rustls::Error::General("ML-KEM768 Algorithm not found".into()))?;
        let (pk, sk) = kem
            .keypair()
            .map_err(|_| rustls::Error::General("Failed to generate ML-KEM768 keypair".into()))?;
        let (auth_pk, auth_sk) = kem.keypair().map_err(|_| {
            rustls::Error::General("Failed to generate authentication keypair".into())
        })?;

        Ok(Box::new(KeyExchange::new(pk, sk, kem, auth_pk, auth_sk)))
    }
    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::MLKEM768
    }
}
impl crypto::SupportedKxGroup for MLKEM1024 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        let kem = Kem::new(oqs::kem::Algorithm::MlKem1024)
            .map_err(|_| rustls::Error::General("ML-KEM1024 Algorithm not found".into()))?;
        let (pk, sk) = kem
            .keypair()
            .map_err(|_| rustls::Error::General("Failed to generate ML-KEM1024 keypair".into()))?;
        let (auth_pk, auth_sk) = kem.keypair().map_err(|_| {
            rustls::Error::General("Failed to generate authentication keypair".into())
        })?;

        Ok(Box::new(KeyExchange::new(pk, sk, kem, auth_pk, auth_sk)))
    }
    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::MLKEM1024
    }
}

// TESTS UNITARIOS

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlkem512_initialization() {
        let provider = MLKEM512;
        let result = provider.start();
        assert!(result.is_ok(), "Failed to initialize ML-KEM-512");

        let key_exchange = result.unwrap();
        assert_eq!(key_exchange.group(), rustls::NamedGroup::MLKEM512);
    }

    #[test]
    fn test_mlkem768_initialization() {
        let provider = MLKEM768;
        let result = provider.start();
        assert!(result.is_ok(), "Failed to initialize ML-KEM-768");

        let key_exchange = result.unwrap();
        assert_eq!(key_exchange.group(), rustls::NamedGroup::MLKEM768);
    }

    #[test]
    fn test_mlkem1024_initialization() {
        let provider = MLKEM1024;
        let result = provider.start();
        assert!(result.is_ok(), "Failed to initialize ML-KEM-1024");

        let key_exchange = result.unwrap();
        assert_eq!(key_exchange.group(), rustls::NamedGroup::MLKEM1024);
    }
}
