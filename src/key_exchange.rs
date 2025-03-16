extern crate alloc;
use alloc::boxed::Box;
use oqs::kem::Kem;
use rustls::crypto;

pub struct KeyExchange {
    pk: oqs::kem::PublicKey,
    sk: oqs::kem::SecretKey,
    kem: Kem,
    auth_pk: oqs::kem::PublicKey,
    auth_sk: oqs::kem::SecretKey,
    encryption_ct: Option<Vec<u8>>,
    auth_ct: Option<Vec<u8>>,
    encryption_ss: Option<Vec<u8>>,
    auth_ss: Option<Vec<u8>>,
}
impl KeyExchange {
    pub fn new(
        pk: oqs::kem::PublicKey,
        sk: oqs::kem::SecretKey,
        kem: Kem,
        auth_pk: oqs::kem::PublicKey,
        auth_sk: oqs::kem::SecretKey,
    ) -> Self {
        Self {
            pk,
            sk,
            kem,
            auth_pk,
            auth_sk,
            encryption_ct: None,
            auth_ct: None,
            encryption_ss: None,
            auth_ss: None,
        }
    }
}
impl crypto::ActiveKeyExchange for KeyExchange {
    fn complete(
        self: Box<KeyExchange>,
        peer_pub_key: &[u8], //peer Public Key
    ) -> Result<crypto::SharedSecret, rustls::Error> {
        let peer_pk = self
            .kem
            .public_key_from_bytes(peer_pub_key)
            .ok_or_else(|| rustls::Error::General("Invalid public key".into()))?;
        let (encryption_ct, encryption_ss) = self
            .kem
            .encapsulate(&peer_pk)
            .map_err(|_| rustls::Error::General("Encryption ecapsulation failed".into()))?;
        let (auth_ct, auth_ss) = self
            .kem
            .encapsulate(&peer_pk)
            .map_err(|_| rustls::Error::General("Authentication encapsulation failed".into()))?;

        let mut this = *self;
        this.encryption_ct = Some(encryption_ct.as_ref().to_vec());
        this.auth_ct = Some(auth_ct.as_ref().to_vec());

        let combined_secret = [encryption_ss.as_ref(), auth_ss.as_ref()].concat();

        Ok(crypto::SharedSecret::from(&combined_secret[..]))
    }
    fn pub_key(&self) -> &[u8] {
        self.pk.as_ref()
    }
    fn group(&self) -> rustls::NamedGroup {
        match self.kem.algorithm() {
            oqs::kem::Algorithm::MlKem512 => rustls::NamedGroup::MLKEM512,
            oqs::kem::Algorithm::MlKem768 => rustls::NamedGroup::MLKEM768,
            oqs::kem::Algorithm::MlKem1024 => rustls::NamedGroup::MLKEM1024,
            _ => rustls::NamedGroup::Unknown(0),
        }
    }
}
