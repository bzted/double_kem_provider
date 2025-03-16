use rustls::crypto::aws_lc_rs;

mod algorithms;
mod key_exchange;
pub use algorithms::{KX_GROUPS, MLKEM1024, MLKEM512, MLKEM768};
pub use key_exchange::KeyExchange;

pub fn provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::CryptoProvider {
        kx_groups: KX_GROUPS.to_vec(),
        ..aws_lc_rs::default_provider()
    }
}

// TESTS UNITARIOS

#[cfg(test)]
mod tests {
    use super::*;
    use oqs::kem::Kem;

    #[test]
    fn test_double_kem_flow() {
        // Initialize KEM
        let kem = Kem::new(oqs::kem::Algorithm::MlKem512).unwrap();

        // Generate keypairs for encryption and authentication
        let (enc_pk1, enc_sk1) = kem.keypair().unwrap();
        let (auth_pk1, auth_sk1) = kem.keypair().unwrap();

        let (enc_pk2, enc_sk2) = kem.keypair().unwrap();
        let (auth_pk2, auth_sk2) = kem.keypair().unwrap();

        // First party encapsulates to second party's keys
        let (enc_ct1, enc_ss1) = kem.encapsulate(&enc_pk2).unwrap();
        let (auth_ct1, auth_ss1) = kem.encapsulate(&auth_pk2).unwrap();

        // Second party encapsulates to first party's keys
        let (enc_ct2, enc_ss2) = kem.encapsulate(&enc_pk1).unwrap();
        let (auth_ct2, auth_ss2) = kem.encapsulate(&auth_pk1).unwrap();

        // First party decapsulates second party's ciphertexts
        let dec_enc_ss1 = kem.decapsulate(&enc_sk1, &enc_ct2).unwrap();
        let dec_auth_ss1 = kem.decapsulate(&auth_sk1, &auth_ct2).unwrap();

        // Second party decapsulates first party's ciphertexts
        let dec_enc_ss2 = kem.decapsulate(&enc_sk2, &enc_ct1).unwrap();
        let dec_auth_ss2 = kem.decapsulate(&auth_sk2, &auth_ct1).unwrap();

        // Verify decapsulated secrets match encapsulated ones
        assert_eq!(dec_enc_ss2, enc_ss1);
        assert_eq!(dec_enc_ss1, enc_ss2);
        assert_eq!(dec_auth_ss2, auth_ss1);
        assert_eq!(dec_auth_ss1, auth_ss2);

        // Create combined secrets for both parties
        let combined_ss1 = [enc_ss1.as_ref(), auth_ss1.as_ref()].concat();
        let combined_ss2 = [dec_enc_ss2.as_ref(), dec_auth_ss2.as_ref()].concat();

        // Verify combined secrets match
        assert_eq!(combined_ss1, combined_ss2);
    }

    #[test]
    fn test_crypto_provider() {
        let custom_provider = provider();

        // Verify our KX groups are in the provider
        let has_mlkem512 = custom_provider
            .kx_groups
            .iter()
            .any(|group| group.name() == rustls::NamedGroup::MLKEM512);

        let has_mlkem768 = custom_provider
            .kx_groups
            .iter()
            .any(|group| group.name() == rustls::NamedGroup::MLKEM768);

        let has_mlkem1024 = custom_provider
            .kx_groups
            .iter()
            .any(|group| group.name() == rustls::NamedGroup::MLKEM1024);

        assert!(has_mlkem512, "Provider missing ML-KEM-512");
        assert!(has_mlkem768, "Provider missing ML-KEM-768");
        assert!(has_mlkem1024, "Provider missing ML-KEM-1024");
    }
}
