pub use key_provider::{KemKeyProvider, MlKemKey};
use rustls::crypto::aws_lc_rs;

mod algorithms;
mod key_exchange;
mod key_provider;
pub use algorithms::{KX_GROUPS, MLKEM1024, MLKEM512, MLKEM768};
pub use key_exchange::KeyExchange;

pub fn provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::CryptoProvider {
        kx_groups: KX_GROUPS.to_vec(),
        key_provider: &KemKeyProvider,
        ..aws_lc_rs::default_provider()
    }
}
