// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cardano Shelley key derivation and base-address encoding.

pub mod address;
pub mod bech32;
pub mod hash;
pub mod hd;
pub mod network;
pub mod prefix;

pub use address::{base_address, base_bytes, credential_hash, ADDRESS_LEN, HASH_LEN};
pub use hd::{
    account_key, derive_wallet, entropy_from_mnemonic, external_chain, harden, icarus_root,
    mnemonic_from_entropy, payment_credential, payment_path, stake_credential, stake_path,
    DerivedWallet, Xprv, Xpub, COIN_TYPE, GAP_LIMIT, HARDENED_BIT, PAYMENT_INDEX_LIMIT, PURPOSE,
    ROLE_EXTERNAL, ROLE_STAKE, STAKE_INDEX,
};
pub use network::Network;
pub use prefix::{
    analyze, attempts_for_probability, earliest_zuzu, group_digits, require_searchable, Analysis,
    HashMask, CONFIRMATION_THRESHOLD,
};

pub fn random_entropy() -> Result<zeroize::Zeroizing<[u8; 32]>, crate::error::Error> {
    let mut entropy = zeroize::Zeroizing::new([0u8; 32]);
    getrandom::getrandom(entropy.as_mut_slice()).map_err(|_| crate::error::Error::Rng)?;
    Ok(entropy)
}

/// Names kept next to the path formatters so a caller cannot invent a scheme.
pub fn earliest_paths(account: u32, index: u32) -> (String, String) {
    (payment_path(account, index), stake_path(account))
}
