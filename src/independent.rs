// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Second reconstruction of a Shelley base address.
//!
//! Child keys come from `ed25519-bip32` scheme V2. Credential hashes come
//! from cryptoxide's Blake2b-224. The text comes from the `bech32` crate.
//! None of those are the search stack's CKD, `blake2` crate, or this crate's
//! Bech32 encoder. PBKDF2 stays in the search stack; this module starts from
//! the 96-byte Icarus root.

use bech32::{Bech32, Hrp};
use cryptoxide::hashing::blake2b::Blake2b;
use ed25519_bip32::{DerivationScheme, XPrv};
use zeroize::Zeroize;

use crate::ada::network::Network;
use crate::ada::{
    harden, payment_path, stake_path, COIN_TYPE, PURPOSE, ROLE_EXTERNAL, ROLE_STAKE, STAKE_INDEX,
};
use crate::error::Error;

pub struct Reconstructed {
    pub address: String,
    pub payment: [u8; 28],
    pub stake: [u8; 28],
    pub payment_public: [u8; 32],
    pub stake_public: [u8; 32],
}

pub fn reconstruct(
    root: &[u8; 96],
    network: Network,
    account: u32,
    payment_index: u32,
) -> Result<Reconstructed, Error> {
    if payment_index >= crate::ada::HARDENED_BIT {
        return Err(Error::Index);
    }
    let account = harden(account)?;
    let mut root_bytes = *root;
    let master = XPrv::from_bytes_verified(root_bytes).map_err(|_| Error::InvalidKey)?;
    root_bytes.zeroize();
    let scheme = DerivationScheme::V2;
    let account_key = master
        .derive(scheme, harden(PURPOSE)?)
        .derive(scheme, harden(COIN_TYPE)?)
        .derive(scheme, account);
    let payment = account_key
        .derive(scheme, ROLE_EXTERNAL)
        .derive(scheme, payment_index);
    let stake = account_key
        .derive(scheme, ROLE_STAKE)
        .derive(scheme, STAKE_INDEX);
    let payment_key = payment.public().public_key();
    let stake_key = stake.public().public_key();
    let payment_hash = blake2b_224(&payment_key);
    let stake_hash = blake2b_224(&stake_key);
    let mut raw = [0u8; 57];
    raw[0] = network.header();
    raw[1..29].copy_from_slice(&payment_hash);
    raw[29..].copy_from_slice(&stake_hash);
    let address = encode_bech32(network.hrp(), &raw)?;
    Ok(Reconstructed {
        address,
        payment: payment_hash,
        stake: stake_hash,
        payment_public: payment_key,
        stake_public: stake_key,
    })
}

pub fn payment_path_text(account: u32, index: u32) -> String {
    payment_path(account, index)
}

pub fn stake_path_text(account: u32) -> String {
    stake_path(account)
}

fn blake2b_224(bytes: &[u8]) -> [u8; 28] {
    Blake2b::<224>::new().update(bytes).finalize()
}

fn encode_bech32(hrp: &str, data: &[u8]) -> Result<String, Error> {
    let hrp = Hrp::parse(hrp).map_err(|_| Error::Checksum)?;
    bech32::encode::<Bech32>(hrp, data).map_err(|_| Error::Checksum)
}
