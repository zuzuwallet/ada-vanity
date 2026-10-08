// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shelley base address: header || payment credential || stake credential.
//!
//! Type 0 is a key hash plus a key hash. Enterprise addresses (type 6,
//! header `0x61`, text `addr1v...`) are not produced.

use crate::ada::bech32;
use crate::ada::hash::blake2b_224;
use crate::ada::network::Network;
use crate::error::Error;

pub const HASH_LEN: usize = 28;
pub const ADDRESS_LEN: usize = 1 + HASH_LEN + HASH_LEN;

pub fn credential_hash(public_key: &[u8; 32]) -> [u8; HASH_LEN] {
    blake2b_224(public_key)
}

pub fn base_bytes(
    network: Network,
    payment: &[u8; HASH_LEN],
    stake: &[u8; HASH_LEN],
) -> [u8; ADDRESS_LEN] {
    let mut out = [0u8; ADDRESS_LEN];
    out[0] = network.header();
    out[1..1 + HASH_LEN].copy_from_slice(payment);
    out[1 + HASH_LEN..].copy_from_slice(stake);
    out
}

pub fn base_address(
    network: Network,
    payment: &[u8; HASH_LEN],
    stake: &[u8; HASH_LEN],
) -> Result<String, Error> {
    bech32::encode(network.hrp(), &base_bytes(network, payment, stake))
}
