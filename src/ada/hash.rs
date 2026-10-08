// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Blake2b-224, the Cardano credential hash. This is not SHA-256 and not
//! 32-byte Blake2b. No personalization string is used.

use blake2::digest::consts::U28;
use blake2::digest::Digest;
use blake2::Blake2b;

pub(crate) fn blake2b_224(bytes: &[u8]) -> [u8; 28] {
    let digest = Blake2b::<U28>::new().chain_update(bytes).finalize();
    let mut out = [0u8; 28];
    out.copy_from_slice(&digest);
    out
}
