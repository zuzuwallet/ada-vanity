// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Offline Cardano Shelley vanity address generator.
//!
//! The search path is this crate's CIP-1852 derivation, `curve25519-dalek`,
//! the `blake2` crate, and this crate's Bech32. The independent check uses
//! `ed25519-bip32` scheme V2, cryptoxide's Blake2b-224, and the `bech32`
//! crate. `ed25519-dalek` accepts the payment and stake verification keys
//! before a wallet is trusted.

#![forbid(unsafe_code)]

pub mod ada;
pub mod error;
mod hexutil;
pub mod independent;
pub mod search;
pub mod secret;
pub mod self_test;
pub mod verify;
pub mod wallet;

pub use ada::{
    analyze, attempts_for_probability, derive_wallet, earliest_zuzu, group_digits,
    mnemonic_from_entropy, random_entropy, require_searchable, Analysis, Network,
    CONFIRMATION_THRESHOLD, GAP_LIMIT, PAYMENT_INDEX_LIMIT,
};
pub use error::Error;
pub use search::{
    measure_miss_rate, search, validate_threads, SearchHit, SearchRequest, MAX_THREADS,
};
pub use secret::{SecretBytes, SecretString};
pub use self_test::run_self_tests;
pub use verify::{recover_address, Recovered};
pub use wallet::{
    check_new_passphrase, check_passphrase, export_wallet_text, open_and_verify,
    write_encrypted_wallet, ICARUS_RECOVERY_SCHEME, MIN_NEW_PASSPHRASE_CHARS,
    RECOVERY_NOTICE_LINE_1, RECOVERY_NOTICE_LINE_2, SCHEME_INCOMPATIBILITY,
};
