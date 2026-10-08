// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::Path;

/// Errors from derivation, search, and wallet I/O.
///
/// Display text is static, or a filesystem path plus an OS error, or a public
/// prefix diagnostic. It never includes a mnemonic, an extended key, a
/// passphrase, or ciphertext.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("self-test failed: {0}")]
    SelfTest(&'static str),
    #[error("invalid prefix: {0}")]
    Prefix(String),
    #[error("extended key is not a valid Cardano key")]
    InvalidKey,
    #[error("derivation index is outside the allowed range")]
    Index,
    #[error("checksum mismatch")]
    Checksum,
    #[error("random number generator failed")]
    Rng,
    #[error("search cancelled")]
    Cancelled { attempts: u64 },
    #[error("search failed")]
    SearchFailed,
    #[error("derivation index range exhausted")]
    RangeExhausted { attempts: u64 },
    #[error("FATAL ERROR — DO NOT USE THE WALLET")]
    VerificationFailed,
    #[error("invalid thread count")]
    Threads,
    #[error("output file already exists")]
    OutputExists,
    #[error("output directory is missing")]
    OutputDir,
    #[error("wallet file is not valid")]
    WalletFormat,
    #[error("decryption failed")]
    Decrypt,
    #[error("passphrase rejected")]
    Passphrase,
    #[error("mnemonic rejected: a 24-word English BIP-39 phrase is required")]
    Mnemonic,
    #[error("a terminal is required")]
    NeedTerminal,
    #[error("export requires a terminal on both stdin and stdout")]
    ExportNeedsTerminal,
    #[error("confirmation was not given")]
    NotConfirmed,
    #[error("I/O error: {0}")]
    Io(String),
}

impl Error {
    pub(crate) fn io(path: &Path, err: std::io::Error) -> Self {
        Error::Io(format!("{}: {err}", path.display()))
    }

    pub(crate) fn prefix(text: impl Into<String>) -> Self {
        Error::Prefix(text.into())
    }
}
