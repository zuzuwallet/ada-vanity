// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

#![forbid(unsafe_code)]

use std::process::Command;

fn bin() -> std::path::PathBuf {
    if let Some(path) = option_env!("CARGO_BIN_EXE_ada_vanity") {
        return std::path::PathBuf::from(path);
    }
    if let Some(path) = option_env!("CARGO_BIN_EXE_ada-vanity") {
        return std::path::PathBuf::from(path);
    }
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target");
    path.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    path.push("ada-vanity");
    path
}

#[test]
fn ctrl_c_on_a_pty_restores_echo_and_hides_secrets() {
    let script = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/pty_ctrlc.py");
    let phrase = ada_vanity::mnemonic_from_entropy(&[0u8; 32]).expect("abandon vector");
    let derived = ada_vanity::derive_wallet(&[0u8; 32], ada_vanity::Network::Mainnet, 0, 20)
        .expect("abandon address");
    let output = Command::new("python3")
        .arg(&script)
        .env("ADA_VANITY_BIN", bin())
        .env("ADA_RECOVER_MNEMONIC", phrase.as_str())
        .env("ADA_RECOVER_ADDRESS", &derived.address)
        .output()
        .expect("python3 is required for the PTY test");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "pty test failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("PTY_OK"), "{stdout}");
}
