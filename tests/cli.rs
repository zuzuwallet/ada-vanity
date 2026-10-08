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

fn scratch(label: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ada-vanity-cli-{label}-{nanos}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn self_test_command_passes_without_printing_the_vector_phrase() {
    let output = Command::new(bin()).arg("self-test").output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stdout {stdout}\nstderr {stderr}");
    assert!(stdout.contains("Cryptographic self-tests: PASS"));
    assert!(!stdout.contains("eight country"));
    assert!(!stdout.contains("prevent company"));
    assert!(!stdout.contains("b8ab42f1"));
    assert!(!stdout.contains("Mnemonic:"));
    assert!(!stderr.contains("eight country"));
    assert!(!stderr.contains("prevent company"));
    assert!(!stderr.contains("b8ab42f1"));
}

#[test]
fn analyze_addr1qzuzu_is_unreachable_and_exits_zero() {
    let output = Command::new(bin())
        .args(["analyze", "addr1qzuzu"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stdout {stdout}\nstderr {stderr}");
    assert!(stdout.contains("Target reachable:\nNO"));
    assert!(stdout.contains("addr1qyzuzu"));
    assert!(stdout.contains("addr1q9zuzu"));
    assert!(stdout.contains("addr1qxzuzu"));
    assert!(stdout.contains("addr1q8zuzu"));
    assert!(stdout.contains("does not substitute"));
    assert!(!stdout.contains("FOUND"));
    assert!(!stdout.contains("Cryptographic self-tests"));
}

#[test]
fn analyze_addr1qyzuzu_prints_the_bit_model() {
    let output = Command::new(bin())
        .args(["analyze", "addr1qyzuzu"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    assert!(stdout.contains("Target reachable:\nYES"));
    assert!(stdout.contains("22"));
    assert!(stdout.contains("4,194,304"));
    assert!(stdout.contains("2,907,270"));
    assert!(stdout.contains("9,657,741"));
    assert!(stdout.contains("19,315,482"));
    assert!(stdout.contains("not 32^n"));
}

#[test]
fn generate_addr1qzuzu_writes_nothing_and_skips_self_test() {
    let dir = scratch("impossible");
    let output = Command::new(bin())
        .args(["generate", "addr1qzuzu"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains("Target reachable:\nNO"), "{stdout}");
    assert!(stdout.contains("addr1qyzuzu"));
    assert!(!stdout.contains("Cryptographic self-tests"));
    assert!(!stdout.contains("FOUND"));
    assert!(!stdout.contains("Address:"));
    assert!(!stdout.contains("Searching"));
    assert!(stderr.contains("invalid prefix"));
    assert!(!dir.join("addr1qzuzu-wallet.json").exists());
    assert!(std::fs::read_dir(&dir).unwrap().next().is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn zero_threads_and_a_huge_thread_count_create_no_wallet() {
    let dir = scratch("threads");
    for threads in ["0", "257"] {
        let output = Command::new(bin())
            .args(["generate", "addr1qy", "--threads", threads])
            .current_dir(&dir)
            .output()
            .unwrap();
        assert!(!output.status.success(), "{threads}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("invalid thread count"), "{stderr}");
        assert!(!dir.join("addr1qy-wallet.json").exists());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn mixed_case_and_alphabet_errors_are_rejected() {
    let mixed = Command::new(bin())
        .args(["analyze", "addr1qYzuzu"])
        .output()
        .unwrap();
    assert!(!mixed.status.success());
    let stderr = String::from_utf8_lossy(&mixed.stderr);
    assert!(stderr.contains("mixed-case"));

    for prefix in ["addr1qb", "addr1qi", "addr1qo", "addr11q"] {
        let output = Command::new(bin())
            .args(["analyze", prefix])
            .output()
            .unwrap();
        assert!(!output.status.success(), "{prefix}");
    }
}

#[test]
fn a_full_address_is_not_a_search_prefix() {
    let address = "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x";
    let output = Command::new(bin())
        .args(["analyze", address])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("complete address"));
}

#[test]
fn an_existing_output_file_is_left_untouched() {
    let dir = scratch("exists");
    let path = dir.join("addr1qy-wallet.json");
    std::fs::write(&path, b"keep\n").unwrap();
    let output = Command::new(bin())
        .args(["generate", "addr1qy", "--output"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("output file already exists"), "{stderr}");
    assert!(!stdout.contains("FOUND"));
    assert!(!stdout.contains("Address:"));
    assert_eq!(std::fs::read(&path).unwrap(), b"keep\n");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn recover_without_a_terminal_does_not_read_a_mnemonic() {
    let output = Command::new(bin())
        .args(["recover", "--index", "0"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("terminal"), "{stderr}");
    assert!(!stdout.contains("Address:"));
    assert!(!stdout.contains("HD derivation"));
    assert!(!stderr.contains("abandon"));
}

#[test]
fn recover_rejects_a_hardened_payment_index_before_a_prompt() {
    let output = Command::new(bin())
        .args(["recover", "--index", "2147483648"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("derivation index"), "{stderr}");
    assert!(!stderr.contains("terminal"));
}

#[test]
fn an_account_past_the_hardened_boundary_is_rejected() {
    let dir = scratch("account");
    let output = Command::new(bin())
        .args(["generate", "addr1qy", "--account", "2147483648"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("derivation index"));
    assert!(!dir.join("addr1qy-wallet.json").exists());
    let _ = std::fs::remove_dir_all(&dir);
}
