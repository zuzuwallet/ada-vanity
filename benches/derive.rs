// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Miss path: one soft public child, Blake2b-224, and the prefix mask.
//! The Icarus stretch is outside this loop.

#![forbid(unsafe_code)]

use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_miss(c: &mut Criterion) {
    let entropy = ada_vanity::random_entropy().expect("rng");
    let root = ada_vanity::ada::icarus_root(entropy.as_slice(), b"").expect("root");
    let account = ada_vanity::ada::account_key(&root, 0).expect("account");
    let external = ada_vanity::ada::external_chain(&account).expect("external");
    drop(account);
    drop(root);
    drop(entropy);
    let analysis =
        ada_vanity::analyze(ada_vanity::Network::Mainnet, "addr1qyzuzu").expect("prefix");
    let mut index = 0u32;
    let mut group = c.benchmark_group("derive");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(2));
    group.bench_function("soft_child_blake2b224_mask", |b| {
        b.iter(|| {
            let public = external.child_public(index).expect("child");
            let payment = ada_vanity::ada::credential_hash(&public);
            index = index.wrapping_add(1) & 0x7fff_ffff;
            black_box(analysis.mask.matches(&payment))
        });
    });
    group.finish();
}

criterion_group!(benches, bench_miss);
criterion_main!(benches);
