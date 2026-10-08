// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Parallel search over the non-hardened payment index.
//!
//! The mnemonic entropy is one operating-system CSPRNG draw and stays in the
//! parent thread. Workers receive the external-chain extended public key and
//! the stake credential hash. The payment index is a counter, not entropy.
//! A hit reports only the index. The parent derives that private child again
//! and checks it with the independent stack before any wallet exists.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::ada::address::{base_address, credential_hash};
use crate::ada::{
    account_key, analyze, external_chain, icarus_root, payment_path, random_entropy,
    require_searchable, stake_credential, stake_path, Analysis, Network, HARDENED_BIT,
    PAYMENT_INDEX_LIMIT,
};
use crate::error::Error;
use zeroize::Zeroize;

use crate::verify::confirm_material;
use crate::wallet::WalletMaterial;

pub const MAX_THREADS: usize = 256;

pub fn validate_threads(threads: usize) -> Result<(), Error> {
    if threads == 0 || threads > MAX_THREADS {
        Err(Error::Threads)
    } else {
        Ok(())
    }
}

pub struct SearchRequest {
    pub network: Network,
    pub prefix: String,
    pub account: u32,
    /// Exclusive end of the soft payment index. The command line uses `2^31`.
    pub index_limit: u32,
}

pub struct SearchHit {
    pub address: String,
    pub attempts: u64,
    pub payment_path: String,
    pub stake_path: String,
    pub material: WalletMaterial,
}

impl std::fmt::Debug for SearchHit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SearchHit")
            .field("address", &self.address)
            .field("attempts", &self.attempts)
            .field("payment_path", &self.payment_path)
            .field("material", &self.material)
            .finish()
    }
}

struct WorkerView {
    public: [u8; 32],
    chain: [u8; 32],
    stake: [u8; 28],
}

impl Drop for WorkerView {
    fn drop(&mut self) {
        self.public.zeroize();
        self.chain.zeroize();
    }
}

pub fn search<F>(
    request: &SearchRequest,
    threads: usize,
    cancel: Arc<AtomicBool>,
    progress: F,
) -> Result<SearchHit, Error>
where
    F: Fn(u64, u64) + Send + Sync + 'static,
{
    if request.account >= HARDENED_BIT
        || request.index_limit == 0
        || request.index_limit > PAYMENT_INDEX_LIMIT
    {
        return Err(Error::Index);
    }
    let analysis = analyze(request.network, &request.prefix)?;
    require_searchable(&analysis)?;
    validate_threads(threads)?;

    let entropy = random_entropy()?;
    let root = icarus_root(entropy.as_slice(), b"")?;
    let account = account_key(&root, request.account)?;
    let stake = stake_credential(&account)?;
    let external = external_chain(&account)?;
    drop(account);
    drop(root);

    let attempts = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<u32>();
    let reporter = spawn_reporter(Arc::clone(&attempts), Arc::clone(&cancel), progress);
    let view = WorkerView {
        public: *external.public_key(),
        chain: *external.chain_code(),
        stake,
    };
    drop(external);

    let mut handles = Vec::with_capacity(threads);
    for worker_id in 0..threads {
        let tx = tx.clone();
        let cancel_worker = Arc::clone(&cancel);
        let attempts = Arc::clone(&attempts);
        let failed_worker = Arc::clone(&failed);
        let analysis = analysis.clone();
        let network = request.network;
        let index_limit = request.index_limit;
        let view = WorkerView {
            public: view.public,
            chain: view.chain,
            stake: view.stake,
        };
        match thread::Builder::new()
            .name("ada-vanity".to_owned())
            .spawn(move || {
                let outcome = catch_unwind(AssertUnwindSafe(|| {
                    worker(WorkerTask {
                        analysis,
                        network,
                        view,
                        index: worker_id as u32,
                        step: threads as u32,
                        limit: index_limit,
                        cancel: Arc::clone(&cancel_worker),
                        attempts,
                        tx,
                    })
                }));
                if !matches!(outcome, Ok(Ok(()))) {
                    failed_worker.store(true, Ordering::Release);
                    cancel_worker.store(true, Ordering::Release);
                }
            }) {
            Ok(handle) => handles.push(handle),
            Err(_) => {
                failed.store(true, Ordering::Release);
                cancel.store(true, Ordering::Release);
                break;
            }
        }
    }
    drop(tx);
    drop(view);

    let first = rx.recv();
    let user_cancelled = cancel.load(Ordering::Acquire);
    cancel.store(true, Ordering::Release);
    join_workers(handles);
    let _ = reporter.join();
    while rx.try_recv().is_ok() {}

    let total = attempts.load(Ordering::Relaxed);
    if failed.load(Ordering::Acquire) {
        return Err(Error::SearchFailed);
    }
    let Some(index) = first.ok() else {
        return Err(if user_cancelled {
            Error::Cancelled { attempts: total }
        } else {
            Error::RangeExhausted { attempts: total }
        });
    };
    finish_hit(request, &analysis, index, total, entropy)
}

fn finish_hit(
    request: &SearchRequest,
    analysis: &Analysis,
    index: u32,
    attempts: u64,
    entropy: zeroize::Zeroizing<[u8; 32]>,
) -> Result<SearchHit, Error> {
    let derived = crate::ada::derive_wallet(&entropy, request.network, request.account, index)?;
    if !derived.address.starts_with(analysis.prefix.as_str()) {
        return Err(Error::SearchFailed);
    }
    let material = WalletMaterial::hd(request.network, entropy, request.account, index);
    confirm_material(&material, &derived.address)?;
    Ok(SearchHit {
        address: derived.address,
        attempts,
        payment_path: payment_path(request.account, index),
        stake_path: stake_path(request.account),
        material,
    })
}

struct WorkerTask {
    analysis: Analysis,
    network: Network,
    view: WorkerView,
    index: u32,
    step: u32,
    limit: u32,
    cancel: Arc<AtomicBool>,
    attempts: Arc<AtomicU64>,
    tx: mpsc::Sender<u32>,
}

fn worker(task: WorkerTask) -> Result<(), Error> {
    let WorkerTask {
        analysis,
        network,
        view,
        mut index,
        step,
        limit,
        cancel,
        attempts,
        tx,
    } = task;
    if index >= limit {
        return Ok(());
    }
    let parent = crate::ada::Xpub::from_parts(view.public, view.chain);
    loop {
        if cancel.load(Ordering::Acquire) {
            return Ok(());
        }
        let public = parent.child_public(index)?;
        let payment = credential_hash(&public);
        attempts.fetch_add(1, Ordering::Relaxed);
        if analysis.mask.matches(&payment) {
            let address = base_address(network, &payment, &view.stake)?;
            if address.starts_with(analysis.prefix.as_str()) {
                let _ = tx.send(index);
                return Ok(());
            }
        }
        let Some(next) = index.checked_add(step) else {
            return Ok(());
        };
        if next >= limit {
            return Ok(());
        }
        index = next;
    }
}

pub fn measure_miss_rate(
    network: Network,
    threads: usize,
    duration: Duration,
) -> Result<u64, Error> {
    validate_threads(threads)?;
    let prefix = match network {
        Network::Mainnet => "addr1qyzuzu",
        Network::Testnet => "addr_test1qzuzu",
    };
    let analysis = analyze(network, prefix)?;
    require_searchable(&analysis)?;
    let entropy = random_entropy()?;
    let root = icarus_root(entropy.as_slice(), b"")?;
    let account = account_key(&root, 0)?;
    let external = external_chain(&account)?;
    drop(account);
    drop(root);
    let attempts = Arc::new(AtomicU64::new(0));
    let cancel = Arc::new(AtomicBool::new(false));
    let started = Instant::now();
    let mut handles = Vec::new();
    for worker_id in 0..threads {
        let attempts = Arc::clone(&attempts);
        let cancel = Arc::clone(&cancel);
        let analysis = analysis.clone();
        let parent = external.clone();
        handles.push(thread::spawn(move || {
            let mut index = worker_id as u32;
            let step = threads as u32;
            while !cancel.load(Ordering::Acquire) {
                let Ok(public) = parent.child_public(index) else {
                    cancel.store(true, Ordering::Release);
                    break;
                };
                let payment = credential_hash(&public);
                attempts.fetch_add(1, Ordering::Relaxed);
                let _ = analysis.mask.matches(&payment);
                let Some(next) = index.checked_add(step) else {
                    break;
                };
                if next >= HARDENED_BIT {
                    break;
                }
                index = next;
            }
        }));
    }
    while started.elapsed() < duration {
        thread::sleep(Duration::from_millis(20));
    }
    cancel.store(true, Ordering::Release);
    join_workers(handles);
    let total = attempts.load(Ordering::Relaxed);
    let seconds = started.elapsed().as_secs_f64();
    if seconds <= 0.0 {
        Ok(total)
    } else {
        Ok((total as f64 / seconds) as u64)
    }
}

fn spawn_reporter<F>(
    attempts: Arc<AtomicU64>,
    cancel: Arc<AtomicBool>,
    progress: F,
) -> JoinHandle<()>
where
    F: Fn(u64, u64) + Send + Sync + 'static,
{
    thread::spawn(move || {
        let mut last_count = 0u64;
        let mut last_time = Instant::now();
        while !cancel.load(Ordering::Acquire) {
            thread::sleep(Duration::from_millis(200));
            if last_time.elapsed() >= Duration::from_secs(1) {
                let count = attempts.load(Ordering::Relaxed);
                let rate = (count.saturating_sub(last_count) as f64
                    / last_time.elapsed().as_secs_f64()) as u64;
                progress(count, rate);
                last_count = count;
                last_time = Instant::now();
            }
        }
    })
}

fn join_workers(handles: Vec<JoinHandle<()>>) {
    for handle in handles {
        let _ = handle.join();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    use super::{search, validate_threads, SearchRequest, MAX_THREADS};
    use crate::ada::{analyze, require_searchable, Network, PAYMENT_INDEX_LIMIT};
    use crate::error::Error;

    #[test]
    fn thread_count_bounds() {
        assert!(validate_threads(0).is_err());
        assert!(validate_threads(MAX_THREADS + 1).is_err());
        assert!(validate_threads(1).is_ok());
        assert!(validate_threads(MAX_THREADS).is_ok());
    }

    #[test]
    fn short_prefix_is_found_and_cancelled_search_writes_nothing() {
        let cancel = Arc::new(AtomicBool::new(false));
        let hit = search(
            &SearchRequest {
                network: Network::Mainnet,
                prefix: "addr1qy".to_owned(),
                account: 0,
                index_limit: PAYMENT_INDEX_LIMIT,
            },
            2,
            Arc::clone(&cancel),
            |_, _| {},
        )
        .unwrap();
        assert!(hit.address.starts_with("addr1qy"));
        assert!(hit.payment_path.starts_with("m/1852'/1815'/0'/0/"));
        assert_eq!(hit.stake_path, "m/1852'/1815'/0'/2/0");
        assert!(hit.attempts >= 1);

        let cancel = Arc::new(AtomicBool::new(true));
        let stopped = search(
            &SearchRequest {
                network: Network::Mainnet,
                prefix: "addr1qyzuzu".to_owned(),
                account: 0,
                index_limit: PAYMENT_INDEX_LIMIT,
            },
            1,
            cancel,
            |_, _| {},
        );
        assert!(matches!(stopped, Err(Error::Cancelled { .. })));
    }

    #[test]
    fn a_rare_prefix_exhausts_a_tiny_range() {
        let result = search(
            &SearchRequest {
                network: Network::Mainnet,
                prefix: "addr1qyzuzu".to_owned(),
                account: 0,
                index_limit: 8,
            },
            2,
            Arc::new(AtomicBool::new(false)),
            |_, _| {},
        );
        assert!(matches!(result, Err(Error::RangeExhausted { attempts: 8 })));
    }

    #[test]
    fn benchmark_prefixes_are_searchable() {
        for (network, prefix) in [
            (Network::Mainnet, "addr1qyzuzu"),
            (Network::Testnet, "addr_test1qzuzu"),
        ] {
            let analysis = analyze(network, prefix).unwrap();
            assert!(analysis.reachable, "{prefix}");
            require_searchable(&analysis).unwrap();
        }
    }
}
