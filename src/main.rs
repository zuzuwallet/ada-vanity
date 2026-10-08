// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! CLI for the offline Cardano vanity generator.
//!
//! The mnemonic is printed only by `export`, after the word EXPORT, and only
//! when both stdin and stdout are terminals. `recover` reads a mnemonic with
//! echo disabled and prints the public address only.

#![forbid(unsafe_code)]

use std::io::{self, IsTerminal, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use ada_vanity::ada::icarus_root;
use ada_vanity::{
    analyze, check_new_passphrase, check_passphrase, export_wallet_text, group_digits,
    measure_miss_rate, open_and_verify, random_entropy, recover_address, require_searchable,
    run_self_tests, search, write_encrypted_wallet, Analysis, Error, Network, SearchRequest,
    CONFIRMATION_THRESHOLD, GAP_LIMIT, ICARUS_RECOVERY_SCHEME, MAX_THREADS,
    MIN_NEW_PASSPHRASE_CHARS, PAYMENT_INDEX_LIMIT, RECOVERY_NOTICE_LINE_1, RECOVERY_NOTICE_LINE_2,
    SCHEME_INCOMPATIBILITY,
};

#[derive(Parser)]
#[command(
    name = "ada-vanity",
    about = "Offline Cardano Shelley vanity address generator",
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the known-answer tests and exit.
    SelfTest,
    /// Show whether PREFIX is a reachable Shelley base-address prefix.
    Analyze {
        prefix: String,
        /// mainnet or testnet. The default is mainnet.
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    /// Run the known-answer tests, then measure the public-key miss path.
    Benchmark {
        #[arg(long, default_value = "mainnet")]
        network: String,
        #[arg(long)]
        threads: Option<usize>,
    },
    /// Search for PREFIX and store the recovery entropy in an encrypted wallet.
    Generate {
        prefix: String,
        /// mainnet or testnet. The default is mainnet. Testnet is never labeled mainnet.
        #[arg(long, default_value = "mainnet")]
        network: String,
        /// Worker count, from 1 to 256. The default is the machine's parallelism.
        #[arg(long)]
        threads: Option<usize>,
        /// CIP-1852 account. The default is 0. It must be below 2^31.
        #[arg(long, default_value_t = 0)]
        account: u32,
        /// Encrypted wallet path. The default is PREFIX-wallet.json.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Decrypt a wallet offline and rebuild the stored address.
    Verify { wallet: PathBuf },
    /// Decrypt a wallet and print the mnemonic. Offline only.
    Export { wallet: PathBuf },
    /// Rebuild one address from a 24-word mnemonic. Offline. The mnemonic is prompted, not an argument.
    Recover {
        /// mainnet or testnet. The default is mainnet.
        #[arg(long, default_value = "mainnet")]
        network: String,
        /// CIP-1852 account. The default is 0. It must be below 2^31.
        #[arg(long, default_value_t = 0)]
        account: u32,
        /// Payment index on role 0. Required. It must be below 2^31.
        #[arg(long)]
        index: u32,
    },
}

fn main() -> ExitCode {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn run() -> Result<(), Error> {
    match Cli::parse().command {
        Command::SelfTest => cmd_self_test(),
        Command::Analyze { prefix, network } => cmd_analyze(&prefix, &network),
        Command::Benchmark { network, threads } => cmd_benchmark(&network, threads),
        Command::Generate {
            prefix,
            network,
            threads,
            account,
            output,
        } => cmd_generate(&prefix, &network, threads, account, output),
        Command::Verify { wallet } => cmd_verify(&wallet),
        Command::Export { wallet } => cmd_export(&wallet),
        Command::Recover {
            network,
            account,
            index,
        } => cmd_recover(&network, account, index),
    }
}

fn cmd_self_test() -> Result<(), Error> {
    if let Err(err) = run_self_tests() {
        println!("Cryptographic self-tests: FAIL");
        return Err(err);
    }
    println!("Cryptographic self-tests: PASS");
    Ok(())
}

fn cmd_analyze(prefix: &str, network: &str) -> Result<(), Error> {
    let network = Network::parse(network)?;
    let analysis = analyze(network, prefix)?;
    println!("{}", analysis.report());
    Ok(())
}

fn cmd_benchmark(network: &str, threads: Option<usize>) -> Result<(), Error> {
    let network = Network::parse(network)?;
    let threads = resolve_threads(threads)?;
    if let Err(err) = run_self_tests() {
        println!("Cryptographic self-tests: FAIL");
        return Err(err);
    }
    println!("Cryptographic self-tests: PASS");
    let root_started = Instant::now();
    let entropy = random_entropy()?;
    let root = icarus_root(entropy.as_slice(), b"")?;
    let root_elapsed = root_started.elapsed();
    drop(root);
    drop(entropy);
    let rate = measure_miss_rate(network, threads, Duration::from_secs(1))?;
    println!("Cardano Vanity Benchmark");
    println!();
    println!("Network:");
    println!("{}", network.label());
    println!();
    println!("Address type:");
    println!("Base (key hash / key hash)");
    println!();
    println!("Threads:");
    println!("{threads}");
    println!();
    println!("One Icarus root stretch:");
    println!("{}", format_elapsed(root_elapsed));
    println!("That stretch runs once per wallet. It is not part of the attempt loop.");
    println!();
    println!("Measured miss-path rate:");
    println!("{} candidates/sec", group_u64(rate));
    println!();
    println!("There is no guaranteed completion time.");
    println!();
    for prefix in benchmark_targets(network) {
        let analysis = analyze(network, prefix)?;
        if !analysis.reachable || analysis.exceeds_index_space {
            continue;
        }
        println!("Target:");
        println!("{prefix}");
        println!("Search bits:");
        println!("{}", analysis.search_bits);
        println!("Expected attempts:");
        println!("{}", display_option(analysis.expected));
        println!("50% probability:");
        println!("{}", display_option(analysis.median));
        println!("90% probability:");
        println!("{}", display_option(analysis.p90));
        println!("99% probability:");
        println!("{}", display_option(analysis.p99));
        println!();
    }
    Ok(())
}

fn benchmark_targets(network: Network) -> &'static [&'static str] {
    match network {
        Network::Mainnet => &["addr1q", "addr1qy", "addr1qyz", "addr1qyzu", "addr1qyzuzu"],
        Network::Testnet => &[
            "addr_test1q",
            "addr_test1qz",
            "addr_test1qzu",
            "addr_test1qzuzu",
        ],
    }
}

fn cmd_generate(
    prefix: &str,
    network: &str,
    threads: Option<usize>,
    account: u32,
    output: Option<PathBuf>,
) -> Result<(), Error> {
    let network = Network::parse(network)?;
    let analysis = analyze(network, prefix)?;
    if let Err(err) = require_searchable(&analysis) {
        println!("{}", analysis.report());
        return Err(err);
    }
    let threads = resolve_threads(threads)?;
    if account >= PAYMENT_INDEX_LIMIT {
        return Err(Error::Index);
    }
    let output = output.unwrap_or_else(|| PathBuf::from(format!("{prefix}-wallet.json")));
    ensure_output_available(&output)?;
    warn_if_output_dir_is_shared(&output);
    print_banner(&analysis, threads, account, &output);
    if let Err(err) = run_self_tests() {
        println!("Cryptographic self-tests: FAIL");
        return Err(err);
    }
    println!("Cryptographic self-tests: PASS");
    println!();
    print_difficulty(&analysis);
    require_tty()?;
    if analysis.needs_large_search_confirmation() {
        println!(
            "This prefix is expected to take at least {} attempts.",
            group_digits(&CONFIRMATION_THRESHOLD.to_string())
        );
        println!("Type SEARCH to continue:");
        confirm_line("SEARCH")?;
    }

    let cancel = Arc::new(AtomicBool::new(false));
    let interrupt = Arc::new(AtomicBool::new(false));
    install_interrupt(Arc::clone(&cancel), Arc::clone(&interrupt))?;
    println!("Searching...");
    let _ = io::stdout().flush();
    let started = Instant::now();
    let request = SearchRequest {
        network,
        prefix: prefix.to_owned(),
        account,
        index_limit: PAYMENT_INDEX_LIMIT,
    };
    let hit = search(
        &request,
        threads,
        Arc::clone(&cancel),
        move |attempts, rate| {
            println!("Attempts: {}", group_u64(attempts));
            println!("Rate: {} candidates/sec", group_u64(rate));
            println!("Elapsed: {}", format_elapsed(started.elapsed()));
            let _ = io::stdout().flush();
        },
    );
    let hit = match hit {
        Ok(hit) if interrupt.load(Ordering::Acquire) => {
            return Err(Error::Cancelled {
                attempts: hit.attempts,
            });
        }
        other => other?,
    };

    println!();
    println!("Match found.");
    println!("Attempts: {}", group_u64(hit.attempts));
    println!("Elapsed: {}", format_elapsed(started.elapsed()));
    println!("The public address is printed after the encrypted wallet is saved.");
    println!();
    let _ = io::stdout().flush();

    let passphrase = match prompt_new_passphrase(interrupt.as_ref()) {
        Ok(passphrase) => passphrase,
        Err(err) => {
            eprintln!("Wallet was not saved.");
            return match err {
                Error::Cancelled { .. } => Err(Error::Cancelled {
                    attempts: hit.attempts,
                }),
                other => Err(other),
            };
        }
    };
    if interrupt.load(Ordering::Acquire) {
        eprintln!("Wallet was not saved.");
        return Err(Error::Cancelled {
            attempts: hit.attempts,
        });
    }
    let attempts = hit.attempts;
    let address = hit.address.clone();
    let payment_path = hit.payment_path.clone();
    let stake_path = hit.stake_path.clone();
    let index = hit.material.payment_index();
    warn_if_output_dir_is_shared(&output);
    if let Err(err) = write_encrypted_wallet(&output, passphrase.as_str(), &hit.material, &address)
    {
        eprintln!("Wallet was not saved successfully.");
        return Err(err);
    }
    drop(hit);
    drop(passphrase);
    print_found(&FoundView {
        address: &address,
        attempts,
        elapsed: started.elapsed(),
        output: &output,
        payment_path: &payment_path,
        stake_path: &stake_path,
        index,
        account,
    });
    Ok(())
}

fn print_banner(analysis: &Analysis, threads: usize, account: u32, output: &Path) {
    println!("Cardano Vanity Generator");
    println!();
    println!("Network:");
    println!("{}", analysis.network.label());
    println!();
    println!("Address type:");
    println!("Base (key hash / key hash)");
    println!();
    println!("Target:");
    println!("{}", analysis.prefix);
    println!();
    println!("Target reachability:");
    println!("PASS");
    println!();
    println!("Account:");
    println!("{account}");
    print_advanced_account(account);
    println!();
    println!("Role:");
    println!("0 (external). Change role 1 is not searched. Stake role 2 stays at index 0.");
    println!();
    println!("Threads:");
    println!("{threads}");
    println!();
    println!("Output:");
    println!("{}", output.display());
    println!();
    println!("Create the wallet directory with: mkdir -m 700 <dir>");
    println!("A private umask is: umask 077");
    println!();
}

fn print_difficulty(analysis: &Analysis) {
    println!("Expected attempts:");
    println!("{}", display_option(analysis.expected));
    println!("50% probability:");
    println!("{}", display_option(analysis.median));
    println!("90% probability:");
    println!("{}", display_option(analysis.p90));
    println!("99% probability:");
    println!("{}", display_option(analysis.p99));
    println!("Vanity search is probabilistic. There is no guaranteed completion time.");
    println!();
}

struct FoundView<'a> {
    address: &'a str,
    attempts: u64,
    elapsed: Duration,
    output: &'a Path,
    payment_path: &'a str,
    stake_path: &'a str,
    index: u32,
    account: u32,
}

fn print_found(view: &FoundView<'_>) {
    println!("FOUND");
    println!();
    print_recovery_notice();
    println!();
    println!("Address:");
    println!("{}", view.address);
    println!();
    println!("Derivation path:");
    println!("{}", view.payment_path);
    println!();
    println!("Stake derivation path:");
    println!("{}", view.stake_path);
    println!();
    println!("Attempts: {}", group_u64(view.attempts));
    println!("Elapsed: {}", format_elapsed(view.elapsed));
    println!(
        "Rate: {} candidates/sec",
        group_u64(rate(view.attempts, view.elapsed))
    );
    println!();
    print_gap(view.index);
    print_advanced_account(view.account);
    println!();
    println!("Secret storage:");
    println!("{}", view.output.display());
    println!();
    println!("The address is not a backup. Back up the mnemonic, the account index, and the payment index.");
    println!(
        "The encryption passphrase is not the Icarus passphrase. The Icarus passphrase is empty."
    );
    println!("Addresses in this account share one stake credential.");
    println!();
    println!("Independent verification:");
    println!("PASS");
    println!();
    println!("This program did not submit a transaction.");
}

fn print_recovery_notice() {
    println!("{RECOVERY_NOTICE_LINE_1}");
    println!("{RECOVERY_NOTICE_LINE_2}");
}

fn print_gap(index: u32) {
    if index >= GAP_LIMIT {
        println!(
            "A wallet that scans about 20 unused addresses will not discover payment index {index}."
        );
        println!("Recovery test:");
        println!("PENDING");
    } else {
        println!("Payment index {index} is inside a 20-address scan.");
    }
}

fn print_advanced_account(account: u32) {
    if account != 0 {
        println!("Account {account} is an advanced setting.");
        println!(
            "This program did not restore a nonzero account in Daedalus, Yoroi, Lace, or Eternl."
        );
    }
}

fn cmd_recover(network: &str, account: u32, index: u32) -> Result<(), Error> {
    let network = Network::parse(network)?;
    if account >= PAYMENT_INDEX_LIMIT || index >= PAYMENT_INDEX_LIMIT {
        return Err(Error::Index);
    }
    require_tty()?;
    let interrupt = install_command_interrupt()?;
    let phrase = prompt_password_interruptible("Mnemonic: ", interrupt.as_ref())?;
    let recovered = {
        let result = recover_address(phrase.as_str(), network, account, index);
        drop(phrase);
        result?
    };
    println!("HD derivation: PASS");
    println!("Payment credential: PASS");
    println!("Stake credential: PASS");
    println!("Address construction: PASS");
    println!();
    println!("Address:");
    println!("{}", recovered.address);
    println!();
    println!("Payment derivation path:");
    println!("{}", recovered.payment_path);
    println!("Stake derivation path:");
    println!("{}", recovered.stake_path);
    println!();
    println!("Recovery scheme:");
    println!("{ICARUS_RECOVERY_SCHEME}");
    println!("Icarus passphrase:");
    println!("empty");
    println!("{SCHEME_INCOMPATIBILITY}");
    println!();
    print_recovery_notice();
    print_gap(index);
    print_advanced_account(account);
    println!();
    println!("This program did not submit a transaction.");
    Ok(())
}

fn cmd_verify(path: &Path) -> Result<(), Error> {
    require_tty()?;
    let interrupt = install_command_interrupt()?;
    let passphrase = prompt_password_interruptible("Passphrase: ", interrupt.as_ref())?;
    check_passphrase(passphrase.as_str())?;
    let opened = open_and_verify(path, passphrase.as_str())?;
    drop(passphrase);
    let address = opened.address.clone();
    let payment_path = opened.payment_path.clone();
    let stake_path = opened.stake_path.clone();
    drop(opened);
    println!("Wallet authentication: PASS");
    println!("HD derivation: PASS");
    println!("Payment credential: PASS");
    println!("Stake credential: PASS");
    println!("Address construction: PASS");
    println!();
    println!("Payment derivation path:");
    println!("{payment_path}");
    println!("Stake derivation path:");
    println!("{stake_path}");
    println!();
    println!("Stored:");
    println!("{address}");
    println!();
    println!("Derived:");
    println!("{address}");
    println!();
    println!("MATCH: YES");
    Ok(())
}

fn cmd_export(path: &Path) -> Result<(), Error> {
    require_export_terminals()?;
    println!("WARNING: This operation prints the Cardano mnemonic to this terminal.");
    println!(
        "Do not paste it into a website, chat, AI, issue tracker, shell history, or online verifier."
    );
    println!("Only the public addr1 address and the derivation path may be shared.");
    println!(
        "Clear the terminal scrollback after the mnemonic has been copied onto offline media."
    );
    println!("Type EXPORT to continue:");
    confirm_line("EXPORT")?;
    let interrupt = install_command_interrupt()?;
    let passphrase = prompt_password_interruptible("Passphrase: ", interrupt.as_ref())?;
    check_passphrase(passphrase.as_str())?;
    let opened = open_and_verify(path, passphrase.as_str())?;
    drop(passphrase);
    secret_output_allowed(interrupt.load(Ordering::Acquire))?;
    let secret = export_wallet_text(&opened)?;
    drop(opened);
    secret_output_allowed(interrupt.load(Ordering::Acquire))?;
    print!("{}", secret.as_str());
    Ok(())
}

fn display_option(value: Option<u64>) -> String {
    match value {
        Some(value) => group_digits(&value.to_string()),
        None => "n/a".to_owned(),
    }
}

fn warn_if_output_dir_is_shared(path: &Path) {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let Ok(meta) = std::fs::metadata(parent) else {
        return;
    };
    if meta.permissions().mode() & 0o022 != 0 {
        eprintln!(
            "warning: output directory is writable by group or others. Create a private directory with: mkdir -m 700 <dir>"
        );
    }
}

fn ensure_output_available(path: &Path) -> Result<(), Error> {
    if path.exists() {
        return Err(Error::OutputExists);
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.is_dir() {
            return Err(Error::OutputDir);
        }
    }
    Ok(())
}

fn resolve_threads(threads: Option<usize>) -> Result<usize, Error> {
    match threads {
        Some(value) => validate_threads_cli(value),
        None => Ok(default_threads()),
    }
}

fn validate_threads_cli(threads: usize) -> Result<usize, Error> {
    if threads == 0 || threads > MAX_THREADS {
        Err(Error::Threads)
    } else {
        Ok(threads)
    }
}

fn default_threads() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .clamp(1, MAX_THREADS)
}

fn require_tty() -> Result<(), Error> {
    if io::stdin().is_terminal() {
        Ok(())
    } else {
        Err(Error::NeedTerminal)
    }
}

fn require_export_terminals() -> Result<(), Error> {
    export_terminals_ok(io::stdin().is_terminal(), io::stdout().is_terminal())
}

fn export_terminals_ok(stdin_tty: bool, stdout_tty: bool) -> Result<(), Error> {
    if stdin_tty && stdout_tty {
        Ok(())
    } else {
        Err(Error::ExportNeedsTerminal)
    }
}

fn confirm_line(expected: &str) -> Result<(), Error> {
    require_tty()?;
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|err| Error::Io(format!("stdin: {err}")))?;
    if line.trim() == expected {
        Ok(())
    } else {
        Err(Error::NotConfirmed)
    }
}

fn install_command_interrupt() -> Result<Arc<AtomicBool>, Error> {
    let interrupt = Arc::new(AtomicBool::new(false));
    let cancel = Arc::new(AtomicBool::new(false));
    install_interrupt(cancel, Arc::clone(&interrupt))?;
    Ok(interrupt)
}

fn secret_output_allowed(interrupted: bool) -> Result<(), Error> {
    if interrupted {
        Err(Error::Cancelled { attempts: 0 })
    } else {
        Ok(())
    }
}

fn prompt_new_passphrase(interrupt: &AtomicBool) -> Result<Zeroizing<String>, Error> {
    require_tty()?;
    for _ in 0..3 {
        if interrupt.load(Ordering::Acquire) {
            return Err(Error::Cancelled { attempts: 0 });
        }
        let first = prompt_password_interruptible("Passphrase: ", interrupt)?;
        let second = prompt_password_interruptible("Confirm passphrase: ", interrupt)?;
        if first.as_str() != second.as_str() {
            eprintln!("error: passphrase did not match");
            continue;
        }
        match check_new_passphrase(first.as_str()) {
            Ok(()) => return Ok(first),
            Err(_) => {
                if check_passphrase(first.as_str()).is_ok() {
                    eprintln!(
                        "error: a new passphrase must be at least {MIN_NEW_PASSPHRASE_CHARS} characters"
                    );
                    eprintln!(
                        "That minimum only stops accidents. It is not a measure of strength."
                    );
                } else {
                    eprintln!("error: passphrase rejected");
                }
            }
        }
    }
    Err(Error::Passphrase)
}

fn prompt_password_interruptible(
    label: &str,
    interrupt: &AtomicBool,
) -> Result<Zeroizing<String>, Error> {
    if interrupt.load(Ordering::Acquire) {
        return Err(Error::Cancelled { attempts: 0 });
    }
    password_prompt_result(
        rpassword::prompt_password(label),
        interrupt.load(Ordering::Acquire),
    )
}

fn password_prompt_result(
    read: Result<String, std::io::Error>,
    interrupted: bool,
) -> Result<Zeroizing<String>, Error> {
    if interrupted {
        if let Ok(password) = read {
            drop(Zeroizing::new(password));
        }
        return Err(Error::Cancelled { attempts: 0 });
    }
    match read {
        Ok(password) => Ok(Zeroizing::new(password)),
        Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {
            Err(Error::Cancelled { attempts: 0 })
        }
        Err(_) => Err(Error::NeedTerminal),
    }
}

fn install_interrupt(cancel: Arc<AtomicBool>, interrupt: Arc<AtomicBool>) -> Result<(), Error> {
    ctrlc::set_handler(move || {
        interrupt.store(true, Ordering::Release);
        cancel.store(true, Ordering::Release);
    })
    .map_err(|_| Error::Io("could not install the interrupt handler".to_owned()))
}

fn group_u64(value: u64) -> String {
    group_digits(&value.to_string())
}

fn rate(attempts: u64, elapsed: Duration) -> u64 {
    let seconds = elapsed.as_secs_f64();
    if seconds <= 0.0 {
        attempts
    } else {
        (attempts as f64 / seconds) as u64
    }
}

fn format_elapsed(elapsed: Duration) -> String {
    if elapsed.as_secs() < 60 {
        format!("{:.3}s", elapsed.as_secs_f64())
    } else {
        let seconds = elapsed.as_secs();
        format!("{}m {}s", seconds / 60, seconds % 60)
    }
}

#[cfg(test)]
mod tests {
    use super::{export_terminals_ok, password_prompt_result, Error};

    #[test]
    fn export_requires_both_terminals() {
        assert!(export_terminals_ok(true, true).is_ok());
        assert_eq!(
            export_terminals_ok(true, false),
            Err(Error::ExportNeedsTerminal)
        );
        assert_eq!(
            export_terminals_ok(false, true),
            Err(Error::ExportNeedsTerminal)
        );
    }

    #[test]
    fn interrupted_passphrase_read_cancels_without_keeping_it() {
        let accepted =
            password_prompt_result(Ok("correct horse battery".to_owned()), false).unwrap();
        assert_eq!(accepted.as_str(), "correct horse battery");
        assert!(matches!(
            password_prompt_result(Ok("secret-passphrase".to_owned()), true),
            Err(Error::Cancelled { attempts: 0 })
        ));
        let interrupted = std::io::Error::new(std::io::ErrorKind::Interrupted, "interrupted");
        assert!(matches!(
            password_prompt_result(Err(interrupted), false),
            Err(Error::Cancelled { attempts: 0 })
        ));
    }
}
