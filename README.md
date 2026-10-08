# ada-vanity

Offline generator for a Cardano Shelley mainnet **base address** (payment key hash and stake key hash) whose Bech32 text starts with a chosen prefix.

`addr1qzuzu` cannot be that address. Header byte `0x01` forces every such mainnet address to start with `addr1q`, and the next character can only be `y`, `9`, `x`, or `8`. `z` is not in that set. `ada-vanity analyze addr1qzuzu` prints `Target reachable: NO` and exits 0. `generate` prints the same report and exits 1. It does not search, it does not write a wallet, and it does not substitute another prefix.

The earliest complete `zuzu`, and the worked example below, is `addr1qyzuzu`. Three other prefixes are equally early and equally difficult: `addr1q9zuzu`, `addr1qxzuzu`, and `addr1q8zuzu`. Each is 22 search bits, expected attempts `4,194,304`. That figure is the bit model in this document. It is not `32^n`, and it is not a promise of wall-clock time.

This is a normal CIP-1852 / Icarus wallet. The result is one 24-word BIP-39 mnemonic, account `0` unless you pass another account, a non-hardened payment index, and stake index `0`. It is not an enterprise address, not a Byron address, and not a raw Ed25519 key with no derivation path.

The mnemonic alone is not sufficient for practical recovery through a standard wallet UI. Back up the exact payment derivation index and path. Cardano wallets stop external-address discovery after about 20 unused addresses. For `addr1qyzuzu`, each index hits with probability `1/2^22`, so the chance that the first match is inside indexes 0 through 19 is about `1 - (1 - 2^-22)^20` ≈ 0.000004768, about 0.000477%. Under that model, more than 99.9995% of those matches sit outside a 20-address scan. `ada-vanity recover` rebuilds the address from the mnemonic and the recorded index without that scan.

A recognizable address is a public identifier. Vanity does not improve privacy. Every address in one account shares one stake credential, so those addresses are linkable on chain. Do not describe the prefix as an anonymity feature.

Never paste a mnemonic, root key, extended private key, payment signing key, stake signing key, encryption passphrase, or wallet file into a website, an AI or chat system, an issue tracker, a shell command, or an online verification service. The terminal scrollback, shell history, and process list are copies of a secret. Only the public `addr1...` address and the non-secret derivation path may be shared.

Passing `cargo test` does not make a wallet appropriate for a substantial amount of ADA. Before an address from this program receives meaningful funds, require all of the following on the machine that will hold the key:

1. The known-answer self-test passes.
2. `verify` rebuilds the stored address from the encrypted file.
3. An encrypted backup exists and opens on a second offline copy.
4. A disposable wallet restore in the wallet you actually use has been rehearsed, including the recorded payment index.
5. A disposable receive-and-spend has succeeded on a test network.

This tree completed items 1 and 2 in process. It did not run `cardano-cli` or `cardano-address`. It did not broadcast a transaction, and it did not fund an address. The last section lists that explicitly.

## What you must back up

The public address is not a backup. Recovery needs every one of these:

| Item | This program |
| --- | --- |
| BIP-39 mnemonic | 24 English words from 256 bits of OS CSPRNG entropy. Printed only by `export`. |
| Icarus passphrase | Empty. There is no second mnemonic passphrase in this version. |
| Encryption passphrase | Separate from the Icarus passphrase. It is not stored in the file. |
| Account index | Default `0`. Hardened, and below `2^31`. Account `0` is the normal mode. A nonzero account is advanced: this program did not restore one in Daedalus, Yoroi, Lace, or Eternl. |
| Payment index | The non-hardened index the search found. `recover` needs this number. |
| Stake index | Always `0`. |
| Scheme | Cardano Icarus / CIP-3, path scheme `cip-1852-icarus-v2`. |
| Network | `mainnet` or `testnet`. A testnet address is never labeled mainnet. |

`export` is the only command that prints the mnemonic. It requires a terminal on both stdin and stdout, the word `EXPORT`, and a second interrupt check immediately before the secret line. The export names the recovery scheme and says this 24-word phrase is not guaranteed to restore to the same keys under Trezor's 24-word Cardano derivation, Ledger / BitBox02 master-key derivation, a generic BIP-39 wallet, or a SLIP-0010 wallet. Those schemes are not implemented here.

`recover --network mainnet --account 0 --index N` prompts for the 24 words with echo disabled. The mnemonic is not a command-line argument. It accepts only a 24-word English BIP-39 phrase and an empty Icarus passphrase. Both derivation stacks must agree before it prints the public address and both paths. A terminal is required. It does not write a file and it does not scan a wallet's 20-address window.

## Why `addr1qzuzu` is unreachable

A Shelley key-hash/key-hash base address is 57 bytes:

```text
header (1) || payment credential (28) || stake credential (28)
```

Mainnet type 0 uses header `0x01` (`0000 0001`). Testnet type 0 uses header `0x00`. The human-readable parts are `addr` and `addr_test`. Credentials are Blake2b-224 of the 32-byte Ed25519 verification key, with no personalization. The hash is 28 bytes, not SHA-256 and not 32-byte Blake2b.

Bech32 packs those 57 bytes most-significant bit first into 5-bit groups. The charset is `qpzry9x8gf2tvdw0s3jn54khce6mua7l`. Character `1` is only the separator after the HRP. `b`, `i`, and `o` are not in the charset. Mixed case is rejected. CIP-19 does not apply BIP-173's 90-character limit, so a full address is longer than 90 characters and is rejected as a search prefix.

Header `0x01` occupies the first 8 payload bits:

```text
bits:        0 1 2 3 4 | 5 6 7 | 8 9 ...
header 0x01: 0 0 0 0 0 | 0 0 1 | payment-hash bits
group:       group 0   | group 1 (plus two hash bits)
charset:     q         | y, 9, x, or 8
```

Group 0 is `00000`, charset index 0, the character `q`. Every mainnet type-0 base address therefore starts with `addr1q`. That prefix has probability 1. It is not a search.

Group 1 is the header's remaining `001` plus the top two bits of the payment hash. The four possible symbols are indexes 4 through 7: `y`, `9`, `x`, `8`. `z` is index 2, bits `00010`. Its top three bits are `000`, not `001`, so no amount of grinding can produce it. `r` (index 3) is impossible for the same reason.

The stake credential starts at payload bit 232 (`8 + 224`). A prefix that reaches those bits is unreachable for this search, because the stake key is fixed for the account. Enterprise addresses (header `0x61`, text `addr1v...`) are not generated and are not a fallback.

Testnet header `0x00` leaves the second data character in `q`, `p`, `z`, or `r`. That is why the CIP-19 testnet vector starts `addr_test1qz`.

`ada-vanity analyze addr1qzuzu` on this tree prints:

```text
Cardano Vanity Target Analyzer

Network:
Mainnet

Address type:
Base (key hash / key hash)

Requested:
addr1qzuzu

Type-fixed prefix:
addr1q

Fixed/constrained prefix:
addr1q

Constrained second character:
y, 9, x, or 8

Vanity-controlled portion:
uzu

Target reachable:
NO

Estimated difficulty:
n/a

Reason:
no mainnet key-hash/key-hash base address has second data character outside y, 9, x, or 8

Earliest complete zuzu:
addr1qyzuzu
addr1q9zuzu
addr1qxzuzu
addr1q8zuzu
Those four prefixes are equally early and equally difficult. This program does not substitute one of them.

The model assumes Blake2b-224 of BIP32-Ed25519 child keys behaves like independent uniform prefix bits. It is not a uniformity proof and not a promise of wall-clock time.
Vanity search is probabilistic.
```

`uzu` in that report is the remainder of the typed string after the illegal second character. It is not a target the program searches.

## Worked example: `addr1qyzuzu`

`y` is a legal second character. It contributes the two variable bits in group 1. The following `zuzu` is four unconstrained 5-bit groups, 20 bits. The total is 22 bits.

```text
probability per payment index = 1/2^22 = 1/4,194,304
```

This is not `32^6` and not `32^4`. Only the 22 bits that fall inside the payment hash are free. The header bits are fixed, and the second character is a 4-way choice rather than a 32-way choice.

The attempt counts use the geometric distribution. The count for probability `p` is the smallest integer `k` with success probability at least `p`:

```text
k = ceil(ln(1 - p) / ln(1 - 1/N))
```

For `N = 4,194,304`:

| Probability | Attempts |
| --- | --- |
| Expected (`N`) | 4,194,304 |
| 50% | 2,907,270 |
| 90% | 9,657,741 |
| 99% | 19,315,482 |

Vanity search is probabilistic. There is no guaranteed completion time. The same 22-bit cost applies to `addr1q9zuzu`, `addr1qxzuzu`, and `addr1q8zuzu`.

A wallet that discovers addresses by scanning about 20 unused indexes will miss almost every `addr1qyzuzu` result. The probability that the first match lands in indexes 0 through 19 is about 0.000477%. The success text says so, and it says to back up the payment index. `recover --index N` is the offline check that does not depend on that scan.

Because of the 5-bit grouping, the search-bit counts that fit in one account are 0, 2, 7, 12, 17, 22, and 27. The next one is 32, and `2^32` does not fit in the `2^31` soft payment indexes. `generate` refuses a prefix at 32 bits or more. It does not walk hardened indexes, change addresses (role 1), or stake indexes to chase it. The largest in-range expectation is `2^27 = 134,217,728`, which is below the 1,000,000,000 confirmation threshold. The `SEARCH` prompt is still implemented.

## Derivation

The path is CIP-1852:

```text
m / 1852' / 1815' / account' / role / index
```

Purpose `1852'` and coin type `1815'` (SLIP-0044) are hardened. The account is hardened. Role `0` is the external payment chain and is the only chain the search walks. Role `1` (change) is never walked. Role `2` is the stake key and stays at index `0`. The payment index is not hardened: `0 .. 2^31 - 1`.

The root is the Icarus master key from CIP-0003, not the BIP-39 seed:

```text
PBKDF2-HMAC-SHA512
  password   = Icarus passphrase bytes (empty in this tool)
  salt       = BIP-39 entropy bytes
  iterations = 4096
  output     = 96 bytes
then clamp the left 32 bytes:
  byte 0  &= 0xf8
  byte 31 &= 0x1f
  byte 31 |= 0x40
```

The salt is not the string `"mnemonic"`, and the iteration count is not BIP-39's 2048. The self-test rejects a root that matches `Mnemonic::to_seed`.

Child derivation is Cardano BIP32-Ed25519 scheme V2, as implemented by IOG `ed25519-bip32` 0.4.3. It is not Bitcoin HMAC-BIP32, not SLIP-0010, and not Byron scheme V1. The Trezor 24-word checksum bug is not implemented. CIP-3 distinguishes Icarus, Icarus-Trezor, and Ledger / BitBox02 master-key generation. This tool implements Icarus only. The same 24 words in one of those other schemes, or in a generic BIP-39 or SLIP-0010 wallet, are not a recovery of this address.

- The index is 32-bit little-endian.
- A hardened child HMACs the full 64-byte extended secret (`kL || kR`), not `kL` alone.
- The chain code is the right 32 bytes of a second HMAC-SHA512. It is not HMAC-SHA256.
- `kL' = kL + 8 * trunc28(ZL)` as a little-endian add (the top 4 bytes absorb carry only).
- `kR' = kR + ZR` modulo `2^256`.
- A soft public child is `A + [8 * trunc28(ZL)] * G`.

The search loop derives that public child and skips the child chain-code HMAC. The chain code is not an input to the address. A hit still builds the full checksummed Bech32 text and requires `starts_with`. The checksum is never skipped. `derive_soft` still computes the chain code so the self-test can compare it.

One 256-bit draw from `getrandom` produces the mnemonic. The payment index is a counter, not entropy. Workers receive the external-chain extended public key and the 28-byte stake hash. They do not receive the mnemonic or an extended private key. The chain code can derive child public keys, so it is not printed, and it is not a spending key. A hit is an index. The parent derives that private child again and checks it on the second stack before any wallet file exists.

All of the addresses in one account share the stake credential. A wallet that scans about 20 unused addresses will not discover a payment index at or above 20. The success text says when the index is inside that window and says `Recovery test: PENDING` when it is not. It also says the mnemonic alone is not sufficient for practical recovery through a standard wallet UI. This program does not click through a GUI restore. `recover` reproduces the address from the mnemonic and the recorded index on this machine.

## Base address

```text
payment verification key -- Blake2b-224 --> payment credential
stake verification key   -- Blake2b-224 --> stake credential
header || payment credential || stake credential
        -- Bech32, HRP addr (mainnet) or addr_test -->
addr1...
```

The hot loop compares the payment-hash prefix bits. Stake bits are not varied. Enterprise, pointer, script, reward, and Byron addresses are out of scope.

## Difficulty model

`analyze` computes the constrained bits from the header and the typed prefix. It does not special-case the string `zuzu`.

Report the fixed prefix, the legal second characters, the vanity-controlled characters, the search-bit count, the probability, and the 50/90/99 percent attempt counts. A probability of `32^n` is used only when every counted character is an independent 5-bit group. The second character of this address type is not.

## Commands

```text
ada-vanity self-test
ada-vanity analyze addr1qzuzu
ada-vanity analyze addr1qyzuzu
ada-vanity benchmark
ada-vanity generate addr1qyzuzu
ada-vanity generate addr1qyzuzu --threads 16
ada-vanity generate addr1qyzuzu --output ada-zuzu-wallet.json
ada-vanity verify ada-zuzu-wallet.json
ada-vanity export ada-zuzu-wallet.json
ada-vanity recover --index 3812744
```

`--network` is `mainnet` or `testnet`. The default is mainnet. `--threads N` accepts 1 through 256. The default is `available_parallelism`, clamped to that range. `--threads 0` fails. `--account` defaults to 0 and must be below `2^31`. Account 0 is the supported release mode. A nonzero account prints that it is advanced and was not restored in Daedalus, Yoroi, Lace, or Eternl by this tree. The default output path is `PREFIX-wallet.json`. An existing file is never overwritten. `recover` requires `--index`. The mnemonic is prompted with echo off. It is never a flag.

`generate` of an unreachable prefix prints the analyzer report and exits 1 before the self-test, before the search, and before any file is created. A reachable `generate` runs the self-test first and aborts if it fails. The public address is printed only after the encrypted file has been written. A failed write says the wallet was not saved and does not print the address.

There is no `--password`. The passphrase is read with echo disabled. A new passphrase must be at least 12 Unicode scalars and at most 1024 bytes. It is not trimmed. That minimum only stops accidents. `verify` and `export` still open a shorter passphrase so an existing file remains readable. Ctrl-C sets an atomic flag. It does not call `process::exit`.

`verify` decrypts, rebuilds both derivation stacks, checks the payment hash, the stake hash, and the Bech32 text, zeroizes the secrets, and prints only the public match report.

## Encrypted wallet

The file is versioned JSON (`deny_unknown_fields`) with `format_version`, `blockchain` (`cardano`), `network`, `address_type` (`base_keyhash_keyhash`), `public_address`, `derivation_scheme` (`cip-1852-icarus-v2`), `account_index`, `address_index`, `stake_index`, both derivation paths, the KDF name and parameters, salt, cipher name, nonce, and ciphertext.

The KDF is Argon2id, RFC 9106 section 4, second recommended option: 64 MiB, `t=3`, `p=4`, version `0x13`, a 16-byte salt, and a 32-byte output. The cipher is ChaCha20-Poly1305. Associated data binds the format, blockchain, network, address type, scheme, account, payment index, stake index, address, and both paths. The ciphertext is the magic `AV1`, the 32-byte BIP-39 entropy, and the three indexes. A second copy of the root private key is not stored.

The file is created with mode `0600` from the first moment it exists (`O_CREAT|O_EXCL`). Reads use `O_NOFOLLOW`. A same-directory temporary file is synced, then published with `hard_link` only while the destination is absent, and the directory is synced. A group- or world-writable parent directory produces a warning before the search and the same warning again immediately before the file is published. Prefer:

```text
umask 077
mkdir -m 700 ~/ada-wallets
```

The public writer rejects the cheap KDF used in tests (32 KiB, `t=1`, `p=1`). The public opener rejects a file that was not written with the production parameters.

## Memory

Secrets this crate owns are wrapped so they are zeroized on drop: entropy, the Icarus root, each derived child extended secret, the child `kL` and `kR` staging buffers, passphrases, the Argon2 output, and the HMAC-SHA512 digest after it has been copied into that wrapper. The Icarus root and each child extended secret are moved into `Xprv` as those wrappers. This crate does not offer a public constructor that accepts a plain 96-byte array. The wallet export text is built in one zeroizing string and is not copied into a second secret string. Scalar values that would otherwise be copied are erased in place.

That is not a guarantee on Fedora. A secret can remain in swap, a core dump, a register, an allocator freelist, a kernel buffer, or the memory of a process that can read another process. A compromised kernel or root account defeats zeroization. Before a long run, consider `ulimit -c 0` and encrypted swap or no swap. Do not keep the mnemonic in shell history.

## Two stacks

The search path is this crate's scheme-V2 derivation, `curve25519-dalek` for the point, the `blake2` crate for Blake2b-224, and this crate's Bech32. Before a wallet is trusted, `confirm_material` calls `ed25519-dalek` on the payment verification key and the stake verification key. The Icarus stretch uses `pbkdf2` and `sha2`.

The check path starts from those 96 root bytes and uses `ed25519-bip32` scheme V2, cryptoxide's Blake2b-224, and the `bech32` crate. The child public key, the credential, and the address text come from those libraries. Calling this crate's address function a second time is not the check. If the stacks disagree on the full CIP-1852 path, generation stops.

`ed25519-bip32` 0.4.3 links cryptoxide 0.6.5 for its own arithmetic. This crate's check hash uses cryptoxide 0.4.4 directly. `cargo deny` warns about that duplicate and does not fail the build.

## Known answers

`self-test` runs these and prints no secret. `generate` and `benchmark` run it before searching. `analyze` of an impossible prefix does not, so the rejection stays fast.

Public vectors, checked in full rather than by `starts_with("addr1")`:

- BIP-39 English checksum: 32 zero bytes encode the standard 24-word `abandon ... art` phrase. The Icarus root of that entropy is required to differ from `Mnemonic::to_seed("")`.
- CIP-19 type-00 mainnet, header `0x01`, 57 bytes:

```text
addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x
```

Payment hash `9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e`. Stake hash `337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251`. The testnet twin uses header `0x00` and HRP `addr_test`:

```text
addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs68faae
```

- The public Cardano Forum verification key `2adf6929fdfd736fd41ed8680d57ea9e8d55aa75529feb053c1a4a8fc0735250` hashes with Blake2b-224 to `4dd72a04967860d2721640ad36cc353be67702a6da31344ef8d32313`. Using that hash for both credentials produces:

```text
addr1q9xaw2syjeuxp5njzeq26dkvx5a7vacz5mdrzdzwlrfjxy6d6u4qf9ncvrf8y9jq45mvcdfmuems9fk6xy6ya7xnyvfsm5jwj3
```

`addr1q9` is inside the legal second-character window. The same hash is required from the `blake2` crate and from cryptoxide.

- CIP-0003 Icarus vectors for an empty passphrase and for the passphrase `foo` are compared against the published 96-byte roots inside `self-test`. The phrase and the roots are not printed, and they are not repeated here.
- CIP-0011 locks `m/1852'/1815'/0'/2/0` inside `self-test`, including the 96-byte extended stake key on both derivation stacks. The published mainnet reward address is `stake1uy8ykk8dzmeqxm05znz65nhr80m0k3gxnjvdngf8azh6sjc6hyh36`. The recovery phrase and the extended key are not printed, and they are not repeated here. Reward addresses are not a search mode.
- Both stacks must agree on `m/1852'/1815'/0'/0/0` and stake `m/1852'/1815'/0'/2/0` for that CIP-0003 root, and on a separate 24-word path from the all-zero entropy. There is no published address for that full path. The comparison failure does not print the root.

## Fedora: build online, then disconnect

This crate is pure Rust. `python3` is required for the PTY test. A normal Fedora machine installs Rust while it can reach the network:

```bash
sudo dnf install python3
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup component add rustfmt clippy
cargo install cargo-audit cargo-deny
```

This environment did not run `sudo dnf`. The compiler was rustc 1.99.0. A user-local GCC was on `PATH` because other trees in this workspace compile C. This crate did not need it. The exports used here, which are an environment workaround and not a normal Fedora install, were:

```bash
source "$HOME/.cargo/env"
export PATH="/home/code/.local/gccroot/usr/bin:$PATH"
export CC=/home/code/.local/gccroot/usr/bin/gcc
export AR=/home/code/.local/gccroot/usr/bin/ar
export C_INCLUDE_PATH=/home/code/.local/gccroot/usr/include
export LIBRARY_PATH=/home/code/.local/gccroot/usr/lib64
```

From this directory, while still online:

```bash
umask 077
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
cargo audit
cargo deny check
cargo build --release
```

Read `Cargo.toml` and `Cargo.lock` before you trust the binary. `cargo audit` and `cargo deny` download advisory data. The `ada-vanity` binary does not.

Then disconnect and use only the binary you just built:

```text
install dependencies online
        ↓
review source and Cargo.lock
        ↓
run known-answer tests
        ↓
run the security and dependency audit
        ↓
build the release binary
        ↓
disconnect networking
        ↓
self-test
        ↓
analyze addr1qzuzu
        ↓
analyze addr1qyzuzu
        ↓
generate the vanity wallet
        ↓
verify the encrypted file
        ↓
make encrypted offline backups
        ↓
only then consider funding
```

```bash
nmcli networking off
./target/release/ada-vanity self-test
./target/release/ada-vanity analyze addr1qzuzu
./target/release/ada-vanity analyze addr1qyzuzu
./target/release/ada-vanity benchmark
./target/release/ada-vanity generate addr1qyzuzu --threads 16
./target/release/ada-vanity verify addr1qyzuzu-wallet.json
```

`nmcli networking off` may require privileges. Unplugging the network is the same step. This environment did not run `nmcli networking off`. The release binary's dynamic symbol table was checked with `nm -u` instead. It does not list `connect`, `getaddrinfo`, or `sendto`. Generation does not open a socket: there is no node client, no Blockfrost client, no HTTP client, and no telemetry.

Copy the wallet file to offline storage. Keep the encryption passphrase with the same care as the file. Only after that backup opens, a disposable restore has been rehearsed at the recorded index, and a disposable spend has succeeded, consider funding the address.

## Benchmarks

Measured on this machine on 2026-10-08, release profile, after the self-test passed. 16 workers is what `available_parallelism` returned. It is not a claim about how many physical cores the machine has.

| Measurement | Result |
| --- | --- |
| One Icarus root (4096 iterations), once per wallet | 0.024 s |
| Miss path, one thread, criterion median | 119.94 µs (about 8,300 candidates/s) |
| Miss path, 16 workers, one-second CLI sample | 73,356 candidates/s |

The miss path is one soft public child, Blake2b-224, and the prefix-bit mask. Bech32 runs only after the mask matches. At the 16-worker sample, the expected `4,194,304` attempts for `addr1qyzuzu` are on the order of one minute, and the 50 percent count is shorter. That is one measurement. It is not a schedule. A different CPU, a debug build, or a machine under load will differ.

The root stretch is hundreds of times one attempt, which is why the search does not draw a new mnemonic per index. The security consequence is the one in "What you must back up": one mnemonic, one shared stake credential, and a payment index that must be recorded because a 20-address scan will miss a high index.

## Threat model

Assume the following can go wrong. The tests catch some of them. They do not catch a compromised machine.

- A compromised Fedora install, a malicious Cargo crate, or a compromised Rust toolchain can replace the generator. Read the lockfile and build the binary yourself. `publish = false`. This crate is not on crates.io.
- OS CSPRNG failure. Wallet entropy comes from `getrandom`. A failed draw aborts and writes no wallet. The payment index is not used as entropy.
- RNG substitutes. There is no `rand` crate in `Cargo.lock`. `rand_core` 0.6.4 is present as a trait used by the hash and cipher crates. Candidates are not drawn from it.
- A BIP32-Ed25519 bug, a wrong clamp, or a V1/SLIP-0010 mix-up. The CIP-0003 vectors lock the root. Both stacks must agree on the child public key, the chain code, and the address before a file is written. Agreement does not prove both are right about an untested property.
- The wrong network header, or an enterprise address used because it is easier to grind. Known answers require mainnet header `0x01` and testnet header `0x00`, and the encoder has no enterprise path.
- A Blake2b-224 bug, including a 32-byte hash or SHA-256. The Forum vector locks 28 bytes on both hash crates.
- A Bech32 bug: wrong charset, mixed case accepted, checksum skipped, or a full address used as a prefix. Those are rejected. A mask hit is re-encoded and must still start with the typed prefix.
- A wrong HD path: Bitcoin coin type 0, a hardened payment index, change role 1, or a stake index other than 0. The path is stored in the wallet. Indexes at or above 20 are reported as outside a 20-address scan.
- Treating the address as sufficient to recover the wallet. `export` says it is not.
- An optimized matcher false positive. The full checksummed text is required, and the second stack must rebuild it.
- Mnemonic or passphrase exposure through a flag, a log, a panic payload, or the terminal. Secrets are not command-line arguments. `Debug` redacts entropy. `export` is the only printer.
- Swap, core dumps, allocator copies, and a hostile root account. See "Memory".
- A weak encryption passphrase. Twelve characters is not a strength measure. Argon2id raises the cost of guessing; it does not make a short passphrase strong.
- Backup loss, or a backup that cannot be decrypted. Rehearse `verify` and `export` on a disposable file before funding.
- Linkability. Addresses that share a stake credential are connected. A memorable prefix makes the connection easier to recognize.
- Supply chain. Lockfile review, `cargo audit`, and `cargo deny` are the checks this tree ran. They are not a proof that every transitive crate is benign.
- Independent verification limits. The second stack is another Rust implementation of the same specifications. `cardano-cli` and `cardano-address` were not executed. A bug shared by both Rust stacks would not be caught here.
- Side channels. Scalar timing and cache leaks are outside this version.

## Dependencies

Direct dependencies, as resolved for this tree:

| Crate | Version |
| --- | --- |
| `argon2` | 0.5.3 |
| `base64` | 0.22.1 |
| `bech32` | 0.11.1 |
| `bip39` | 2.2.2 |
| `blake2` | 0.10.6 |
| `chacha20poly1305` | 0.10.1 |
| `clap` | 4.6.7 |
| `cryptoxide` | 0.4.4 |
| `ctrlc` | 3.5.2 |
| `curve25519-dalek` | 4.1.3 |
| `ed25519-bip32` | 0.4.3 |
| `ed25519-dalek` | 2.2.0 |
| `generic-array` | 0.14.7 |
| `getrandom` | 0.2.17 |
| `hmac` | 0.12.1 |
| `pbkdf2` | 0.12.2 |
| `rpassword` | 7.5.4 |
| `serde` / `serde_json` | 1.0.229 / 1.0.151 |
| `sha2` | 0.10.9 |
| `thiserror` | 2.0.21 |
| `zeroize` | 1.9.1 |

`criterion` 0.5.1 is a dev-dependency. It is not linked into the release binary. `ed25519-bip32` 0.4.3 additionally resolves cryptoxide 0.6.5. `bip39` brings `bitcoin_hashes` 0.14.101 for its own checksum. Wallet entropy does not pass through that hash as a BIP-39 seed.

`Cargo.lock` contains no crate named `rand`. On this cargo, `cargo tree -i rand` exits 101 with "did not match any packages" because the name is absent. That is the empty result. `rand_core` 0.6.4 remains, as described above.

The advisory run is historical (2026-10-08). Run `cargo audit` and `cargo deny check` again on the day you build.

## References

- [CIP-19](https://github.com/cardano-foundation/CIPs/blob/master/CIP-0019/README.md), Cardano addresses. Header, Bech32, and the type-00 test vectors.
- [CIP-1852](https://github.com/cardano-foundation/CIPs/blob/master/CIP-1852/README.md), HD wallet path `m/1852'/1815'/account'/role/index`.
- [CIP-0003](https://github.com/cardano-foundation/CIPs/blob/master/CIP-0003/Icarus.md), Icarus master key. PBKDF2 inputs and the clamp. The phrase and the 96-byte roots stay in `self-test`. Icarus-Trezor and Ledger / BitBox02 are different master-key schemes and are not implemented.
- [CIP-0011](https://github.com/cardano-foundation/CIPs/blob/master/CIP-0011/README.md), staking-key derivation vector for `m/1852'/1815'/0'/2/0`. The phrase and the 96-byte extended key stay in `self-test`. The public reward address is named above.
- SLIP-0044 coin type 1815 for Cardano. Testnet is a different address header, not coin type 1, in this Shelley scheme.
- BIP-39 mnemonic checksum. This tool does not use the BIP-39 2048-iteration seed.
- BIP-173 Bech32. Cardano addresses exceed its 90-character limit; `bech32` 0.11 allows the length CIP-19 requires.
- RFC 9106, Argon2id parameter choice used for the wallet (section 4, second option).
- Khovratovich and Law, "BIP32-Ed25519: Hierarchical Deterministic Keys over a Non-linear Keyspace". Cardano scheme V2 follows the IOG `ed25519-bip32` 0.4.3 implementation of that construction.
- The public Cardano Forum verification-key example locked in `self-test` (key, Blake2b-224, and `addr1q9...` address above).

## What this tree did not verify

- `cardano-cli` was not executed. It was not installed.
- `cardano-address` was not executed. It was not installed.
- No ADA was sent or received. No transaction was submitted. The release binary has no node client and no Blockfrost client.
- No multi-million-attempt search was run to completion, and nothing was funded.
- A high payment index was not restored by clicking through Daedalus, Yoroi, Lace, or Eternl. `recover` rebuilds the address locally from the mnemonic and the index. That is not a GUI restore. The gap-limit warning is the sequential scan rule, checked here by recording the index.
- A nonzero account was not restored in Daedalus, Yoroi, Lace, or Eternl. Account 0 is the normal mode.
- `nmcli networking off` was not run. `nm -u` on the release binary did not list `connect`, `getaddrinfo`, or `sendto`.
- Side channels, swap, core dumps, and a compromised kernel remain outside the tests.
- The difficulty figures are the bit model. They assume Blake2b-224 of these child keys behaves like independent uniform prefix bits. That is not a uniformity proof.
- The second stack is another Rust library, not Cardano's Haskell tools. A bug shared by both Rust implementations would pass these tests.
- Passing the tests in this file does not make the software appropriate for storing a substantial amount of ADA.
- The GitHub repository is the distribution source. This crate is not published to crates.io. `publish = false`.

## Checks in this session

Toolchain: rustc 1.99.0 (`b940084d7`, 2026-09-28), cargo 1.99.0 (`5f94df478`, 2026-08-27). Date: 2026-10-08.

- `cargo fmt --all -- --check` passed before this public source release.
- `cargo clippy --locked --all-targets --all-features -- -D warnings` passed before this public source release.
- `cargo test --locked --all -- --test-threads=8` passed before this public source release: 12 library tests, 2 binary tests, 11 CLI tests, 1 PTY test. The CIP-0011 stake vector is inside the library self-test. `recover` was checked against the public 24-word all-zero BIP-39 vector, including a PTY run that keeps echo off and does not print the phrase.
- `cargo audit --deny warnings` loaded 1294 advisories and scanned 143 crate dependencies. It exited 0 and printed no vulnerabilities or warnings.
- `cargo deny check advisories bans licenses sources` reported advisories, bans, licenses, and sources ok. Warnings, which do not fail the check: duplicate `cryptoxide` 0.4.4 (this crate) and 0.6.5 (via `ed25519-bip32`); duplicate `syn` 2.0.119 and 3.0.6; the ISC license allowance was not encountered.
- `cargo tree -i rand --locked` found no package named `rand`.
- `cargo build --release --locked` finished before this public source release, and `./target/release/ada-vanity self-test` printed `Cryptographic self-tests: PASS`.
- `nm -u` on that release binary did not list `connect`, `getaddrinfo`, or `sendto`.
- The criterion miss-path median was 119.94 µs. The 16-worker CLI sample was 73,356 candidates/s. One Icarus root was 0.024 s. Those timings are from before the recovery changes. The miss-path arithmetic is the same.

## License

MIT OR Apache-2.0. See `LICENSE-MIT`, `LICENSE-APACHE`, and `NOTICE`.
