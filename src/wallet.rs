// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Encrypted wallet file.
//!
//! The secret is an Argon2id key (RFC 9106 section 4, second recommended
//! option: 64 MiB, t=3, p=4, version 0x13, 16-byte salt, 32-byte output) and
//! ChaCha20-Poly1305. Associated data binds the address, network, scheme,
//! account, payment index, and stake index.
//!
//! The file is created with mode `0600` via `O_CREAT|O_EXCL` and `O_NOFOLLOW`
//! on read. `hard_link` publishes it only when the destination is still absent.
//! `confirm_material` runs before any ciphertext is written.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Block, Params, Version};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::ada::{mnemonic_from_entropy, payment_path, stake_path, Network, STAKE_INDEX};
use crate::error::Error;
use crate::hexutil;
use crate::secret::SecretString;
use crate::verify::confirm_material;

const FORMAT_VERSION: u32 = 1;
const BLOCKCHAIN: &str = "cardano";
const ADDRESS_TYPE: &str = "base_keyhash_keyhash";
const SCHEME: &str = "cip-1852-icarus-v2";
const KDF_NAME: &str = "argon2id";
const KDF_VERSION: u32 = 19;
const CIPHER_NAME: &str = "chacha20poly1305";

/// Shown after a successful search and on `export` and `recover`.
pub const RECOVERY_NOTICE_LINE_1: &str =
    "The mnemonic alone is not sufficient for practical recovery through a standard wallet UI.";
pub const RECOVERY_NOTICE_LINE_2: &str = "Back up the exact payment derivation index/path.";
pub const ICARUS_RECOVERY_SCHEME: &str = "Cardano Icarus / CIP-3";
pub const SCHEME_INCOMPATIBILITY: &str = "\
This 24-word phrase is NOT guaranteed to restore to the same keys using:
- Trezor's 24-word Cardano derivation
- Ledger / BitBox02 master-key derivation
- generic BIP-39 wallets
- SLIP-0010 wallets";
const AAD_PREFIX: &[u8] = b"ada-vanity-wallet-v1\0";
const MAX_WALLET_BYTES: u64 = 1_048_576;
const MAX_PLAINTEXT: usize = 4096;
const MAX_MEMORY_KIB: u32 = 1_048_576;
const MAX_ITERATIONS: u32 = 100;
const MAX_PARALLELISM: u32 = 16;
const TAG_LEN: usize = 16;
/// Linux `O_NOFOLLOW`. Do not follow a symlink.
const O_NOFOLLOW: i32 = 0x20000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfParams {
    pub const PRODUCTION: Self = Self {
        memory_kib: 65_536,
        iterations: 3,
        parallelism: 4,
    };

    pub fn is_production(self) -> bool {
        self == Self::PRODUCTION
    }

    pub(crate) fn within_caps(self) -> bool {
        self.iterations >= 1
            && self.iterations <= MAX_ITERATIONS
            && self.parallelism >= 1
            && self.parallelism <= MAX_PARALLELISM
            && self.memory_kib >= self.parallelism.saturating_mul(8)
            && self.memory_kib <= MAX_MEMORY_KIB
    }
}

/// BIP-39 entropy for one CIP-1852 account. `Debug` redacts the entropy.
pub struct WalletMaterial {
    network: Network,
    entropy: Zeroizing<[u8; 32]>,
    account: u32,
    payment_index: u32,
    stake_index: u32,
}

impl std::fmt::Debug for WalletMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletMaterial")
            .field("network", &self.network)
            .field("entropy", &"[redacted]")
            .field("account", &self.account)
            .field("payment_index", &self.payment_index)
            .field("stake_index", &self.stake_index)
            .finish()
    }
}

impl WalletMaterial {
    pub(crate) fn hd(
        network: Network,
        entropy: Zeroizing<[u8; 32]>,
        account: u32,
        payment_index: u32,
    ) -> Self {
        Self {
            network,
            entropy,
            account,
            payment_index,
            stake_index: STAKE_INDEX,
        }
    }

    pub fn network(&self) -> Network {
        self.network
    }
    pub fn account(&self) -> u32 {
        self.account
    }
    pub fn payment_index(&self) -> u32 {
        self.payment_index
    }
    pub fn stake_index(&self) -> u32 {
        self.stake_index
    }
    pub fn payment_path(&self) -> String {
        payment_path(self.account, self.payment_index)
    }
    pub fn stake_path(&self) -> String {
        stake_path(self.account)
    }
    pub(crate) fn entropy(&self) -> &[u8; 32] {
        &self.entropy
    }
}

pub struct OpenedWallet {
    pub address: String,
    pub network: Network,
    pub payment_path: String,
    pub stake_path: String,
    pub account: u32,
    pub payment_index: u32,
    pub(crate) material: WalletMaterial,
}

impl std::fmt::Debug for OpenedWallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedWallet")
            .field("address", &self.address)
            .field("network", &self.network)
            .field("payment_path", &self.payment_path)
            .field("material", &self.material)
            .finish()
    }
}

pub const MIN_NEW_PASSPHRASE_CHARS: usize = 12;

pub fn check_passphrase(passphrase: &str) -> Result<(), Error> {
    if passphrase.is_empty() || passphrase.len() > 1024 {
        Err(Error::Passphrase)
    } else {
        Ok(())
    }
}

pub fn check_new_passphrase(passphrase: &str) -> Result<(), Error> {
    check_passphrase(passphrase)?;
    if passphrase.chars().count() < MIN_NEW_PASSPHRASE_CHARS {
        Err(Error::Passphrase)
    } else {
        Ok(())
    }
}

pub fn write_encrypted_wallet(
    path: &Path,
    passphrase: &str,
    material: &WalletMaterial,
    address: &str,
) -> Result<(), Error> {
    check_new_passphrase(passphrase)?;
    write_encrypted_wallet_with_kdf(path, passphrase, material, address, &KdfParams::PRODUCTION)
}

pub(crate) fn write_encrypted_wallet_with_kdf(
    path: &Path,
    passphrase: &str,
    material: &WalletMaterial,
    address: &str,
    kdf: &KdfParams,
) -> Result<(), Error> {
    check_passphrase(passphrase)?;
    if !kdf.within_caps() {
        return Err(Error::WalletFormat);
    }
    if path.exists() {
        return Err(Error::OutputExists);
    }
    confirm_material(material, address)?;
    let meta = public_meta(material, address);
    let plaintext = encode_plaintext(material)?;
    let mut salt = Zeroizing::new([0u8; 16]);
    let mut nonce = Zeroizing::new([0u8; 12]);
    getrandom::getrandom(salt.as_mut_slice()).map_err(|_| Error::Rng)?;
    getrandom::getrandom(nonce.as_mut_slice()).map_err(|_| Error::Rng)?;
    let ciphertext = encrypt(passphrase, &plaintext, &meta, kdf, &salt, &nonce)?;
    let file = WalletFile {
        format_version: FORMAT_VERSION,
        blockchain: BLOCKCHAIN.to_owned(),
        network: meta.network,
        address_type: ADDRESS_TYPE.to_owned(),
        public_address: meta.address,
        derivation_scheme: SCHEME.to_owned(),
        account_index: material.account(),
        address_index: material.payment_index(),
        stake_index: material.stake_index(),
        payment_path: meta.payment_path,
        stake_path: meta.stake_path,
        kdf: KDF_NAME.to_owned(),
        kdf_parameters: KdfFile {
            version: KDF_VERSION,
            memory_kib: kdf.memory_kib,
            iterations: kdf.iterations,
            parallelism: kdf.parallelism,
            output_length: 32,
        },
        salt: STANDARD.encode(salt.as_slice()),
        cipher: CIPHER_NAME.to_owned(),
        nonce: STANDARD.encode(nonce.as_slice()),
        ciphertext: STANDARD.encode(&ciphertext),
    };
    let mut json = serde_json::to_string_pretty(&file).map_err(|_| Error::WalletFormat)?;
    json.push('\n');
    write_private_file(path, json.as_bytes())
}

pub fn export_wallet_text(opened: &OpenedWallet) -> Result<SecretString, Error> {
    confirm_material(&opened.material, &opened.address)?;
    let phrase = mnemonic_from_entropy(opened.material.entropy())?;
    let mut text = Zeroizing::new(String::new());
    text.push_str("Mnemonic:\n");
    text.push_str(phrase.as_str());
    text.push_str("\nIcarus passphrase:\nempty\n");
    text.push_str("Derivation scheme:\n");
    text.push_str(SCHEME);
    text.push_str("\nRecovery scheme:\n");
    text.push_str(ICARUS_RECOVERY_SCHEME);
    text.push('\n');
    text.push_str(SCHEME_INCOMPATIBILITY);
    text.push_str("\nPayment derivation path:\n");
    text.push_str(&opened.payment_path);
    text.push_str("\nStake derivation path:\n");
    text.push_str(&opened.stake_path);
    text.push('\n');
    text.push_str(RECOVERY_NOTICE_LINE_1);
    text.push('\n');
    text.push_str(RECOVERY_NOTICE_LINE_2);
    text.push_str(
        "\nThe address is not a backup. A wallet that scans about 20 unused addresses will not discover a high payment index.\nThe encryption passphrase is not the Icarus passphrase.\n",
    );
    Ok(SecretString::from_zeroizing(text))
}

pub fn open_and_verify(path: &Path, passphrase: &str) -> Result<OpenedWallet, Error> {
    open_and_verify_inner(path, passphrase, true)
}

#[cfg(test)]
pub(crate) fn open_and_verify_with_kdf(
    path: &Path,
    passphrase: &str,
) -> Result<OpenedWallet, Error> {
    open_and_verify_inner(path, passphrase, false)
}

fn open_and_verify_inner(
    path: &Path,
    passphrase: &str,
    require_production: bool,
) -> Result<OpenedWallet, Error> {
    check_passphrase(passphrase)?;
    let file = read_wallet(path)?;
    if file.format_version != FORMAT_VERSION
        || file.blockchain != BLOCKCHAIN
        || file.address_type != ADDRESS_TYPE
        || file.derivation_scheme != SCHEME
        || file.kdf != KDF_NAME
        || file.cipher != CIPHER_NAME
        || file.kdf_parameters.version != KDF_VERSION
        || file.kdf_parameters.output_length != 32
        || file.stake_index != STAKE_INDEX
    {
        return Err(Error::WalletFormat);
    }
    let kdf = KdfParams {
        memory_kib: file.kdf_parameters.memory_kib,
        iterations: file.kdf_parameters.iterations,
        parallelism: file.kdf_parameters.parallelism,
    };
    let accepted = if require_production {
        kdf.is_production()
    } else {
        kdf.within_caps()
    };
    if !accepted {
        return Err(Error::WalletFormat);
    }
    let network = Network::parse(&file.network)?;
    let meta = Meta {
        address: file.public_address.clone(),
        network: file.network.clone(),
        payment_path: file.payment_path.clone(),
        stake_path: file.stake_path.clone(),
        account: file.account_index,
        payment_index: file.address_index,
        stake_index: file.stake_index,
    };
    if meta.payment_path != payment_path(meta.account, meta.payment_index)
        || meta.stake_path != stake_path(meta.account)
    {
        return Err(Error::WalletFormat);
    }
    let salt = decode_len::<16>(&file.salt)?;
    let nonce = decode_len::<12>(&file.nonce)?;
    let ciphertext = STANDARD
        .decode(&file.ciphertext)
        .map_err(|_| Error::WalletFormat)?;
    if ciphertext.len() < TAG_LEN || ciphertext.len() > MAX_PLAINTEXT + TAG_LEN {
        return Err(Error::WalletFormat);
    }
    let plaintext = decrypt(passphrase, &ciphertext, &meta, &kdf, &salt, &nonce)?;
    let material = decode_plaintext(&plaintext, &meta, network)?;
    confirm_material(&material, &meta.address)?;
    Ok(OpenedWallet {
        address: meta.address,
        network,
        payment_path: material.payment_path(),
        stake_path: material.stake_path(),
        account: material.account(),
        payment_index: material.payment_index(),
        material,
    })
}

struct Meta {
    address: String,
    network: String,
    payment_path: String,
    stake_path: String,
    account: u32,
    payment_index: u32,
    stake_index: u32,
}

fn public_meta(material: &WalletMaterial, address: &str) -> Meta {
    Meta {
        address: address.to_owned(),
        network: material.network().name().to_owned(),
        payment_path: material.payment_path(),
        stake_path: material.stake_path(),
        account: material.account(),
        payment_index: material.payment_index(),
        stake_index: material.stake_index(),
    }
}

fn encode_plaintext(material: &WalletMaterial) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut out = Vec::with_capacity(47);
    out.extend_from_slice(b"AV1");
    out.extend_from_slice(material.entropy());
    out.extend_from_slice(&material.account().to_be_bytes());
    out.extend_from_slice(&material.payment_index().to_be_bytes());
    out.extend_from_slice(&material.stake_index().to_be_bytes());
    if out.len() > MAX_PLAINTEXT {
        return Err(Error::WalletFormat);
    }
    Ok(Zeroizing::new(out))
}

fn decode_plaintext(bytes: &[u8], meta: &Meta, network: Network) -> Result<WalletMaterial, Error> {
    if bytes.len() != 47 || &bytes[..3] != b"AV1" {
        return Err(Error::WalletFormat);
    }
    if network.name() != meta.network {
        return Err(Error::VerificationFailed);
    }
    let mut entropy = Zeroizing::new([0u8; 32]);
    entropy.copy_from_slice(&bytes[3..35]);
    let account = u32::from_be_bytes(bytes[35..39].try_into().map_err(|_| Error::WalletFormat)?);
    let payment = u32::from_be_bytes(bytes[39..43].try_into().map_err(|_| Error::WalletFormat)?);
    let stake = u32::from_be_bytes(bytes[43..47].try_into().map_err(|_| Error::WalletFormat)?);
    if account != meta.account || payment != meta.payment_index || stake != meta.stake_index {
        return Err(Error::VerificationFailed);
    }
    Ok(WalletMaterial::hd(network, entropy, account, payment))
}

fn encrypt(
    passphrase: &str,
    plaintext: &[u8],
    meta: &Meta,
    kdf: &KdfParams,
    salt: &[u8; 16],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, Error> {
    let derived = derive_key(passphrase.as_bytes(), salt, kdf)?;
    let cipher =
        ChaCha20Poly1305::new_from_slice(derived.as_slice()).map_err(|_| Error::WalletFormat)?;
    let nonce = Nonce::from_slice(nonce.as_slice());
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad_bytes(meta),
            },
        )
        .map_err(|_| Error::Decrypt)
}

fn decrypt(
    passphrase: &str,
    ciphertext: &[u8],
    meta: &Meta,
    kdf: &KdfParams,
    salt: &[u8; 16],
    nonce: &[u8; 12],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let derived = derive_key(passphrase.as_bytes(), salt, kdf)?;
    let cipher =
        ChaCha20Poly1305::new_from_slice(derived.as_slice()).map_err(|_| Error::WalletFormat)?;
    let nonce = Nonce::from_slice(nonce.as_slice());
    let plain = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: &aad_bytes(meta),
            },
        )
        .map_err(|_| Error::Decrypt)?;
    Ok(Zeroizing::new(plain))
}

fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    kdf: &KdfParams,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let params = Params::new(kdf.memory_kib, kdf.iterations, kdf.parallelism, Some(32))
        .map_err(|_| Error::WalletFormat)?;
    let block_count = params.block_count();
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut memory = Zeroizing::new(vec![Block::default(); block_count].into_boxed_slice());
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into_with_memory(passphrase, salt, key.as_mut(), &mut *memory)
        .map_err(|_| Error::WalletFormat)?;
    Ok(key)
}

fn aad_bytes(meta: &Meta) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(AAD_PREFIX);
    for part in [
        FORMAT_VERSION.to_string(),
        BLOCKCHAIN.to_owned(),
        meta.network.clone(),
        ADDRESS_TYPE.to_owned(),
        SCHEME.to_owned(),
        meta.account.to_string(),
        meta.payment_index.to_string(),
        meta.stake_index.to_string(),
        meta.address.clone(),
        meta.payment_path.clone(),
        meta.stake_path.clone(),
    ] {
        out.extend_from_slice(part.as_bytes());
        out.push(0);
    }
    out
}

fn decode_len<const N: usize>(text: &str) -> Result<[u8; N], Error> {
    let bytes = STANDARD.decode(text).map_err(|_| Error::WalletFormat)?;
    if bytes.len() != N {
        return Err(Error::WalletFormat);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn read_wallet(path: &Path) -> Result<WalletFile, Error> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|err| map_wallet_open_error(path, err))?;
    let meta = file.metadata().map_err(|err| Error::io(path, err))?;
    if meta.len() > MAX_WALLET_BYTES || !meta.is_file() {
        return Err(Error::WalletFormat);
    }
    let mut text = String::new();
    Read::by_ref(&mut file)
        .take(MAX_WALLET_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|err| Error::io(path, err))?;
    if text.len() as u64 > MAX_WALLET_BYTES {
        return Err(Error::WalletFormat);
    }
    serde_json::from_str(&text).map_err(|_| Error::WalletFormat)
}

fn map_wallet_open_error(path: &Path, err: std::io::Error) -> Error {
    if err.raw_os_error() == Some(40) {
        Error::Io(format!(
            "{}: wallet path must be a regular file",
            path.display()
        ))
    } else {
        Error::io(path, err)
    }
}

fn write_private_file(dest: &Path, contents: &[u8]) -> Result<(), Error> {
    if dest.exists() {
        return Err(Error::OutputExists);
    }
    let parent = parent_dir(dest);
    if !parent.is_dir() {
        return Err(Error::OutputDir);
    }
    let file_name = dest.file_name().ok_or(Error::OutputDir)?;
    let mut suffix = [0u8; 8];
    getrandom::getrandom(&mut suffix).map_err(|_| Error::Rng)?;
    let tmp_path = parent.join(format!(
        ".{}.tmp.{}",
        file_name.to_string_lossy(),
        hexutil::encode_upper(&suffix)
    ));
    let mut guard = RemoveOnDrop {
        path: tmp_path.clone(),
        armed: true,
    };
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp_path)
        .map_err(|err| Error::io(&tmp_path, err))?;
    let mode = file
        .metadata()
        .map_err(|err| Error::io(&tmp_path, err))?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        return Err(Error::Io(format!(
            "{}: created file was not private",
            tmp_path.display()
        )));
    }
    file.write_all(contents)
        .map_err(|err| Error::io(&tmp_path, err))?;
    file.sync_all().map_err(|err| Error::io(&tmp_path, err))?;
    drop(file);
    match fs::hard_link(&tmp_path, dest) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(Error::OutputExists);
        }
        Err(err) => return Err(Error::io(dest, err)),
    }
    fs::remove_file(&tmp_path).map_err(|err| Error::io(&tmp_path, err))?;
    guard.armed = false;
    sync_directory(dest, parent)?;
    Ok(())
}

fn sync_directory(dest: &Path, parent: &Path) -> Result<(), Error> {
    let dir = File::open(parent).map_err(|err| {
        Error::Io(format!(
            "{}: wallet file was written, but opening its directory for sync failed: {err}. It may not survive a power loss.",
            dest.display()
        ))
    })?;
    dir.sync_all().map_err(|err| {
        Error::Io(format!(
            "{}: wallet file was written, but syncing its directory failed: {err}. It may not survive a power loss.",
            dest.display()
        ))
    })
}

fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

struct RemoveOnDrop {
    path: PathBuf,
    armed: bool,
}

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletFile {
    format_version: u32,
    blockchain: String,
    network: String,
    address_type: String,
    public_address: String,
    derivation_scheme: String,
    account_index: u32,
    address_index: u32,
    stake_index: u32,
    payment_path: String,
    stake_path: String,
    kdf: String,
    kdf_parameters: KdfFile,
    salt: String,
    cipher: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KdfFile {
    version: u32,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    output_length: u32,
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        check_new_passphrase, export_wallet_text, open_and_verify, open_and_verify_with_kdf,
        write_encrypted_wallet, write_encrypted_wallet_with_kdf, KdfParams, WalletMaterial,
        ICARUS_RECOVERY_SCHEME, RECOVERY_NOTICE_LINE_1, RECOVERY_NOTICE_LINE_2,
        SCHEME_INCOMPATIBILITY,
    };
    use crate::ada::{derive_wallet, Network};
    use crate::error::Error;

    fn scratch(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("ada-vanity-{label}-{nanos}"));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn sample() -> (WalletMaterial, String) {
        let entropy = zeroize::Zeroizing::new([7u8; 32]);
        let derived = derive_wallet(&entropy, Network::Mainnet, 0, 3).unwrap();
        let material = WalletMaterial::hd(Network::Mainnet, entropy, 0, 3);
        (material, derived.address)
    }

    fn cheap() -> KdfParams {
        KdfParams {
            memory_kib: 32,
            iterations: 1,
            parallelism: 1,
        }
    }

    #[test]
    fn cheap_round_trip_is_private_and_public_opener_rejects_it() {
        let dir = scratch("wallet");
        let path = dir.join("sample-wallet.json");
        let (material, address) = sample();
        write_encrypted_wallet_with_kdf(&path, "short-pass", &material, &address, &cheap())
            .unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let opened = open_and_verify_with_kdf(&path, "short-pass").unwrap();
        assert_eq!(opened.address, address);
        assert_eq!(opened.payment_index, 3);
        assert!(open_and_verify(&path, "short-pass").is_err());
        let again =
            write_encrypted_wallet_with_kdf(&path, "short-pass", &material, &address, &cheap());
        assert_eq!(again.err(), Some(Error::OutputExists));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn wrong_passphrase_and_tampering_fail() {
        let dir = scratch("tamper");
        let path = dir.join("wallet.json");
        let (material, address) = sample();
        write_encrypted_wallet_with_kdf(&path, "correct horse", &material, &address, &cheap())
            .unwrap();
        assert!(matches!(
            open_and_verify_with_kdf(&path, "wrong passphrase"),
            Err(Error::Decrypt)
        ));
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 2;
        bytes[last] ^= 0x01;
        fs::write(&path, &bytes).unwrap();
        assert!(open_and_verify_with_kdf(&path, "correct horse").is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn public_writer_rejects_a_short_passphrase() {
        let (material, address) = sample();
        let dir = scratch("public");
        let path = dir.join("wallet.json");
        assert_eq!(
            write_encrypted_wallet(&path, "short", &material, &address),
            Err(Error::Passphrase)
        );
        assert!(!path.exists());
        assert!(check_new_passphrase("twelve chars!").is_ok());
        assert!(check_new_passphrase("short").is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn debug_redacts_entropy() {
        let (material, _) = sample();
        let text = format!("{material:?}");
        assert!(text.contains("redacted"));
        assert!(!text.contains("070707"));
    }

    #[test]
    fn export_names_icarus_and_the_recovery_limit() {
        let dir = scratch("export-text");
        let path = dir.join("wallet.json");
        let (material, address) = sample();
        write_encrypted_wallet_with_kdf(&path, "correct horse", &material, &address, &cheap())
            .unwrap();
        let opened = open_and_verify_with_kdf(&path, "correct horse").unwrap();
        let secret = export_wallet_text(&opened).unwrap();
        let text = secret.as_str();
        assert!(text.contains(ICARUS_RECOVERY_SCHEME));
        assert!(text.contains(SCHEME_INCOMPATIBILITY));
        assert!(text.contains("Trezor"));
        assert!(text.contains("Ledger / BitBox02"));
        assert!(text.contains("SLIP-0010"));
        assert!(text.contains(RECOVERY_NOTICE_LINE_1));
        assert!(text.contains(RECOVERY_NOTICE_LINE_2));
        assert!(text.contains("Icarus passphrase:\nempty"));
        assert!(!text.contains("070707"));
        let _ = fs::remove_dir_all(dir);
    }
}
