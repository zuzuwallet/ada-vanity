// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! CIP-1852 keys on the Icarus master key and Cardano BIP32-Ed25519 scheme V2.
//!
//! The root is PBKDF2-HMAC-SHA512, 4096 iterations, 96-byte output. The
//! password is the Icarus passphrase (empty in this tool). The salt is the
//! BIP-39 entropy, not the string `"mnemonic"`, and the iteration count is
//! not BIP-39's 2048. The left 32 bytes are then clamped the CIP-0003 way:
//! clear the low 3 bits, clear the top bit, clear the third-highest bit, and
//! set the second-highest bit.
//!
//! Child derivation follows IOG `ed25519-bip32` scheme V2, which is what
//! Daedalus, Yoroi, Lace, Eternl, and cardano-serialization-lib use:
//!
//! - the index is 32-bit little-endian
//! - a hardened child HMACs the full 64-byte extended secret, not `kL` alone
//! - the chain code is the right half of a second HMAC-SHA512, not HMAC-SHA256
//! - `kL' = kL + 8 * trunc28(ZL)` as a little-endian 256-bit add
//! - `kR' = kR + ZR` as a little-endian add modulo 2^256
//! - a soft public child is `A + [8 * trunc28(ZL)] * G`
//!
//! This is not Bitcoin BIP-32, not SLIP-0010, and not Byron scheme V1.
//! The Trezor 24-word checksum bug is not implemented. Entropy is passed
//! without an extra checksum byte.

use bip39::{Language, Mnemonic};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;
use zeroize::Zeroize;

use crate::ada::address::{credential_hash, HASH_LEN};
use crate::error::Error;
use crate::secret::SecretString;

pub const HARDENED_BIT: u32 = 0x8000_0000;
pub const PURPOSE: u32 = 1852;
pub const COIN_TYPE: u32 = 1815;
pub const ROLE_EXTERNAL: u32 = 0;
pub const ROLE_STAKE: u32 = 2;
pub const STAKE_INDEX: u32 = 0;
/// Exclusive end of the soft payment-index space. Indexes `0 .. 2^31`.
pub const PAYMENT_INDEX_LIMIT: u32 = HARDENED_BIT;
pub const GAP_LIMIT: u32 = 20;

type HmacSha512 = Hmac<Sha512>;

/// 96-byte extended secret: `kL || kR || chain code`. `Debug` redacts it.
pub struct Xprv {
    bytes: zeroize::Zeroizing<[u8; 96]>,
}

impl std::fmt::Debug for Xprv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Xprv([redacted])")
    }
}

impl Xprv {
    /// Moves an already protected 96-byte extended secret into `Xprv`.
    fn from_zeroizing(bytes: zeroize::Zeroizing<[u8; 96]>) -> Result<Self, Error> {
        verify_scalar_bits(&bytes)?;
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &[u8; 96] {
        &self.bytes
    }

    pub fn public_key(&self) -> Result<[u8; 32], Error> {
        let mut kl = [0u8; 32];
        kl.copy_from_slice(&self.bytes[..32]);
        let point = public_from_scalar(&kl);
        kl.zeroize();
        point
    }

    pub fn extended_public(&self) -> Result<Xpub, Error> {
        let public = self.public_key()?;
        let mut chain = [0u8; 32];
        chain.copy_from_slice(&self.bytes[64..]);
        Ok(Xpub { public, chain })
    }

    pub fn derive(&self, index: u32) -> Result<Self, Error> {
        Self::from_zeroizing(derive_private(self.as_bytes(), index)?)
    }
}

/// Account external-chain public key. The chain code derives child public
/// keys, so `Debug` redacts the whole value. It is not a spending key.
#[derive(Clone)]
pub struct Xpub {
    public: [u8; 32],
    chain: [u8; 32],
}

impl std::fmt::Debug for Xpub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Xpub([redacted])")
    }
}

impl Drop for Xpub {
    fn drop(&mut self) {
        self.chain.zeroize();
        self.public.zeroize();
    }
}

impl Xpub {
    pub(crate) fn from_parts(public: [u8; 32], chain: [u8; 32]) -> Self {
        Self { public, chain }
    }

    pub fn public_key(&self) -> &[u8; 32] {
        &self.public
    }

    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain
    }

    /// Soft child, including its chain code. Hardened indexes are rejected.
    pub fn derive_soft(&self, index: u32) -> Result<Self, Error> {
        if index >= HARDENED_BIT {
            return Err(Error::Index);
        }
        let (public, chain) = derive_public(&self.public, &self.chain, index, true)?;
        Ok(Self { public, chain })
    }

    /// Soft child verification key only. The address does not depend on the
    /// child chain code, so the search skips that HMAC.
    pub fn child_public(&self, index: u32) -> Result<[u8; 32], Error> {
        if index >= HARDENED_BIT {
            return Err(Error::Index);
        }
        let (public, _chain) = derive_public(&self.public, &self.chain, index, false)?;
        Ok(public)
    }
}

pub fn mnemonic_from_entropy(entropy: &[u8; 32]) -> Result<SecretString, Error> {
    let mnemonic = Mnemonic::from_entropy(entropy).map_err(|_| Error::Rng)?;
    Ok(SecretString::new(mnemonic.to_string()))
}

pub fn entropy_from_mnemonic(phrase: &str) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase)
        .map_err(|_| Error::VerificationFailed)?;
    Ok(zeroize::Zeroizing::new(mnemonic.to_entropy()))
}

/// Icarus root. `passphrase` is the mnemonic passphrase, which is empty for
/// the wallets this tool writes.
pub fn icarus_root(entropy: &[u8], passphrase: &[u8]) -> Result<Xprv, Error> {
    if entropy.is_empty() || entropy.len() > 64 {
        return Err(Error::InvalidKey);
    }
    let mut stretched = zeroize::Zeroizing::new([0u8; 96]);
    pbkdf2_hmac::<Sha512>(passphrase, entropy, 4096, stretched.as_mut());
    stretched[0] &= 0b1111_1000;
    stretched[31] &= 0b0001_1111;
    stretched[31] |= 0b0100_0000;
    Xprv::from_zeroizing(stretched)
}

pub fn harden(index: u32) -> Result<u32, Error> {
    if index >= HARDENED_BIT {
        Err(Error::Index)
    } else {
        Ok(index | HARDENED_BIT)
    }
}

pub fn account_key(root: &Xprv, account: u32) -> Result<Xprv, Error> {
    let account = harden(account)?;
    let purpose = root.derive(harden(PURPOSE)?)?;
    let coin = purpose.derive(harden(COIN_TYPE)?)?;
    coin.derive(account)
}

pub fn external_chain(account: &Xprv) -> Result<Xpub, Error> {
    let child = account.derive(ROLE_EXTERNAL)?;
    child.extended_public()
}

pub fn stake_credential(account: &Xprv) -> Result<[u8; HASH_LEN], Error> {
    let role = account.derive(ROLE_STAKE)?;
    let key = role.derive(STAKE_INDEX)?;
    let public = key.public_key()?;
    Ok(credential_hash(&public))
}

pub fn payment_credential(external: &Xpub, index: u32) -> Result<[u8; HASH_LEN], Error> {
    let public = external.child_public(index)?;
    Ok(credential_hash(&public))
}

pub fn payment_path(account: u32, index: u32) -> String {
    format!("m/1852'/1815'/{account}'/0/{index}")
}

pub fn stake_path(account: u32) -> String {
    format!("m/1852'/1815'/{account}'/2/0")
}

pub fn derive_wallet(
    entropy: &[u8; 32],
    network: crate::ada::network::Network,
    account: u32,
    payment_index: u32,
) -> Result<DerivedWallet, Error> {
    if payment_index >= HARDENED_BIT {
        return Err(Error::Index);
    }
    let root = icarus_root(entropy, b"")?;
    let account_key = account_key(&root, account)?;
    let stake_key = account_key.derive(ROLE_STAKE)?.derive(STAKE_INDEX)?;
    let stake_public = stake_key.public_key()?;
    let stake = credential_hash(&stake_public);
    let external = external_chain(&account_key)?;
    let payment_key = external.derive_soft(payment_index)?;
    let payment_public = *payment_key.public_key();
    let payment = credential_hash(&payment_public);
    let address = crate::ada::address::base_address(network, &payment, &stake)?;
    Ok(DerivedWallet {
        address,
        payment,
        stake,
        payment_public,
        stake_public,
        account,
        payment_index,
    })
}

pub struct DerivedWallet {
    pub address: String,
    pub payment: [u8; HASH_LEN],
    pub stake: [u8; HASH_LEN],
    /// Payment verification key. It is public. `confirm_material` asks
    /// `ed25519-dalek` to accept it before a wallet is trusted.
    pub payment_public: [u8; 32],
    /// Stake verification key at role 2, index 0. It is public.
    pub stake_public: [u8; 32],
    pub account: u32,
    pub payment_index: u32,
}

fn verify_scalar_bits(bytes: &[u8; 96]) -> Result<(), Error> {
    let first = bytes[0];
    let last = bytes[31];
    if (last & 0b1100_0000) != 0b0100_0000 || (first & 0b0000_0111) != 0 {
        return Err(Error::InvalidKey);
    }
    Ok(())
}

fn public_from_scalar(kl: &[u8; 32]) -> Result<[u8; 32], Error> {
    let mut scalar = Scalar::from_bytes_mod_order(*kl);
    let point = EdwardsPoint::mul_base(&scalar);
    scalar.zeroize();
    Ok(point.compress().to_bytes())
}

fn derive_private(parent: &[u8; 96], index: u32) -> Result<zeroize::Zeroizing<[u8; 96]>, Error> {
    let mut kl = zeroize::Zeroizing::new([0u8; 32]);
    let mut kr = zeroize::Zeroizing::new([0u8; 32]);
    let mut chain = zeroize::Zeroizing::new([0u8; 32]);
    kl.copy_from_slice(&parent[..32]);
    kr.copy_from_slice(&parent[32..64]);
    chain.copy_from_slice(&parent[64..]);
    let serial = index.to_le_bytes();
    let (z, right_mac) = if index >= HARDENED_BIT {
        let extended = &parent[..64];
        (
            hmac_sha512(&chain[..], &[&[0x00], extended, &serial])?,
            hmac_sha512(&chain[..], &[&[0x01], extended, &serial])?,
        )
    } else {
        let public = public_from_scalar(&kl)?;
        (
            hmac_sha512(&chain[..], &[&[0x02], &public, &serial])?,
            hmac_sha512(&chain[..], &[&[0x03], &public, &serial])?,
        )
    };
    let mut zl = zeroize::Zeroizing::new([0u8; 32]);
    let mut zr = zeroize::Zeroizing::new([0u8; 32]);
    zl.copy_from_slice(&z[..32]);
    zr.copy_from_slice(&z[32..]);
    let left = add_28_mul8(&kl, &zl);
    let right = add_256bits(&kr, &zr);
    let mut out = zeroize::Zeroizing::new([0u8; 96]);
    out[..32].copy_from_slice(&left[..]);
    out[32..64].copy_from_slice(&right[..]);
    out[64..].copy_from_slice(&right_mac[32..]);
    Ok(out)
}

fn derive_public(
    public: &[u8; 32],
    chain: &[u8; 32],
    index: u32,
    with_chain_code: bool,
) -> Result<([u8; 32], [u8; 32]), Error> {
    let serial = index.to_le_bytes();
    let z = hmac_sha512(chain, &[&[0x02], public, &serial])?;
    let mut zl = [0u8; 32];
    zl.copy_from_slice(&z[..32]);
    let tweak = add_28_mul8(&[0u8; 32], &zl);
    let child_public = point_plus(public, &tweak)?;
    let mut child_chain = [0u8; 32];
    if with_chain_code {
        let right_mac = hmac_sha512(chain, &[&[0x03], public, &serial])?;
        child_chain.copy_from_slice(&right_mac[32..]);
    }
    zl.zeroize();
    Ok((child_public, child_chain))
}

fn point_plus(public: &[u8; 32], tweak: &[u8; 32]) -> Result<[u8; 32], Error> {
    let parent = CompressedEdwardsY(*public)
        .decompress()
        .ok_or(Error::InvalidKey)?;
    let mut scalar = Scalar::from_bytes_mod_order(*tweak);
    let delta = EdwardsPoint::mul_base(&scalar);
    scalar.zeroize();
    Ok((parent + delta).compress().to_bytes())
}

fn hmac_sha512(key: &[u8], parts: &[&[u8]]) -> Result<zeroize::Zeroizing<[u8; 64]>, Error> {
    let mut mac = HmacSha512::new_from_slice(key).map_err(|_| Error::InvalidKey)?;
    for part in parts {
        mac.update(part);
    }
    let mut digest = mac.finalize().into_bytes();
    let mut out = zeroize::Zeroizing::new([0u8; 64]);
    out.copy_from_slice(&digest);
    digest.zeroize();
    Ok(out)
}

/// `kL + 8 * trunc28(zl)`, little-endian. Bytes 28..32 of `zl` are not multiplied.
pub(crate) fn add_28_mul8(left: &[u8; 32], right: &[u8; 32]) -> zeroize::Zeroizing<[u8; 32]> {
    let mut carry = 0u16;
    let mut out = zeroize::Zeroizing::new([0u8; 32]);
    for index in 0..28 {
        let sum = u16::from(left[index]) + (u16::from(right[index]) << 3) + carry;
        out[index] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    for index in 28..32 {
        let sum = u16::from(left[index]) + carry;
        out[index] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    out
}

/// Little-endian add modulo 2^256. The final carry is discarded.
pub(crate) fn add_256bits(left: &[u8; 32], right: &[u8; 32]) -> zeroize::Zeroizing<[u8; 32]> {
    let mut carry = 0u16;
    let mut out = zeroize::Zeroizing::new([0u8; 32]);
    for index in 0..32 {
        let sum = u16::from(left[index]) + u16::from(right[index]) + carry;
        out[index] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    out
}
