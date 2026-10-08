// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compare the search stack with the independent stack before a wallet is kept.

use ed25519_dalek::VerifyingKey;
use zeroize::Zeroizing;

use crate::ada::bech32;
use crate::ada::{
    derive_wallet, entropy_from_mnemonic, icarus_root, payment_path, stake_path, HARDENED_BIT,
    STAKE_INDEX,
};
use crate::error::Error;
use crate::independent;
use crate::wallet::WalletMaterial;

/// Public result of `recover_address`. It has no mnemonic and no extended key.
#[derive(Debug)]
pub struct Recovered {
    pub address: String,
    pub network: crate::ada::Network,
    pub account: u32,
    pub payment_index: u32,
    pub payment_path: String,
    pub stake_path: String,
}

/// Rebuild one Shelley base address from a 24-word English mnemonic.
///
/// The Icarus passphrase is empty. Both derivation stacks must agree, and
/// `ed25519-dalek` must accept both verification keys. The phrase is not
/// returned.
pub fn recover_address(
    phrase: &str,
    network: crate::ada::Network,
    account: u32,
    payment_index: u32,
) -> Result<Recovered, Error> {
    if account >= HARDENED_BIT || payment_index >= HARDENED_BIT {
        return Err(Error::Index);
    }
    let wide = entropy_from_mnemonic(phrase).map_err(|_| Error::Mnemonic)?;
    if wide.len() != 32 {
        return Err(Error::Mnemonic);
    }
    let mut entropy = Zeroizing::new([0u8; 32]);
    entropy.copy_from_slice(&wide);
    drop(wide);
    let material = WalletMaterial::hd(network, entropy, account, payment_index);
    let derived = derive_wallet(material.entropy(), network, account, payment_index)?;
    confirm_material(&material, &derived.address)?;
    Ok(Recovered {
        address: derived.address,
        network,
        account,
        payment_index,
        payment_path: material.payment_path(),
        stake_path: material.stake_path(),
    })
}

pub fn confirm_material(material: &WalletMaterial, address: &str) -> Result<(), Error> {
    if material.stake_index() != STAKE_INDEX || material.payment_index() >= crate::ada::HARDENED_BIT
    {
        return Err(Error::VerificationFailed);
    }
    let ours = derive_wallet(
        material.entropy(),
        material.network(),
        material.account(),
        material.payment_index(),
    )?;
    let root = icarus_root(material.entropy(), b"")?;
    let theirs = independent::reconstruct(
        root.as_bytes(),
        material.network(),
        material.account(),
        material.payment_index(),
    )?;
    if ours.address != address
        || theirs.address != address
        || ours.payment != theirs.payment
        || ours.stake != theirs.stake
        || ours.payment_public != theirs.payment_public
        || ours.stake_public != theirs.stake_public
    {
        return Err(Error::VerificationFailed);
    }
    if VerifyingKey::from_bytes(&ours.payment_public).is_err()
        || VerifyingKey::from_bytes(&ours.stake_public).is_err()
    {
        return Err(Error::VerificationFailed);
    }
    if payment_path(material.account(), material.payment_index()) != material.payment_path()
        || stake_path(material.account()) != material.stake_path()
    {
        return Err(Error::VerificationFailed);
    }
    let (hrp, raw) = bech32::decode(address).map_err(|_| Error::VerificationFailed)?;
    let expected_header = material.network().header();
    if hrp != material.network().hrp() || raw.len() != 57 || raw[0] != expected_header {
        return Err(Error::VerificationFailed);
    }
    if raw[1..29] != ours.payment || raw[29..] != ours.stake {
        return Err(Error::VerificationFailed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::recover_address;
    use crate::ada::{derive_wallet, mnemonic_from_entropy, Network};
    use crate::error::Error;

    #[test]
    fn recover_matches_both_stacks_for_the_abandon_vector() {
        let phrase = mnemonic_from_entropy(&[0u8; 32]).unwrap();
        for (network, account, index) in [
            (Network::Mainnet, 0, 0u32),
            (Network::Mainnet, 0, 20),
            (Network::Mainnet, 1, 3),
            (Network::Testnet, 0, 7),
        ] {
            let recovered = recover_address(phrase.as_str(), network, account, index).unwrap();
            let direct = derive_wallet(&[0u8; 32], network, account, index).unwrap();
            assert_eq!(recovered.address, direct.address);
            assert_eq!(
                recovered.payment_path,
                format!("m/1852'/1815'/{account}'/0/{index}")
            );
            assert_eq!(
                recovered.stake_path,
                format!("m/1852'/1815'/{account}'/2/0")
            );
            let prefix = match network {
                Network::Mainnet => "addr1",
                Network::Testnet => "addr_test1",
            };
            assert!(recovered.address.starts_with(prefix));
        }
    }

    #[test]
    fn recover_rejects_a_phrase_that_is_not_24_english_words() {
        let phrase = mnemonic_from_entropy(&[0u8; 32]).unwrap();
        let short = bip39::Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        assert_eq!(
            recover_address(short.to_string().as_str(), Network::Mainnet, 0, 0).unwrap_err(),
            Error::Mnemonic
        );
        let mut words: Vec<&str> = phrase.as_str().split_whitespace().collect();
        assert_eq!(words.len(), 24);
        words[23] = "abandon";
        let bad = words.join(" ");
        assert_eq!(
            recover_address(&bad, Network::Mainnet, 0, 0).unwrap_err(),
            Error::Mnemonic
        );
        assert_eq!(
            recover_address("", Network::Mainnet, 0, 0).unwrap_err(),
            Error::Mnemonic
        );
        assert_eq!(
            recover_address(phrase.as_str(), Network::Mainnet, 0, 1 << 31).unwrap_err(),
            Error::Index
        );
        assert_eq!(
            recover_address(phrase.as_str(), Network::Mainnet, 1 << 31, 0).unwrap_err(),
            Error::Index
        );
    }
}
