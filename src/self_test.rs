// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Known-answer tests. A failure aborts generation. The CIP-0003 phrase and
//! master key, and the CIP-0011 phrase and stake key, are compared here and
//! are not printed.

use bip39::{Language, Mnemonic};
use ed25519_dalek::VerifyingKey;
use zeroize::Zeroize;

use crate::ada::bech32;
use crate::ada::{
    account_key, analyze, attempts_for_probability, base_address, base_bytes, credential_hash,
    derive_wallet, earliest_zuzu, entropy_from_mnemonic, external_chain, icarus_root, payment_path,
    require_searchable, stake_path, Network, CONFIRMATION_THRESHOLD, HASH_LEN,
};
use crate::error::Error;
use crate::hexutil;
use crate::independent;

const CIP19_MAINNET: &str = "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x";
const CIP19_TESTNET: &str = "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs68faae";
const CIP19_PAYMENT: &str = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e";
const CIP19_STAKE: &str = "337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251";
const FORUM_KEY: &str = "2adf6929fdfd736fd41ed8680d57ea9e8d55aa75529feb053c1a4a8fc0735250";
const FORUM_ADDRESS: &str = "addr1q9xaw2syjeuxp5njzeq26dkvx5a7vacz5mdrzdzwlrfjxy6d6u4qf9ncvrf8y9jq45mvcdfmuems9fk6xy6ya7xnyvfsm5jwj3";
const FORUM_HASH: &str = "4dd72a04967860d2721640ad36cc353be67702a6da31344ef8d32313";

pub fn run_self_tests() -> Result<(), Error> {
    bip39_vector()?;
    icarus_vectors()?;
    cip11_stake_vector()?;
    cip19_vectors()?;
    forum_vector()?;
    prefix_vectors()?;
    stacks_agree()?;
    dalek_accepts_payment_key()?;
    Ok(())
}

fn bip39_vector() -> Result<(), Error> {
    let entropy = [0u8; 32];
    let mnemonic =
        Mnemonic::from_entropy(&entropy).map_err(|_| Error::SelfTest("BIP-39 entropy"))?;
    let phrase = mnemonic.to_string();
    let expected = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    if phrase != expected {
        return Err(Error::SelfTest("BIP-39 24-word checksum"));
    }
    let parsed = Mnemonic::parse_in_normalized(Language::English, expected)
        .map_err(|_| Error::SelfTest("BIP-39 parse"))?;
    if parsed.to_entropy() != entropy {
        return Err(Error::SelfTest("BIP-39 entropy round trip"));
    }
    let bip39_seed = parsed.to_seed("");
    let icarus = icarus_root(&entropy, b"")?;
    if icarus.as_bytes()[..64] == bip39_seed {
        return Err(Error::SelfTest("Icarus root matched BIP-39 to_seed"));
    }
    Ok(())
}

fn icarus_vectors() -> Result<(), Error> {
    // CIP-0003 Icarus.md. This phrase is a published test vector.
    let phrase = "eight country switch draw meat scout mystery blade tip drift useless good keep usage title";
    let entropy = entropy_from_mnemonic(phrase)?;
    let empty = icarus_root(&entropy, b"")?;
    let with_passphrase = icarus_root(&entropy, b"foo")?;
    let empty_expected = decode_exact::<96>("c065afd2832cd8b087c4d9ab7011f481ee1e0721e78ea5dd609f3ab3f156d245d176bd8fd4ec60b4731c3918a2a72a0226c0cd119ec35b47e4d55884667f552a23f7fdcd4a10c6cd2c7393ac61d877873e248f417634aa3d812af327ffe9d620")?;
    let foo_expected = decode_exact::<96>("70531039904019351e1afb361cd1b312a4d0565d4ff9f8062d38acf4b15cce41d7b5738d9c893feea55512a3004acb0d222c35d3e3d5cde943a15a9824cbac59443cf67e589614076ba01e354b1a432e0e6db3b59e37fc56b5fb0222970a010e")?;
    if empty.as_bytes() != &empty_expected || with_passphrase.as_bytes() != &foo_expected {
        return Err(Error::SelfTest("CIP-0003 Icarus master key"));
    }
    if empty.as_bytes()[0] & 0b0000_0111 != 0 || empty.as_bytes()[31] & 0b1110_0000 != 0b0100_0000 {
        return Err(Error::SelfTest("CIP-0003 clamp"));
    }
    Ok(())
}

fn cip11_stake_vector() -> Result<(), Error> {
    // CIP-0011 staking-key vector. The phrase is 15 words, so this does not
    // call `derive_wallet` (that function takes 32-byte entropy).
    let phrase = "prevent company field green slot measure chief hero apple task eagle sunset endorse dress seed";
    let entropy = entropy_from_mnemonic(phrase)?;
    if entropy.len() == 32 {
        return Err(Error::SelfTest("CIP-0011 phrase length"));
    }
    let root = icarus_root(&entropy, b"")?;
    let account = account_key(&root, 0)?;
    let stake = account.derive(2)?.derive(0)?;
    let expected = decode_exact::<96>("b8ab42f1aacbcdb3ae858e3a3df88142b3ed27a2d3f432024e0d943fc1e597442d57545d84c8db2820b11509d944093bc605350e60c533b8886a405bd59eed6dcf356648fe9e9219d83e989c8ff5b5b337e2897b6554c1ab4e636de791fe5427")?;
    if stake.as_bytes() != &expected {
        return Err(Error::SelfTest("CIP-0011 stake extended key"));
    }
    let mut root_bytes = *root.as_bytes();
    let master = match ed25519_bip32::XPrv::from_bytes_verified(root_bytes) {
        Ok(key) => key,
        Err(_) => {
            root_bytes.zeroize();
            return Err(Error::SelfTest("CIP-0011 root"));
        }
    };
    root_bytes.zeroize();
    let scheme = ed25519_bip32::DerivationScheme::V2;
    let theirs = master
        .derive(scheme, crate::ada::harden(1852)?)
        .derive(scheme, crate::ada::harden(1815)?)
        .derive(scheme, crate::ada::harden(0)?)
        .derive(scheme, 2)
        .derive(scheme, 0);
    if theirs.as_ref() != stake.as_bytes().as_slice() {
        return Err(Error::SelfTest("CIP-0011 independent stake key"));
    }
    let public = stake.public_key()?;
    if cryptoxide_hash(&public) != credential_hash(&public) {
        return Err(Error::SelfTest("CIP-0011 stake hash"));
    }
    let mut raw = [0u8; 29];
    raw[0] = 0xe1;
    raw[1..].copy_from_slice(&credential_hash(&public));
    let address = bech32::encode("stake", &raw)?;
    const CIP11_REWARD: &str = "stake1uy8ykk8dzmeqxm05znz65nhr80m0k3gxnjvdngf8azh6sjc6hyh36";
    if address != CIP11_REWARD {
        return Err(Error::SelfTest("CIP-0011 reward address"));
    }
    let hrp = ::bech32::Hrp::parse("stake").map_err(|_| Error::SelfTest("CIP-0011 hrp"))?;
    let external = ::bech32::encode::<::bech32::Bech32>(hrp, &raw)
        .map_err(|_| Error::SelfTest("CIP-0011 external bech32"))?;
    if external != CIP11_REWARD {
        return Err(Error::SelfTest("CIP-0011 reward address check stack"));
    }
    Ok(())
}

fn cip19_vectors() -> Result<(), Error> {
    let payment = decode_exact::<HASH_LEN>(CIP19_PAYMENT)?;
    let stake = decode_exact::<HASH_LEN>(CIP19_STAKE)?;
    let main = base_address(Network::Mainnet, &payment, &stake)?;
    let test = base_address(Network::Testnet, &payment, &stake)?;
    if main != CIP19_MAINNET || test != CIP19_TESTNET {
        return Err(Error::SelfTest("CIP-19 Bech32"));
    }
    if base_bytes(Network::Mainnet, &payment, &stake)[0] != 0x01
        || base_bytes(Network::Testnet, &payment, &stake)[0] != 0x00
    {
        return Err(Error::SelfTest("network header"));
    }
    let (hrp, raw) = bech32::decode(CIP19_MAINNET).map_err(|_| Error::SelfTest("CIP-19 decode"))?;
    if hrp != "addr"
        || raw.len() != 57
        || raw[0] != 0x01
        || raw[1..29] != payment
        || raw[29..] != stake
    {
        return Err(Error::SelfTest("CIP-19 payload"));
    }
    let (test_hrp, test_raw) =
        bech32::decode(CIP19_TESTNET).map_err(|_| Error::SelfTest("CIP-19 testnet decode"))?;
    if test_hrp != "addr_test" || test_raw[0] != 0x00 {
        return Err(Error::SelfTest("CIP-19 testnet payload"));
    }
    Ok(())
}

fn forum_vector() -> Result<(), Error> {
    let key = decode_exact::<32>(FORUM_KEY)?;
    let hash = credential_hash(&key);
    let expected = decode_exact::<HASH_LEN>(FORUM_HASH)?;
    if hash != expected {
        return Err(Error::SelfTest("Forum Blake2b-224"));
    }
    let address = base_address(Network::Mainnet, &hash, &hash)?;
    if address != FORUM_ADDRESS || !address.starts_with("addr1q9") {
        return Err(Error::SelfTest("Forum base address"));
    }
    if cryptoxide_hash(&key) != hash {
        return Err(Error::SelfTest("cryptoxide Blake2b-224"));
    }
    Ok(())
}

fn prefix_vectors() -> Result<(), Error> {
    let impossible = analyze(Network::Mainnet, "addr1qzuzu")?;
    if impossible.reachable || require_searchable(&impossible).is_ok() {
        return Err(Error::SelfTest("addr1qzuzu was treated as reachable"));
    }
    if !impossible.reason.contains("y, 9, x, or 8")
        || impossible.fixed_prefix != "addr1q"
        || impossible.type_fixed != "addr1q"
    {
        return Err(Error::SelfTest("second-character set"));
    }
    let targets = ["addr1qyzuzu", "addr1q9zuzu", "addr1qxzuzu", "addr1q8zuzu"];
    let documented = earliest_zuzu(Network::Mainnet);
    for (index, prefix) in targets.iter().enumerate() {
        if documented[index] != *prefix {
            return Err(Error::SelfTest("earliest zuzu list"));
        }
        let analysis = analyze(Network::Mainnet, prefix)?;
        if !analysis.reachable
            || analysis.exceeds_index_space
            || analysis.search_bits != 22
            || analysis.expected != Some(4_194_304)
            || analysis.median != Some(2_907_270)
            || analysis.p90 != Some(9_657_741)
            || analysis.p99 != Some(19_315_482)
            || analysis.vanity != "zuzu"
            || Some(analysis.fixed_prefix.as_str()) != prefix.strip_suffix("zuzu")
            || analysis.needs_large_search_confirmation()
        {
            return Err(Error::SelfTest("zuzu difficulty"));
        }
        require_searchable(&analysis)?;
    }
    let short = analyze(Network::Mainnet, "addr1qy")?;
    if short.search_bits != 2 || short.expected != Some(4) || !short.reachable {
        return Err(Error::SelfTest("addr1qy difficulty"));
    }
    let implied = analyze(Network::Mainnet, "addr1q")?;
    if implied.expected != Some(1) || implied.search_bits != 0 {
        return Err(Error::SelfTest("addr1q is not type-implied"));
    }
    if attempts_for_probability(4_194_304, 0.5) != 2_907_270 {
        return Err(Error::SelfTest("median rounding"));
    }
    let y_not = analyze(Network::Mainnet, "addr1qr")?;
    if y_not.reachable {
        return Err(Error::SelfTest("r is not a mainnet second character"));
    }
    let test_z = analyze(Network::Testnet, "addr_test1qz")?;
    if !test_z.reachable || test_z.search_bits != 2 {
        return Err(Error::SelfTest("testnet second character"));
    }
    if analyze(Network::Mainnet, "addr1qYzuzu").is_ok() {
        return Err(Error::SelfTest("mixed case was accepted"));
    }
    for bad in ["addr11q", "addr1qb", "addr1qi", "addr1qo"] {
        if analyze(Network::Mainnet, bad).is_ok() {
            return Err(Error::SelfTest("Bech32 alphabet"));
        }
    }
    if analyze(Network::Mainnet, CIP19_MAINNET).is_ok() {
        return Err(Error::SelfTest("full address was accepted as a prefix"));
    }
    let wide = analyze(Network::Mainnet, "addr1qyzuzuzu")?;
    if !wide.exceeds_index_space || wide.search_bits != 32 {
        return Err(Error::SelfTest("index-space limit"));
    }
    let _ = CONFIRMATION_THRESHOLD;
    let payment = decode_exact::<HASH_LEN>(CIP19_PAYMENT)?;
    let qx = analyze(Network::Mainnet, "addr1qx")?;
    let qy = analyze(Network::Mainnet, "addr1qy")?;
    if !qx.mask.matches(&payment) || qy.mask.matches(&payment) {
        return Err(Error::SelfTest("prefix mask"));
    }
    let address = base_address(
        Network::Mainnet,
        &payment,
        &decode_exact::<HASH_LEN>(CIP19_STAKE)?,
    )?;
    if !address.starts_with("addr1qx") || address.starts_with("addr1qy") {
        return Err(Error::SelfTest("optimized match disagreed with Bech32"));
    }
    Ok(())
}

fn stacks_agree() -> Result<(), Error> {
    let phrase = "eight country switch draw meat scout mystery blade tip drift useless good keep usage title";
    let entropy = entropy_from_mnemonic(phrase)?;
    let root = icarus_root(&entropy, b"")?;
    let account = account_key(&root, 0)?;
    let external = external_chain(&account)?;
    let stake_private = {
        let role = account.derive(2)?;
        let key = role.derive(0)?;
        key.public_key()?
    };
    let stake_public = {
        let role = account.extended_public()?.derive_soft(2)?;
        let key = role.derive_soft(0)?;
        *key.public_key()
    };
    if stake_private != stake_public {
        return Err(Error::SelfTest("soft public derivation"));
    }
    for index in [0u32, 1, 20, 1_000] {
        let from_public = external.derive_soft(index)?;
        let from_private = {
            let role = account.derive(0)?;
            let key = role.derive(index)?;
            key.extended_public()?
        };
        if from_public.public_key() != from_private.public_key()
            || from_public.chain_code() != from_private.chain_code()
        {
            return Err(Error::SelfTest("public and private children differ"));
        }
        if external
            .derive_soft(index | crate::ada::HARDENED_BIT)
            .is_ok()
        {
            return Err(Error::SelfTest("hardened payment index was accepted"));
        }
    }
    for network in [Network::Mainnet, Network::Testnet] {
        for index in [0u32, 1, 20] {
            let payment_public = external.child_public(index)?;
            let payment = credential_hash(&payment_public);
            let stake = crate::ada::stake_credential(&account)?;
            let address = base_address(network, &payment, &stake)?;
            let theirs = independent::reconstruct(root.as_bytes(), network, 0, index)?;
            if address != theirs.address
                || payment != theirs.payment
                || stake != theirs.stake
                || payment_public != theirs.payment_public
                || stake_public != theirs.stake_public
            {
                return Err(Error::SelfTest("the two derivation stacks disagree"));
            }
            if payment_path(0, index) != independent::payment_path_text(0, index)
                || stake_path(0) != independent::stake_path_text(0)
            {
                return Err(Error::SelfTest("derivation path text"));
            }
            if network == Network::Mainnet && !address.starts_with("addr1q") {
                return Err(Error::SelfTest("mainnet address prefix"));
            }
            if network == Network::Testnet && !address.starts_with("addr_test1q") {
                return Err(Error::SelfTest("testnet address prefix"));
            }
        }
    }
    let abandon = [0u8; 32];
    let abandon_root = icarus_root(&abandon, b"")?;
    let ours = derive_wallet(&abandon, Network::Mainnet, 0, 0)?;
    let theirs = independent::reconstruct(abandon_root.as_bytes(), Network::Mainnet, 0, 0)?;
    if ours.address != theirs.address
        || ours.payment != theirs.payment
        || ours.stake != theirs.stake
        || ours.payment_public != theirs.payment_public
        || ours.stake_public != theirs.stake_public
    {
        return Err(Error::SelfTest("24-word stacks disagree"));
    }
    VerifyingKey::from_bytes(&ours.payment_public)
        .map_err(|_| Error::SelfTest("ed25519-dalek payment"))?;
    VerifyingKey::from_bytes(&ours.stake_public)
        .map_err(|_| Error::SelfTest("ed25519-dalek stake"))?;
    Ok(())
}

fn dalek_accepts_payment_key() -> Result<(), Error> {
    let phrase = "eight country switch draw meat scout mystery blade tip drift useless good keep usage title";
    let entropy = entropy_from_mnemonic(phrase)?;
    let root = icarus_root(&entropy, b"")?;
    let account = account_key(&root, 0)?;
    let external = external_chain(&account)?;
    let child = external.derive_soft(0)?;
    VerifyingKey::from_bytes(child.public_key()).map_err(|_| Error::SelfTest("ed25519-dalek"))?;
    Ok(())
}

fn cryptoxide_hash(bytes: &[u8]) -> [u8; 28] {
    use cryptoxide::hashing::blake2b::Blake2b;
    Blake2b::<224>::new().update(bytes).finalize()
}

fn decode_exact<const N: usize>(text: &str) -> Result<[u8; N], Error> {
    let bytes = hexutil::decode(text).map_err(|_| Error::SelfTest("hex"))?;
    if bytes.len() != N {
        return Err(Error::SelfTest("hex length"));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::run_self_tests;

    #[test]
    fn known_answers_pass() {
        run_self_tests().unwrap();
    }
}
