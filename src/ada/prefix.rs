// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! What a Shelley base-address prefix can actually constrain.
//!
//! A mainnet type-0 address is 57 bytes: header `0x01`, a 28-byte payment
//! hash, and a 28-byte stake hash. Bech32 packs those bytes most-significant
//! bit first into 5-bit groups.
//!
//! Header `0x01` is `0000 0001`.
//!
//! - Group 0 is `00000`, charset index 0, the character `q`. Every mainnet
//!   key-hash/key-hash base address starts with `addr1q`.
//! - Group 1 is the header's remaining `001` plus the top two bits of the
//!   payment hash. Charset indexes 4, 5, 6, and 7 are `y`, `9`, `x`, and `8`.
//! - `z` is index 2, bits `00010`. Its top three bits are `000`, not `001`.
//!
//! `addr1qzuzu` is therefore impossible. The earliest complete `zuzu` is the
//! four characters after one legal second character.

use crate::ada::bech32::{charset_index, CHARSET};
use crate::ada::network::Network;
use crate::error::Error;

/// A full type-0 payload is 57 bytes, 456 bits, 92 five-bit groups.
const PAYLOAD_GROUPS: usize = 92;
const HEADER_BITS: u32 = 8;
const PAYMENT_BITS: u32 = 224;
const STAKE_BIT: u32 = HEADER_BITS + PAYMENT_BITS;
/// One account has `2^31` soft payment indexes. A rarer prefix is refused.
const INDEX_SPACE_BITS: u32 = 31;
pub const CONFIRMATION_THRESHOLD: u64 = 1_000_000_000;

/// Leading payment-hash bits required by a reachable prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashMask {
    pub bits: u32,
    pub expected: [u8; 28],
}

impl HashMask {
    pub fn matches(&self, hash: &[u8; 28]) -> bool {
        let full = (self.bits / 8) as usize;
        if hash.len() < 28 || full > 28 {
            return false;
        }
        if hash[..full] != self.expected[..full] {
            return false;
        }
        let remainder = (self.bits % 8) as u8;
        if remainder == 0 {
            return true;
        }
        let mask = 0xffu8 << (8 - remainder);
        (hash[full] & mask) == (self.expected[full] & mask)
    }
}

#[derive(Clone, Debug)]
pub struct Analysis {
    pub network: Network,
    pub prefix: String,
    pub reachable: bool,
    pub exceeds_index_space: bool,
    pub reason: String,
    pub type_fixed: String,
    pub fixed_prefix: String,
    pub vanity: String,
    pub legal_second: [char; 4],
    pub search_bits: u32,
    pub expected: Option<u64>,
    pub median: Option<u64>,
    pub p90: Option<u64>,
    pub p99: Option<u64>,
    pub mask: HashMask,
}

impl Analysis {
    pub fn report(&self) -> String {
        let mut out = String::new();
        push(&mut out, "Cardano Vanity Target Analyzer");
        out.push('\n');
        push(&mut out, "Network:");
        push(&mut out, self.network.label());
        out.push('\n');
        push(&mut out, "Address type:");
        push(&mut out, "Base (key hash / key hash)");
        out.push('\n');
        push(&mut out, "Requested:");
        push(&mut out, &self.prefix);
        out.push('\n');
        push(&mut out, "Type-fixed prefix:");
        push(&mut out, &self.type_fixed);
        out.push('\n');
        push(&mut out, "Fixed/constrained prefix:");
        push(&mut out, &self.fixed_prefix);
        out.push('\n');
        push(&mut out, "Constrained second character:");
        push(&mut out, &second_list(&self.legal_second));
        out.push('\n');
        push(&mut out, "Vanity-controlled portion:");
        if self.vanity.is_empty() {
            push(&mut out, "(none)");
        } else {
            push(&mut out, &self.vanity);
        }
        out.push('\n');
        push(&mut out, "Target reachable:");
        push(&mut out, if self.reachable { "YES" } else { "NO" });
        out.push('\n');
        if self.reachable {
            push(&mut out, "Search bits:");
            push(&mut out, &self.search_bits.to_string());
            out.push('\n');
            push(&mut out, "Estimated difficulty:");
            push(&mut out, &difficulty_line(self));
            out.push('\n');
            push(&mut out, "Expected attempts:");
            push(&mut out, &display_option(self.expected));
            push(&mut out, "50% probability:");
            push(&mut out, &display_option(self.median));
            push(&mut out, "90% probability:");
            push(&mut out, &display_option(self.p90));
            push(&mut out, "99% probability:");
            push(&mut out, &display_option(self.p99));
            out.push('\n');
            if self.exceeds_index_space {
                push(&mut out, "Fits in one account's payment indexes:");
                push(&mut out, "NO");
                push(
                    &mut out,
                    "The payment index space is 2^31. This prefix is rarer than that, so generate will not walk hardened indexes, change addresses, or stake indexes.",
                );
                out.push('\n');
            }
        } else {
            push(&mut out, "Estimated difficulty:");
            push(&mut out, "n/a");
            out.push('\n');
            push(&mut out, "Reason:");
            push(&mut out, &self.reason);
            out.push('\n');
            if self.prefix.contains("zuzu") {
                push(&mut out, "Earliest complete zuzu:");
                for item in earliest_zuzu(self.network) {
                    push(&mut out, &item);
                }
                push(
                    &mut out,
                    "Those four prefixes are equally early and equally difficult. This program does not substitute one of them.",
                );
                out.push('\n');
            }
        }
        push(
            &mut out,
            "The model assumes Blake2b-224 of BIP32-Ed25519 child keys behaves like independent uniform prefix bits. It is not a uniformity proof and not a promise of wall-clock time.",
        );
        push(&mut out, "Vanity search is probabilistic.");
        out
    }

    pub fn needs_large_search_confirmation(&self) -> bool {
        self.reachable
            && !self.exceeds_index_space
            && self.expected.unwrap_or(0) >= CONFIRMATION_THRESHOLD
    }
}

pub fn analyze(network: Network, prefix: &str) -> Result<Analysis, Error> {
    let data = parse_prefix(network, prefix)?;
    Ok(layout(network, prefix, &data))
}

pub fn require_searchable(analysis: &Analysis) -> Result<(), Error> {
    if !analysis.reachable {
        return Err(Error::prefix(if analysis.reason.is_empty() {
            format!(
                "no {} key-hash/key-hash base address begins with {}",
                analysis.network.name(),
                analysis.prefix
            )
        } else {
            analysis.reason.clone()
        }));
    }
    if analysis.exceeds_index_space {
        return Err(Error::prefix(
            "expected attempts exceed the 2^31 payment-index space",
        ));
    }
    Ok(())
}

pub fn earliest_zuzu(network: Network) -> [String; 4] {
    let legal = legal_second(network.header());
    let mut out = [String::new(), String::new(), String::new(), String::new()];
    for (index, character) in legal.iter().enumerate() {
        out[index] = format!(
            "{}1{}{character}zuzu",
            network.hrp(),
            fixed_first(network.header())
        );
    }
    out
}

pub fn group_digits(digits: &str) -> String {
    if digits.is_empty() {
        return String::new();
    }
    let mut grouped = String::new();
    for (index, ch) in digits.chars().rev().enumerate() {
        if index > 0 && index.is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(ch);
    }
    grouped.chars().rev().collect()
}

/// Smallest attempt count whose geometric success probability is at least `probability`.
pub fn attempts_for_probability(expected: u64, probability: f64) -> u64 {
    if expected <= 1 {
        return 1;
    }
    let trials = expected as f64;
    let count = (1.0 - probability).ln() / (1.0 - 1.0 / trials).ln();
    if !count.is_finite() || count <= 1.0 {
        return 1;
    }
    let rounded = count.ceil();
    if rounded >= u64::MAX as f64 {
        u64::MAX
    } else {
        rounded as u64
    }
}

fn layout(network: Network, prefix: &str, data: &[u8]) -> Analysis {
    let header = network.header();
    let legal = legal_second(header);
    let first = fixed_first(header);
    let type_fixed = format!("{}1{first}", network.hrp());
    let mut expected = [0u8; 28];
    let mut search_bits = 0u32;
    let mut fixed_prefix = format!("{}1", network.hrp());
    let mut vanity = String::new();
    let mut header_conflict = false;
    let mut stake_conflict = false;
    let mut bad_second = false;

    for (index, &symbol) in data.iter().enumerate() {
        let character = CHARSET[symbol as usize] as char;
        let mut touches_header = false;
        let mut touches_stake = false;
        let mut payment_only = true;
        for bit in 0..5 {
            let payload_bit = (index as u32) * 5 + bit;
            let symbol_bit = (symbol >> (4 - bit)) & 1;
            if payload_bit < HEADER_BITS {
                touches_header = true;
                payment_only = false;
                let header_bit = (header >> (7 - payload_bit as u8)) & 1;
                if symbol_bit != header_bit {
                    header_conflict = true;
                }
            } else if payload_bit < STAKE_BIT {
                let hash_bit = payload_bit - HEADER_BITS;
                set_hash_bit(&mut expected, hash_bit, symbol_bit);
                search_bits += 1;
            } else {
                touches_stake = true;
                payment_only = false;
                stake_conflict = true;
            }
        }
        if touches_stake {
            // Stake bits are not a free payment-hash group.
        } else if touches_header && !header_conflict {
            fixed_prefix.push(character);
        } else if payment_only {
            vanity.push(character);
        }
        if index == 1 && !legal.contains(&character) {
            bad_second = true;
        }
    }

    let reachable = !header_conflict && !stake_conflict;
    let exceeds_index_space = reachable && search_bits > INDEX_SPACE_BITS;
    let first_symbol = charset_index(first as u8).unwrap_or(0);
    let first_matches = data.first().copied() == Some(first_symbol);
    let reason = if stake_conflict && !header_conflict {
        "this prefix constrains stake-credential bits, and the search does not vary the stake key"
            .to_owned()
    } else if header_conflict && bad_second && first_matches {
        format!(
            "no {} key-hash/key-hash base address has second data character outside {}",
            network.name(),
            second_list(&legal)
        )
    } else if header_conflict || stake_conflict {
        format!(
            "no {} key-hash/key-hash base address begins with {prefix}",
            network.name()
        )
    } else {
        String::new()
    };
    let (expected_attempts, median, p90, p99) = if reachable && search_bits < 63 {
        let expected_attempts = 1u64 << search_bits;
        (
            Some(expected_attempts),
            Some(attempts_for_probability(expected_attempts, 0.50)),
            Some(attempts_for_probability(expected_attempts, 0.90)),
            Some(attempts_for_probability(expected_attempts, 0.99)),
        )
    } else {
        (None, None, None, None)
    };
    Analysis {
        network,
        prefix: prefix.to_owned(),
        reachable,
        exceeds_index_space,
        reason,
        type_fixed,
        fixed_prefix,
        vanity,
        legal_second: legal,
        search_bits,
        expected: expected_attempts,
        median,
        p90,
        p99,
        mask: HashMask {
            bits: if reachable { search_bits } else { 0 },
            expected,
        },
    }
}

fn parse_prefix(network: Network, prefix: &str) -> Result<Vec<u8>, Error> {
    if prefix.is_empty() {
        return Err(Error::prefix("prefix is empty"));
    }
    if prefix.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(Error::prefix("mixed-case Bech32 is not accepted"));
    }
    if prefix.bytes().any(|byte| !byte.is_ascii()) {
        return Err(Error::prefix("prefix contains a character outside ASCII"));
    }
    let separator_count = prefix.bytes().filter(|byte| *byte == b'1').count();
    if separator_count == 0 {
        return Err(Error::prefix(
            "prefix must contain the Bech32 separator 1 after the HRP",
        ));
    }
    if separator_count > 1 {
        return Err(Error::prefix(
            "the character 1 is the Bech32 separator and is not a data character",
        ));
    }
    let Some((hrp, data)) = prefix.split_once('1') else {
        return Err(Error::prefix("prefix is not Bech32"));
    };
    if hrp != network.hrp() {
        return Err(Error::prefix(format!(
            "prefix HRP does not match {} ({})",
            network.name(),
            network.hrp()
        )));
    }
    if data.len() >= PAYLOAD_GROUPS {
        return Err(Error::prefix("a complete address is not a search prefix"));
    }
    let mut symbols = Vec::with_capacity(data.len());
    for byte in data.bytes() {
        match charset_index(byte) {
            Some(index) => symbols.push(index),
            None => {
                return Err(Error::prefix(format!(
                    "character '{}' is not in the Bech32 alphabet",
                    byte as char
                )));
            }
        }
    }
    Ok(symbols)
}

fn legal_second(header: u8) -> [char; 4] {
    let top = u16::from(header & 0x07);
    let mut out = ['?'; 4];
    for extra in 0..4u16 {
        let symbol = ((top << 2) | extra) as usize;
        out[extra as usize] = CHARSET[symbol] as char;
    }
    out
}

fn fixed_first(header: u8) -> char {
    CHARSET[(header >> 3) as usize] as char
}

fn set_hash_bit(expected: &mut [u8; 28], bit: u32, value: u8) {
    let byte = (bit / 8) as usize;
    let shift = 7 - (bit % 8);
    if value == 1 {
        expected[byte] |= 1 << shift;
    }
}

fn second_list(chars: &[char; 4]) -> String {
    format!("{}, {}, {}, or {}", chars[0], chars[1], chars[2], chars[3])
}

fn difficulty_line(analysis: &Analysis) -> String {
    match analysis.expected {
        Some(1) => "1 (this prefix is implied by the address type)".to_owned(),
        Some(expected) => format!(
            "1/{} per payment index ({} search bits, not 32^n)",
            group_digits(&expected.to_string()),
            analysis.search_bits
        ),
        None => "n/a".to_owned(),
    }
}

fn display_option(value: Option<u64>) -> String {
    match value {
        Some(value) => group_digits(&value.to_string()),
        None => "n/a".to_owned(),
    }
}

fn push(out: &mut String, line: &str) {
    out.push_str(line);
    out.push('\n');
}
