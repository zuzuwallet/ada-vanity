// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! BIP-173 Bech32 used by Shelley addresses.
//!
//! Cardano does not apply BIP-173's 90-character limit (CIP-19). This encoder
//! does not apply it either. The search stack uses this module. The check
//! stack uses the `bech32` crate.

use crate::error::Error;

pub(crate) const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

const GENERATOR: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

pub(crate) fn charset_index(byte: u8) -> Option<u8> {
    CHARSET
        .iter()
        .position(|&item| item == byte)
        .map(|index| index as u8)
}

pub(crate) fn encode(hrp: &str, data: &[u8]) -> Result<String, Error> {
    if !hrp_ok(hrp) {
        return Err(Error::Checksum);
    }
    let values = convert_8_to_5(data);
    let checksum = create_checksum(hrp, &values);
    let mut out = String::with_capacity(hrp.len() + 1 + values.len() + checksum.len());
    out.push_str(hrp);
    out.push('1');
    for value in values.iter().chain(checksum.iter()) {
        out.push(CHARSET[*value as usize] as char);
    }
    Ok(out)
}

pub(crate) fn decode(text: &str) -> Result<(String, Vec<u8>), Error> {
    if text.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(Error::prefix("mixed-case Bech32 is not accepted"));
    }
    let Some((hrp, data)) = text.rsplit_once('1') else {
        return Err(Error::Checksum);
    };
    if !hrp_ok(hrp) || data.len() < 6 {
        return Err(Error::Checksum);
    }
    let mut values = Vec::with_capacity(data.len());
    for byte in data.bytes() {
        values.push(charset_index(byte).ok_or(Error::Checksum)?);
    }
    let mut expanded = hrp_expand(hrp);
    expanded.extend_from_slice(&values);
    if polymod(expanded.iter().copied()) != 1 {
        return Err(Error::Checksum);
    }
    let payload = convert_5_to_8(&values[..values.len() - 6])?;
    Ok((hrp.to_owned(), payload))
}

fn hrp_ok(hrp: &str) -> bool {
    !hrp.is_empty()
        && hrp.len() <= 83
        && hrp
            .bytes()
            .all(|byte| (33..=126).contains(&byte) && !byte.is_ascii_uppercase())
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(hrp.len() * 2 + 1);
    for byte in hrp.bytes() {
        out.push(byte >> 5);
    }
    out.push(0);
    for byte in hrp.bytes() {
        out.push(byte & 31);
    }
    out
}

fn polymod(values: impl Iterator<Item = u8>) -> u32 {
    let mut chk = 1u32;
    for value in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(value);
        for (bit, generator) in GENERATOR.iter().enumerate() {
            if (top >> bit) & 1 == 1 {
                chk ^= generator;
            }
        }
    }
    chk
}

fn create_checksum(hrp: &str, data: &[u8]) -> [u8; 6] {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0; 6]);
    let mixed = polymod(values.iter().copied()) ^ 1;
    let mut checksum = [0u8; 6];
    for (index, item) in checksum.iter_mut().enumerate() {
        *item = ((mixed >> (5 * (5 - index))) & 31) as u8;
    }
    checksum
}

fn convert_8_to_5(data: &[u8]) -> Vec<u8> {
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(data.len() * 8 / 5 + 1);
    for &value in data {
        acc = (acc << 8) | u32::from(value);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        out.push(((acc << (5 - bits)) & 31) as u8);
    }
    out
}

fn convert_5_to_8(data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(data.len() * 5 / 8);
    for &value in data {
        if value > 31 {
            return Err(Error::Checksum);
        }
        acc = (acc << 5) | u32::from(value);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    if bits >= 5 || (acc & ((1u32 << bits) - 1)) != 0 {
        return Err(Error::Checksum);
    }
    Ok(out)
}
