// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error::Error;

/// Shelley network tag. Mainnet and testnet are different headers and HRPs.
/// A testnet address is never labeled mainnet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    pub fn parse(text: &str) -> Result<Self, Error> {
        match text {
            "mainnet" => Ok(Self::Mainnet),
            "testnet" => Ok(Self::Testnet),
            _ => Err(Error::prefix("network must be mainnet or testnet")),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Mainnet => "Mainnet",
            Self::Testnet => "Testnet",
        }
    }

    /// CIP-19 header for a type-0 key-hash/key-hash base address.
    pub fn header(self) -> u8 {
        match self {
            Self::Mainnet => 0x01,
            Self::Testnet => 0x00,
        }
    }

    pub fn hrp(self) -> &'static str {
        match self {
            Self::Mainnet => "addr",
            Self::Testnet => "addr_test",
        }
    }
}
