// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0
use anyhow::{ensure, format_err, Error, Result};
use serde::{de::Visitor, Deserialize, Deserializer, Serialize};
use std::{convert::TryFrom, fmt, str::FromStr};

/// A registry of named chain IDs
/// Its main purpose is to improve human readability of reserved chain IDs in config files and CLI
/// When signing transactions for such chains, the numerical chain ID should still be used
/// (e.g. MAINNET has numeric chain ID 1, TESTNET has chain ID 2, etc)
#[repr(u8)]
#[derive(Copy, Clone, Debug, Serialize, Deserialize)] ///////// 0L ////////
pub enum NamedChain {
    /// Users might accidentally initialize the ChainId field to 0, hence reserving ChainId 0 for accidental
    /// initialization.
    /// MAINNET is the Diem mainnet production chain and is reserved for 1
    MAINNET = 1,
    // Even though these CHAIN IDs do not correspond to MAINNET, changing them should be avoided since they
    // can break test environments for various organisations.
    TESTNET = 2,
    DEVNET = 3,
    TESTING = 4,
    PREMAINNET = 5,
    EXPERIMENTAL = 7, //////// 0L ////////    
}

impl NamedChain {
    pub fn str_to_named(s: &str) -> Result<Self> { //////// 0L ////////
      let n = match s {
          "MAINNET" => NamedChain::MAINNET,
          "TESTNET" => NamedChain::TESTNET,
          "DEVNET" => NamedChain::DEVNET,
          "TESTING" => NamedChain::TESTING,
          "PREMAINNET" => NamedChain::PREMAINNET,
          "EXPERIMENTAL" => NamedChain::EXPERIMENTAL, //////// 0L ////////
          "1" => NamedChain::MAINNET,
          "2" => NamedChain::TESTNET,
          "3" => NamedChain::DEVNET,
          "4" => NamedChain::TESTING,
          "5" => NamedChain::PREMAINNET,
          "7" => NamedChain::EXPERIMENTAL, //////// 0L ////////         
          _ => {
              return Err(format_err!("Not a reserved chain: {:?}", s));
          }
      };
      Ok(n)
    }


    pub fn to_chain_id(&self) -> ChainId { //////// 0L ////////
        ChainId::new(self.id())
    }

    pub fn id(&self) -> u8 {
        *self as u8
    }

    pub fn from_chain_id(chain_id: &ChainId) -> Result<NamedChain, String> {
        match chain_id.id() {
            1 => Ok(NamedChain::MAINNET),
            2 => Ok(NamedChain::TESTNET),
            3 => Ok(NamedChain::DEVNET),
            4 => Ok(NamedChain::TESTING),
            5 => Ok(NamedChain::PREMAINNET),
            7 => Ok(NamedChain::EXPERIMENTAL), //////// 0L ////////            
            _ => Err(String::from("Not a named chain")),
        }
    }
}

impl FromStr for NamedChain { //////// 0L ////////
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::str_to_named(s)
    }
}
/// Note: u7 in a u8 is uleb-compatible, and any usage of this should be aware
/// that this field maybe updated to be uleb64 in the future
#[derive(Clone, Copy, Eq, Hash, PartialEq, Serialize)]
pub struct ChainId(u8);

struct ChainIdVisitor;

pub fn deserialize_config_chain_id<'de, D>(
    deserializer: D,
) -> std::result::Result<ChainId, D::Error>
where
    D: Deserializer<'de>,
{
    
    impl<'de> Visitor<'de> for ChainIdVisitor {
        type Value = ChainId;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("ChainId as string or u8")
        }

        fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            dbg!("trying to deserialize str");
            ChainId::from_str(value).map_err(serde::de::Error::custom)
        }

        fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            dbg!("trying to deserialize u64");

            Ok(ChainId::new(
                u8::try_from(value).map_err(serde::de::Error::custom)?,
            ))
        }
    }

    deserializer.deserialize_any(ChainIdVisitor)
}

impl<'de> Deserialize<'de> for ChainId {
    fn deserialize<D>(deserializer: D) -> Result<ChainId, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_u64(ChainIdVisitor)
    }
}


impl fmt::Debug for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            NamedChain::from_chain_id(&self)
                .map_or_else(|_| self.0.to_string(), |chain| chain.to_string())
        )
    }
}

impl fmt::Display for NamedChain {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                NamedChain::DEVNET => "DEVNET",
                NamedChain::TESTNET => "TESTNET",
                NamedChain::MAINNET => "MAINNET",
                NamedChain::TESTING => "TESTING",
                NamedChain::PREMAINNET => "PREMAINNET",
                NamedChain::EXPERIMENTAL => "EXPERIMENTAL", //////// 0L ////////
            }
        )
    }
}

impl Default for ChainId {
    fn default() -> Self {
        Self::test()
    }
}

impl FromStr for ChainId {
    type Err = Error;
    
    fn from_str(s: &str) -> Result<Self> {
        ensure!(!s.is_empty(), "Cannot create chain ID from empty string");
        match NamedChain::from_str(s) { //////// 0L ////////
            Ok(n) => Ok(n.to_chain_id()),
            Err(_) => {
              let value = s.parse::<u8>()?;
              ensure!(value > 0, "cannot have chain ID with 0");
              Ok(ChainId::new(value))
            },
        }
    }
}

impl ChainId {
    pub fn new(id: u8) -> Self {
        assert!(id > 0, "cannot have chain ID with 0");
        Self(id)
    }

    pub fn id(&self) -> u8 {
        self.0
    }

    pub fn test() -> Self {
        ChainId::new(NamedChain::TESTING.id())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_chain_id_from_str() {
        assert!(ChainId::from_str("").is_err());
        assert!(ChainId::from_str("0").is_err());
        assert!(ChainId::from_str("256").is_err());
        assert!(ChainId::from_str("255255").is_err());
        assert_eq!(ChainId::from_str("TESTING").unwrap(), ChainId::test());
        assert_eq!(ChainId::from_str("255").unwrap(), ChainId::new(255));
    }
}
