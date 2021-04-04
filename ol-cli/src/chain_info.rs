//! `chain_info`
use crate::{cache::DB_CACHE, client};
use chrono::Utc;
use libra_types::{account_address::AccountAddress, account_state::AccountState};
use std::convert::{TryFrom};
use serde::{Serialize, Deserialize};

/// name of chain info key for db
pub const CHAIN_INFO_DB_KEY: &str = "chain_info";
/// name of val info key for db
pub const VAL_INFO_DB_KEY: &str = "val_info";

#[derive(Default, Clone, Debug, Deserialize, Serialize)]
/// ChainInfo struct
pub struct ChainInfo {
    /// epoch
    pub epoch: u64,
    /// height/version
    pub height: u64,
    /// validator count
    pub validator_count: u64,
    /// total supply of GAS
    pub total_supply: u64,
    /// latest epoch change time
    pub latest_epoch_change_time: u64,
    /// epoch_progress
    pub epoch_progress: f64,
}


#[derive(Default, Debug, Deserialize, Serialize)]
/// Validator info struct
pub struct ValidatorInfo {
    /// account address
    pub account_address: String,
    /// public key
    pub pub_key: String,
    /// voting power
    pub voting_power: u64,
    /// full node ip
    pub full_node_ip: String,
    /// validator ip
    pub validator_ip: String,
    /// tower height
    pub tower_height: u64,
    /// tower epoch
    pub tower_epoch: u64,
    /// proof counts in current epoch
    pub count_proofs_in_epoch: u64,
    /// epoch validating and mining
    pub epochs_validating_and_mining: u64,
    /// contiguous epochs of mining
    pub contiguous_epochs_validating_and_mining: u64,
    /// epoch count since creation
    pub epochs_since_last_account_creation: u64,
}


/// fetch state from system address 0x0
pub fn fetch_chain_info() -> (Option<ChainInfo>, Option<Vec<ValidatorInfo>>){
    let mut client = client::default_remote_client().0.unwrap();
    let (blob, _version) = client.get_account_state_blob(AccountAddress::ZERO).unwrap();
    let mut cs = ChainInfo::default();
    if let Some(account_blob) = blob {
        let account_state = AccountState::try_from(&account_blob).unwrap();
        let meta = client.get_metadata().unwrap();
        cs.epoch = account_state
            .get_configuration_resource()
            .unwrap()
            .unwrap()
            .epoch();
        cs.validator_count = account_state
            .get_validator_set()
            .unwrap()
            .unwrap()
            .payload()
            .len() as u64;
        
        // Calculate Epoch Progress
        let ts = account_state
            .get_configuration_resource()
            .unwrap()
            .unwrap()
            .last_reconfiguration_time() as i64
            / 1000000;
        let now = Utc::now().timestamp();

        match meta.chain_id {
            // testnet has faster epochs
            4 => cs.epoch_progress = (now - ts) as f64 / 61f64, // 1 minute
            // for main net
            _ => cs.epoch_progress = (now - ts) as f64 / 86401f64, // 24 hours
        }
        if cs.epoch_progress > 1f64 {
            cs.epoch_progress = 0f64;
        };

        if let Some(first) = account_state
            .get_registered_currency_info_resources()
            .unwrap()
            .first()
        {
            cs.total_supply = (first.total_value() / first.scaling_factor() as u128) as u64;
        }

        cs.height = meta.version;
        let chain_state = Some(cs);

        let validators: Vec<ValidatorInfo> = account_state
            .get_validator_set()
            .unwrap()
            .unwrap()
            .payload()
            .iter()
            .map(|v| {
                let full_node_ip = match v.config().fullnode_network_addresses() {
                    Ok(ips) => {
                        if !ips.is_empty() {
                            ips.last().unwrap().to_string()
                        } else {
                            "--".to_string()
                        }
                    }
                    Err(_) => "--".to_string(),
                };
                let validator_ip = match v.config().validator_network_addresses() {
                    Ok(ips) => {
                        if !ips.is_empty() {
                            ips.get(0).unwrap().seq_num().to_string()
                        } else {
                            "--".to_string()
                        }
                    }
                    Err(_) => "--".to_string(),
                };
                let ms = client
                    .get_miner_state(v.account_address().clone())
                    .unwrap()
                    .unwrap();

                ValidatorInfo {
                    account_address: v.account_address().to_string(),
                    voting_power: v.consensus_voting_power(),
                    full_node_ip,
                    pub_key: v.consensus_public_key().to_string(),
                    validator_ip,

                    tower_height: ms.verified_tower_height,
                    tower_epoch: ms.latest_epoch_mining,

                    count_proofs_in_epoch: ms.count_proofs_in_epoch,
                    epochs_validating_and_mining: ms.epochs_validating_and_mining,
                    contiguous_epochs_validating_and_mining: ms
                        .contiguous_epochs_validating_and_mining,
                    epochs_since_last_account_creation: ms.epochs_since_last_account_creation,
                }
            })
            .collect();

            // also save to cache
            let cs_ser = serde_json::to_vec(&chain_state).unwrap();
            let val_ser = serde_json::to_vec(&validators).unwrap();

            DB_CACHE.put(CHAIN_INFO_DB_KEY.as_bytes(), cs_ser).unwrap();
            DB_CACHE.put(VAL_INFO_DB_KEY.as_bytes(), val_ser).unwrap();

            return (chain_state, Some(validators))
    }

    (None, None)
}

/// get chain info from cache
pub fn read_chain_info_cache() -> ChainInfo {
  let chain_state = DB_CACHE.get(CHAIN_INFO_DB_KEY.as_bytes()).unwrap().expect("could not reach chain_info cache");
  let c: ChainInfo = serde_json::de::from_slice(&chain_state.as_slice()).unwrap();
  c
}

/// get chain info from cache
pub fn read_val_info_cache() -> Vec<ValidatorInfo> {
  let val_info = DB_CACHE.get(VAL_INFO_DB_KEY.as_bytes()).unwrap().expect("could not reach chain_info cache");
  let v: Vec<ValidatorInfo> = serde_json::de::from_slice(&val_info.as_slice()).unwrap();
  v
}