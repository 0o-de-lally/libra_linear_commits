//! `version` subcommand

#![allow(clippy::never_loop)]

use crate::{block::parse_block_file, config::MinerConfig};

use libra_genesis_tool::keyscheme::KeyScheme;


use libra_types::transaction::SignedTransaction;
use libra_wallet::WalletLibrary;
use ol_types::{account::ValConfigs, autopay::PayInstruction};
use std::path::PathBuf;
use crate::prelude::app_config;

/// Creates an account.json file for the validator
pub fn write_manifest(
  path: &Option<PathBuf>,
  wallet: WalletLibrary,
  wizard_config: Option<MinerConfig>,
  autopay_batch: Option<Vec<PayInstruction>>,
  autopay_signed: Option<Vec<SignedTransaction>>,
) {
    let cfg = if wizard_config.is_some() { wizard_config.unwrap() }
    else { app_config().clone() };

    let miner_home = path
    .clone()
    .unwrap_or_else(|| cfg.workspace.node_home.clone()
    );

    let keys = KeyScheme::new(&wallet);
    let block = parse_block_file(cfg.get_block_dir().join("block_0.json").to_owned());

    ValConfigs::new(
        block,
        keys,  
        cfg.profile.ip.to_string(),
        autopay_batch,
        autopay_signed,
    ).create_manifest(miner_home);
}


