//! `sign tx`

use libra_types::{
  chain_id::ChainId,
  transaction::{helpers::create_user_txn, Script, SignedTransaction, TransactionPayload},
};

use crate::submit_tx::TxParams;
use anyhow::Error;

/// sign a raw transaction script, and return a SignedTransaction
pub fn sign_tx(script: &Script, tx_params: &TxParams, sequence_number: u64, chain_id: ChainId) -> Result<SignedTransaction, Error> {

  
  // TODO, how does Alice get Bob's tx sequence number?
  // sign the transaction script
  create_user_txn(
    &tx_params.keypair,
    TransactionPayload::Script(script.to_owned()),
    tx_params.signer_address,
    sequence_number,
    tx_params.max_gas_unit_for_tx,
    tx_params.coin_price_per_unit,
    "GAS".parse().unwrap(),
    tx_params.user_tx_timeout as i64, // for compatibility with UTC's timestamp.
    chain_id,
  )
}