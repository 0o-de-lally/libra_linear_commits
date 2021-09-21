// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use diem_api_types::{Address, Error, LedgerInfo};
use diem_types::{
    account_address::AccountAddress, account_state::AccountState,
    account_state_blob::AccountStateBlob, chain_id::ChainId,
};
use storage_interface::MoveDbReader;

use anyhow::Result;
use serde_json::json;
use std::{
    borrow::Borrow,
    convert::{Infallible, TryFrom},
    sync::Arc,
};
use warp::Filter;

// Context holds application scope context
#[derive(Clone)]
pub struct Context {
    chain_id: ChainId,
    db: Arc<dyn MoveDbReader>,
}

impl Context {
    pub fn new(chain_id: ChainId, db: Arc<dyn MoveDbReader>) -> Self {
        Self { chain_id, db }
    }

    pub fn db(&self) -> &dyn MoveDbReader {
        self.db.borrow()
    }

    pub fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    pub fn filter(self) -> impl Filter<Extract = (Context,), Error = Infallible> + Clone {
        warp::any().map(move || self.clone())
    }

    pub fn get_latest_ledger_info(&self) -> Result<LedgerInfo, Error> {
        Ok(LedgerInfo::new(
            self.chain_id(),
            &self.db.get_latest_ledger_info()?,
        ))
    }

    pub fn get_account_state(
        &self,
        address: &Address,
        ledger_version: u64,
    ) -> Result<AccountState, Error> {
        let state = self
            .get_account_state_blob(address.into_inner(), ledger_version)?
            .ok_or_else(|| account_not_found(&address.to_string(), ledger_version))?;
        Ok(AccountState::try_from(&state)?)
    }

    pub fn get_account_state_blob(
        &self,
        account: AccountAddress,
        version: u64,
    ) -> Result<Option<AccountStateBlob>> {
        let (account_state_blob, _) = self
            .db
            .get_account_state_with_proof_by_version(account, version)?;
        Ok(account_state_blob)
    }
}

fn account_not_found(address: &str, ledger_version: u64) -> Error {
    Error::not_found(
        format!("could not find account by address: {}", address),
        json!({ "ledger_version": ledger_version.to_string() }),
    )
}
