// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! Module contains RPC method handlers for Full Node JSON-RPC interface
use crate::{
    data,
    errors::JsonRpcError,
    views::{
        AccountStateWithProofView, AccountView, CurrencyInfoView, EventView, EventWithProofView,
        MetadataView, MinerStateResourceView, OracleUpgradeStateView, StateProofView,
        TransactionListView, TransactionView, TransactionsWithProofsView,
    },
};
use anyhow::Result;
use diem_config::config::RoleType;
use diem_json_rpc_types::request::{
    GetAccountParams, GetAccountStateWithProofParams, GetAccountTransactionParams,
    GetAccountTransactionsParams, GetCurrenciesParams, GetEventsParams, GetEventsWithProofsParams,
    GetMetadataParams, GetMinerStateParams, GetNetworkStatusParams, GetStateProofParams,
    GetTransactionsParams, GetTransactionsWithProofsParams, MethodRequest,
    SubmitParams,
};
use diem_mempool::{MempoolClientSender, SubmissionStatus};
use diem_types::{
    chain_id::ChainId,
    ledger_info::LedgerInfoWithSignatures, mempool_status::MempoolStatusCode,
    transaction::SignedTransaction,
};
use fail::fail_point;
use futures::{channel::oneshot, SinkExt};
use serde_json::Value;
use std::{borrow::Borrow, sync::Arc};
use storage_interface::DbReader;

#[derive(Clone)]
pub(crate) struct JsonRpcService {
    db: Arc<dyn DbReader>,
    mempool_sender: MempoolClientSender,
    role: RoleType,
    chain_id: ChainId,
    batch_size_limit: u16,
    page_size_limit: u16,
}

impl JsonRpcService {
    pub fn new(
        db: Arc<dyn DbReader>,
        mempool_sender: MempoolClientSender,
        role: RoleType,
        chain_id: ChainId,
        batch_size_limit: u16,
        page_size_limit: u16,
    ) -> Self {
        Self {
            db,
            mempool_sender,
            role,
            chain_id,
            batch_size_limit,
            page_size_limit,
        }
    }

    pub async fn mempool_request(
        &self,
        transaction: SignedTransaction,
    ) -> Result<SubmissionStatus> {
        let (req_sender, callback) = oneshot::channel();

        self.mempool_sender
            .clone()
            .send((transaction, req_sender))
            .await?;

        callback.await?
    }

    pub fn get_latest_ledger_info(&self) -> Result<LedgerInfoWithSignatures> {
        fail_point!("jsonrpc::get_latest_ledger_info", |_| {
            Err(anyhow::anyhow!(
                "Injected error for get latest ledger info error"
            ))
        });

        self.db.get_latest_ledger_info()
    }

    pub fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    pub fn validate_batch_size_limit(&self, size: usize) -> Result<(), JsonRpcError> {
        self.validate_size_limit("batch size", self.batch_size_limit, size)
    }

    pub fn validate_page_size_limit(&self, size: usize) -> Result<(), JsonRpcError> {
        self.validate_size_limit("page size", self.page_size_limit, size)
    }

    fn validate_size_limit(&self, name: &str, limit: u16, size: usize) -> Result<(), JsonRpcError> {
        if size > limit as usize {
            Err(JsonRpcError::invalid_request_with_msg(format!(
                "{} = {}, exceed limit {}",
                name, size, limit
            )))
        } else {
            Ok(())
        }
    }
}

pub(crate) struct Handler<'a> {
    service: &'a JsonRpcService,
    ledger_info: &'a LedgerInfoWithSignatures,
}

impl<'a> Handler<'a> {
    pub fn new(service: &'a JsonRpcService, ledger_info: &'a LedgerInfoWithSignatures) -> Self {
        Self {
            service,
            ledger_info,
        }
    }

    fn version(&self) -> u64 {
        self.ledger_info.ledger_info().version()
    }

    fn version_param(&self, version: Option<u64>, name: &str) -> Result<u64, JsonRpcError> {
        let version = if let Some(version) = version {
            if version > self.version() {
                return Err(JsonRpcError::invalid_param(&format!(
                    "{} should be <= known latest version {}",
                    name,
                    self.version()
                )));
            }
            version
        } else {
            self.version()
        };
        Ok(version)
    }

    pub async fn handle(&self, method_request: MethodRequest) -> Result<Value, JsonRpcError> {
        let response: Value = match method_request {
            MethodRequest::Submit(params) => self.submit(params).await?.into(),
            MethodRequest::GetMetadata(params) => {
                serde_json::to_value(self.get_metadata(params).await?)?
            }
            MethodRequest::GetAccount(params) => {
                serde_json::to_value(self.get_account(params).await?)?
            }
            MethodRequest::GetTransactions(params) => {
                serde_json::to_value(self.get_transactions(params).await?)?
            }
            MethodRequest::GetAccountTransaction(params) => {
                serde_json::to_value(self.get_account_transaction(params).await?)?
            }
            MethodRequest::GetAccountTransactions(params) => {
                serde_json::to_value(self.get_account_transactions(params).await?)?
            }
            MethodRequest::GetEvents(params) => {
                serde_json::to_value(self.get_events(params).await?)?
            }
            MethodRequest::GetCurrencies(params) => {
                serde_json::to_value(self.get_currencies(params).await?)?
            }
            MethodRequest::GetNetworkStatus(params) => {
                serde_json::to_value(self.get_network_status(params).await?)?
            }
            MethodRequest::GetStateProof(params) => {
                serde_json::to_value(self.get_state_proof(params).await?)?
            }
            MethodRequest::GetAccountStateWithProof(params) => {
                serde_json::to_value(self.get_account_state_with_proof(params).await?)?
            }
            MethodRequest::GetTransactionsWithProofs(params) => {
                serde_json::to_value(self.get_transactions_with_proofs(params).await?)?
            }
            MethodRequest::GetEventsWithProofs(params) => {
                serde_json::to_value(self.get_events_with_proofs(params).await?)?
            }

            //////// 0L ////////
            MethodRequest::GetMinerStateView(params) => {
                serde_json::to_value(self.get_miner_state(params).await?)?
            }
            MethodRequest::GetOracleUpgradeStateView() => {
                serde_json::to_value(self.get_oracle_upgrade_state().await?)?
            }
        };
        Ok(response)
    }

    async fn submit(&self, params: SubmitParams) -> Result<(), JsonRpcError> {
        let (mempool_status, vm_status_opt) = self.service.mempool_request(params.data).await?;

        if let Some(vm_status) = vm_status_opt {
            Err(JsonRpcError::vm_status(vm_status))
        } else if mempool_status.code == MempoolStatusCode::Accepted {
            Ok(())
        } else {
            Err(JsonRpcError::mempool_error(mempool_status)?)
        }
    }

    /// Returns the blockchain metadata for a specified version. If no version is specified, default to
    /// returning the current blockchain metadata
    /// Can be used to verify that target Full Node is up-to-date
    async fn get_metadata(&self, params: GetMetadataParams) -> Result<MetadataView, JsonRpcError> {
        let chain_id = self.service.chain_id();
        let version = self.version_param(params.version, "version")?;
        data::get_metadata(self.service.db.borrow(), self.version(), chain_id, version)
    }

    /// Returns account state (AccountView) by given address
    async fn get_account(
        &self,
        params: GetAccountParams,
    ) -> Result<Option<AccountView>, JsonRpcError> {
        let account_address = params.account;
        let version = self.version_param(params.version, "version")?;
        data::get_account(self.service.db.borrow(), account_address, version)
    }

    /// Returns transactions by range
    async fn get_transactions(
        &self,
        params: GetTransactionsParams,
    ) -> Result<TransactionListView, JsonRpcError> {
        let GetTransactionsParams {
            start_version,
            limit,
            include_events,
        } = params;

        self.service.validate_page_size_limit(limit as usize)?;
        data::get_transactions(
            self.service.db.borrow(),
            self.version(),
            start_version,
            limit,
            include_events,
        )
    }

    /// Returns transactions by range with proofs
    async fn get_transactions_with_proofs(
        &self,
        params: GetTransactionsWithProofsParams,
    ) -> Result<Option<TransactionsWithProofsView>, JsonRpcError> {
        let GetTransactionsWithProofsParams {
            start_version,
            limit,
            include_events,
        } = params;

        // Notice limit is a u16 normally, but some APIs require u64 below
        self.service.validate_page_size_limit(limit as usize)?;
        data::get_transactions_with_proofs(
            self.service.db.borrow(),
            self.version(),
            start_version,
            limit,
            include_events,
        )
    }

    /// Returns account transaction by account and sequence_number
    async fn get_account_transaction(
        &self,
        params: GetAccountTransactionParams,
    ) -> Result<Option<TransactionView>, JsonRpcError> {
        let GetAccountTransactionParams {
            account,
            sequence_number,
            include_events,
        } = params;
        data::get_account_transaction(
            self.service.db.borrow(),
            self.version(),
            account,
            sequence_number,
            include_events,
        )
    }

    /// Returns all account transactions
    async fn get_account_transactions(
        &self,
        params: GetAccountTransactionsParams,
    ) -> Result<Vec<TransactionView>, JsonRpcError> {
        let GetAccountTransactionsParams {
            account,
            start,
            limit,
            include_events,
        } = params;

        self.service.validate_page_size_limit(limit as usize)?;
        data::get_account_transactions(
            self.service.db.borrow(),
            self.version(),
            account,
            start,
            limit,
            include_events,
        )
    }

    /// Returns events by given access path
    async fn get_events(&self, params: GetEventsParams) -> Result<Vec<EventView>, JsonRpcError> {
        let GetEventsParams { key, start, limit } = params;

        self.service.validate_page_size_limit(limit as usize)?;
        data::get_events(self.service.db.borrow(), self.version(), key, start, limit)
    }

    /// Returns events by given access path along with their proofs
    async fn get_events_with_proofs(
        &self,
        params: GetEventsWithProofsParams,
    ) -> Result<Vec<EventWithProofView>, JsonRpcError> {
        let GetEventsWithProofsParams { key, start, limit } = params;

        self.service.validate_page_size_limit(limit as usize)?;
        data::get_events_with_proofs(self.service.db.borrow(), self.version(), key, start, limit)
    }

    /// Returns meta information about supported currencies
    async fn get_currencies(
        &self,
        _params: GetCurrenciesParams,
    ) -> Result<Vec<CurrencyInfoView>, JsonRpcError> {
        data::get_currencies(self.service.db.borrow(), self.version())
    }

    /// Returns the number of peers this node is connected to
    async fn get_network_status(
        &self,
        _params: GetNetworkStatusParams,
    ) -> Result<u64, JsonRpcError> {
        data::get_network_status(self.service.role.as_str())
    }

    /// Returns proof of new state relative to version known to client
    async fn get_state_proof(
        &self,
        params: GetStateProofParams,
    ) -> Result<StateProofView, JsonRpcError> {
        let version = self.version_param(Some(params.version), "version")?;
        data::get_state_proof(self.service.db.borrow(), version, &self.ledger_info)
    }

    /// Returns the account state to the client, alongside a proof relative to the version and
    /// ledger_version specified by the client. If version or ledger_version are not specified,
    /// the latest known versions will be used.
    async fn get_account_state_with_proof(
        &self,
        params: GetAccountStateWithProofParams,
    ) -> Result<AccountStateWithProofView, JsonRpcError> {
        // If versions are specified by the request parameters, use them, otherwise use the defaults
        let version = self.version_param(params.version, "version")?;
        let ledger_version = self.version_param(params.ledger_version, "ledger_version")?;

        data::get_account_state_with_proof(
            self.service.db.borrow(),
            ledger_version,
            params.account,
            version,
        )
    }

    //////// 0L ////////
    async fn get_miner_state(
        &self,
        params: GetMinerStateParams,
    ) -> Result<MinerStateResourceView, JsonRpcError> {
        data::get_miner_state(self.service.db.borrow(), self.version(), params.account)
    }

    async fn get_oracle_upgrade_state(
        &self,
    ) -> Result<OracleUpgradeStateView, JsonRpcError> {
        data::get_oracle_upgrade_state(self.service.db.borrow(), self.version())
    }
}