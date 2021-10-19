// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{context::Context, page::Page, param::TransactionIdParam};

use diem_api_types::{
    mime_types, Error, LedgerInfo, Response, Transaction, TransactionData, TransactionId,
    TransactionSigningMessage, UserTransactionRequest,
};
use diem_types::{
    mempool_status::MempoolStatusCode,
    transaction::{RawTransaction, SignedTransaction, TransactionInfo},
};

use anyhow::Result;
use warp::{
    http::{header::CONTENT_TYPE, StatusCode},
    reply, Filter, Rejection, Reply,
};

pub fn routes(context: Context) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    get_transaction(context.clone())
        .or(get_transactions(context.clone()))
        .or(post_transactions(context.clone()))
        .or(post_signing_message(context))
}

// GET /transactions/{txn-hash / version}
pub fn get_transaction(
    context: Context,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path!("transactions" / TransactionIdParam)
        .and(warp::get())
        .and(context.filter())
        .and_then(handle_get_transaction)
}

async fn handle_get_transaction(
    id: TransactionIdParam,
    context: Context,
) -> Result<impl Reply, Rejection> {
    Ok(Transactions::new(context)?
        .get_transaction(id.parse("transaction hash or version")?)
        .await?)
}

// GET /transactions?start={u64}&limit={u16}
pub fn get_transactions(
    context: Context,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path!("transactions")
        .and(warp::get())
        .and(warp::query::<Page>())
        .and(context.filter())
        .and_then(handle_get_transactions)
}

async fn handle_get_transactions(page: Page, context: Context) -> Result<impl Reply, Rejection> {
    Ok(Transactions::new(context)?.list(page)?)
}

// POST /transactions
pub fn post_transactions(
    context: Context,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path!("transactions")
        .and(warp::post())
        .and(warp::header::<String>(CONTENT_TYPE.as_str()))
        .and(warp::body::bytes())
        .and(context.filter())
        .and_then(handle_post_transactions)
}

async fn handle_post_transactions(
    content_type: String,
    body: bytes::Bytes,
    context: Context,
) -> Result<impl Reply, Rejection> {
    let txn = match content_type.to_lowercase().as_str() {
        mime_types::BCS_SIGNED_TRANSACTION => bcs::from_bytes(&body).map_err(|_| {
            Error::invalid_request_body("deserialize SignedTransaction BCS bytes failed".to_owned())
        })?,
        mime_types::JSON => {
            let txn = deserialize_user_transaction_request(body)?;
            let converter = context.move_converter();
            converter
                .try_into_signed_transaction(txn, context.chain_id())
                .map_err(|e| {
                    Error::invalid_request_body(format!(
                        "failed to create SignedTransaction from UserTransactionRequest: {}",
                        e
                    ))
                })?
        }
        _ => {
            return Err(
                Error::bad_request(format!("unsupported content-type: {}", content_type)).into(),
            )
        }
    };
    Ok(Transactions::new(context)?.create(txn).await?)
}

// POST /transactions/signing_message
pub fn post_signing_message(
    context: Context,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path!("transactions" / "signing_message")
        .and(warp::post())
        .and(warp::header::exact(CONTENT_TYPE.as_str(), mime_types::JSON))
        .and(warp::body::bytes())
        .and(context.filter())
        .and_then(handle_post_signing_message)
}

async fn handle_post_signing_message(
    body: bytes::Bytes,
    context: Context,
) -> Result<impl Reply, Rejection> {
    let txn = deserialize_user_transaction_request(body)?;
    Ok(Transactions::new(context)?.signing_message(txn)?)
}

fn deserialize_user_transaction_request(
    body: bytes::Bytes,
) -> Result<UserTransactionRequest, Error> {
    serde_json::from_slice(&body).map_err(|e| {
        Error::invalid_request_body(format!(
            "deserialize into UserTransactionRequest failed: {:?}",
            e
        ))
    })
}

struct Transactions {
    ledger_info: LedgerInfo,
    context: Context,
}

impl Transactions {
    fn new(context: Context) -> Result<Self, Error> {
        let ledger_info = context.get_latest_ledger_info()?;
        Ok(Self {
            ledger_info,
            context,
        })
    }

    pub async fn create(self, txn: SignedTransaction) -> Result<impl Reply, Error> {
        let (mempool_status, vm_status_opt) = self.context.submit_transaction(txn.clone()).await?;
        match mempool_status.code {
            MempoolStatusCode::Accepted => {
                let converter = self.context.move_converter();
                let pending_txn = converter.try_into_pending_transaction(txn)?;
                let resp = Response::new(self.ledger_info, &pending_txn)?;
                Ok(reply::with_status(resp, StatusCode::ACCEPTED))
            }
            MempoolStatusCode::VmError => Err(Error::bad_request(format!(
                "invalid transaction: {}",
                vm_status_opt
                    .map(|s| format!("{:?}", s))
                    .unwrap_or_else(|| "UNKNOWN".to_owned())
            ))),
            _ => Err(Error::bad_request(format!(
                "transaction is rejected: {}",
                mempool_status,
            ))),
        }
    }

    pub fn list(self, page: Page) -> Result<impl Reply, Error> {
        let ledger_version = self.ledger_info.version();
        let start_version = page.start(ledger_version)?;
        let limit = page.limit()?;

        let data = self
            .context
            .get_transactions(start_version, limit, ledger_version)?;

        let converter = self.context.move_converter();

        let txns: Vec<Transaction> = data
            .into_iter()
            .map(|t| converter.try_into_onchain_transaction(t))
            .collect::<Result<_>>()?;
        Response::new(self.ledger_info, &txns)
    }

    pub async fn get_transaction(self, id: TransactionId) -> Result<impl Reply, Error> {
        let txn_data = match id.clone() {
            TransactionId::Hash(hash) => self.get_by_hash(hash.into()).await?,
            TransactionId::Version(version) => self.get_by_version(version)?,
        }
        .ok_or_else(|| self.transaction_not_found(id))?;

        let converter = self.context.move_converter();
        let ret = converter.try_into_transaction(txn_data)?;

        Response::new(self.ledger_info, &ret)
    }

    pub fn signing_message(self, txn: UserTransactionRequest) -> Result<impl Reply, Error> {
        let converter = self.context.move_converter();
        let raw_txn: RawTransaction = converter
            .try_into_raw_transaction(txn, self.context.chain_id())
            .map_err(|e| {
                Error::invalid_request_body(format!("invalid UserTransactionRequest: {:?}", e))
            })?;

        Response::new(
            self.ledger_info,
            &TransactionSigningMessage::new(raw_txn.signing_message()),
        )
    }

    fn transaction_not_found(&self, id: TransactionId) -> Error {
        Error::not_found("transaction", id, self.ledger_info.version())
    }

    fn get_by_version(&self, version: u64) -> Result<Option<TransactionData<TransactionInfo>>> {
        if version > self.ledger_info.version() {
            return Ok(None);
        }
        Ok(Some(
            self.context
                .get_transaction_by_version(version, self.ledger_info.version())?
                .into(),
        ))
    }

    // This function looks for the transaction by hash in database and then mempool,
    // because the period a transaction stay in the mempool is likely short.
    // Although the mempool get transation is async, but looking up txn in database is a sync call,
    // thus we keep it simple and call them in sequence.
    async fn get_by_hash(
        &self,
        hash: diem_crypto::HashValue,
    ) -> Result<Option<TransactionData<TransactionInfo>>> {
        let from_db = self
            .context
            .get_transaction_by_hash(hash, self.ledger_info.version())?;
        Ok(match from_db {
            None => self
                .context
                .get_pending_transaction_by_hash(hash)
                .await?
                .map(|t| t.into()),
            _ => from_db.map(|t| t.into()),
        })
    }
}
