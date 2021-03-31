// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use libra_crypto::ed25519::Ed25519PublicKey;
use libra_global_constants::{OPERATOR_ACCOUNT, OWNER_ACCOUNT};
use libra_management::{config:: ConfigPath, error::Error, secure_backend::{SecureBackend, SharedBackend}};
use libra_secure_storage::OnDiskStorageInternal;
use libra_types::transaction::authenticator::AuthenticationKey;
use std::path::PathBuf;
use structopt::StructOpt;
use libra_secure_storage::CryptoStorage;
use libra_secure_storage::KVStorage;

libra_management::secure_backend!(
    ValidatorBackend,
    validator_backend,
    "validator configuration",
    "path-to-key"
);

#[derive(Debug, StructOpt)]
struct Key {
    #[structopt(flatten)]
    config: ConfigPath,
    #[structopt(flatten)]
    shared_backend: SharedBackend,
    #[structopt(flatten)]
    validator_backend: ValidatorBackend,
    #[structopt(long, help = "ed25519 public key in lcs or hex format")]
    path_to_key: Option<PathBuf>,
}

impl Key {
    fn submit_key(
        &self,
        key_name: &'static str,
        account_name: Option<&'static str>,
    ) -> Result<Ed25519PublicKey, Error> {
        let config = self
            .config
            .load()?
            .override_shared_backend(&self.shared_backend.shared_backend)?
            .override_validator_backend(&self.validator_backend.validator_backend)?;

        let key = if let Some(path_to_key) = &self.path_to_key {
            libra_management::read_key_from_file(path_to_key)
                .map_err(|e| Error::UnableToReadFile(format!("{:?}", path_to_key), e))?
        } else {
            let mut validator_storage = config.validator_backend();
            let key = validator_storage.ed25519_public_from_private(key_name)?;

            if let Some(account_name) = account_name {
                let peer_id = libra_types::account_address::from_public_key(&key);
                validator_storage.set(account_name, peer_id)?;
            }
            key
        };

        let mut shared_storage = config.shared_backend();
        shared_storage.set(key_name, key.clone())?;

        Ok(key)
    }
}

//////// 0L /////////
pub fn set_operator_key(path: &PathBuf, namespace: &str) {
    let mut storage = libra_secure_storage::Storage::OnDiskStorage(OnDiskStorageInternal::new(path.join("key_store.json").to_owned()));
    // TODO: Remove hard coded field
    let field = format!("{}-oper/operator", namespace);
    let key = storage.get_public_key(&field).unwrap().public_key;
    let peer_id = libra_types::account_address::from_public_key(&key);
    storage.set(OPERATOR_ACCOUNT, peer_id).unwrap();
}

pub fn set_owner_key(path: &PathBuf, namespace: &str) {
    let mut storage = libra_secure_storage::Storage::OnDiskStorage(OnDiskStorageInternal::new(path.join("key_store.json").to_owned()));
    let authkey: AuthenticationKey = namespace.parse().unwrap();
    let account = authkey.derived_address();
    storage.set(&format!("{}-oper/{}", namespace, OWNER_ACCOUNT), account).unwrap();
}

#[derive(Debug, StructOpt)]
pub struct LibraRootKey {
    #[structopt(flatten)]
    key: Key,
}

impl LibraRootKey {
    pub fn execute(self) -> Result<Ed25519PublicKey, Error> {
        self.key
            .submit_key(libra_global_constants::LIBRA_ROOT_KEY, None)
    }
}

#[derive(Debug, StructOpt)]
pub struct OperatorKey {
    #[structopt(flatten)]
    key: Key,
}

impl OperatorKey {
    pub fn execute(self) -> Result<Ed25519PublicKey, Error> {
        self.key.submit_key(
            libra_global_constants::OPERATOR_KEY,
            Some(libra_global_constants::OPERATOR_ACCOUNT),
        )
    }
}

#[derive(Debug, StructOpt)]
pub struct OwnerKey {
    #[structopt(flatten)]
    key: Key,
}

impl OwnerKey {
    pub fn execute(self) -> Result<Ed25519PublicKey, Error> {
        self.key.submit_key(libra_global_constants::OWNER_KEY, None)
    }
}

#[derive(Debug, StructOpt)]
pub struct TreasuryComplianceKey {
    #[structopt(flatten)]
    key: Key,
}

impl TreasuryComplianceKey {
    pub fn execute(self) -> Result<Ed25519PublicKey, Error> {
        self.key
            .submit_key(libra_global_constants::TREASURY_COMPLIANCE_KEY, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage_helper::StorageHelper;
    use libra_secure_storage::{CryptoStorage, KVStorage};

    #[test]
    fn test_owner_key() {
        test_key(libra_global_constants::OWNER_KEY, StorageHelper::owner_key);
    }

    #[test]
    fn test_operator_key() {
        test_key(
            libra_global_constants::OPERATOR_KEY,
            StorageHelper::operator_key,
        );
    }

    fn test_key(
        key_name: &str,
        op: fn(&StorageHelper, &str, &str) -> Result<Ed25519PublicKey, Error>,
    ) {
        let helper = StorageHelper::new();
        let local_ns = format!("local_{}_key", key_name);
        let remote_ns = format!("remote_{}_key", key_name);

        op(&helper, &local_ns, &remote_ns).unwrap_err();

        helper.initialize_by_idx(local_ns.clone(), 0);
        let local = helper.storage(local_ns.clone());
        let local_key = local.get_public_key(key_name).unwrap().public_key;

        let output_key = op(&helper, &local_ns, &remote_ns).unwrap();
        let remote = helper.storage(remote_ns);
        let remote_key = remote.get::<Ed25519PublicKey>(key_name).unwrap().value;

        assert_eq!(local_key, output_key);
        assert_eq!(local_key, remote_key);
    }
}
