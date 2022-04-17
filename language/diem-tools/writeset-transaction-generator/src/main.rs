// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, format_err, Result};
use diem_types::{
    account_address::AccountAddress,
    chain_id::ChainId,
    transaction::{Transaction, TransactionPayload},
};

use diem_writeset_generator::{
    create_release, encode_custom_script, encode_halt_network_payload,
    encode_remove_validators_payload, script_bulk_update_vals_payload, release_flow::artifacts::load_latest_artifact,
    verify_release, ol_writeset_stdlib_upgrade, ol_create_reconfig_payload, ol_writset_encode_rescue, ol_writset_update_timestamp, ol_writeset_force_boundary, ol_writeset_set_testnet, ol_writeset_debug_epoch
};
use move_binary_format::CompiledModule;
use std::path::PathBuf;
use structopt::StructOpt;

const GENESIS_MODULE_NAME: &str = "Genesis";

#[derive(Debug, StructOpt)]
struct Opt {
    /// Path to the output serialized bytes
    #[structopt(long, short, parse(from_os_str))]
    output: Option<PathBuf>,

    #[structopt(long, short, parse(from_os_str))]
    db: Option<PathBuf>,
    /// Output as serialized WriteSet payload. Set this flag if this payload is submitted to AOS portal.
    #[structopt(long)]
    output_payload: bool,
    #[structopt(subcommand)]
    cmd: Command,
}

#[derive(Debug, StructOpt)]
enum Command {
    /// List of addresses to remove from validator set
    #[structopt(name = "remove-validators")]
    RemoveValidators { addresses: Vec<AccountAddress> },
    /// List of addresses to remove from validator set
    #[structopt(name = "update-validators")]
    UpdateValidators { addresses: Vec<AccountAddress> },
    #[structopt(name = "update-stdlib")]
    UpdateStdlib { },
    #[structopt(name = "rescue")]
    Rescue { addresses: Vec<AccountAddress> },
    #[structopt(name = "debug-epoch")]
    DebugEpoch { addresses: Vec<AccountAddress> },
    #[structopt(name = "boundary")]
    Boundary { addresses: Vec<AccountAddress> },
    #[structopt(name = "reconfig")]
    Reconfig { },
    #[structopt(name = "time")]
    Timestamp { },
    #[structopt(name = "testnet")]
    Testnet { },
    /// Block the execution of any transaction in the network
    #[structopt(name = "halt-network")]
    HaltNetwork,
    /// Build a custom file in templates into admin script
    #[structopt(name = "build-custom-script")]
    BuildCustomScript {
        script_name: String,
        args: String,
        execute_as: Option<AccountAddress>,
    },
    /// Create a release writeset by comparing local Diem Framework against a remote blockchain state.
    #[structopt(name = "create-release")]
    CreateDiemFrameworkRelease {
        /// ChainID to distinguish the diem network. e.g: PREMAINNET
        chain_id: ChainId,
        /// Public JSON-rpc endpoint URL.
        // TODO: Get rid of this URL argument once we have a stable mapping from ChainId to its url.
        url: String,
        /// Blockchain height
        version: u64,
        /// Set the flag to true in the first release. This will manually create the first release artifact on disk.
        #[structopt(long)]
        first_release: bool,
        /// Set this value when there's feature gated by DiemVersion.
        #[structopt(long)]
        diem_version: Option<u64>,
    },
    /// Verify if a blob is generated by the checked-in artifact.
    #[structopt(name = "verify-release")]
    VerifyDiemFrameworkRelease {
        /// ChainID to distinguish the diem network. e.g: PREMAINNET
        chain_id: ChainId,
        /// Public JSON-rpc endpoint URL.
        url: String,
        /// Path to the serialized bytes of WriteSet.
        #[structopt(parse(from_os_str))]
        writeset_path: PathBuf,
        /// The verification tool will automatically verify the payload against the latest blockchain state. Set this flag to false if we want to verify the payload against the height when the payload gets created.
        #[structopt(long)]
        use_latest_version: bool,
    },
}

fn save_bytes(bytes: Vec<u8>, path: PathBuf) -> Result<()> {
    std::fs::write(path.as_path(), bytes.as_slice())
        .map_err(|err| format_err!("Unable to write to path: {:?}", err))
}

fn diem_framework_modules(release_name: &str) -> Vec<(Vec<u8>, CompiledModule)> {
    // Need to filter out Genesis module similiar to what is done in vmgenesis to make sure Genesis
    // module isn't published on-chain.
    diem_framework_releases::load_modules_from_release(release_name)
        .unwrap_or_else(|_| {
            panic!(
                "Failed to load modules from given release name: {:?}",
                release_name
            )
        })
        .into_iter()
        .map(|bytes| {
            (
                bytes.clone(),
                CompiledModule::deserialize(&bytes).expect("Failed to deserialize compiled module"),
            )
        })
        .filter(|module| module.1.self_id().name().as_str() != GENESIS_MODULE_NAME)
        .collect()
}

fn main() -> Result<()> {
    let opt = Opt::from_args();
    let payload = match opt.cmd {
        Command::RemoveValidators { addresses } => encode_remove_validators_payload(addresses),
        //////// 0L ////////
        Command::Boundary { addresses } => ol_writeset_force_boundary(opt.db.unwrap(), addresses),
        Command::UpdateValidators { addresses } => script_bulk_update_vals_payload(addresses),
        
        Command::UpdateStdlib {} => ol_writeset_stdlib_upgrade(opt.db.unwrap()),
        Command::Reconfig {} => ol_create_reconfig_payload(opt.db.unwrap()),
        Command::Rescue { addresses } => ol_writset_encode_rescue(opt.db.unwrap(), addresses),
        Command::Timestamp {} => ol_writset_update_timestamp(opt.db.unwrap()),
        Command::Testnet {} => ol_writeset_set_testnet(opt.db.unwrap()),
        Command::DebugEpoch { addresses } => ol_writeset_debug_epoch(opt.db.unwrap(), addresses),
        //////// end 0L ////////
        
        Command::HaltNetwork => encode_halt_network_payload(),
        Command::BuildCustomScript {
            script_name,
            args,
            execute_as,
        } => encode_custom_script(
            &script_name,
            &serde_json::from_str::<serde_json::Value>(args.as_str())?,
            execute_as,
        ),
        Command::CreateDiemFrameworkRelease {
            chain_id,
            url,
            version,
            first_release,
            diem_version,
        } => {
            let release_name = opt
                .output
                .clone()
                .expect("Empty output path provided")
                .file_stem()
                .expect("Path should be a file")
                .to_str()
                .expect("Path name should be able to convert to string")
                .to_owned();

            let release_modules = diem_framework_modules(release_name.as_str());
            create_release(
                chain_id,
                url,
                version,
                first_release,
                &release_modules,
                diem_version,
                release_name.as_str(),
            )?
        }
        Command::VerifyDiemFrameworkRelease {
            url,
            chain_id,
            writeset_path,
            use_latest_version,
        } => {
            let release_name = load_latest_artifact(&chain_id)?.release_name;
            let writeset_payload = {
                let raw_bytes = std::fs::read(writeset_path.as_path()).unwrap();
                if let Ok(txn_payload) = bcs::from_bytes::<TransactionPayload>(raw_bytes.as_slice())
                {
                    match txn_payload {
                        TransactionPayload::WriteSet(payload) => payload,
                        _ => bail!("Unexpected transacton type"),
                    }
                } else {
                    let txn: Transaction = bcs::from_bytes(raw_bytes.as_slice())?;
                    match txn {
                        Transaction::GenesisTransaction(ws) => ws,
                        _ => bail!("Unexpected transacton type"),
                    }
                }
            };
            let release_modules = diem_framework_modules(release_name.as_str());
            verify_release(
                chain_id,
                url,
                &writeset_payload,
                &release_modules,
                use_latest_version,
            )?;
            return Ok(());
        }
    };
    let output_path = if let Some(p) = opt.output {
        p
    } else {
        bail!("Empty output path provided");
    };
    if opt.output_payload {
        save_bytes(
            bcs::to_bytes(&TransactionPayload::WriteSet(payload))
                .map_err(|_| format_err!("Transaction Serialize Error"))?,
            output_path,
        )
    } else {
        save_bytes(
            bcs::to_bytes(&Transaction::GenesisTransaction(payload))
                .map_err(|_| format_err!("Transaction Serialize Error"))?,
            output_path,
        )
    }
}
