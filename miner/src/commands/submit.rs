// `submit` subcommand

use abscissa_core::{Command, Options, Runnable};
use crate::{prelude::*};
use libra_types::{account_address::AccountAddress, transaction::authenticator::AuthenticationKey};
use libra_crypto::{
    test_utils::KeyPair,
    PrivateKey,
};
// use libra_crypto::test_utils::KeyPair;
use anyhow::Error;
// use client::{
//     account::{Account, AccountData, AccountTypeSpecifier},
//     keygen::KeyGen,
// };
use cli::{libra_client::LibraClient, AccountData, AccountStatus};
use reqwest::Url;
use std::{thread, path::PathBuf, time};
use libra_config::config::NodeConfig;
use libra_types::transaction::{Script, TransactionArgument, TransactionPayload};
use libra_types::{vm_error::StatusCode, transaction::helpers::*};
use crate::delay::delay_difficulty;
use stdlib::transaction_scripts;

#[derive(Command, Debug, Default, Options)]
pub struct SubmitCmd {
    #[options(help = "Provide a waypoint for the libra chain")]
    waypoint: String, //Option<Waypoint>,

    #[options(help = "Path of swarm config directory.")]
    path: PathBuf,

    #[options(help = "Already mined height to submit")]
    height: usize,
}

impl Runnable for SubmitCmd {
    fn run(&self) {
        println!("TESTING SUBMITTING WITH KEYPAIR TO SWARM");

        // submit_noop(self.path.clone(), self.height.clone());

        match submit_test(self.path.clone(), self.height.clone()){
            Ok(res) => {
                println!("Ok: {}", &res)
            }
            Err(err) => {
                println!("Err: {}", &err)

            }
        };
    }

}

fn submit_test(mut config_path: PathBuf, height_to_submit: usize ) -> Result<String, Error> {
    let miner_configs = app_config();
    let mut tower_height: usize = 1;

    // let file = fs::File::open(format!("{:?}/block_{}.json", &miner_configs.get_block_dir(), height_to_submit)).expect("Could not open block file");

    // let file = fs::File::open("./blocks/block_1.json").expect("Could not open block file");
    // let reader = BufReader::new(file);
    // let block: Block = serde_json::from_reader(reader).unwrap();
    // let challenge = block.preimage;
    // let proof = block.data;

    // NOTE: these fixtures are exactly what is submitted in the e2e test.
    //for comparison, we have the e2e test for the exact same script here: language/e2e-tests/src/tests/ol_e2e_test_redeem.rs
    // which you can run with cargo xtest -p language-e2e-tests ol_e2e_test_redeem -- --nocapture
    // let challenge = b"aa".to_vec();

    // let proof = hex::decode("005c9ee73ddaa19d050bc9944ac9ae5a16043fda1d0b20bfce0f7e18c1f7608eafb1e25b1fcf1e55cef3728bdcc695ecd51dcfafe297aa35a945d47e7b20266f501b0b7f636cd85f82a40cff7b57dfa96a521ff49f6daee00e65e1f44634443b818c088f40ef8dcb6cf4b0bdef336dd4c51aca0d6100e0acdcbd9bf26891a92e501bed6809762e0825624c82fbc38a692eac18457c0d74c126cfb62bdb665ee51a812758fc702865798b9f9cdb8d8236d068192f3f99df988f5ea55206353e0a54ca763350aae3ee10f4188c607e426fc52e7aa122b7df4b18cf2d0d50e964e3a721d83d4b9fee3090414965dfce75cd74c96fedcc269bc6baaf2a218865f1e63bffb02ac54d3e03d9018ec05a383a8b6acfc30d5e14db766d6cf01d5bc01a53ea9c0e55438b6eb9c3eba10682787aa1f57f75dfe69763e905b330b21bb6c8c0fb29327fe2085cfcbff7dd564e32ec2bcec261786d9598590c9abde29a96da79b56bb7bf171b413d3cd24b31b70df6b6488dd3cc4a5b26adced63f9e791b59c9ff3d7efff3fea92198d287287fd4f8f7b39917a6b7d8a53d4406bf41479560135deab1921c760b9480f16de2466bdbbb9ddd1a4fb2ea8f9378850064ba71ce01ea93f74aefb1bb7687c6cfc6f7fa8e492d611ac4a19a18309eb860d2c7b5f574b8d1b38132738946a5bbbb767352d58d2de16365e813665aa9921a9edec49dacabe500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001").unwrap();


    let challenge = hex::decode("3a18e936c07cb5760783d450f75c257e9a80a394bff06219637da0900df3b459").unwrap();

    let proof = hex::decode("006b55ef8b3dcca6a37dd5358cace06f9a636ebf1f414177e486f39a62a27f7a45ea31cb0579a6cca00f9f6bd5fd3613a648f28b0d58563154db6ed33ff6b88ce1a3a0dc4ce2e78cecf9ba69a992aa1b4b4dabbe8a2e49ad10592f10ea5a8050a984aeaa9a61ea9724894e84d29577e261fcdd537b53937366de30df8daaa6d3570da85565286995dfa1fc73c2ddea5ae9dc3e620cbcc0b01f236f90a33b60cdab3f0b64c16987eb5e9993ebece8011e650547e9ac2a2d71e70c71a09f7826e284055ecdb227822aa282d46739929d8edbdc53ff6f555baa8834505dc77e2331c012f261c6dcd3c8c0d21ed8fc755e015fcfcfc852a142737e14030514e092ed5e005656b267a11bc3e3c1bf25c1dec218cd62dccf858957e6e9b356e713cf4904eb5272636908f65cf1603a733ae2b962fe5a01021bd26536c768f2c4abfb438ff0ed733e43410e64dfaeeb2354a3284af6d1b1e1170965d3effd2aa85faabc31003edb1cfccd5084cd733d9aa67b86dab75e9cf299c42fbdec5ffce82fc4ab8422eb3254759f133f98dfc849f182d4657f76bc83c69d1af258b52b60610a562224b9c6a152484e15597f50a503b0ba6aa604ce8b9675f237e3c2ab6988e45ca2712645cffc3fa054c292c21d73ab3b146c34353284d2c68c3f1b05351f7c551f6f0ceb666556469d81495003eb4d43fb28e772622398f41db5ddacfdefa2bd2ee500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001").unwrap();

    config_path.push("../saved_logs/0/node.config.toml");

    let config = NodeConfig::load(&config_path)
        .unwrap_or_else(|_| panic!("Failed to load NodeConfig from file: {:?}", config_path));
    match &config.test {
        Some( conf) => {
            println!("Swarm Keys : {:?}", conf);
            tower_height = 0;
        },
        None =>{
            println!("test config does not set.");
        }
    }
    
    // TODO (LG): When we are not testing swarm.
    // let mut is_prod = true;
    // if is_prod {
    //     let hex_literal = format!("0x{}", &miner_configs.profile.account);
    //     let account_address = AccountAddress::from_hex_literal(&hex_literal).unwrap();
    //     dbg!(&account_address);
        
    //     let url = miner_configs.chain_info.node.as_ref().unwrap().parse::<Url>();
    //     // let url: Result<Url, Error> = miner_configs.chain_info.node;
    //     let parsed_waypoint: Result<Waypoint, Error> = miner_configs.chain_info.base_waypoint.parse();
        
    //     //unwrap().parse::<Waypoint>();
    //     let auth_key = &miner_configs.profile.auth_key;
    //     dbg!(auth_key);
    //     let privkey = &miner_configs.profile.operator_private_key;
    //     tower_height = height_to_submit;
    //     // let operator_keypair = Some(AccountKeyPair::load(privkey));
    //     dbg!(privkey);
    // }
    

    // Create a client object
    let mut client = LibraClient::new(
        Url::parse(format!("http://localhost:{}", config.rpc.address.port()).as_str()).unwrap(),
        config.base.waypoint.waypoint_from_config().unwrap().clone()
    ).unwrap();

    
    let mut private_key = config.test.unwrap().operator_keypair.unwrap();
    let auth_key = AuthenticationKey::ed25519(&private_key.public_key());

    let address = auth_key.derived_address();
    let account_state = client.get_account_state(address.clone(), true).unwrap();
    dbg!(&account_state);


    let mut sequence_number = 0u64;
    if account_state.0.is_some() {
        sequence_number = account_state.0.unwrap().sequence_number;
    }
    dbg!(&sequence_number);

    // Create the unsigned MinerState transaction script
    let script = Script::new(
        transaction_scripts::StdlibScript::Redeem.compiled_bytes().into_vec(),
        vec![],
        vec![
            TransactionArgument::U8Vector(challenge),
            TransactionArgument::U64(delay_difficulty()),
            TransactionArgument::U8Vector(proof),
            TransactionArgument::U64(tower_height as u64),
        ],
    );

    // Doing a no-op transaction here which will print
    // [debug] 000000000000000011e110  in the logs if successful.
    // NoOp => "ol_no_op.move",

    // let script = Script::new(
    //     transaction_scripts::StdlibScript::NoOp.compiled_bytes().into_vec(),
    //     vec![],
    //     vec![
    //         // TransactionArgument::U8Vector(challenge),
    //         // TransactionArgument::U64(delay_difficulty()),
    //         // TransactionArgument::U8Vector(proof),
    //         // TransactionArgument::U64(tower_height as u64),
    //     ],
    // );




    let keypair = KeyPair::from(private_key.take_private().clone().unwrap());
    dbg!(&keypair);
    // Plz Halp (ZM):
    // sign the transaction script
    let txn = create_user_txn(
        &keypair,
        TransactionPayload::Script(script),
        address,
        sequence_number,
        700_000,
        0,
        "GAS".parse()?,
        5000000, // for compatibility with UTC's timestamp.
    )?;

    // Plz Halp  (ZM):
    // get account_data struct
    let mut sender_account_data = AccountData {
        address,
        authentication_key: Some(auth_key.to_vec()),
        key_pair: Some(keypair),
        sequence_number,
        status: AccountStatus::Persisted,
    };

    dbg!(&sender_account_data);
    // Plz Halp (ZM):
    // // Submit the transaction with libra_client
    match client.submit_transaction(
        Some(&mut sender_account_data),
        txn
    ){
        Ok(_) => {
            ol_wait_for_tx(address, sequence_number, &mut client);
            Ok("Tx submitted".to_string())

        }
        Err(err) => Err(err)
    }

    // TODO (LG): Make synchronous to libra client.

    // Ok(())
    // Ok("Succcess".to_owned())
}

fn submit_noop(mut config_path: PathBuf, height_to_submit: usize ) -> Result<String, Error> {

    config_path.push("../saved_logs/0/node.config.toml");

    let config = NodeConfig::load(&config_path)
        .unwrap_or_else(|_| panic!("Failed to load NodeConfig from file: {:?}", config_path));
    match &config.test {
        Some( conf) => {
            println!("Swarm Keys : {:?}", conf);
        },
        None =>{
            println!("test config does not set.");
        }
    }

    // Create a client object
    let mut client = LibraClient::new(
        Url::parse(format!("http://localhost:{}", config.rpc.address.port()).as_str()).unwrap(),
        config.base.waypoint.waypoint_from_config().unwrap().clone()
    ).unwrap();

    
    let mut private_key = config.test.unwrap().operator_keypair.unwrap();
    let auth_key = AuthenticationKey::ed25519(&private_key.public_key());

    let address = auth_key.derived_address();
    let account_state = client.get_account_state(address.clone(), true).unwrap();
    dbg!(&account_state);


    let mut sequence_number = 0u64;
    if account_state.0.is_some() {
        sequence_number = account_state.0.unwrap().sequence_number;
    }
    dbg!(&sequence_number);

    // Doing a no-op transaction here which will print
    // [debug] 000000000000000011e110  in the logs if successful.
    // NoOp => "ol_no_op.move",

    let script = Script::new(
        transaction_scripts::StdlibScript::NoOp.compiled_bytes().into_vec(),
        vec![],
        vec![
            // TransactionArgument::U8Vector(challenge),
            // TransactionArgument::U64(delay_difficulty()),
            // TransactionArgument::U8Vector(proof),
            // TransactionArgument::U64(tower_height as u64),
        ],
    );

    let keypair = KeyPair::from(private_key.take_private().clone().unwrap());
    dbg!(&keypair);
    // Plz Halp (ZM):
    // sign the transaction script
    let txn = create_user_txn(
        &keypair,
        TransactionPayload::Script(script),
        address,
        sequence_number,
        700_000,
        0,
        "GAS".parse()?,
        5_000_000, // for compatibility with UTC's timestamp.
    )?;

    // Plz Halp  (ZM):
    // get account_data struct
    let mut sender_account_data = AccountData {
        address,
        authentication_key: Some(auth_key.to_vec()),
        key_pair: Some(keypair),
        sequence_number,
        status: AccountStatus::Persisted,
    };

    dbg!(&sender_account_data);
    // Plz Halp (ZM):
    // // Submit the transaction with libra_client
    match client.submit_transaction(
        Some(&mut sender_account_data),
        txn
    ){
        Ok(_) => {
            ol_wait_for_tx(address, sequence_number, &mut client);
            Ok("Tx submitted".to_string())

        }
        Err(err) => Err(err)
    }

    // TODO (LG): Make synchronous to libra client.

    // Ok(())
    // Ok("Succcess".to_owned())
}

fn ol_wait_for_tx (
    sender_address: AccountAddress,
    sequence_number: u64,
    client: &mut LibraClient) -> Result<(), Error>{
        if sequence_number == 0 {
            println!("First transaction, cannot query.");
            return Ok(());
        }

        let mut max_iterations = 10;
        println!(
            "waiting for tx from acc: {} with sequence number: {}",
            sender_address, sequence_number
        );

        loop {
            println!("test");
        //     stdout().flush().unwrap();

        //     // TODO: first transaction in sequence fails


            match &mut client
                .get_txn_by_acc_seq(sender_address, sequence_number - 1, true)
            {
                Ok(Some(txn_view)) => {
                    print!("txn_view: {:?}", txn_view);
                    if txn_view.vm_status == StatusCode::EXECUTED {
                        println!("transaction executed!");
                        if txn_view.events.is_empty() {
                            println!("no events emitted");
                        }
                        break Ok(());
                    } else {
                        // break Err(format_err!(
                        //     "transaction failed to execute; status: {:?}!",
                        //     txn_view.vm_status
                        // ));

                        break Ok(());

                    }
                }
                Err(e) => {
                    println!("Response with error: {:?}", e);
                }
                _ => {
                    print!(".");
                }
            }
            max_iterations -= 1;
        //     if max_iterations == 0 {
        //         panic!("wait_for_transaction timeout");
        //     }
            thread::sleep(time::Duration::from_millis(100));
    }
}