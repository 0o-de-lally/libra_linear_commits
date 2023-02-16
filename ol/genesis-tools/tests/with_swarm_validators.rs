//! Tests for the `make_genesis` binary.
mod support;

use diem_types::transaction::authenticator::AuthenticationKey;
use ol_genesis_tools::compare;
use ol_genesis_tools::{
    fork_genesis::make_recovery_genesis_from_vec_legacy_recovery
};
use ol_types::legacy_recovery::{LegacyRecovery, ValStateRecover, OperRecover};
use std::fs;
use support::path_utils::json_path;
use ol_smoke_tests::ol_test_config_builder::test_config;

#[test]
// test that a genesis blob created from struct, will actually contain the data
fn replace_vals_with_swarm_val() {

  let genesis_vals = vec!["ADCB1D42A46292AE89E938BD982F2867".parse().unwrap()];
  let json = json_path().parent().unwrap().join("single_json_entry.json");

  let json_str = fs::read_to_string(json.clone()).unwrap();
  let user_accounts: Vec<LegacyRecovery> = serde_json::from_str(&json_str).unwrap();

    // dbg!(&mock_val);

    let temp_genesis_blob_path = json_path().parent().unwrap().join("fork_genesis.blob");

    let (v, o) = get_val_from_test_config();

    make_recovery_genesis_from_vec_legacy_recovery(
      &user_accounts,
      genesis_vals.clone(),
      temp_genesis_blob_path.clone(), 
      true,
      Some((&[v], &[o])),
    )
    .unwrap();

    assert!(temp_genesis_blob_path.exists(), "file not created");

        match compare::compare_json_to_genesis_blob(json, temp_genesis_blob_path.clone()){
        Ok(list) => {
          if !list.is_empty() {
            println!("{:?}", &list);
            fs::remove_file(&temp_genesis_blob_path).unwrap();
            assert!(false, "list is not empty");
          }
        },
        Err(_e) => assert!(false, "error comparison"),
    }

    // the val set should be different
    match compare::check_val_set(genesis_vals, temp_genesis_blob_path.clone()){
        Ok(_) => {},
        Err(_) => {
          assert!(false, "validator set not correct");
          fs::remove_file(&temp_genesis_blob_path).unwrap()
        },
    }

    fs::remove_file(temp_genesis_blob_path).unwrap();
}


// use the test acount generator to create keys so we can have a functional
// validator set. We will overwrite the validator set of the production genesis blob for testing.
fn get_val_from_test_config() -> (ValStateRecover, OperRecover){
  let cfg = test_config(true);
  let test_cfg = cfg.0.test.unwrap();

  let owner_auth = AuthenticationKey::ed25519(&test_cfg.owner_key.as_ref().unwrap().public_key());
  let val_account = owner_auth.derived_address();
  let oper_acc = AuthenticationKey::ed25519(&test_cfg.operator_key.as_ref().unwrap().public_key()).derived_address();

  let v = ValStateRecover {
      val_account,
      operator_delegated_account: oper_acc.clone(),
      val_auth_key: owner_auth,
  };

  let o = OperRecover {
    operator_account: oper_acc,
    operator_auth_key: AuthenticationKey::ed25519(&test_cfg.operator_key.as_ref().unwrap().public_key()),
    validator_to_represent: val_account,
    operator_consensus_pubkey: bcs::to_bytes(&test_cfg.execution_key.unwrap().public_key()).unwrap(),
    validator_network_addresses: bcs::to_bytes(&vec![cfg.0.validator_network.unwrap().listen_address]).unwrap() ,
    fullnode_network_addresses: bcs::to_bytes(&vec![&cfg.0.full_node_networks.first().unwrap().listen_address]).unwrap(),
  };

  (v, o)
}