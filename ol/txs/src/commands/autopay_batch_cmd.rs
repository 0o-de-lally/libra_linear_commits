//! `CreateAccount` subcommand

#![allow(clippy::never_loop)]

use abscissa_core::{Command, Options, Runnable};
use libra_types::transaction::{Script, SignedTransaction};
use crate::{entrypoint, sign_tx::sign_tx, submit_tx::{tx_params_wrapper, batch_wrapper, TxParams}};
use dialoguer::Confirm;
use std::path::PathBuf;
use ol_types::{autopay::PayInstruction, config::{TxType, IS_CI}};

/// command to submit a batch of autopay tx from file
#[derive(Command, Debug, Default, Options)]
pub struct AutopayBatchCmd {
    #[options(short = "f", help = "path of autopay_batch_file.json")]
    autopay_batch_file: PathBuf,
}


impl Runnable for AutopayBatchCmd {
    fn run(&self) {
        // Note: autopay batching needs to have id numbers to each instruction.
        // will not increment automatically, since this can lead to user error.
        let entry_args = entrypoint::get_args();

        let tx_params = tx_params_wrapper(TxType::Cheap).unwrap();

        let epoch = crate::epoch::get_epoch(&tx_params);
        println!("The current epoch is: {}", epoch);
        let instructions = PayInstruction::parse_autopay_instructions(&self.autopay_batch_file);
        let scripts = process_instructions(instructions, epoch);
        batch_wrapper(scripts, &tx_params, entry_args.no_send, entry_args.save_path)

    }
}

/// Process autopay instructions in to scripts
pub fn process_instructions(instructions: Vec<PayInstruction>, current_epoch: u64) -> Vec<Script> {
    // TODO: Check instruction IDs are sequential.
    instructions.into_iter().filter_map(|i| {
        let warning = format!(
            "Instruction {uid}:\nSend {percent_balance:.2?}% of your total balance every epoch {duration_epochs} times (until epoch {epoch_ending}) to address: {destination}?",
            uid = &i.uid,
            percent_balance = *&i.percent_balance_cast.unwrap() as f64 /100f64,
            duration_epochs = &i.duration_epochs.unwrap(),
            epoch_ending = &i.duration_epochs.unwrap() + current_epoch,
            destination = &i.destination,
        );
        println!("{}", &warning);
        // accept if CI mode.
        if *IS_CI { return Some(i) }            
        
        // check the user wants to do this.
        match Confirm::new().with_prompt("").interact().unwrap() {
          true => Some(i),
          _ =>  {
            println!("skipping instruction, going to next in batch");
            None
          }
        }            
    })
    .map(|i| {
      transaction_builder::encode_autopay_create_instruction_script(i.uid, i.destination, i.end_epoch, i.percent_balance_cast.unwrap())
    })
    .collect()
}
 
/// return a vec of signed transactions
pub fn sign_instructions(scripts: Vec<Script>, starting_sequence_num: u64, tx_params: &TxParams) -> Vec<SignedTransaction>{
  scripts.into_iter()
  .enumerate()
  .map(|(i, s)| {
    let seq = i as u64 + starting_sequence_num;
    sign_tx(&s, tx_params, seq, tx_params.chain_id).unwrap()
    })
  .collect()
}

#[test]
fn test_instruction_script_match() {
  use libra_types::account_address::AccountAddress;

  let script = transaction_builder::encode_autopay_create_instruction_script(1, AccountAddress::ZERO, 100, 1000);

  let instr = PayInstruction {
      uid: 1,
      destination: AccountAddress::ZERO,
      percent_inflow: None,
      percent_inflow_cast: None,
      percent_balance: Some(10.00),
      percent_balance_cast: Some(1000),
      fixed_payment: None,
      end_epoch: 100,
      duration_epochs: Some(10)
  };

  instr.check_instruction_safety(script).unwrap();

}