use std::{path::PathBuf, sync::Arc};

use diem_config::config::NodeConfig;
use diemdb::DiemDB;
use move_core_types::identifier::Identifier;
use storage_interface::DbReaderWriter;
use move_vm_runtime::move_vm::MoveVM;

// What I want to do: 
// 1) take a snapshot of an epoch. 
// 2) load a fresh database from it. 
// 3) submit the management "RemoveValidator" transaction.
// 4) only then, start the nodes.

fn test_apply_write(path: PathBuf) -> anyhow::Result<()>{
  let n = NodeConfig::default();

  let (_, db_rw) =   DbReaderWriter::wrap(
        DiemDB::open(
            &n.storage.dir(),
            false, /* readonly */
            n.storage.prune_window,
            n.storage.rocksdb_config,
        )
        .expect("DB should open."),
    );

  let vm = MoveVM::new();
  let mut sess = vm.new_session(&db_rw);

    // let fun_name = Identifier::new("foo").unwrap();
    // let mut gas_status = GasStatus::new_unmetered();
    // let context = NoContextLog::new();

  //   let args: Vec<_> = args
  //       .into_iter()
  //       .map(|val| val.simple_serialize().unwrap())
  //       .collect();

  //   sess.execute_function(
  //       &module_id,
  //       &fun_name,
  //       ty_args,
  //       args,
  //       &mut gas_status,
  //       &context,
  //   )?;

  Ok(())
}



fn get_db(node_config: NodeConfig) -> (Arc<DiemDB>, DbReaderWriter){

  DbReaderWriter::wrap(
        DiemDB::open(
            &node_config.storage.dir(),
            false, /* readonly */
            node_config.storage.prune_window,
            node_config.storage.rocksdb_config,
        )
        .expect("DB should open."),
    )
}

    