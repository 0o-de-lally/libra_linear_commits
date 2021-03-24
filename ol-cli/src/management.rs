//! `management` functions

use crate::{check, prelude::app_config};
use anyhow::Error;
use reqwest::Url;
use serde::{Serialize, Deserialize};
use std::{collections::HashSet, env, fs::{self, File}, process::{Command, Stdio}};
use once_cell::sync::Lazy;

const BINARY_NODE: &str = "libra-node";
const BINARY_MINER: &str = "miner";

/// Process name and its set of PIDs ever spawned
#[derive(Serialize, Deserialize, Debug)]
struct Process {
    name: String,
    pids: HashSet<u32>,
}

/// Check if we are in prod mode
pub static IS_PROD: Lazy<bool> = Lazy::new(||{  
    match env::var("NODE_ENV") {
        Ok(val) => {
            match val.as_str() {
                "prod" =>  {true},
                // if anything else is set by user is false
                _ => {false} 
            }
        }
        // default to prod if nothig is set
        _ => {true}
    }
});
// /// Construct Lazy Binary
// pub static BINARY: Lazy<Binaries> = Lazy::new(||{        
//         match env::var("NODE_ENV") {
//         Ok(val) => {
//             match val.as_str() {
//                 "prod" =>  {},
//                 // defaults to prod unless something else was set
//                 _ => return Binaries {
//                     // build current source
//                     node: "cargo r -p libra-node --",
//                     miner: "cargo r -p miner --"
//                 } 
//             }
//         }
//         _ => {}// default to "prod" if not set
//     }
//     Binaries {
//         node: "libra-node",
//         miner: "miner"
//     }
// });

// /// what apps the mgmt command can run
// pub enum Binary {
//     /// Node
//     Node,
//     /// Miner
//     Miner
// }

// /// get a Child object formatted
// pub fn new_process(app: Binary) -> Command {

//     let app = match app {
//         Binary::Miner => "miner",
//         Binary::Node => "libra-node"
//     };
    
//     // match env::var("NODE_ENV") {
//     //     Ok(val) => {
//     //         match val.as_str() {
//     //             "prod" =>  {},
//     //             // any other node env defined is debug, otherwise is prod
//     //             _ => { 
//     //                 return std::process::Command::new("cargo")
//     //                 .arg(
//     //                     format!("r -p {} --", app.clone())
//     //                 )
//     //             }
//     //         }
//     //     }
//     //     _ => {}
//     // }

//     std::process::Command::new(app)
// }

/// Save PID
pub fn save_pid(name: &str, pid: u32) {
    // Handle empty case
    match check::DB_CACHE.get(name.as_bytes()) {
        Ok(Some(_value)) => { /* TODO */},
        Ok(None) => { 
            let process = Process { 
                name: name.to_owned(), pids: vec![pid].into_iter().collect() 
            };
            let serialized = serde_json::to_vec(&process).unwrap();
            check::DB_CACHE.put(name.as_bytes(), serialized).unwrap();
        },
        Err(e) => println!("RocksDB operational problem occured: {}", e),
    }    

    // Load, update and save
    let pids_loaded = check::DB_CACHE.get(name.as_bytes()).unwrap().unwrap();
    let mut process: Process = serde_json::de::from_slice(
        &pids_loaded
    ).unwrap();    
    process.pids.insert(pid);    
    let serialized = serde_json::to_vec(&process).unwrap();
    let _res = check::DB_CACHE.put(name.as_bytes(), serialized);
}

/// Kill all the processes that are running
pub fn kill_zombies(name: &str) {
    if check::DB_CACHE.get(name.as_bytes()).unwrap().is_none() {
        return;
    }

    let pids_loaded = check::DB_CACHE.get(name.as_bytes()).unwrap().unwrap();
    let process: Process = serde_json::de::from_slice(&pids_loaded).unwrap();

    println!("Killing zombie '{}' processes...", name);
    use nix::sys::signal::{self, Signal};
    for pid in process.pids.iter() {
        let _res = signal::kill(
            nix::unistd::Pid::from_raw(*pid as i32), Signal::SIGTERM
        );
    }
}

/// What kind of node are we starting
pub enum NodeType {
    /// Validator
    Validator,
    /// Fullnode
    Fullnode,
}

/// 
pub fn create_log_file(file_name: &str) -> File {
    let conf = app_config();
    let logs_dir = conf.workspace.node_home.join("logs/");
    fs::create_dir_all(&logs_dir).expect("could not create logs dir");
    let logs_file = logs_dir.join([file_name, ".log"].join(""));

    File::create(logs_file).expect("could not create log file")
}

/// Start Node, as fullnode
pub fn start_node(config_type: NodeType) -> Result<(), Error> {
    // Stop any processes we may have started and detached from.
    // Do not need to start

    // if is running do nothing
    if check::Check::new().node_running() {
        println!("node is already running. Exiting.");
        return Ok(())
    }

    // Create log file, and pipe stdout/err    
    let outputs = create_log_file("node");
    let errors = outputs.try_clone().unwrap();

    // Start as validator or fullnode
    // Get the yaml file
    let conf = app_config();
    let node_home = conf.workspace.node_home.to_str().unwrap();
    let config_file_name = match config_type {
        NodeType::Validator => {format!("{}validator.node.yaml", node_home)}
        NodeType::Fullnode => {format!("{}fullnode.node.yaml", node_home)}
    };

    // TODO: Boilerplate, figure out how to make generic
    let child = if *IS_PROD {
        Command::new("libra-node")
        .arg("--config")
        .arg(config_file_name)
        .stdout(Stdio::from(outputs))
        .stderr(Stdio::from(errors))
        .spawn()
        .expect("failed to execute child")
    } else {
        Command::new("cargo").args(&["r", "-p", "libra-node", "--"])
        .arg("--config")
        .arg(config_file_name)
        .stdout(Stdio::from(outputs))
        .stderr(Stdio::from(errors))
        .spawn()
        .expect("failed to execute child")
    };

    let pid = &child.id();
    save_pid(BINARY_NODE, *pid);
    println!("Started new '{}' with PID: {}", BINARY_NODE, pid);
    Ok(())
}

/// Stop node, as validator
pub fn stop_node() {
    kill_zombies(BINARY_NODE);
}

/// Start Miner
pub fn start_miner() {
    // Stop any processes we may have started and detached from.
    // if is running do nothing
    if check::Check::new().miner_running() {
        println!("node is already running. Exiting.");
        return
    }

    // Create log file, and pipe stdout/err
    let outputs = create_log_file("miner");
    let errors = outputs.try_clone().unwrap();

    // if node is NOT synced, then should use a backup/upstream node
    // let url = choose_rpc_node().unwrap();
    let use_backup = if check::Check::node_is_synced() {"--backup-url"} else { "" };
    
    // TODO: Boilerplate, figure out how to make generic
    let child = if *IS_PROD {
        Command::new("miner")
        .arg("start")
        .arg(use_backup)
        .stdout(Stdio::from(outputs))
        .stderr(Stdio::from(errors))
        .spawn()
        .expect("failed to execute child")
    } else {
        Command::new("cargo").args(&["r", "-p", "miner", "--"])
        .arg("start")
        .arg(use_backup)
        .stdout(Stdio::from(outputs))
        .stderr(Stdio::from(errors))
        .spawn()
        .expect("failed to execute child")
    };

    let pid = &child.id();
    save_pid(BINARY_MINER, *pid);
    println!("Started new {} with PID: {}", BINARY_MINER, pid);
}

/// Stop Miner
pub fn stop_miner() {
    kill_zombies(BINARY_MINER);
}

/// Choose a node to connect for rpc, local or upstream
pub fn choose_rpc_node() -> Option<Url> {
    let conf = app_config().to_owned();

    // check the node is in sync
    // Note this assumes that we can connect to local and to a backup.
    if check::Check::node_is_synced() {
        // always choose local node if in sync
        return conf.chain_info.default_node
    } else {
        // otherwise use a backup
        // TODO: check all backups in vector to see which connects
        Some(conf.chain_info
            .upstream_nodes
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
        )
    }
}

/// 
pub fn run_validator_wizard() -> bool {
    println!("Running validator wizard");
    dbg!(&BINARY_MINER);
    // TODO: switch between debug mode?
    let mut miner = std::process::Command::new(BINARY_MINER)
                        .arg("val-wizard")
                        .arg("--keygen")
                        .spawn()
                        .expect(&format!("failed to start miner app"));

    let exit_code = miner.wait().expect("failed to wait on miner"); 
    assert!(exit_code.success());

    true
}