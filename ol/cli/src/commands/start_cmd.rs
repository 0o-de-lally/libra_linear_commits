//! `start-cmd` subcommand

use std::process::exit;

use abscissa_core::{Command, Options, Runnable};
use crate::{
  check::{self, pilot}, entrypoint, node::client, node::node::Node, prelude::app_config
};

/// `start` subcommand

#[derive(Command, Debug, Options)]
pub struct StartCmd {
    /// Silent mode, defaults to verbose
    #[options(short = "s", help = "silent mode, no prints")]
    silent: bool,
  
    /// Check if DB needs to be restored.
    #[options(short = "r", help = "check if DB bootstraps if not will attempt restore")]
    restore: bool,

    // /// Check if DB needs to be restored.
    // #[options(short = "u", help = "fetches list of fullnode peers from onchain discovery, and saves to 0L.toml")]
    // refresh_upstream: bool,
}

impl Runnable for StartCmd {
    /// Start the application.
    fn run(&self) {
        let args = entrypoint::get_args();
        let is_swarm = *&args.swarm_path.is_some();
        let mut cfg = app_config().clone();
        let client = match client::pick_client(args.swarm_path, &mut cfg) {
            Ok(c) => c,
            Err(e) => {
              println!("ERROR: Could not create a client to connect to network, exiting. Message: {:?}", e );
              exit(1);
            },
        };
        let mut node = Node::new(client, &cfg, is_swarm);
        
        // if *&self.refresh_upstream {
        //     // fix 0L.toml file
        //     let cfg_path = cfg.workspace.node_home;
        //     match node.refresh_peers_update_toml(cfg_path.join("0L.toml")) {
        //         Ok(_) => return,
        //         Err(e) => {
        //           println!("ERROR: unable to update seed peers, message:{:?}", e);
        //           exit(1);
        //         },
        //     };
            
        // };
        if *&self.restore { pilot::maybe_restore_db(&mut node, !self.silent); }
        check::runner::run_checks(&mut node, true ,true, !self.silent, !self.silent);
    }
}