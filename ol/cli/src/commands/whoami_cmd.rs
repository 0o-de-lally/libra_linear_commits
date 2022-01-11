//! `whoami` subcommand

#![allow(clippy::never_loop)]

use std::{net::Ipv4Addr, path::PathBuf, process::exit};

use abscissa_core::{Command, Options, Runnable};
use anyhow::{anyhow, Error};
use diem_config::{config::NodeConfig, network_id::NetworkId};
use diem_crypto::x25519;
use ol_keys::{scheme::KeyScheme, wallet};
use ol_types::account::ValConfigs;

use crate::prelude::app_config;

/// `version` subcommand
#[derive(Command, Debug, Default, Options)]
pub struct WhoamiCmd {
    #[options(short = "c", help = "check a local file for the IDs published")]
    check_yaml: Option<PathBuf>,
}

impl Runnable for WhoamiCmd {
    /// Print version message
    fn run(&self) {
        let app_cfg = app_config().to_owned();
        
        if let Some(f) = &self.check_yaml {
            display_id_in_file(f).unwrap_or_else(|e| {
                println!("error reading yaml file: {:?}", &e);
                exit(1);
            });
            return;
        }

        let (auth, addr, wallet) = wallet::get_account_from_prompt();

        let val_cfg = ValConfigs::new(
            None,
            KeyScheme::new(&wallet),
            app_cfg.profile.ip,
            app_cfg.profile.vfn_ip.unwrap_or("0.0.0.0".parse().unwrap()),
            None,
            None,
        );

        println!("\n0L ACCOUNT\n");
        println!("address: {}", addr);
        println!("authentication key (for account creation): {}\n", auth);

        let scheme = KeyScheme::new(&wallet);
        println!("----- pub ed25519 keys -----\n");
        println!("key 0: {}\n", scheme.child_0_owner.get_public());
        println!("key 1: {}\n", scheme.child_1_operator.get_public());
        println!("key 2: {}\n", scheme.child_2_val_network.get_public());
        println!("key 3: {}\n", scheme.child_3_fullnode_network.get_public());
        println!("key 4: {}\n", scheme.child_4_consensus.get_public());
        println!("key 5: {}\n", scheme.child_5_executor.get_public());

        println!("----- pub x25519 network keys -----\n");
        // println!("0 key: {}\n", hex::encode());

        let val_net_priv = scheme.child_2_val_network.get_private_key().to_bytes();

        let key = x25519::PrivateKey::from_ed25519_private_bytes(&val_net_priv)
            .expect("Unable to convert key");
        println!(
            "validator network key: {:?}\n",
            key.public_key().to_string()
        );

        let fn_net_priv = scheme.child_3_fullnode_network.get_private_key().to_bytes();

        let key = x25519::PrivateKey::from_ed25519_private_bytes(&fn_net_priv)
            .expect("Unable to convert key");
        println!(
            "fullnode network key: {:?}\n",
            &key.public_key().to_string()
        );

        println!("----- noise protocol addresses -----\n");

        println!("Validator (encrypted) address on VALIDATOR network\n");
        println!("{}\n", val_cfg.op_val_net_addr_for_vals);

        println!("Validator address on PRIVATE VFN Network\n");
        println!("{}\n", val_cfg.op_val_net_addr_for_vfn);

        println!("VFN address on PUBLIC fullnode network\n");
        println!("{}\n", val_cfg.op_vfn_net_addr_for_public);
    }
}

fn display_id_in_file(yaml_path: &PathBuf) -> Result<(), Error> {
    let node_conf = NodeConfig::load(&yaml_path).map_err(|e| {
        anyhow!(
            "could not read the node config file {:?}, message: {:?} ",
            &yaml_path,
            &e
        )
    })?;
    let ip = get_my_ip()?;

    // TODO: fetch this from 0L.toml
    let vfn_ip: Ipv4Addr = "0.0.0.0".parse().unwrap();

    println!("\n ACTUAL NETWORK IDs IN {:?}\n", yaml_path.as_os_str());
    println!("----- noise protocol addresses -----\n");

    if let Some(val_net) = &node_conf.validator_network {
        let peer_id = &val_net.peer_id();
        let priv_key = &val_net.identity_key();
        let pub_key = priv_key.public_key();
        let addr = ValConfigs::make_unencrypted_addr(
            &ip,
            pub_key,
            NetworkId::Validator,
        );
        println!("Address (encrypted) on VALIDATOR network\n");
        println!("{:?}:\n", &peer_id);
        println!("{:?}\n", &addr);
    };

    node_conf.full_node_networks.into_iter().for_each(|n| {
        match n.network_id {
            NetworkId::Validator => {
                println!(
                    "Something is wrong, there should be no validator config in full_node_networks"
                );
            }
            NetworkId::Public => {
                println!("Address on PUBLIC fullnode network\n");

                let peer_id = &n.peer_id();
                let priv_key = &n.identity_key();
                let pub_key = priv_key.public_key();
                let addr = ValConfigs::make_unencrypted_addr(
                    &ip,
                    pub_key,
                    NetworkId::Validator,
                );
                println!("{:?}:\n", &peer_id);
                println!("{:?}\n", &addr);
            }
            NetworkId::Private(_) => {
                println!("Address on PRIVATE VFN Network\n");

                let peer_id = &n.peer_id();
                let priv_key = &n.identity_key();
                let pub_key = priv_key.public_key();
                let addr = ValConfigs::make_unencrypted_addr(
                    &vfn_ip,
                    pub_key,
                    NetworkId::Private("vfn".to_string()),
                );
                println!("{:?}:\n", &peer_id);
                println!("{:?}\n", &addr);
            }
        };
    });

    Ok(())
}

fn get_my_ip() -> Result<Ipv4Addr, Error> {
   Ok( match reqwest::blocking::get("https://ifconfig.me") {
        Ok(resp) => {
            let ip_str = resp.text()?;
            ip_str.parse()?
        }
        Err(_) => {
            println!("couldn't detect external IP address, using 0.0.0.0 for display");
            "0.0.0.0".parse()?
        }
    }
  )
}
