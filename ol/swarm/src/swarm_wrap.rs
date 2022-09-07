use std::{num::NonZeroUsize, collections::HashMap};
use forge::{LocalSwarm, LocalFactory, LocalSwarmBuilder, Version, LocalVersion, cargo};
use rand::rngs::OsRng;

pub struct OLSwarm(LocalSwarm);

impl OLSwarm {
    pub async fn run() -> anyhow::Result<Self> {
      
      let b = LocalFactory::from_workspace().unwrap(); // TODO
      let a = NonZeroUsize::new(1).unwrap();
      let s = b.new_swarm(OsRng, a).await?;
      Ok(Self(s))
    }

    pub fn new() -> anyhow::Result<Self> {
      
      let b = LocalFactory::from_workspace().unwrap(); // TODO
      // let l = LocalSwarmBuilder::new().build(OsRng)?;
      // LocalSwarm::builder(versions)
      todo!()
      // Ok(Self(l))
    }

    pub fn get_inner(self) -> LocalSwarm{
      self.0
    }
}
