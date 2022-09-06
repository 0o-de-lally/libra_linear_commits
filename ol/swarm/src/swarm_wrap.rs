use std::num::NonZeroUsize;
use forge::{LocalSwarm, LocalFactory};
use rand::rngs::OsRng;

pub struct OLSwarm(LocalSwarm);

impl OLSwarm {
    pub async fn new() -> anyhow::Result<Self> {
      
      let b = LocalFactory::from_workspace().unwrap(); // TODO
      let a = NonZeroUsize::new(1).unwrap();
      let s = b.new_swarm(OsRng, a).await?;
      Ok(Self(s))
    }
    pub fn get_inner(self) -> LocalSwarm{
      self.0
    }
}