use crate::probe::Probe;
use anyhow::Result;
use tokio::task::LocalSet;

pub struct Manager {
    probe: Probe,
}

impl Manager {
    pub fn new() -> Result<Self> {
        Ok(Self {
            probe: Probe::new()?,
        })
    }

    pub async fn run(&self) -> Result<()> {
        println!("Running manager...");

        let local_set = LocalSet::new();
        let mut probe = self.probe;

        local_set.spawn_local(async move {
            probe.attach().await.expect("Failed to attach probe");
            println!("Attached probe for target_function");
        });

        local_set.await;
        Ok(())
    }
}
