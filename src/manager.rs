use crate::probe::Probe;
use anyhow::Result;

pub struct Manager {
    probe: Probe,
}

impl Manager {
    pub fn new() -> Result<Self> {
        Ok(Self {
            probe: Probe::new()?,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        println!("Starting eBPF manager...");
        self.probe.attach().await?;

        // Keep the program running
        tokio::signal::ctrl_c().await?;
        println!("Shutting down...");

        Ok(())
    }
}
