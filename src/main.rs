mod probe;
mod manager;

use anyhow::Result;
use opentelemetry::global;
use opentelemetry_sdk::trace::TracerProvider as SdkTracerProvider;
use std::{thread::sleep, time::Duration};
use tracing::info;

#[inline(never)]
fn target_function() {
    println!("🚀 target_function() is executing...");
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    // Initialize OpenTelemetry
    let exporter = opentelemetry_stdout::SpanExporter::default();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter)
        .build();
    global::set_tracer_provider(provider);
    info!("OpenTelemetry tracing initialized");

    sleep(Duration::from_secs(5)); // Ensure tracing is ready

    target_function(); // This function should be traced

    let manager = manager::Manager::new()?;
    manager.run().await?;
    Ok(())
}
