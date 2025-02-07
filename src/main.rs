use anyhow::Result;
use opentelemetry::global;
use opentelemetry_sdk::trace::TracerProvider as SdkTracerProvider;
use std::{thread::sleep, time::Duration};

mod manager;
mod probe;

#[no_mangle]
pub extern "C" fn target_function() {
    println!("🚀 target_function() is executing...");
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize OpenTelemetry with stdout exporter
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(opentelemetry_stdout::SpanExporter::default())
        .build();
    global::set_tracer_provider(provider);

    println!("Tracing initialized, waiting for setup...");
    sleep(Duration::from_secs(2));

    // Execute monitored function
    target_function();

    // Start eBPF monitoring
    let mut manager = manager::Manager::new()?;
    manager.run().await?;

    Ok(())
}
