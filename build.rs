use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("---->cargo:rerun-if-changed=build.rs");
    // Get the output directory for compiled artifacts
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR environment variable not set");

    // Define the path to the eBPF source file
    let bpf_source = "probe.bpf.c";
    let bpf_output = PathBuf::from(&out_dir).join("probe.bpf.o");

    // Compile the eBPF program
    let status = Command::new("clang")
        .args(&[
            "-O2",
            "-g", // Enable debug symbols (needed for BTF)
            "-target",
            "bpf",
            "-c",
            bpf_source,
            "-o",
            bpf_output.to_str().unwrap(),
            "-D__KERNEL__",      // Required for kernel eBPF
            "-D__BPF_TRACING__", // Required for tracing BPF programs
            "-Wall",
            "-Werror",
        ])
        .status()
        .expect("Failed to execute clang");

    if !status.success() {
        panic!("eBPF compilation failed");
    }

    // Inform Cargo to watch the eBPF source file for changes
    println!("cargo:rerun-if-changed={}", bpf_source);
    println!("cargo:rustc-env=BPF_OBJECT={}", bpf_output.display());
}
