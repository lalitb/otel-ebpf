use libbpf_rs::{ObjectBuilder, MapCore};
use anyhow::Result;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct Probe {
    pub(crate) bpf_object: Arc<Mutex<libbpf_rs::Object>>,
    name: String,
}

impl Probe {
    pub fn new() -> Result<Self> {
        let out_dir = std::env::var("OUT_DIR").unwrap_or_else(|_| "target/debug".to_string());
        let bpf_path = PathBuf::from(out_dir).join("probe.bpf.o");

        let open_obj = ObjectBuilder::default().open_file(bpf_path.to_str().unwrap())?;
        let obj = open_obj.load()?;
        println!("Loaded eBPF program for target_function");

        Ok(Self {
            bpf_object: Arc::new(Mutex::new(obj)),
            name: "target_function".to_string(),
        })
    }

    pub async fn attach(&mut self) -> Result<()> {
        let bpf_object = self.bpf_object.lock().await;
        let binary_path = std::env::current_exe()?;
        let offset = Self::find_function_offset("target_function")?;

        println!("Found target_function at offset: {:#x}", offset);

        // Attach entry probe (uprobe)
        if let Some(prog) = bpf_object.prog("trace_enter") {
            prog.attach_uprobe(-1, binary_path.to_str().unwrap(), offset)?;
            println!("Attached uprobe for target_function");
        }

        // Attach exit probe (uretprobe)
        if let Some(prog) = bpf_object.prog("trace_exit") {
            prog.attach_uretprobe(-1, binary_path.to_str().unwrap(), offset)?;
            println!("Attached uretprobe for target_function");
        }

        Ok(())
    }

    fn find_function_offset(function_name: &str) -> Result<u64> {
        let binary_path = std::env::current_exe()?;
        let binary_data = fs::read(&binary_path)?;
        let obj_file = object::File::parse(&*binary_data)?;

        for sym in obj_file.dynamic_symbols() {
            if let Ok(name) = sym.name() {
                if name == function_name {
                    return Ok(sym.address());
                }
            }
        }
        Err(anyhow::anyhow!("Function {} not found", function_name))
    }
}
