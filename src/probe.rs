use anyhow::Result;
use libbpf_rs::{ObjectBuilder, Object};
use std::{fs, path::PathBuf};

pub struct Probe {
    bpf_object: Object,
    target_fn_name: String,
}

impl Probe {
    pub fn new() -> Result<Self> {
        let bpf_path = PathBuf::from("target").join("bpf").join("probe.bpf.o");
        let obj = ObjectBuilder::default()
            .open_file(bpf_path.to_str().unwrap())?
            .load()?;

        Ok(Self {
            bpf_object: obj,
            target_fn_name: "target_function".to_string(),
        })
    }

    pub async fn attach(&self) -> Result<()> {
        let binary_path = std::env::current_exe()?;
        let offset = self.find_function_offset(&self.target_fn_name)?;
        
        // Attach uprobe
        if let Some(prog) = self.bpf_object.prog("trace_enter") {
            prog.attach_uprobe(-1, binary_path.to_str().unwrap(), offset)?;
            println!("Attached entry probe at offset {:#x}", offset);
        }

        // Attach uretprobe
        if let Some(prog) = self.bpf_object.prog("trace_exit") {
            prog.attach_uretprobe(-1, binary_path.to_str().unwrap(), offset)?;
            println!("Attached exit probe at offset {:#x}", offset);
        }

        Ok(())
    }

    fn find_function_offset(&self, function_name: &str) -> Result<u64> {
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