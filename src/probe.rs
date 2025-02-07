use anyhow::Result;
use libbpf_rs::UprobeAttachType;
use libbpf_rs::{Object as BpfObject, ObjectBuilder};
use object::Object as ElfObject;
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
        let opts = libbpf_rs::UprobeAttachOpts::default();

        // Attach uprobe
        if let Some(prog) = self.bpf_object.progs().find(|p| p.name() == "trace_enter") {
            prog.attach_uprobe_opts(
                UprobeAttachType::Entry,
                -1,
                binary_path.to_str().unwrap(),
                offset,
                &opts,
            )?;
            println!("Attached entry probe at offset {:#x}", offset);
        }

        // Attach uretprobe
        if let Some(prog) = self.bpf_object.progs().find(|p| p.name() == "trace_exit") {
            prog.attach_uprobe_opts(
                UprobeAttachType::Return,
                -1,
                binary_path.to_str().unwrap(),
                offset,
                &opts,
            )?;
            println!("Attached exit probe at offset {:#x}", offset);
        }

        Ok(())
    }

    fn find_function_offset(&self, function_name: &str) -> Result<u64> {
        let binary_path = std::env::current_exe()?;
        let binary_data = fs::read(&binary_path)?;
        let obj_file = object::File::parse(&*binary_data)?;

        if let Some(symbol_table) = obj_file.dynamic_symbol_table() {
            for sym in symbol_table.symbols() {
                if let Ok(name) = sym.name() {
                    if name == function_name {
                        return Ok(sym.address());
                    }
                }
            }
        }
        Err(anyhow::anyhow!("Function {} not found", function_name))
    }
}
