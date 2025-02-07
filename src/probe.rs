use anyhow::Result;
use libbpf_rs::{Link, Object, ObjectBuilder}; // Removed UprobeAttachOpts
use std::{fs, path::PathBuf};
use object::{Object as ElfObject, ObjectSymbol, ObjectSymbolTable}; // Add ObjectSymbol trait

pub struct Probe {
    bpf_object: Object,
    target_fn_name: String,
    // Store links to keep probes attached
    _links: Vec<Link>,
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
            _links: Vec::new(),
        })
    }

    pub async fn attach(&mut self) -> Result<()> {
        let binary_path = std::env::current_exe()?;
        let offset = self.find_function_offset(&self.target_fn_name)?;
        let binary_path_str = binary_path.to_str().unwrap();

        // Attach uprobe (entry probe)
        if let Some(prog) = self.bpf_object.prog("trace_enter") {
            let link = prog.attach_uprobe(false, -1, binary_path_str, offset)?;
            println!("Attached entry probe at offset {:#x}", offset);
            self._links.push(link);
        }

        // Attach uretprobe (return probe)
        if let Some(prog) = self.bpf_object.prog("trace_exit") {
            let link = prog.attach_uprobe(true, -1, binary_path_str, offset)?;
            println!("Attached exit probe at offset {:#x}", offset);
            self._links.push(link);
        }

        Ok(())
    }

    fn find_function_offset(&self, function_name: &str) -> Result<u64> {
        let binary_path = std::env::current_exe()?;
        let binary_data = fs::read(&binary_path)?;
        let obj_file = object::File::parse(&*binary_data)?;

        if let Some(symbol_table) = obj_file.symbol_table() {
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
