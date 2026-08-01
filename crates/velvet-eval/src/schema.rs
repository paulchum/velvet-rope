use std::fs;
use std::path::Path;

use crate::Result;

pub fn write_thread_schema(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(
        path,
        serde_json::to_string_pretty(&velvet_core::thread_schema_json())?,
    )?;
    Ok(())
}
