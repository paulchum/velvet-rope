use std::env;
use std::path::PathBuf;

use velvet_policy_loader::{policy_schema_json, schema_markdown, write_generated_artifacts};

fn main() {
    match env::args().nth(1).as_deref() {
        Some("--docs") => print!("{}", schema_markdown()),
        Some("--write") => {
            let schema_path = env::args()
                .nth(2)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("schemas/policy-v1alpha1.schema.json"));
            let docs_path = env::args()
                .nth(3)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("docs/policy-schema.md"));
            if let Err(error) = write_generated_artifacts(&schema_path, &docs_path) {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
        None | Some("--json") => {
            println!(
                "{}",
                serde_json::to_string_pretty(&policy_schema_json())
                    .expect("policy schema should serialize")
            );
        }
        Some(other) => {
            eprintln!("unknown option: {other}");
            std::process::exit(2);
        }
    }
}
