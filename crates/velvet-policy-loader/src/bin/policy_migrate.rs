use std::env;
use std::path::PathBuf;

use velvet_policy_loader::migrate_paths;

fn main() {
    let paths = env::args().skip(1).map(PathBuf::from).collect::<Vec<_>>();
    if paths.is_empty() {
        eprintln!("usage: velvet-policy-migrate <path> [<path> ...]");
        std::process::exit(2);
    }
    match migrate_paths(&paths) {
        Ok(_) => {}
        Err(errors) => {
            for error in errors {
                eprintln!("{error}");
            }
            std::process::exit(1);
        }
    }
}
