use std::env;
use std::path::PathBuf;

use velvet_policy_loader::run_policy_tests;

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 2 {
        eprintln!("usage: velvet-policy-test <policy.yaml> <tests.yaml>");
        std::process::exit(2);
    }
    match run_policy_tests(&PathBuf::from(&args[0]), &PathBuf::from(&args[1])) {
        Ok(()) => {}
        Err(errors) => {
            for error in errors {
                eprintln!("{error}");
            }
            std::process::exit(1);
        }
    }
}
