fn main() -> std::process::ExitCode {
    match velvet_eval::cli::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("velvet-eval: {error}");
            std::process::ExitCode::from(1)
        }
    }
}
