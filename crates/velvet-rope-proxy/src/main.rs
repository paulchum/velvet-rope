#[tokio::main]
async fn main() -> std::process::ExitCode {
    match velvet_rope_proxy::run_cli().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("velvet-rope-proxy: {error:#}");
            std::process::ExitCode::from(1)
        }
    }
}
