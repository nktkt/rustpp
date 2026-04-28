use std::env;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.first().is_some_and(|arg| arg == "pp") {
        args.remove(0);
    }

    if args.is_empty() {
        args.push("build".to_string());
    }

    if is_rpp_command(&args[0]) {
        return run_rpp(args);
    }

    run_cargo(args)
}

fn is_rpp_command(command: &str) -> bool {
    matches!(
        command,
        "audit"
            | "build"
            | "check"
            | "effects"
            | "expand"
            | "lower"
            | "new"
            | "policy"
            | "prove"
            | "sbom"
            | "test"
    )
}

fn run_rpp(args: Vec<String>) -> ExitCode {
    let Some(rpp) = sibling_rpp_binary() else {
        eprintln!("cargo-pp: could not locate sibling `rpp` binary");
        return ExitCode::FAILURE;
    };

    run_command(Command::new(rpp).args(args), "rpp")
}

fn sibling_rpp_binary() -> Option<PathBuf> {
    let mut path = env::current_exe().ok()?;
    path.set_file_name(if cfg!(windows) { "rpp.exe" } else { "rpp" });
    path.exists().then_some(path)
}

fn run_cargo(args: Vec<String>) -> ExitCode {
    run_command(Command::new("cargo").args(args), "cargo")
}

fn run_command(command: &mut Command, name: &str) -> ExitCode {
    match command.status() {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(status) => ExitCode::from(status.code().unwrap_or(1) as u8),
        Err(error) => {
            eprintln!("cargo-pp: failed to run {name}: {error}");
            ExitCode::FAILURE
        }
    }
}
