mod inventory;
mod policy;
mod replica;

use peertree::json;
use std::env;
use std::ffi::OsString;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const AGENT_HELP: &str = "PeerTree agent CLI\n\
Usage: peertree [--repo PATH] [--json] COMMAND\n\n\
  pr list|submit|diff|comment|review|merge   Inspect and update branch reviews\n\
  checks run                               Run committed local checks\n\
  sync [BRANCH]                            Import or export an exchange, or sync a branch\n\
  policy show                              Inspect the committed merge policy\n\
  team identity|trust|integrator|pipeline  Manage the clone's local team settings\n\
  publish                                  Publish shared branch tips\n\n\
Use --help after a command for its arguments.";

fn packaged_script(executable: &Path) -> Option<PathBuf> {
    let parent = executable.parent()?;
    if parent.file_name()? == "Helpers" {
        let script = parent.parent()?.join("Resources").join("app.py");
        return script.is_file().then_some(script);
    }
    None
}

fn app_script(executable: &Path) -> Result<PathBuf, String> {
    env::var_os("PEERTREE_APP")
        .map(PathBuf::from)
        .or_else(|| packaged_script(executable))
        .or_else(|| {
            executable
                .ancestors()
                .skip(1)
                .take(5)
                .filter(|path| path.join("Cargo.toml").is_file())
                .map(|path| path.join("app.py"))
                .find(|path| path.is_file())
        })
        .ok_or_else(|| {
            "Could not locate the PeerTree application. Set PEERTREE_APP to app.py.".into()
        })
}

fn core_request(operation: &OsString) -> Result<(), String> {
    let mut body = String::new();
    io::stdin()
        .take(2_097_153)
        .read_to_string(&mut body)
        .map_err(|error| error.to_string())?;
    if body.len() > 2_097_152 {
        return Err("The PeerTree core request exceeds 2 MB.".into());
    }
    let request = json::parse(&body)?;
    let response = match operation.to_str() {
        Some("__policy") => policy::request(request)?,
        Some("__tracking") => replica::refresh(request)?,
        Some("__inventory") => inventory::plan(request)?,
        _ => return Err("Unknown PeerTree core operation.".into()),
    };
    println!("{}", response.encode());
    Ok(())
}

fn main() -> ExitCode {
    let arguments: Vec<OsString> = env::args_os().skip(1).collect();
    if let Some(operation) = arguments
        .first()
        .filter(|arg| *arg == "__policy" || *arg == "__tracking" || *arg == "__inventory")
    {
        return match core_request(operation) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    if arguments.is_empty()
        || arguments.as_slice() == [OsString::from("--help")]
        || arguments.as_slice() == [OsString::from("-h")]
    {
        println!("{AGENT_HELP}");
        return ExitCode::SUCCESS;
    }
    if arguments.as_slice() == [OsString::from("--version")] {
        println!("peertree-core {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }

    let executable = match env::current_exe() {
        Ok(path) => path,
        Err(error) => return failure(&arguments, &error.to_string()),
    };
    let script = match app_script(&executable) {
        Ok(path) => path,
        Err(error) => return failure(&arguments, &error),
    };
    let python = env::var_os("PEERTREE_PYTHON").unwrap_or_else(|| "/usr/bin/python3".into());
    match Command::new(python)
        .arg("-B")
        .arg(script)
        .arg("--agent-cli")
        .args(&arguments)
        .env("PEERTREE_CORE", executable)
        .status()
    {
        Ok(status) => ExitCode::from(status.code().unwrap_or(1) as u8),
        Err(error) => failure(
            &arguments,
            &format!("Could not run the PeerTree repository service. {error}"),
        ),
    }
}

fn failure(arguments: &[OsString], error: &str) -> ExitCode {
    if arguments.iter().any(|arg| arg == "--json") {
        println!("{{\"ok\":false,\"error\":{}}}", json::quote(error));
    } else {
        eprintln!("{error}");
    }
    ExitCode::FAILURE
}
