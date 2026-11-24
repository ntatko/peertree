use crate::json::{self, Value};
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

pub struct WorkspaceRequest {
    pub folder: PathBuf,
    pub clone_project: Option<String>,
    pub enable_peer: bool,
}

pub struct DesktopSession {
    port: u16,
    child: Option<Child>,
}

impl DesktopSession {
    pub fn start(script: &Path, request: WorkspaceRequest) -> Result<Self, String> {
        if !script.is_file() {
            return Err("The PeerTree repository service is missing.".into());
        }
        let folder = request
            .folder
            .canonicalize()
            .map_err(|error| error.to_string())?;
        if !folder.is_dir() {
            return Err("Choose a folder to open in PeerTree.".into());
        }
        let mut command = Command::new("/usr/bin/python3");
        command
            .args(["-B"])
            .arg(script)
            .args(["--desktop-ready", "--no-open"]);
        command.env("PATH", executable_path());
        if let Some(project) = request.clone_project {
            let project = project.trim();
            if project.is_empty() || project.chars().count() > 80 {
                return Err(
                    "Enter the project name shown on the integrator’s PeerTree window.".into(),
                );
            }
            command
                .arg("clone")
                .arg(folder)
                .arg(format!("--project={project}"));
        } else {
            command.arg("--repo").arg(folder);
        }
        if request.enable_peer {
            command.arg("--peer");
        }
        Self::spawn(command, Duration::from_secs(15))
    }

    pub fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn spawn(mut command: Command, timeout: Duration) -> Result<Self, String> {
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|error| format!("Could not start the PeerTree service. {error}"))?;
        let output = child.stdout.take().expect("stdout is piped");
        let (send, receive) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let mut line = String::new();
            let read = BufReader::new(output).take(8193).read_line(&mut line);
            let result = match read {
                Ok(0) => {
                    Err("The PeerTree service exited before reporting its local address.".into())
                }
                Ok(_) if line.len() > 8192 => {
                    Err("The PeerTree service sent an oversized startup reply.".into())
                }
                Ok(_) => parse_ready(&line),
                Err(error) => Err(error.to_string()),
            };
            let _ = send.send(result);
        });
        match receive.recv_timeout(timeout) {
            Ok(Ok((port, true))) => Ok(Self {
                port,
                child: Some(child),
            }),
            Ok(Ok((port, false))) => {
                reap(child, false);
                Ok(Self { port, child: None })
            }
            Ok(Err(error)) => {
                reap(child, true);
                Err(error)
            }
            Err(_) => {
                reap(child, true);
                Err("PeerTree did not report a local address in time.".into())
            }
        }
    }
}

impl Drop for DesktopSession {
    fn drop(&mut self) {
        if let Some(child) = self.child.take() {
            reap(child, true);
        }
    }
}

fn parse_ready(line: &str) -> Result<(u16, bool), String> {
    let value = json::parse(line)?;
    let reply = value.object()?;
    if let Some(error) = reply.get("error") {
        return Err(error.string()?.into());
    }
    let port = reply
        .get("port")
        .ok_or("Missing the local service port.")?
        .unsigned()?;
    let port = u16::try_from(port)
        .ok()
        .filter(|port| *port > 0)
        .ok_or("Invalid local service port.")?;
    let owned = match reply.get("owned") {
        Some(Value::Bool(owned)) => *owned,
        _ => return Err("Missing local service ownership.".into()),
    };
    Ok((port, owned))
}

fn executable_path() -> OsString {
    let mut directories = Vec::new();
    if let Some(inherited) = std::env::var_os("PATH") {
        directories.extend(std::env::split_paths(&inherited));
    }
    if let Some(home) = std::env::var_os("HOME") {
        directories.push(PathBuf::from(home).join(".local/homebrew/bin"));
    }
    directories
        .extend(["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"].map(PathBuf::from));
    std::env::join_paths(directories).unwrap_or_else(|_| "/usr/bin:/bin".into())
}

fn reap(mut child: Child, stop: bool) {
    if stop && child.try_wait().ok().flatten().is_none() {
        let _ = Command::new("/bin/kill")
            .arg("-TERM")
            .arg(child.id().to_string())
            .status();
    }
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if child.try_wait().ok().flatten().is_some() {
                return;
            }
            thread::sleep(Duration::from_millis(25));
        }
        let _ = child.kill();
        let _ = child.wait();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_accepts_a_local_port_and_typed_ownership() {
        assert_eq!(
            parse_ready(r#"{"port":49152,"owned":true}"#).unwrap(),
            (49152, true)
        );
        assert!(parse_ready(r#"{"url":"https://example.com","owned":false}"#).is_err());
        assert!(parse_ready(r#"{"port":65536,"owned":false}"#).is_err());
        assert_eq!(
            parse_ready(r#"{"error":"Folder is not a worktree."}"#).unwrap_err(),
            "Folder is not a worktree."
        );
    }

    #[test]
    fn attaches_to_an_existing_service_without_owning_it() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", r#"printf '%s\n' '{"port":49152,"owned":false}'"#]);
        let session = DesktopSession::spawn(command, Duration::from_secs(2)).unwrap();
        assert_eq!(session.origin(), "http://127.0.0.1:49152");
        assert!(session.child.is_none());
    }

    #[test]
    fn times_out_an_unresponsive_startup() {
        let mut command = Command::new("/bin/sleep");
        command.arg("5");
        let result = DesktopSession::spawn(command, Duration::from_millis(20));
        assert!(matches!(result, Err(error) if error.contains("in time")));
    }
}
