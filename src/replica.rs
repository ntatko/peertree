use crate::json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const FETCH: &str = "+refs/heads/*:refs/remotes/team/*";
const ALTERNATES: &str = "../../../objects\n";

fn git(root: &Path, arguments: &[&str], input: Option<&str>) -> Result<Output, String> {
    let mut child = Command::new("git")
        .current_dir(root)
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(arguments)
        .env_remove("GIT_DIR")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .env_remove("GIT_NAMESPACE")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| error.to_string())?;
    if let Some(value) = input {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(value.as_bytes())
            .map_err(|error| error.to_string())?;
    }
    child.wait_with_output().map_err(|error| error.to_string())
}

fn successful(output: Output) -> Result<String, String> {
    if output.status.success() {
        return String::from_utf8(output.stdout).map_err(|error| error.to_string());
    }
    let detail = String::from_utf8_lossy(&output.stderr);
    Err(if detail.trim().is_empty() {
        format!("Git exited with {}.", output.status)
    } else {
        detail.trim().to_owned()
    })
}

fn run(root: &Path, arguments: &[&str]) -> Result<String, String> {
    successful(git(root, arguments, None)?)
}

fn config(root: &Path, key: &str) -> Result<Option<String>, String> {
    let output = git(root, &["config", "--get-all", key], None)?;
    if output.status.code() == Some(1) {
        return Ok(None);
    }
    Ok(Some(successful(output)?.trim_end_matches('\n').to_owned()))
}

fn set_managed_remote(root: &Path, url: &str) -> Result<(), String> {
    let keys = [
        ("remote.team.url", url),
        ("remote.team.fetch", FETCH),
        ("remote.team.pushurl", "/dev/null"),
        ("remote.team.tagopt", "--no-tags"),
    ];
    let marker = config(root, "remote.team.peertreeManaged")?;
    let existing = run(root, &["remote"])?;
    if marker.as_deref() != Some("true") {
        if marker.is_some() || existing.lines().any(|name| name == "team") {
            return Err(
                "The Git remote team already exists. Rename it before enabling PeerTree tracking."
                    .into(),
            );
        }
        run(
            root,
            &["config", "--local", "remote.team.peertreeManaged", "true"],
        )?;
    }
    for (key, expected) in keys {
        let current = config(root, key)?;
        if current.as_deref() == Some(expected) {
            continue;
        }
        if current.is_some() {
            return Err(format!(
                "PeerTree's managed team remote has an unexpected {key}."
            ));
        }
        run(root, &["config", "--local", "--", key, expected])?;
    }
    Ok(())
}

fn required<'a>(input: &'a BTreeMap<String, Value>, key: &str) -> Result<&'a Value, String> {
    input
        .get(key)
        .ok_or_else(|| format!("Missing {key} for the local replica."))
}

pub fn refresh(input: Value) -> Result<Value, String> {
    let input = input.object()?;
    let root = Path::new(required(input, "root")?.string()?);
    let tips = required(input, "tips")?.object()?;
    let default = input.get("default").and_then(|value| value.string().ok());
    let common = run(
        root,
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
    )?;
    let common = Path::new(common.trim_end_matches('\n'));
    let format = run(root, &["rev-parse", "--show-object-format"])?;
    let width = if format.trim_end() == "sha256" {
        64
    } else {
        40
    };

    for (branch, oid) in tips {
        let oid = oid.string()?;
        if oid.len() != width || !oid.bytes().all(|ch| ch.is_ascii_hexdigit()) {
            return Err(format!("Invalid Git object ID for {branch}."));
        }
        run(root, &["check-ref-format", &format!("refs/heads/{branch}")])?;
        if run(root, &["cat-file", "-t", oid])?.trim_end() != "commit" {
            return Err(format!("Published branch {branch} must name a commit."));
        }
    }

    let cache = common.join("neighbor-review").join("team.git");
    let cache_path = cache
        .to_str()
        .ok_or("The Git directory must have a UTF-8 path.")?;
    set_managed_remote(root, cache_path)?;
    if let Ok(info) = fs::symlink_metadata(&cache) {
        if !info.file_type().is_dir() {
            return Err("PeerTree's local replica path is not a directory.".into());
        }
    }
    if !cache.join("HEAD").is_file() {
        run(
            root,
            &[
                "init",
                "--bare",
                "--quiet",
                &format!("--object-format={}", format.trim_end()),
                cache_path,
            ],
        )?;
    }
    let alternates = cache.join("objects/info/alternates");
    if alternates.exists() {
        let existing = fs::read_to_string(&alternates).map_err(|error| error.to_string())?;
        if existing != ALTERNATES {
            return Err("PeerTree's local replica has an unexpected object store.".into());
        }
    } else {
        fs::write(alternates, ALTERNATES).map_err(|error| error.to_string())?;
    }

    let listed = run(
        &cache,
        &["for-each-ref", "--format=%(refname:strip=2)", "refs/heads/"],
    )?;
    let mut updates = String::new();
    for (branch, oid) in tips {
        updates.push_str(&format!("update refs/heads/{branch} {}\n", oid.string()?));
    }
    for branch in listed.lines().filter(|branch| !tips.contains_key(*branch)) {
        updates.push_str(&format!("delete refs/heads/{branch}\n"));
    }
    if !updates.is_empty() {
        successful(git(&cache, &["update-ref", "--stdin"], Some(&updates))?)?;
    }
    if let Some(branch) = default
        .filter(|branch| tips.contains_key(*branch))
        .or_else(|| tips.keys().next().map(String::as_str))
    {
        run(
            &cache,
            &["symbolic-ref", "HEAD", &format!("refs/heads/{branch}")],
        )?;
    }
    // The dedicated bare replica only exposes signed branch tips.
    run(
        root,
        &[
            "-c",
            "protocol.file.allow=always",
            "fetch",
            "--no-tags",
            "--prune",
            "team",
        ],
    )?;
    Ok(Value::Object(BTreeMap::from([
        ("remote".into(), Value::String("team".into())),
        ("refs".into(), Value::Object(tips.clone())),
    ])))
}
