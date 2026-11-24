use peertree::desktop_session::{DesktopSession, WorkspaceRequest};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use tauri::{webview::NewWindowResponse, Manager, WebviewUrl, WebviewWindow, WebviewWindowBuilder};
use tauri_plugin_dialog::DialogExt;

#[derive(Default)]
struct Repository {
    starting: AtomicBool,
    session: Mutex<Option<DesktopSession>>,
}

impl Repository {
    fn close(&self) {
        if let Ok(mut service) = self.session.lock() {
            service.take();
        }
    }
}

struct Opening<'a>(&'a AtomicBool);

impl Drop for Opening<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn from_launcher(window: &WebviewWindow) -> Result<(), String> {
    if window.label() == "launcher" {
        Ok(())
    } else {
        Err("Open repositories from the PeerTree launcher.".into())
    }
}

fn service_script(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let resource = app.path().resource_dir().ok().map(|dir| dir.join("app.py"));
    #[cfg(debug_assertions)]
    let source = Some(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../app.py"));
    #[cfg(not(debug_assertions))]
    let source = None;
    resource
        .into_iter()
        .chain(source)
        .find(|path| path.is_file())
        .ok_or_else(|| "The PeerTree repository service is missing from this app.".into())
}

#[tauri::command]
fn initial_workspace(window: WebviewWindow) -> Result<Option<(String, bool)>, String> {
    from_launcher(&window)?;
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().is_some_and(|arg| arg == "--repo") {
        let folder = arguments
            .next()
            .and_then(|path| path.into_string().ok())
            .ok_or("Provide a Git worktree after --repo.")?;
        let peer = arguments.any(|arg| arg == "--peer");
        Ok(Some((folder, peer)))
    } else {
        Ok(None)
    }
}

#[tauri::command]
async fn choose_folder(
    app: tauri::AppHandle,
    window: WebviewWindow,
    clone: bool,
) -> Result<Option<String>, String> {
    from_launcher(&window)?;
    tauri::async_runtime::spawn_blocking(move || -> Result<Option<String>, String> {
        let title = if clone {
            "Choose an empty folder for the clone"
        } else {
            "Choose a Git worktree"
        };
        let result = app
            .dialog()
            .file()
            .set_title(title)
            .set_parent(&window)
            .set_can_create_directories(clone)
            .blocking_pick_folder();
        result
            .map(|file| {
                let path = file.into_path().map_err(|error| error.to_string())?;
                path.into_os_string()
                    .into_string()
                    .map_err(|_| "Choose a folder with a UTF-8 path.".into())
            })
            .transpose()
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn open_workspace(
    app: tauri::AppHandle,
    window: WebviewWindow,
    folder: String,
    clone_project: Option<String>,
    enable_peer: bool,
) -> Result<(), String> {
    from_launcher(&window)?;
    let repository = app.state::<Repository>();
    if repository.starting.swap(true, Ordering::AcqRel) {
        return Err("PeerTree is already opening a repository.".into());
    }
    let _opening = Opening(&repository.starting);
    if let Some(review) = app.get_webview_window("review") {
        review.set_focus().map_err(|error| error.to_string())?;
        return Ok(());
    }
    let folder = PathBuf::from(folder);
    if !folder.is_absolute() {
        return Err("Choose a folder or enter its absolute path.".into());
    }
    let script = service_script(&app)?;
    let request = WorkspaceRequest {
        folder,
        clone_project,
        enable_peer,
    };
    let session =
        tauri::async_runtime::spawn_blocking(move || DesktopSession::start(&script, request))
            .await
            .map_err(|error| error.to_string())??;
    let url: tauri::Url = format!("{}/", session.origin())
        .parse()
        .map_err(|_| "Invalid local address reported by PeerTree.")?;
    let origin = url.origin();
    // Cancel the launch if its window closed while the service was starting.
    if app.get_webview_window("launcher").is_none() {
        return Err("The repository launcher was closed.".into());
    }
    *repository
        .session
        .lock()
        .map_err(|_| "The repository session is unavailable.")? = Some(session);
    let review = WebviewWindowBuilder::new(&app, "review", WebviewUrl::External(url))
        .title("PeerTree")
        .inner_size(1180.0, 780.0)
        .min_inner_size(640.0, 440.0)
        .on_navigation(move |target| target.origin() == origin)
        .on_new_window(|_, _| NewWindowResponse::Deny)
        .disable_drag_drop_handler()
        .build();
    if let Err(error) = review {
        repository.close();
        return Err(error.to_string());
    }
    let _ = window.hide();
    Ok(())
}

fn main() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(Repository::default())
        .invoke_handler(tauri::generate_handler![
            initial_workspace,
            choose_folder,
            open_workspace
        ])
        .setup(|app| {
            WebviewWindowBuilder::new(app, "launcher", WebviewUrl::App("index.html".into()))
                .title("PeerTree")
                .inner_size(540.0, 520.0)
                .min_inner_size(420.0, 480.0)
                .on_navigation(|url| url.scheme() == "tauri" && url.host_str() == Some("localhost"))
                .on_new_window(|_, _| NewWindowResponse::Deny)
                .build()?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if window.label() == "review" && matches!(event, tauri::WindowEvent::Destroyed) {
                let app = window.app_handle();
                app.state::<Repository>().close();
                if let Some(launcher) = app.get_webview_window("launcher") {
                    let _ = launcher.show();
                    let _ = launcher.set_focus();
                }
            }
        })
        .build(tauri::generate_context!())
        .expect("could not load the PeerTree desktop shell");
    app.run(|app, event| {
        if matches!(event, tauri::RunEvent::Exit) {
            app.state::<Repository>().close();
        }
    });
}
