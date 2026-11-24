fn main() {
    for asset in ["frontend", "icons/icon.png", "Info.plist", "permissions"] {
        println!("cargo:rerun-if-changed={asset}");
    }
    tauri_build::build();
}
