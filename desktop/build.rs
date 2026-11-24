fn main() {
    for asset in ["frontend", "Info.plist", "permissions"] {
        println!("cargo:rerun-if-changed={asset}");
    }
    tauri_build::build();
}
