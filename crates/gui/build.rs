fn main() {
    // Embed the Windows application icon (Explorer / taskbar / titlebar) into unitylan-gui.exe.
    // Only runs when building on Windows, where the MSVC resource compiler is present — that's the
    // official packaging path (packaging/windows/build.ps1). Builds on other hosts skip it, so a
    // resource compiler is never required off-Windows.
    #[cfg(windows)]
    {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("../../assets/icon.ico");
        if let Err(e) = res.compile() {
            println!("cargo:warning=failed to embed exe icon: {e}");
        }
    }
}
