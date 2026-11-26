// Release builds on Windows have no console window; diagnostics go to
// %LOCALAPPDATA%\agoc\agoc-tray.log instead.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use clap::Parser;

fn main() {
    if let Err(error) = agoc::tray::run(agoc::tray::Options::parse()) {
        eprintln!("ERROR: {error:#}");
        std::process::exit(1);
    }
}
