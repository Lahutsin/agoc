use clap::Parser;

fn main() {
    if let Err(error) = agoc::tray::run(agoc::tray::Options::parse()) {
        eprintln!("ERROR: {error:#}");
        std::process::exit(1);
    }
}
