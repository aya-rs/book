fn main() {
    if let Err(e) = try_main() {
        eprintln!("error: {:#}", e);
    }
}

fn try_main() -> Result<(), anyhow::Error> {
    Ok(())
}