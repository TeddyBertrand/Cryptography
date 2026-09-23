use std::io::{self, Write};
use std::panic;
use std::process;

fn main() {
    panic::set_hook(Box::new(|info| {
        eprintln!("{info}");
        process::exit(core::EXIT_CODE);
    }));

    let result = run().and_then(|output| {
        io::stdout()
            .write_all(&output)
            .and_then(|()| io::stdout().flush())
            .map_err(|err| core::Error::new(err.to_string()))
    });
    if let Err(err) = result {
        eprintln!("{err}");
        process::exit(core::EXIT_CODE);
    }
}

/// Output is buffered and only written once the whole command succeeded, so errors never leak partial stdout.
fn run() -> core::Result<Vec<u8>> {
    match cli::parse(std::env::args().skip(1))? {
        cli::Outcome::Usage(usage) => Ok(format!("{usage}\n").into_bytes()),
        cli::Outcome::Run(_) => Ok(Vec::new()),
    }
}
