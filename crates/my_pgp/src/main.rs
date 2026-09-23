use std::process;

fn main() {
    match cli::parse(std::env::args().skip(1)) {
        Ok(cli::Outcome::Usage(usage)) => println!("{usage}"),
        Ok(cli::Outcome::Run(_)) => {}
        Err(err) => {
            eprintln!("{err}");
            process::exit(core::EXIT_CODE);
        }
    }
}
