/// main.rs — dendec entry point
///
/// Wires together:
///   - clap CLI parsing (cli.rs)
///   - Secure password prompting via rpassword
///   - Encode/decode pipelines (encoding.rs)
///   - Error reporting
///
/// No crypto or encoding logic lives here — this is purely I/O glue.

mod cli;
mod crypto;
mod dna;
mod encoding;
mod error;

use clap::Parser;
use cli::{Cli, Command};
use error::DendecError;

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn run() -> error::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Encode { text, group } => {
            // Prompt for password and confirmation (hidden input)
            let password = rpassword::prompt_password("Enter password: ")
                .map_err(DendecError::Io)?;
            let confirm = rpassword::prompt_password("Confirm password: ")
                .map_err(DendecError::Io)?;

            if password != confirm {
                return Err(DendecError::PasswordMismatch);
            }

            if password.is_empty() {
                eprintln!("Warning: using an empty password provides no security.");
            }

            eprintln!("Encoding… (Argon2id key derivation may take a moment)");

            let dna = encoding::encode(&text, &password, group)?;
            println!("{dna}");
        }

        Command::Decode { dna } => {
            let password = rpassword::prompt_password("Enter password: ")
                .map_err(DendecError::Io)?;

            eprintln!("Decoding… (Argon2id key derivation may take a moment)");

            let text = encoding::decode(&dna, &password)?;
            println!("{text}");
        }
    }

    Ok(())
}

