use clap::{Parser, Subcommand};

/// dendec — DNA Encode/Decode
///
/// Encodes arbitrary Unicode text into a DNA base sequence (A/T/G/C)
/// and decodes it back. All data is password-protected with modern
/// authenticated encryption (ChaCha20-Poly1305 + Argon2id).
#[derive(Parser, Debug)]
#[command(
    name = "dendec",
    author,
    version,
    about = "Password-based encrypted Unicode ↔ DNA encoding",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Encode Unicode text into an encrypted DNA sequence
    ///
    /// You will be prompted to enter and confirm a password.
    /// The output is a continuous A/T/G/C string that can only be
    /// decoded with the same password.
    Encode {
        /// The Unicode text to encode (supports emoji, newlines, all UTF-8)
        text: String,

        /// Display DNA output in groups of N bases (default: continuous)
        #[arg(short, long, value_name = "N")]
        group: Option<usize>,
    },

    /// Decode an encrypted DNA sequence back to Unicode text
    ///
    /// You will be prompted to enter the password used during encoding.
    /// Wrong password or corrupted data will produce a clear error.
    Decode {
        /// The DNA sequence to decode (only A, T, G, C characters)
        dna: String,
    },
}

