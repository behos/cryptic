mod encryptor;
mod password;

use anyhow::Result;
use clap::Parser;

use encryptor::{decrypt, encrypt};
use password::get_password;

#[derive(Debug, Parser)]
#[command(name = "cryptic")]
#[command(about = "CLI for quick password encryption and decryption of files")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    #[command(arg_required_else_help = true)]
    Encrypt {
        #[arg(value_name = "INPUT")]
        input: String,
        #[arg(short, long)]
        output: Option<String>,
    },
    #[command(arg_required_else_help = true)]
    Decrypt {
        #[arg(value_name = "INPUT")]
        input: String,
        #[arg(short, long)]
        output: Option<String>,
    },
}

fn main() -> Result<()> {
    let args = Cli::parse();
    match args.command {
        Command::Encrypt { input, output } => {
            encrypt_subcommand(&input, &output.unwrap_or_else(|| input.clone() + ".cpt"))
        }
        Command::Decrypt { input, output } => {
            decrypt_subcommand(&input, &output.unwrap_or_else(|| input.clone() + ".cpt"))
        }
    }
}

fn encrypt_subcommand(input_file: &str, output_file: &str) -> Result<()> {
    let key = get_password(true);
    encrypt(input_file, output_file, &key)
}

fn decrypt_subcommand(input_file: &str, output_file: &str) -> Result<()> {
    let key = get_password(false);
    decrypt(input_file, output_file, &key)
}
