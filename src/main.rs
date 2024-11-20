mod encryptor;
mod password;

use anyhow::{Context, Result};
use clap::{App, YamlLoader};

use encryptor::{decrypt, encrypt};
use password::get_password;

fn main() -> Result<()> {
    let yaml_str = include_str!("cli.yml");
    let yaml = YamlLoader::load_from_str(yaml_str).context("Failed to load argument config")?;
    let m = App::from_yaml(&yaml[0]).get_matches();
    let (matches, command): (_, fn(&str, &str) -> Result<()>) = match m.subcommand() {
        Some(("encrypt", matches)) => (matches, encrypt_subcommand),
        Some(("decrypt", matches)) => (matches, decrypt_subcommand),
        _ => panic!("Unrecognized command"),
    };

    let input_file = matches
        .value_of("INPUT")
        .context("Missing input argument")?;
    let output_file = match matches.value_of("output") {
        Some(output_file) => output_file.to_string(),
        None => format!("{}.cpt", input_file),
    };

    command(input_file, &output_file)
}

fn encrypt_subcommand(input_file: &str, output_file: &str) -> Result<()> {
    let key = get_password(true);
    encrypt(input_file, &output_file, &key)
}

fn decrypt_subcommand(input_file: &str, output_file: &str) -> Result<()> {
    let key = get_password(false);
    decrypt(input_file, &output_file, &key)
}
