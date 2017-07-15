#![feature(conservative_impl_trait)]

extern crate clap;
extern crate rand;
extern crate ring;
extern crate rpassword;

mod encryptor;
mod password;

use clap::{App, ArgMatches, YamlLoader};

use encryptor::{encrypt, decrypt};
use password::get_password;


fn main() {
    let yaml_str = include_str!("cli.yml");
    let yaml = YamlLoader::load_from_str(yaml_str)
        .expect("Failed to load argument config");
    let matches = App::from_yaml(&yaml[0]).get_matches();

    match matches.subcommand() {
        ("encrypt", Some(matches)) => encrypt_subcommand(matches),
        ("decrypt", Some(matches)) => decrypt_subcommand(matches),
        _ => println!("Unrecognized command")
    }
}

fn encrypt_subcommand(matches: &ArgMatches) {
    let key = get_password(true);
    let input_file = matches.value_of("INPUT").expect("Missing input argument");
    let output_file = match matches.value_of("output") {
        Some(output_file) => output_file.to_string(),
        None => format!("{}.cryptic", input_file)
    };
    encrypt(input_file, &output_file, &key)
}

fn decrypt_subcommand(matches: &ArgMatches) {
    let key = get_password(false);
    let input_file = matches.value_of("INPUT").expect("Missing input argument");
    let output_file = match matches.value_of("output") {
        Some(output_file) => output_file.to_string(),
        None => format!("{}.decryptic", input_file)
    };
    decrypt(input_file, &output_file, &key)
}
