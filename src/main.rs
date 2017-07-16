#![feature(conservative_impl_trait, box_syntax)]

extern crate clap;
extern crate rand;
extern crate ring;
extern crate rpassword;

mod encryptor;
mod errors;
mod password;

use clap::{App, YamlLoader};

use encryptor::{encrypt, decrypt};
use password::get_password;


fn main() {
    let yaml_str = include_str!("cli.yml");
    let yaml = YamlLoader::load_from_str(yaml_str)
        .expect("Failed to load argument config");
    let m = App::from_yaml(&yaml[0]).get_matches();
    let (matches, command): (_, Box<Fn(&str, &str)>) = match m.subcommand() {
            ("encrypt", Some(matches)) => (matches, box encrypt_subcommand),
            ("decrypt", Some(matches)) => (matches, box decrypt_subcommand),
            _ => panic!("Unrecognized command")
        };

    let input_file = matches.value_of("INPUT").expect("Missing input argument");
    let output_file = match matches.value_of("output") {
        Some(output_file) => output_file.to_string(),
        None => format!("{}.cpt", input_file)
    };

    command(input_file, &output_file)
}

fn encrypt_subcommand(input_file: &str, output_file: &str) {
    let key = get_password(true);
    if let Err(e) = encrypt(input_file, &output_file, &key) {
        println!("An error occurred: {}", e)
    }
}

fn decrypt_subcommand(input_file: &str, output_file: &str) {
    let key = get_password(false);
    if let Err(e) = decrypt(input_file, &output_file, &key) {
        println!("An error occurred: {}", e)
    }
}
