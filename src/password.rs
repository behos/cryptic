use rpassword::read_password;
use std::io::{stdout, Write};

pub fn get_password(confirm: bool) -> String {
    let password = read_required_input("Please enter password");
    if confirm {
        let confirmation = read_required_input("Please confirm password");
        if confirmation != password {
            panic!("Password and confirmation do not match")
        }
    }
    password
}

fn read_required_input(prompt: &str) -> String {
    let mut input = String::new();
    while input.is_empty() {
        input = read_input(prompt)
    }
    input
}

fn read_input(prompt: &str) -> String {
    print!("{}: ", prompt);
    let _ = stdout().flush();
    read_password().unwrap_or_default()
}
