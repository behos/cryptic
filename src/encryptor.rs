use std::fs::File;
use std::io::{Read, Write, BufReader, BufWriter};
use std::iter::Iterator;

use rand::{Rng, OsRng};
use ring::aead::{
    seal_in_place, SealingKey,
    open_in_place, OpeningKey,
    AES_256_GCM
};


const IV_SIZE: usize = 12;
const BLOCK_SIZE: usize = 100 * 1024;
const TAG_SIZE: usize = 16;
const ENCRYPTED_BLOCK_SIZE: usize = BLOCK_SIZE + TAG_SIZE;


struct BlockReader {
    reader: BufReader<File>,
    block_size: usize,
}

impl BlockReader {
    fn new(input_reader: BufReader<File>, block_size: usize) -> Self {
        Self {
            block_size: block_size,
            reader: input_reader,
        }
    }
}

impl Iterator for BlockReader {
    type Item = Vec<u8>;
    
    fn next(&mut self) -> Option<Self::Item> {
        let mut block = Vec::with_capacity(self.block_size);
        let mut buffer = vec![0; self.block_size];
        while block.len() < self.block_size {
            let remaining = self.block_size - block.len();
            if let Ok(fetched) = self.reader.read(&mut buffer[..remaining]) {
                if fetched == 0 {
                    return if block.len() > 0 { Some(block) } else { None }
                } else {
                    block.extend_from_slice(&mut buffer[..fetched])
                }
            }
        }
        Some(block)
    }
}

pub fn encrypt(input: &str, output: &str, key: &str) {
    let iv = generate_iv();
    let input_file = File::open(input)
        .expect("Could not open input file");

    let output_file = File::create(output)
        .expect("Could not open output file");

    let padded_key = key_with_padding(key.as_bytes());
    let sealing_key = SealingKey::new(&AES_256_GCM, &padded_key)
        .expect("Could not load encryption algorithm");

    let reader = BlockReader::new(BufReader::new(input_file), BLOCK_SIZE);
    let mut writer = BufWriter::new(output_file);

    writer.write(&iv).expect("Error writing to file");
    for block in reader {
        encrypt_and_write_block(&mut writer, block.to_vec(), &sealing_key, &iv)
    }
}

fn generate_iv() -> [u8; IV_SIZE] {
    let mut iv: [u8; IV_SIZE] = [0; IV_SIZE];
    let mut rng = OsRng::new().ok().expect("Couldn't initialize rand");
    rng.fill_bytes(&mut iv);
    iv
}

fn key_with_padding(key: &[u8]) -> [u8; 32]
{
    let mut padded_key: [u8; 32] = [127; 32];
    padded_key[..key.len()].copy_from_slice(key);
    padded_key
}

fn encrypt_and_write_block(
    writer: &mut Write, block: Vec<u8>, key: &SealingKey, iv: &[u8]
) {
    let encrypted = encrypt_block(block, &key, &iv);
    writer.write(&encrypted).expect("Error writing to file");
}

fn encrypt_block(block: Vec<u8>, key: &SealingKey, iv: &[u8]) -> Vec<u8> {
    let mut in_out = vec![0; block.len() + TAG_SIZE];
    in_out[..block.len()].copy_from_slice(&block);
    seal_in_place(&key, &iv, &[0; 0], &mut in_out, TAG_SIZE)
        .expect("Error during encryption");
    in_out
}

pub fn decrypt(input: &str, output: &str, key: &str) {
    let input_file = File::open(input)
        .expect("Could not open input file");

    let output_file = File::create(output)
        .expect("Could not open output file");

    let padded_key = key_with_padding(key.as_bytes());
    let opening_key = OpeningKey::new(&AES_256_GCM, &padded_key)
        .expect("Could not load encryption algorithm");

    let mut reader = BufReader::new(input_file);
    let mut iv: [u8; IV_SIZE] = [0; IV_SIZE];
    reader.read_exact(&mut iv).expect("Could not read from file");

    let block_reader = BlockReader::new(reader, ENCRYPTED_BLOCK_SIZE);
    let mut writer = BufWriter::new(output_file);

    for block in block_reader {
        decrypt_and_write_block(&mut writer, block.to_vec(), &opening_key, &iv)
    }
}

fn decrypt_and_write_block(
    writer: &mut Write, block: Vec<u8>, key: &OpeningKey, iv: &[u8]
) {
    let decrypted = decrypt_block(block, &key, &iv);
    writer.write(&decrypted).expect("Error writing to file");
}


fn decrypt_block(
    mut block: Vec<u8>, key: &OpeningKey, iv: &[u8]
) -> Vec<u8> {
    open_in_place(&key, &iv, &[0; 0], 0, &mut block)
        .expect("Error during decryption").to_vec()
}

#[cfg(test)]
mod test {

    use std::env;
    use std::io::{Read, Write};
    use std::fs::File;
    
    use super::{BLOCK_SIZE, encrypt, decrypt};

    const INITIAL: &'static str = "initial.txt";
    const LARGE: &'static str = "large.txt";
    const ENCRYPTED: &'static str = "encrypted.txt";
    const DECRYPTED: &'static str = "decrypted.txt";

    fn get_test_file(file_name: &str) -> String {
        let mut path = env::current_dir().unwrap();
        path.push("test_data");
        path.push(file_name);
        path.to_str().unwrap().to_string()
    }
    
    #[test]
    fn can_encrypt_file() {

        let initial = get_test_file(INITIAL);
        let encrypted = get_test_file(ENCRYPTED);
        let decrypted = get_test_file(DECRYPTED);
        let password = "hellopassword".to_string();
        encrypt(&initial, &encrypted, &password);
        decrypt(&encrypted, &decrypted, &password);

        let mut initial_file = File::open(initial).unwrap();
        let mut decrypted_file = File::open(decrypted).unwrap();

        let mut initial_content = String::new();
        let mut decrypted_content = String::new();
        initial_file.read_to_string(&mut initial_content).ok();
        decrypted_file.read_to_string(&mut decrypted_content).ok();
        assert_eq!(initial_content, decrypted_content)
    }

    #[test]
    #[should_panic]
    fn decrypt_fails_on_wrong_password() {

        let initial = get_test_file(INITIAL);
        let encrypted = get_test_file(ENCRYPTED);
        let decrypted = get_test_file(DECRYPTED);
        let password = "hellopassword".to_string();
        let wrong_password = "hellopasswords".to_string();
        encrypt(&initial, &encrypted, &password);
        decrypt(&encrypted, &decrypted, &wrong_password);
    }

    #[test]
    fn can_encrypt_file_larger_than_block_size() {

        let file_size = BLOCK_SIZE * 2 + 109;
        let block = vec![115; file_size];

        let large = get_test_file(LARGE);
        let mut large_file = File::create(large).unwrap();
        large_file.write_all(&block).ok();

        let initial = get_test_file(LARGE);
        let encrypted = get_test_file(ENCRYPTED);
        let decrypted = get_test_file(DECRYPTED);
        let password = "hellopassword".to_string();
        encrypt(&initial, &encrypted, &password);
        decrypt(&encrypted, &decrypted, &password);

        let mut initial_file = File::open(initial).unwrap();
        let mut decrypted_file = File::open(decrypted).unwrap();

        let mut initial_content = String::new();
        let mut decrypted_content = String::new();
        initial_file.read_to_string(&mut initial_content).ok();
        decrypted_file.read_to_string(&mut decrypted_content).ok();
        assert_eq!(initial_content, decrypted_content)
    }

}
