use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::iter::Iterator;
use std::result::Result as StdResult;

use rand::{OsRng, Rng};
use ring::aead::{open_in_place, seal_in_place, AES_256_GCM, OpeningKey, SealingKey};

use errors::CrypticError;

const IV_SIZE: usize = 12;
const BLOCK_SIZE: usize = 100 * 1024;
const TAG_SIZE: usize = 16;
const ENCRYPTED_BLOCK_SIZE: usize = BLOCK_SIZE + TAG_SIZE;

type Result<T> = StdResult<T, CrypticError>;

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
                    return if block.len() > 0 { Some(block) } else { None };
                } else {
                    block.extend_from_slice(&mut buffer[..fetched])
                }
            }
        }
        Some(block)
    }
}

trait Processor {
    fn process(&self, input: &str, output: &str) -> Result<()> {
        let input_file = File::open(input)?;
        let output_file = File::create(output)?;
        let mut reader = BufReader::new(input_file);
        let mut writer = BufWriter::new(output_file);
        let iv = self.process_iv(&mut reader, &mut writer)?;
        let block_reader = BlockReader::new(reader, Self::get_block_size());
        for block in block_reader {
            let processed = self.process_block(block.to_vec(), &iv)?;
            writer.write(&processed)?;
        }
        Ok(())
    }

    fn process_iv(
        &self,
        reader: &mut BufReader<File>,
        writer: &mut BufWriter<File>,
    ) -> Result<[u8; IV_SIZE]>;

    fn process_block(&self, block: Vec<u8>, iv: &[u8]) -> Result<Vec<u8>>;
    fn get_block_size() -> usize;
}

struct Encryptor {
    sealing_key: SealingKey,
}

impl Encryptor {
    fn new(key: &str) -> Self {
        let padded_key = key_with_padding(key.as_bytes());
        Self {
            sealing_key: SealingKey::new(&AES_256_GCM, &padded_key)
                .expect("Failed initializing algorithm"),
        }
    }
}

impl Processor for Encryptor {
    fn process_iv(
        &self,
        _: &mut BufReader<File>,
        writer: &mut BufWriter<File>,
    ) -> Result<[u8; IV_SIZE]> {
        let mut iv: [u8; IV_SIZE] = [0; IV_SIZE];
        let mut rng = OsRng::new().ok().expect("Couldn't initialize rand");
        rng.fill_bytes(&mut iv);
        writer.write(&iv)?;
        Ok(iv)
    }

    fn process_block(&self, block: Vec<u8>, iv: &[u8]) -> Result<Vec<u8>> {
        let mut in_out = vec![0; block.len() + TAG_SIZE];
        in_out[..block.len()].copy_from_slice(&block);
        seal_in_place(&self.sealing_key, &iv, &[0; 0], &mut in_out, TAG_SIZE)
            .expect("Unexpected error during encryption");
        Ok(in_out)
    }

    fn get_block_size() -> usize {
        BLOCK_SIZE
    }
}

fn key_with_padding(key: &[u8]) -> [u8; 32] {
    let mut padded_key: [u8; 32] = [127; 32];
    padded_key[..key.len()].copy_from_slice(key);
    padded_key
}

struct Decryptor {
    opening_key: OpeningKey,
}

impl Decryptor {
    fn new(key: &str) -> Self {
        let padded_key = key_with_padding(key.as_bytes());
        Self {
            opening_key: OpeningKey::new(&AES_256_GCM, &padded_key)
                .expect("Failed initializing algorithm"),
        }
    }
}

impl Processor for Decryptor {
    fn process_iv(
        &self,
        reader: &mut BufReader<File>,
        _: &mut BufWriter<File>,
    ) -> Result<[u8; IV_SIZE]> {
        let mut iv: [u8; IV_SIZE] = [0; IV_SIZE];
        reader.read_exact(&mut iv)?;
        Ok(iv)
    }

    fn process_block(&self, mut block: Vec<u8>, iv: &[u8]) -> Result<Vec<u8>> {
        let processed = open_in_place(&self.opening_key, &iv, &[0; 0], 0, &mut block)?;
        Ok(processed.to_vec())
    }

    fn get_block_size() -> usize {
        ENCRYPTED_BLOCK_SIZE
    }
}

pub fn encrypt(input: &str, output: &str, key: &str) -> Result<()> {
    Encryptor::new(key).process(input, output)
}

pub fn decrypt(input: &str, output: &str, key: &str) -> Result<()> {
    Decryptor::new(key).process(input, output)
}

#[cfg(test)]
mod test {

    use std::env;
    use std::fs::File;
    use std::io::{Read, Write};

    use super::{decrypt, encrypt, BLOCK_SIZE};

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
        encrypt(&initial, &encrypted, &password).ok();
        decrypt(&encrypted, &decrypted, &password).ok();

        let mut initial_file = File::open(initial).unwrap();
        let mut decrypted_file = File::open(decrypted).unwrap();

        let mut initial_content = String::new();
        let mut decrypted_content = String::new();
        initial_file.read_to_string(&mut initial_content).ok();
        decrypted_file.read_to_string(&mut decrypted_content).ok();
        assert_eq!(initial_content, decrypted_content)
    }

    #[test]
    fn decrypt_fails_on_wrong_password() {
        let initial = get_test_file(INITIAL);
        let encrypted = get_test_file(ENCRYPTED);
        let decrypted = get_test_file(DECRYPTED);
        let password = "hellopassword".to_string();
        let wrong_password = "hellopasswords".to_string();
        encrypt(&initial, &encrypted, &password).ok();
        let res = decrypt(&encrypted, &decrypted, &wrong_password);
        assert!(res.is_err())
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
        encrypt(&initial, &encrypted, &password).ok();
        decrypt(&encrypted, &decrypted, &password).ok();

        let mut initial_file = File::open(initial).unwrap();
        let mut decrypted_file = File::open(decrypted).unwrap();

        let mut initial_content = String::new();
        let mut decrypted_content = String::new();
        initial_file.read_to_string(&mut initial_content).ok();
        decrypted_file.read_to_string(&mut decrypted_content).ok();
        assert_eq!(initial_content, decrypted_content)
    }

}
