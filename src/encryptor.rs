use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    iter::Iterator,
    result::Result as StdResult,
};

use anyhow::{anyhow, Context, Result};
use rand::{rngs::OsRng, RngCore};
use ring::{
    aead::{
        Aad as RingAad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey,
        AES_256_GCM, NONCE_LEN,
    },
    error::Unspecified,
};

const LEN_SIZE: usize = u32::BITS as usize / 8;
const IV_SIZE: usize = 12;
const BLOCK_SIZE: usize = 100 * 1024;
const TAG_SIZE: usize = 16;
const ENCRYPTED_BLOCK_SIZE: usize = LEN_SIZE + BLOCK_SIZE + TAG_SIZE;

type Aad = RingAad<[u8; IV_SIZE]>;

struct NonceSequencer {
    counter: u128,
}

impl NonceSequencer {
    fn new(bytes: &[u8]) -> Self {
        let mut padded_bytes = [0; 16];
        for (i, b) in bytes.iter().take(16).enumerate() {
            padded_bytes[i] = *b;
        }
        let counter = u128::from_le_bytes(padded_bytes);
        Self { counter }
    }
}

impl NonceSequence for NonceSequencer {
    fn advance(&mut self) -> StdResult<Nonce, Unspecified> {
        self.counter += 1;
        let mut nonce_array = [0; NONCE_LEN];
        for (i, v) in self.counter.to_le_bytes()[..12].iter().enumerate() {
            nonce_array[i] = *v;
        }
        Nonce::try_assume_unique_for_key(&nonce_array)
    }
}

struct BlockReader {
    reader: BufReader<File>,
    block_size: usize,
}

impl BlockReader {
    fn new(input_reader: BufReader<File>, block_size: usize) -> Self {
        Self {
            block_size,
            reader: input_reader,
        }
    }
}

impl Iterator for BlockReader {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut buffer = vec![0; self.block_size];
        let mut filled = 0;
        while filled < self.block_size {
            if let Ok(fetched) = self.reader.read(&mut buffer[filled..]) {
                if fetched == 0 {
                    return if filled > 0 {
                        Some(buffer[..filled].to_vec())
                    } else {
                        None
                    };
                } else {
                    filled += fetched
                }
            }
        }
        Some(buffer)
    }
}

trait Processor {
    fn process(&mut self, input: &str, output: &str) -> Result<()> {
        let input_file = File::open(input).context("failed to open input file")?;
        let output_file = File::create(output).context("failed to open output file")?;
        let mut reader = BufReader::new(input_file);
        let mut writer = BufWriter::new(output_file);
        let iv = self
            .process_iv(&mut reader, &mut writer)
            .context("failed to process iv")?;
        let block_reader = BlockReader::new(reader, Self::get_block_size() as usize);
        for mut block in block_reader {
            let processed = self
                .process_block(&mut block, &iv)
                .context("failed to process block")?;
            writer.write(&processed)?;
        }
        Ok(())
    }

    fn process_iv(&self, reader: &mut BufReader<File>, writer: &mut BufWriter<File>)
        -> Result<Aad>;

    fn process_block(&mut self, block: &mut [u8], iv: &Aad) -> Result<Vec<u8>>;
    fn get_block_size() -> usize;
}

struct Encryptor {
    sealing_key: SealingKey<NonceSequencer>,
}

impl Encryptor {
    fn new(key: &str) -> Result<Self> {
        let nonce_seq = NonceSequencer::new(key.as_bytes());
        let key = key_with_padding(key.as_bytes());
        let key =
            UnboundKey::new(&AES_256_GCM, &key).map_err(|_| anyhow!("failed to create key"))?;
        let sealing_key = SealingKey::new(key, nonce_seq);
        Ok(Self { sealing_key })
    }
}

fn key_with_padding(key: &[u8]) -> [u8; 32] {
    let mut padded_key: [u8; 32] = [127; 32];
    padded_key[..key.len()].copy_from_slice(key);
    padded_key
}

impl Processor for Encryptor {
    fn process_iv(&self, _: &mut BufReader<File>, writer: &mut BufWriter<File>) -> Result<Aad> {
        let mut iv: [u8; IV_SIZE] = [0; IV_SIZE];
        let mut rng = OsRng::default();
        rng.fill_bytes(&mut iv);
        writer.write(&iv).context("failed to write to file")?;
        Ok(Aad::from(iv))
    }

    fn process_block(&mut self, block: &mut [u8], iv: &Aad) -> Result<Vec<u8>> {
        let mut in_out = vec![0; ENCRYPTED_BLOCK_SIZE - TAG_SIZE];
        let block_len = (block.len() as u32).to_le_bytes();
        in_out[..LEN_SIZE].copy_from_slice(&block_len);
        in_out[LEN_SIZE..LEN_SIZE + block.len()].copy_from_slice(&block);
        self.sealing_key
            .seal_in_place_append_tag(*iv, &mut in_out)
            .map_err(|_| anyhow!("failed to seal in place"))?;
        Ok(in_out)
    }

    fn get_block_size() -> usize {
        BLOCK_SIZE
    }
}

struct Decryptor {
    opening_key: OpeningKey<NonceSequencer>,
}

impl Decryptor {
    fn new(key: &str) -> Result<Self> {
        let nonce_seq = NonceSequencer::new(key.as_bytes());
        let key = key_with_padding(key.as_bytes());
        let key =
            UnboundKey::new(&AES_256_GCM, &key).map_err(|_| anyhow!("failed to create key"))?;
        let opening_key = OpeningKey::new(key, nonce_seq);
        Ok(Self { opening_key })
    }
}

impl Processor for Decryptor {
    fn process_iv(&self, reader: &mut BufReader<File>, _: &mut BufWriter<File>) -> Result<Aad> {
        let mut iv: [u8; IV_SIZE] = [0; IV_SIZE];
        reader.read_exact(&mut iv)?;
        Ok(Aad::from(iv))
    }

    fn process_block(&mut self, mut block: &mut [u8], iv: &Aad) -> Result<Vec<u8>> {
        let processed = self
            .opening_key
            .open_in_place(*iv, &mut block)
            .map_err(|_| anyhow!("failed to open in place"))?;
        let mut block_len_bytes = [0; LEN_SIZE];
        block_len_bytes.copy_from_slice(&processed[..LEN_SIZE]);
        let block_len = u32::from_le_bytes(block_len_bytes) as usize;
        let start = LEN_SIZE;
        let end = start + block_len;
        Ok(processed[start..end].to_vec())
    }

    fn get_block_size() -> usize {
        ENCRYPTED_BLOCK_SIZE
    }
}

pub fn encrypt(input: &str, output: &str, key: &str) -> Result<()> {
    Encryptor::new(key)
        .context("failed to create encryptor")?
        .process(input, output)
}

pub fn decrypt(input: &str, output: &str, key: &str) -> Result<()> {
    Decryptor::new(key)
        .context("failed to create decryptor")?
        .process(input, output)
}

#[cfg(test)]
mod test {

    use std::env;
    use std::fs::File;
    use std::io::{Read, Write};

    use tempfile::NamedTempFile;

    use super::{decrypt, encrypt, BLOCK_SIZE};

    const INITIAL: &'static str = "initial.txt";
    const LARGE: &'static str = "large.txt";

    fn get_test_file(file_name: &str) -> String {
        let mut path = env::current_dir().unwrap();
        path.push("test_data");
        path.push(file_name);
        path.to_str().unwrap().to_string()
    }

    #[test]
    fn can_encrypt_file() {
        let initial = get_test_file(INITIAL);
        let tmp_file = NamedTempFile::new().expect("failed to create tmpfile");
        let encrypted = tmp_file.path().to_str().unwrap().to_string();
        let tmp_file = NamedTempFile::new().expect("failed to create tmpfile");
        let decrypted = tmp_file.path().to_str().unwrap().to_string();
        let password = "hellopassword".to_string();
        encrypt(&initial, &encrypted, &password).expect("failed to encrypt");
        decrypt(&encrypted, &decrypted, &password).expect("failed to decrypt");

        let mut initial_file = File::open(initial).unwrap();
        let mut decrypted_file = File::open(decrypted).unwrap();

        let mut initial_content = String::new();
        let mut decrypted_content = String::new();
        initial_file
            .read_to_string(&mut initial_content)
            .expect("failed to read");
        decrypted_file
            .read_to_string(&mut decrypted_content)
            .expect("failed to read");
        assert_eq!(initial_content, decrypted_content)
    }

    #[test]
    fn decrypt_fails_on_wrong_password() {
        let initial = get_test_file(INITIAL);
        let tmp_file = NamedTempFile::new().expect("failed to create tmpfile");
        let encrypted = tmp_file.path().to_str().unwrap().to_string();
        let tmp_file = NamedTempFile::new().expect("failed to create tmpfile");
        let decrypted = tmp_file.path().to_str().unwrap().to_string();
        let password = "hellopassword".to_string();
        let wrong_password = "hellopasswords".to_string();
        encrypt(&initial, &encrypted, &password).expect("failed to encrypt");
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
        let tmp_file = NamedTempFile::new().expect("failed to create tmpfile");
        let encrypted = tmp_file.path().to_str().unwrap().to_string();
        let tmp_file = NamedTempFile::new().expect("failed to create tmpfile");
        let decrypted = tmp_file.path().to_str().unwrap().to_string();
        let password = "hellopassword".to_string();
        encrypt(&initial, &encrypted, &password).expect("failed to encrypt");
        decrypt(&encrypted, &decrypted, &password).expect("failed to decrypt");

        let mut initial_file = File::open(initial).unwrap();
        let mut decrypted_file = File::open(decrypted).unwrap();

        let mut initial_content = String::new();
        let mut decrypted_content = String::new();
        initial_file
            .read_to_string(&mut initial_content)
            .expect("failed to read");
        decrypted_file
            .read_to_string(&mut decrypted_content)
            .expect("failed to read");
        assert_eq!(initial_content, decrypted_content)
    }
}
